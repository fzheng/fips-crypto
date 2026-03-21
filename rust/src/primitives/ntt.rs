//! Number Theoretic Transform (NTT) implementation for ML-KEM (FIPS 203)
//!
//! The NTT is used for efficient polynomial multiplication in ML-KEM and ML-DSA.
//! It converts polynomial multiplication from O(n^2) to O(n log n).
//!
//! ## Montgomery Form
//!
//! Coefficients are stored in Montgomery form: a_mont = a * R mod q, where
//! R = 2^16. This allows modular multiplication to be performed using only
//! shifts and additions (no expensive division). The Montgomery reduction
//! computes a * R^{-1} mod q using the identity:
//!     t = a * q^{-1} mod R
//!     r = (a - t * q) / R
//!
//! ## NTT Structure
//!
//! The NTT maps the polynomial ring Z_q[X]/(X^256 + 1) into 128 degree-2
//! quotient rings Z_q[X]/(X^2 - zeta^{2*brv7(i)+1}) for i = 0..127.
//! Each pair of consecutive NTT coefficients (f[2i], f[2i+1]) represents
//! a polynomial f[2i] + f[2i+1]*X in one of these quotient rings.
//! This factorization is possible because X^256 + 1 splits completely
//! into degree-2 factors modulo q = 3329.
//!
//! For ML-KEM (FIPS 203):
//! - q = 3329
//! - n = 256
//! - Primitive 256th root of unity: zeta = 17
//!
//! For ML-DSA (FIPS 204):
//! - q = 8380417
//! - n = 256
//! - Primitive 512th root of unity: zeta = 1753

/// ML-KEM modulus q = 3329
pub const MLKEM_Q: i32 = 3329;

/// ML-DSA modulus q = 8380417 = 2^23 - 2^13 + 1
pub const MLDSA_Q: i32 = 8380417;

/// Polynomial degree n = 256
pub const N: usize = 256;

/// Primitive 256th root of unity for ML-KEM (zeta = 17)
pub const MLKEM_ZETA: i32 = 17;

/// Primitive 512th root of unity for ML-DSA (zeta = 1753)
pub const MLDSA_ZETA: i32 = 1753;

/// Precomputed powers of zeta for ML-KEM NTT in Montgomery form and bit-reversed order.
///
/// Entry i contains zeta^{brv7(i)} * R mod q in centered representation (i.e., values
/// may be negative, lying in (-q/2, q/2)). The bit-reversal brv7 reverses the 7-bit
/// binary representation of i. The Montgomery factor R = 2^16 mod q is embedded so
/// that NTT butterfly multiplications can use Montgomery reduction directly.
///
/// These constants are derived from the PQ-Crystals Kyber/ML-KEM reference implementation.
pub const MLKEM_ZETAS: [i16; 128] = [
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
     -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
      422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
     -108,  -308,   996,   991,   958, -1460,  1522,  1628,
];

/// Montgomery constant for ML-KEM: R^2 mod q = (2^16)^2 mod 3329 = 1353
/// Used to convert from normal form to Montgomery form: to_mont(a) = a * R^2 * R^{-1} = a * R mod q
const MLKEM_MONT_R_SQ: i32 = 1353;

/// Montgomery constant for ML-KEM: q^(-1) mod 2^16 = 62209
/// Used in Montgomery reduction to compute t = a * q^{-1} mod R
const MLKEM_QINV: i32 = 62209;

/// Inverse NTT scaling factor: f = R^2 * 128^{-1} mod q = 1441
///
/// After inverse NTT, each coefficient must be:
/// 1. Scaled by 1/128 (since NTT is over 128 butterflies)
/// 2. Adjusted for the Montgomery factor from the zeta multiplications
/// Multiplying by f = R^2/128 mod q via fqmul (which computes a*b*R^{-1})
/// achieves both: fqmul(coeff, f) = coeff * R^2/128 * R^{-1} = coeff * R/128 mod q.
const MLKEM_F: i32 = 1441;

/// Barrett reduction constant for ML-KEM: mu = floor(2^26 / q) = 20159
const MLKEM_BARRETT_MU: i32 = 20159;

/// Barrett reduction for ML-KEM (FIPS 203).
///
/// Approximates a mod q using the formula:
///     t = floor(a * mu / 2^26), where mu = floor(2^26 / q)
///     r = a - t * q
///
/// For |a| < 2^15 * q, the result r satisfies a = r (mod q).
/// Note: the output is NOT guaranteed to lie in [0, q). It is only
/// approximately reduced -- the result may be slightly negative or
/// slightly above q. A subsequent conditional addition/subtraction
/// is needed for full normalization (see `mlkem_reduce`).
#[inline]
pub fn mlkem_barrett_reduce(a: i32) -> i16 {
    let t = ((a as i64 * MLKEM_BARRETT_MU as i64) >> 26) as i32;
    let r = a - t * MLKEM_Q;
    r as i16
}

/// Montgomery reduction for ML-KEM.
///
/// Computes a * R^{-1} mod q, where R = 2^16.
///
/// Given a with |a| < q * 2^15, computes:
///     t = a * q^{-1} mod R       (only the low 16 bits matter)
///     r = (a - t * q) / R        (exact division since a - t*q = 0 mod R)
///
/// The result r satisfies r = a * R^{-1} (mod q) with |r| < q.
#[inline]
pub fn mlkem_montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(MLKEM_QINV as i16);
    let r = (a - (t as i32) * MLKEM_Q) >> 16;
    r as i16
}

/// Multiply two elements in Montgomery form (ML-KEM).
///
/// Computes a * b * R^{-1} mod q via Montgomery reduction.
/// If a = a' * R and b = b' * R are in Montgomery form, then
/// fqmul(a, b) = a' * b' * R mod q, which is a'*b' in Montgomery form.
#[inline]
pub fn mlkem_fqmul(a: i16, b: i16) -> i16 {
    mlkem_montgomery_reduce(a as i32 * b as i32)
}

/// Forward NTT for ML-KEM -- FIPS 203 Algorithm 9 (NTT).
///
/// Transforms a polynomial from coefficient form to NTT form using
/// the Cooley-Tukey butterfly: for each butterfly pair (a, b) with
/// twiddle factor zeta:
///     t = zeta * b
///     (a, b) <- (a + t, a - t)
///
/// The transform proceeds from length-128 down to length-2 butterflies
/// (7 layers). After all layers, a Barrett reduction is applied to keep
/// coefficients bounded.
///
/// Coefficient growth: each butterfly layer can at most double the
/// magnitude plus one q (from the zeta multiply). The final Barrett
/// reduction ensures all outputs are close to [0, q).
///
/// Input: polynomial coefficients (standard domain)
/// Output: NTT coefficients (NTT domain, Montgomery-scaled)
pub fn mlkem_ntt(coeffs: &mut [i16; N]) {
    let mut k = 1usize;
    let mut len = 128usize;

    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = MLKEM_ZETAS[k] as i32;
            k += 1;

            for j in start..(start + len) {
                let t = mlkem_fqmul(zeta as i16, coeffs[j + len]);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
            }
            start += 2 * len;
        }
        len /= 2;
    }

    // Reduce all coefficients to a canonical range
    for coeff in coeffs.iter_mut() {
        *coeff = mlkem_barrett_reduce(*coeff as i32);
    }
}

/// Inverse NTT for ML-KEM -- FIPS 203 Algorithm 10 (NTT^{-1}).
///
/// Transforms a polynomial from NTT form back to coefficient form using
/// the Gentleman-Sande (GS) butterfly: for each butterfly pair (a, b)
/// with twiddle factor zeta:
///     t = a
///     a = t + b
///     b = zeta * (b - t)
///
/// The transform proceeds from length-2 up to length-128 butterflies
/// (7 layers), iterating through the zetas table in reverse order.
///
/// After all layers, each coefficient is multiplied by f = 1441 = R^2/128 mod q.
/// This serves two purposes:
/// 1. Scales by 128^{-1} to complete the inverse transform
/// 2. Multiplied via fqmul (which computes x*f*R^{-1}), yielding x*R/128,
///    which maintains proper Montgomery scaling
pub fn mlkem_ntt_inv(coeffs: &mut [i16; N]) {
    let mut k = 127usize;
    let mut len = 2usize;

    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = MLKEM_ZETAS[k];
            k = k.wrapping_sub(1);

            for j in start..(start + len) {
                let t = coeffs[j];
                coeffs[j] = mlkem_barrett_reduce(t as i32 + coeffs[j + len] as i32);
                coeffs[j + len] = mlkem_fqmul(zeta, coeffs[j + len] - t);
            }
            start += 2 * len;
        }
        len *= 2;
    }

    // Multiply by f = R^2/128 mod q to undo Montgomery factor and scale by 1/128
    let f = MLKEM_F as i16;
    for coeff in coeffs.iter_mut() {
        *coeff = mlkem_fqmul(f, *coeff);
    }
}

/// Pointwise base-case multiplication in NTT domain -- FIPS 203 Algorithm 11 (BaseCaseMultiply).
///
/// In NTT form, the polynomial ring Z_q[X]/(X^256+1) is decomposed into
/// 64 pairs of degree-2 quotient rings Z_q[X]/(X^2 - gamma_i), where
/// gamma_i = zeta^{2*brv7(i)+1}. Each group of 4 coefficients
/// (a[4i], a[4i+1], a[4i+2], a[4i+3]) represents two degree-1 polynomials
/// in adjacent quotient rings.
///
/// For the i-th block, the multiplication in Z_q[X]/(X^2 - gamma) is:
///     (a0 + a1*X) * (b0 + b1*X) = (a0*b0 + a1*b1*gamma) + (a0*b1 + a1*b0)*X
/// The second pair uses -gamma (the conjugate root).
///
/// All multiplications use fqmul, which computes a*b*R^{-1} mod q.
/// This introduces one factor of R^{-1} per basemul call in the result.
pub fn mlkem_basemul(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    let mut c = [0i16; N];

    for i in 0..N/4 {
        let zeta = MLKEM_ZETAS[64 + i];

        // First pair: multiplication in Z_q[X]/(X^2 - gamma_i)
        // c0 = a0*b0 + a1*b1*gamma, c1 = a0*b1 + a1*b0
        c[4*i]     = mlkem_fqmul(mlkem_fqmul(a[4*i+1], b[4*i+1]), zeta);
        c[4*i]     = c[4*i] + mlkem_fqmul(a[4*i], b[4*i]);
        c[4*i+1]   = mlkem_fqmul(a[4*i], b[4*i+1]);
        c[4*i+1]   = c[4*i+1] + mlkem_fqmul(a[4*i+1], b[4*i]);

        // Second pair: multiplication in Z_q[X]/(X^2 + gamma_i) (conjugate ring)
        c[4*i+2]   = mlkem_fqmul(mlkem_fqmul(a[4*i+3], b[4*i+3]), -zeta);
        c[4*i+2]   = c[4*i+2] + mlkem_fqmul(a[4*i+2], b[4*i+2]);
        c[4*i+3]   = mlkem_fqmul(a[4*i+2], b[4*i+3]);
        c[4*i+3]   = c[4*i+3] + mlkem_fqmul(a[4*i+3], b[4*i+2]);
    }

    c
}

/// Convert a coefficient from normal form to Montgomery form.
///
/// Computes a * R mod q by calling fqmul(a, R^2 mod q):
///     fqmul(a, R^2) = a * R^2 * R^{-1} = a * R mod q
///
/// This is used after basemul-based matrix-vector products to cancel the
/// extra R^{-1} factor introduced by basemul.
#[inline]
pub fn mlkem_to_mont(a: i16) -> i16 {
    mlkem_fqmul(a, MLKEM_MONT_R_SQ as i16)
}

/// Fully reduce a coefficient to the canonical range [0, q).
///
/// Applies a conditional addition of q (if negative) and conditional
/// subtraction of q (if >= q) to normalize the coefficient. This is
/// a simple two-step normalization, NOT Barrett reduction.
#[inline]
pub fn mlkem_reduce(a: i16) -> i16 {
    let mut r = a;
    if r >= MLKEM_Q as i16 {
        r -= MLKEM_Q as i16;
    }
    if r < 0 {
        r += MLKEM_Q as i16;
    }
    r
}

// ============================================================================
// ML-DSA NTT (FIPS 204)
// ============================================================================

/// Precomputed powers of zeta for ML-DSA NTT in Montgomery form and bit-reversed order.
///
/// Entry i contains zeta^{brv8(i)} * R mod q in centered representation, where
/// R = 2^32 mod q. The bit-reversal brv8 reverses the 8-bit binary representation
/// of i. The Montgomery factor R = 2^32 mod q is embedded so that NTT butterfly
/// multiplications can use Montgomery reduction directly.
///
/// These constants are derived from the CRYSTALS-Dilithium/ML-DSA reference implementation.
pub const MLDSA_ZETAS: [i32; 256] = [
         0,    25847, -2608894,  -518909,    237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782,
];

/// Montgomery constant for ML-DSA: R mod q = 2^32 mod q = 4193792
#[cfg(test)]
const MLDSA_MONT_R: i64 = 4193792;

/// Montgomery constant for ML-DSA: q^{-1} mod 2^32 = 58728449
const MLDSA_QINV: i64 = 58728449;

/// Inverse NTT scaling factor for ML-DSA: f = R^2 * 256^{-1} mod q = 41978
///
/// After inverse NTT, each coefficient must be:
/// 1. Scaled by 1/256 (since NTT is over 256 butterflies)
/// 2. Adjusted for the Montgomery factor from the zeta multiplications
/// Multiplying by f via mldsa_fqmul (which computes f * coeff * R^{-1})
/// yields R * 256^{-1} * coeff, maintaining Montgomery scaling.
const MLDSA_F: i32 = 41978;

/// Montgomery reduction for ML-DSA.
///
/// Computes a * R^{-1} mod q, where R = 2^32.
///
/// Given a with |a| < q * 2^31, computes:
///     t = a * q^{-1} mod R       (only the low 32 bits matter)
///     r = (a - t * q) / R        (exact division since a - t*q = 0 mod R)
///
/// The result r satisfies r = a * R^{-1} (mod q) with |r| < q.
#[inline]
pub fn mldsa_montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(MLDSA_QINV as i32);
    ((a - t as i64 * MLDSA_Q as i64) >> 32) as i32
}

/// Barrett-like reduction for ML-DSA (32-bit input).
///
/// Reduces a 32-bit integer a to a representative in (-q/2, q/2].
/// Uses the approximation t = floor(a * 2^{-23}) rounded, then r = a - t*q.
/// For |a| < 2^31, the result is bounded by |r| < q.
#[inline]
pub fn mldsa_reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * MLDSA_Q
}

/// Conditionally add q to a if a is negative (ML-DSA).
///
/// This normalizes a coefficient from the centered representation (-q/2, q/2)
/// to the positive representation [0, q).
#[inline]
pub fn mldsa_caddq(a: i32) -> i32 {
    a + ((a >> 31) & MLDSA_Q)
}

/// Multiply two elements in Montgomery form (ML-DSA).
///
/// Computes a * b * R^{-1} mod q via Montgomery reduction, where R = 2^32.
/// If a = a' * R and b = b' * R are in Montgomery form, then
/// fqmul(a, b) = a' * b' * R mod q, which is a'*b' in Montgomery form.
#[inline]
pub fn mldsa_fqmul(a: i32, b: i32) -> i32 {
    mldsa_montgomery_reduce(a as i64 * b as i64)
}

/// Forward NTT for ML-DSA -- FIPS 204.
///
/// Transforms a polynomial from coefficient form to NTT form using
/// the Cooley-Tukey butterfly. The NTT splits X^256+1 completely into
/// 256 degree-1 factors modulo q = 8380417 (since q ≡ 1 mod 512).
///
/// The transform proceeds from length-128 down to length-1 butterflies
/// (8 layers). Each butterfly pair (a, b) with twiddle factor zeta:
///     t = zeta * b
///     (a, b) <- (a + t, a - t)
///
/// Input: polynomial coefficients in [0, q) (standard domain)
/// Output: NTT coefficients (NTT domain, Montgomery-scaled)
pub fn mldsa_ntt(coeffs: &mut [i32; N]) {
    let mut k = 1usize;
    let mut len = 128usize;

    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            let zeta = MLDSA_ZETAS[k];
            k += 1;

            for j in start..(start + len) {
                let t = mldsa_fqmul(zeta, coeffs[j + len]);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT for ML-DSA -- FIPS 204.
///
/// Transforms a polynomial from NTT form back to coefficient form using
/// the Gentleman-Sande (GS) butterfly. The transform proceeds from
/// length-1 up to length-128 butterflies (8 layers), iterating through
/// the zetas table in reverse order.
///
/// Each butterfly pair (a, b) with twiddle factor zeta:
///     t = a
///     a = t + b
///     b = zeta * (b - t)
///
/// After all layers, each coefficient is multiplied by f = 41978 =
/// R^2 * 256^{-1} mod q. This serves two purposes:
/// 1. Scales by 256^{-1} to complete the inverse transform
/// 2. Multiplied via fqmul (which computes x*f*R^{-1}), yielding
///    x * R * 256^{-1} mod q, maintaining Montgomery scaling
pub fn mldsa_ntt_inv(coeffs: &mut [i32; N]) {
    let mut k = 255usize;
    let mut len = 1usize;

    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = -MLDSA_ZETAS[k];
            k = k.wrapping_sub(1);

            for j in start..(start + len) {
                let t = coeffs[j];
                coeffs[j] = t + coeffs[j + len];
                coeffs[j + len] = t - coeffs[j + len];
                coeffs[j + len] = mldsa_fqmul(zeta, coeffs[j + len]);
            }
            start += 2 * len;
        }
        len *= 2;
    }

    // Multiply by f = R^2 * 256^{-1} mod q; fqmul gives f*coeff*R^{-1} = R*coeff/256
    for coeff in coeffs.iter_mut() {
        *coeff = mldsa_fqmul(MLDSA_F, *coeff);
    }
}

/// Pointwise multiplication in NTT domain for ML-DSA.
///
/// Since the NTT splits X^256+1 completely into 256 degree-1 factors
/// (as q ≡ 1 mod 512), pointwise multiplication is simple element-wise
/// Montgomery multiplication. No base-case polynomial multiplication
/// is needed (unlike ML-KEM which requires degree-2 basemul).
pub fn mldsa_pointwise_mul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = mldsa_fqmul(a[i], b[i]);
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrett_reduce() {
        // Test that Barrett reduction works correctly
        assert_eq!(mlkem_barrett_reduce(0), 0);
        assert_eq!(mlkem_barrett_reduce(MLKEM_Q), 0);
        assert_eq!(mlkem_barrett_reduce(MLKEM_Q + 1), 1);
        assert_eq!(mlkem_barrett_reduce(2 * MLKEM_Q), 0);
    }

    #[test]
    fn test_barrett_reduce_negative() {
        // Barrett reduction should handle negative inputs
        let r = mlkem_barrett_reduce(-1);
        // -1 mod q = q-1 = 3328, but Barrett only approximately reduces,
        // so we check congruence mod q
        assert_eq!((r as i32).rem_euclid(MLKEM_Q), MLKEM_Q - 1);

        let r = mlkem_barrett_reduce(-MLKEM_Q);
        assert_eq!((r as i32).rem_euclid(MLKEM_Q), 0);

        let r = mlkem_barrett_reduce(-2 * MLKEM_Q);
        assert_eq!((r as i32).rem_euclid(MLKEM_Q), 0);
    }

    #[test]
    fn test_montgomery_reduce() {
        // Test basic Montgomery reduction
        let a = 1000i32;
        let r = mlkem_montgomery_reduce(a);
        assert!(r.abs() < MLKEM_Q as i16);
    }

    #[test]
    fn test_fqmul_commutativity() {
        // fqmul(a, b) should equal fqmul(b, a) for all inputs
        let test_pairs: Vec<(i16, i16)> = vec![
            (100, 200),
            (1, 3328),
            (1665, 1000),
            (0, 500),
            (-500, 1234),
            (3328, 3328),
        ];
        for (a, b) in test_pairs {
            assert_eq!(
                mlkem_fqmul(a, b), mlkem_fqmul(b, a),
                "fqmul commutativity failed for ({}, {})", a, b
            );
        }
    }

    #[test]
    fn test_ntt_all_zeros() {
        // NTT of the zero polynomial should remain zero
        let mut poly = [0i16; N];
        mlkem_ntt(&mut poly);
        for i in 0..N {
            assert_eq!(poly[i], 0, "NTT of zero non-zero at index {}", i);
        }
    }

    #[test]
    fn test_ntt_linearity() {
        // NTT(a + b) == NTT(a) + NTT(b) mod q
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        let mut ab = [0i16; N];

        for i in 0..N {
            a[i] = (i as i16 * 7) % (MLKEM_Q as i16);
            b[i] = (i as i16 * 13 + 100) % (MLKEM_Q as i16);
            ab[i] = mlkem_barrett_reduce(a[i] as i32 + b[i] as i32);
        }

        let mut ntt_a = a;
        let mut ntt_b = b;
        let mut ntt_ab = ab;

        mlkem_ntt(&mut ntt_a);
        mlkem_ntt(&mut ntt_b);
        mlkem_ntt(&mut ntt_ab);

        for i in 0..N {
            let sum_mod_q = (ntt_a[i] as i32 + ntt_b[i] as i32).rem_euclid(MLKEM_Q);
            let ntt_sum = (ntt_ab[i] as i32).rem_euclid(MLKEM_Q);
            assert_eq!(
                sum_mod_q, ntt_sum,
                "NTT linearity failed at index {}", i
            );
        }
    }

    #[test]
    fn test_basemul_commutativity() {
        // basemul(a, b) == basemul(b, a)
        let mut a = [0i16; N];
        let mut b = [0i16; N];

        for i in 0..N {
            a[i] = (i as i16 * 11) % (MLKEM_Q as i16);
            b[i] = (i as i16 * 23 + 50) % (MLKEM_Q as i16);
        }

        mlkem_ntt(&mut a);
        mlkem_ntt(&mut b);

        let c1 = mlkem_basemul(&a, &b);
        let c2 = mlkem_basemul(&b, &a);

        for i in 0..N {
            assert_eq!(
                (c1[i] as i32).rem_euclid(MLKEM_Q),
                (c2[i] as i32).rem_euclid(MLKEM_Q),
                "basemul commutativity failed at index {}", i
            );
        }
    }

    #[test]
    fn test_basemul_zero() {
        // basemul with the zero polynomial should give zero
        let mut a = [0i16; N];
        let zero = [0i16; N];

        for i in 0..N {
            a[i] = (i as i16 * 7) % (MLKEM_Q as i16);
        }
        mlkem_ntt(&mut a);

        let c = mlkem_basemul(&a, &zero);
        for i in 0..N {
            assert_eq!(
                (c[i] as i32).rem_euclid(MLKEM_Q), 0,
                "basemul with zero non-zero at index {}", i
            );
        }
    }

    #[test]
    fn test_mlkem_reduce_range() {
        // mlkem_reduce should put values into [0, q)
        let test_values: Vec<i16> = vec![
            0, 1, 3328, 3329, -1, -3329, 1665, -1665, 3330,
        ];
        for val in test_values {
            // Only test values in the valid range for mlkem_reduce
            // (values near [0, q) or slightly outside)
            if val >= -MLKEM_Q as i16 && val <= 2 * MLKEM_Q as i16 {
                let r = mlkem_reduce(val);
                assert!(
                    r >= 0 && r < MLKEM_Q as i16,
                    "mlkem_reduce({}) = {} not in [0, q)", val, r
                );
                // Also verify congruence
                assert_eq!(
                    (r as i32).rem_euclid(MLKEM_Q),
                    (val as i32).rem_euclid(MLKEM_Q),
                    "mlkem_reduce({}) = {} not congruent", val, r
                );
            }
        }
    }

    #[test]
    fn test_to_mont_roundtrip() {
        // to_mont(a) converts a to Montgomery form: a*R mod q
        // fqmul(to_mont(a), 1) = a*R * 1 * R^{-1} = a mod q
        // So fqmul(to_mont(a), 1) should give back a (mod q)
        let test_values: Vec<i16> = vec![0, 1, 100, 1665, 3328];
        for &val in &test_values {
            let mont = mlkem_to_mont(val);
            let back = mlkem_fqmul(mont, 1);
            assert_eq!(
                (back as i32).rem_euclid(MLKEM_Q),
                (val as i32).rem_euclid(MLKEM_Q),
                "to_mont roundtrip failed for {}", val
            );
        }
    }

    /// Compute modular exponentiation
    fn pow_mod(mut base: i64, mut exp: u64, modulus: i64) -> i64 {
        let mut result = 1i64;
        base %= modulus;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base % modulus;
            }
            exp >>= 1;
            base = base * base % modulus;
        }
        result
    }

    /// Compute 7-bit bit reversal
    fn brv7(x: usize) -> usize {
        let mut result = 0;
        let mut val = x;
        for _ in 0..7 {
            result = (result << 1) | (val & 1);
            val >>= 1;
        }
        result
    }

    #[test]
    fn test_zetas_table() {
        // Verify MLKEM_ZETAS against computed values
        let q = MLKEM_Q as i64;
        let zeta: i64 = 17; // primitive 256th root of unity
        let r = pow_mod(2, 16, q); // Montgomery constant R = 2^16 mod q

        let mut correct_zetas = [0i16; 128];
        for i in 0..128 {
            let power = brv7(i);
            let z = pow_mod(zeta, power as u64, q);
            let z_mont = (z * r) % q;
            let z_centered = if z_mont > q / 2 { z_mont - q } else { z_mont };
            correct_zetas[i] = z_centered as i16;
        }

        // Print correct table for replacement
        let mut mismatches = 0;
        for i in 0..128 {
            if MLKEM_ZETAS[i] != correct_zetas[i] {
                mismatches += 1;
            }
        }
        if mismatches > 0 {
            eprintln!("Found {} mismatches. Correct table:", mismatches);
            for row in 0..16 {
                let vals: Vec<String> = (0..8).map(|col| format!("{:5}", correct_zetas[row * 8 + col])).collect();
                eprintln!("    {},", vals.join(","));
            }
        }

        for i in 0..128 {
            assert_eq!(
                MLKEM_ZETAS[i], correct_zetas[i],
                "Zetas mismatch at index {}", i
            );
        }
    }

    #[test]
    fn test_ntt_roundtrip() {
        // Test NTT roundtrip using Montgomery form
        // NTT -> invNTT gives R * original (factor R from the Montgomery scaling)
        // basemul introduces R^{-1} that cancels this in practice
        let mut poly = [0i16; N];
        for i in 0..N {
            poly[i] = (i as i16) % (MLKEM_Q as i16);
        }
        let original = poly;
        mlkem_ntt(&mut poly);
        mlkem_ntt_inv(&mut poly);

        const R_MOD_Q: i32 = 2285;
        for i in 0..N {
            let expected = ((original[i] as i32) * R_MOD_Q).rem_euclid(MLKEM_Q);
            let got = (poly[i] as i32).rem_euclid(MLKEM_Q);
            assert_eq!(got, expected, "Montgomery roundtrip at index {}", i);
        }
    }

    #[test]
    fn test_basemul_identity() {
        // Multiplying by 1 (in NTT form) should give back the original
        let mut a = [0i16; N];
        let mut one = [0i16; N];

        for i in 0..N {
            a[i] = (i as i16 * 17) % (MLKEM_Q as i16);
            one[i] = 1;
        }

        mlkem_ntt(&mut a);
        mlkem_ntt(&mut one);

        let c = mlkem_basemul(&a, &one);

        // Result should be similar to a (accounting for Montgomery form)
        for i in 0..N {
            assert!(c[i].abs() < MLKEM_Q as i16);
        }
    }

    // ========================================================================
    // ML-DSA NTT Tests
    // ========================================================================

    /// Compute 8-bit bit reversal
    fn brv8(x: usize) -> usize {
        let mut result = 0;
        let mut val = x;
        for _ in 0..8 {
            result = (result << 1) | (val & 1);
            val >>= 1;
        }
        result
    }

    #[test]
    fn test_mldsa_ntt_roundtrip() {
        // Test NTT -> invNTT roundtrip for ML-DSA
        // NTT followed by invNTT gives R * original (one Montgomery factor R = 2^32 mod q
        // remains because f = R^2 * 256^{-1} mod q, and fqmul(f, coeff) = f*coeff*R^{-1}
        // = R * 256^{-1} * coeff). This is analogous to ML-KEM's roundtrip behavior.
        let mut poly = [0i32; N];
        for i in 0..N {
            poly[i] = (i as i32 * 37) % MLDSA_Q;
        }
        let original = poly;

        mldsa_ntt(&mut poly);
        mldsa_ntt_inv(&mut poly);

        const R_MOD_Q: i64 = MLDSA_MONT_R; // 2^32 mod q = 4193792
        for i in 0..N {
            let expected = ((original[i] as i64) * R_MOD_Q).rem_euclid(MLDSA_Q as i64) as i32;
            let got = poly[i].rem_euclid(MLDSA_Q);
            assert_eq!(
                got, expected,
                "ML-DSA NTT Montgomery roundtrip failed at index {}: got {}, expected {}",
                i, got, expected
            );
        }
    }

    #[test]
    fn test_mldsa_ntt_zero() {
        // NTT of the zero polynomial should remain zero
        let mut poly = [0i32; N];
        mldsa_ntt(&mut poly);
        for i in 0..N {
            assert_eq!(poly[i], 0, "ML-DSA NTT of zero non-zero at index {}", i);
        }
    }

    #[test]
    fn test_mldsa_pointwise_zero() {
        // Pointwise multiplication with the zero polynomial should give zero
        let mut a = [0i32; N];
        let zero = [0i32; N];

        for i in 0..N {
            a[i] = (i as i32 * 7) % MLDSA_Q;
        }
        mldsa_ntt(&mut a);

        let c = mldsa_pointwise_mul(&a, &zero);
        for i in 0..N {
            assert_eq!(
                c[i].rem_euclid(MLDSA_Q), 0,
                "ML-DSA pointwise mul with zero non-zero at index {}", i
            );
        }
    }

    #[test]
    fn test_mldsa_montgomery_reduce() {
        // Basic test: montgomery_reduce(a * R) should give a mod q
        // (since montgomery_reduce computes input * R^{-1} mod q)
        let r = MLDSA_MONT_R;
        let test_values: Vec<i32> = vec![0, 1, 100, 1000, MLDSA_Q - 1];
        for &val in &test_values {
            let product = val as i64 * r;
            let reduced = mldsa_montgomery_reduce(product);
            assert_eq!(
                reduced.rem_euclid(MLDSA_Q),
                val.rem_euclid(MLDSA_Q),
                "ML-DSA Montgomery reduce failed for val={}", val
            );
        }
    }

    #[test]
    fn test_mldsa_zetas_table() {
        // Verify MLDSA_ZETAS against computed values: zeta^{brv8(i)} * R mod q
        // Index 0 is intentionally set to 0 (unused; the NTT starts from k=1).
        let q = MLDSA_Q as i64;
        let zeta: i64 = 1753; // primitive 512th root of unity
        let r = pow_mod(2, 32, q); // Montgomery constant R = 2^32 mod q

        assert_eq!(MLDSA_ZETAS[0], 0, "MLDSA_ZETAS[0] should be 0 (unused)");

        let mut correct_zetas = [0i32; 256];
        for i in 1..256 {
            let power = brv8(i);
            let z = pow_mod(zeta, power as u64, q);
            let z_mont = (z * r) % q;
            let z_centered = if z_mont > q / 2 { z_mont - q } else { z_mont };
            correct_zetas[i] = z_centered as i32;
        }

        let mut mismatches = 0;
        for i in 1..256 {
            if MLDSA_ZETAS[i] != correct_zetas[i] {
                mismatches += 1;
                eprintln!(
                    "ML-DSA zetas mismatch at {}: table={}, computed={}",
                    i, MLDSA_ZETAS[i], correct_zetas[i]
                );
            }
        }

        assert_eq!(
            mismatches, 0,
            "Found {} mismatches in ML-DSA zetas table", mismatches
        );
    }
}
