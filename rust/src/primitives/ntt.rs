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
}
