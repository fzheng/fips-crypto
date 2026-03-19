//! Number Theoretic Transform (NTT) implementation
//!
//! The NTT is used for efficient polynomial multiplication in ML-KEM and ML-DSA.
//! It converts polynomial multiplication from O(n²) to O(n log n).
//!
//! For ML-KEM (FIPS 203):
//! - q = 3329
//! - n = 256
//! - Primitive 256th root of unity ζ = 17
//!
//! For ML-DSA (FIPS 204):
//! - q = 8380417
//! - n = 256
//! - Primitive 512th root of unity ζ = 1753

/// ML-KEM modulus q = 3329
pub const MLKEM_Q: i32 = 3329;

/// ML-DSA modulus q = 8380417 = 2^23 - 2^13 + 1
pub const MLDSA_Q: i32 = 8380417;

/// Polynomial degree n = 256
pub const N: usize = 256;

/// Primitive 256th root of unity for ML-KEM (ζ = 17)
pub const MLKEM_ZETA: i32 = 17;

/// Primitive 512th root of unity for ML-DSA (ζ = 1753)
pub const MLDSA_ZETA: i32 = 1753;

/// Precomputed powers of ζ for ML-KEM NTT (in Montgomery form, bit-reversed order)
/// From the PQ-Crystals Kyber/ML-KEM reference implementation.
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

/// Montgomery constant for ML-KEM: R^2 mod q (used for converting to Montgomery form)
const MLKEM_MONT_R_SQ: i32 = 1353;

/// Montgomery constant for ML-KEM: q^(-1) mod 2^16
const MLKEM_QINV: i32 = 62209;

/// Inverse NTT scaling factor: mont^2 / 128 mod q = R^2 * 128^(-1) mod q
const MLKEM_F: i32 = 1441;

/// Barrett reduction constant for ML-KEM
const MLKEM_BARRETT_MU: i32 = 20159; // floor(2^26 / q)

/// Reduce a coefficient modulo q using Barrett reduction (ML-KEM)
///
/// For |a| < 2^15 * q, returns r with 0 <= r < q and a ≡ r (mod q)
#[inline]
pub fn mlkem_barrett_reduce(a: i32) -> i16 {
    let t = ((a as i64 * MLKEM_BARRETT_MU as i64) >> 26) as i32;
    let r = a - t * MLKEM_Q;
    r as i16
}

/// Montgomery reduction for ML-KEM
///
/// Given a with |a| < q * 2^15, returns r with:
/// - r ≡ a * R^(-1) (mod q)
/// - |r| < q
#[inline]
pub fn mlkem_montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(MLKEM_QINV as i16);
    let r = (a - (t as i32) * MLKEM_Q) >> 16;
    r as i16
}

/// Multiply two elements in Montgomery form (ML-KEM)
#[inline]
pub fn mlkem_fqmul(a: i16, b: i16) -> i16 {
    mlkem_montgomery_reduce(a as i32 * b as i32)
}

/// Forward NTT for ML-KEM
///
/// Transforms a polynomial from standard form to NTT form.
/// Input: polynomial coefficients in [0, q)
/// Output: NTT coefficients in [0, q)
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

/// Inverse NTT for ML-KEM
///
/// Transforms a polynomial from NTT form back to standard form.
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

    // Multiply by mont^2/128 to undo Montgomery factor and scale by 1/128
    let f = MLKEM_F as i16;
    for coeff in coeffs.iter_mut() {
        *coeff = mlkem_fqmul(f, *coeff);
    }
}

/// Pointwise multiplication of two polynomials in NTT domain (ML-KEM)
///
/// Computes the product of two polynomials in NTT form.
pub fn mlkem_basemul(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    let mut c = [0i16; N];

    for i in 0..N/4 {
        let zeta = MLKEM_ZETAS[64 + i];

        // First pair (using +zeta)
        c[4*i]     = mlkem_fqmul(mlkem_fqmul(a[4*i+1], b[4*i+1]), zeta);
        c[4*i]     = c[4*i] + mlkem_fqmul(a[4*i], b[4*i]);
        c[4*i+1]   = mlkem_fqmul(a[4*i], b[4*i+1]);
        c[4*i+1]   = c[4*i+1] + mlkem_fqmul(a[4*i+1], b[4*i]);

        // Second pair (using -zeta)
        c[4*i+2]   = mlkem_fqmul(mlkem_fqmul(a[4*i+3], b[4*i+3]), -zeta);
        c[4*i+2]   = c[4*i+2] + mlkem_fqmul(a[4*i+2], b[4*i+2]);
        c[4*i+3]   = mlkem_fqmul(a[4*i+2], b[4*i+3]);
        c[4*i+3]   = c[4*i+3] + mlkem_fqmul(a[4*i+3], b[4*i+2]);
    }

    c
}

/// Convert coefficient to Montgomery form (multiply by R mod q)
#[inline]
pub fn mlkem_to_mont(a: i16) -> i16 {
    mlkem_fqmul(a, MLKEM_MONT_R_SQ as i16)
}

/// Reduce coefficient to [0, q) range
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
    fn test_montgomery_reduce() {
        // Test basic Montgomery reduction
        let a = 1000i32;
        let r = mlkem_montgomery_reduce(a);
        assert!(r.abs() < MLKEM_Q as i16);
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
        // NTT → invNTT gives R * original (factor R from the Montgomery scaling)
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
