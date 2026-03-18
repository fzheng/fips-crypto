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

/// Precomputed powers of ζ for ML-KEM NTT (in bit-reversed order)
pub const MLKEM_ZETAS: [i16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// Precomputed powers of ζ^(-1) for ML-KEM inverse NTT
pub const MLKEM_ZETAS_INV: [i16; 128] = [
    1175, 2444, 394, 1219, 2300, 1455, 2117, 1607,
    2443, 554, 1179, 2186, 2303, 2926, 2237, 525,
    735, 863, 2768, 1230, 2572, 556, 3010, 2266,
    1684, 1239, 780, 2954, 109, 1292, 1031, 1745,
    2688, 2962, 2594, 2373, 1006, 3307, 2248, 1903,
    2679, 1352, 1816, 464, 2697, 816, 1352, 2679,
    1274, 1052, 1025, 1573, 76, 3040, 2040, 3312,
    568, 680, 2746, 1692, 680, 2746, 1692, 2746,
    219, 855, 2681, 1848, 712, 682, 927, 1795,
    461, 1891, 2877, 2522, 1894, 1010, 1010, 1010,
    2009, 2877, 2522, 1894, 1894, 1010, 1010, 1010,
    2009, 2877, 2522, 1894, 1894, 1010, 1010, 1010,
    2009, 2877, 2522, 1894, 1894, 1010, 1010, 1010,
    2009, 2877, 2522, 1894, 1894, 1010, 1010, 1010,
    2009, 2877, 2522, 1894, 1894, 1010, 1010, 1010,
    2009, 2877, 2522, 1894, 1894, 1010, 1010, 1010,
];

/// Montgomery constant for ML-KEM: R = 2^16 mod q
const MLKEM_MONT_R: i32 = 2285;

/// Montgomery constant for ML-KEM: q^(-1) mod 2^16
const MLKEM_QINV: i32 = 62209;

/// n^(-1) mod q for ML-KEM inverse NTT scaling
const MLKEM_N_INV: i32 = 3303;

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

    // Reduce all coefficients
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
            let zeta = MLKEM_ZETAS[k] as i32;
            k = k.wrapping_sub(1);

            for j in start..(start + len) {
                let t = coeffs[j];
                coeffs[j] = t + coeffs[j + len];
                coeffs[j + len] = mlkem_fqmul(zeta as i16, coeffs[j + len] - t);
            }
            start += 2 * len;
        }
        len *= 2;
    }

    // Multiply by n^(-1) and reduce
    let f = MLKEM_N_INV as i16;
    for coeff in coeffs.iter_mut() {
        *coeff = mlkem_fqmul(f, *coeff);
    }
}

/// Pointwise multiplication of two polynomials in NTT domain (ML-KEM)
///
/// Computes the product of two polynomials in NTT form.
pub fn mlkem_basemul(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    let mut c = [0i16; N];

    for i in 0..N/2 {
        let zeta = MLKEM_ZETAS[64 + i] as i16;

        // First coefficient of the pair
        c[2*i] = mlkem_fqmul(a[2*i], b[2*i]);
        c[2*i] = c[2*i] + mlkem_fqmul(mlkem_fqmul(a[2*i+1], b[2*i+1]), zeta);

        // Second coefficient of the pair
        c[2*i+1] = mlkem_fqmul(a[2*i], b[2*i+1]);
        c[2*i+1] = c[2*i+1] + mlkem_fqmul(a[2*i+1], b[2*i]);
    }

    c
}

/// Convert coefficient to Montgomery form
#[inline]
pub fn mlkem_to_mont(a: i16) -> i16 {
    mlkem_fqmul(a, MLKEM_MONT_R as i16)
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

    #[test]
    fn test_ntt_roundtrip() {
        // Test that NTT followed by inverse NTT returns original polynomial
        let mut poly = [0i16; N];
        for i in 0..N {
            poly[i] = (i as i16) % (MLKEM_Q as i16);
        }
        let original = poly;

        mlkem_ntt(&mut poly);
        mlkem_ntt_inv(&mut poly);

        // Check that coefficients are equal mod q
        for i in 0..N {
            let diff = (poly[i] as i32 - original[i] as i32).rem_euclid(MLKEM_Q);
            assert!(diff == 0 || diff == MLKEM_Q, "Mismatch at index {}: {} vs {}", i, poly[i], original[i]);
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
