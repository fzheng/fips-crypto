//! ML-DSA sampling functions per FIPS 204
//!
//! Provides the core sampling operations used by ML-DSA for generating
//! cryptographic polynomials from seeds:
//!
//! - `expand_a`: Matrix A sampling via RejNTTPoly (Algorithm 32)
//! - `expand_s`: Secret vector sampling via RejBoundedPoly (Algorithm 33)
//! - `expand_mask`: Masking vector sampling (Algorithm 34)
//! - `sample_in_ball`: Challenge polynomial sampling (Algorithm 31)
//!
//! ## Author
//!
//! Feng Zheng (https://github.com/fzheng)

use crate::ml_dsa::params::{N, Q};
use crate::primitives::sha3::{Shake128Xof, Shake256Xof};

// =============================================================================
// ML-DSA Polynomial Types
// =============================================================================

/// A polynomial in R_q with i32 coefficients for ML-DSA (q = 8380417).
#[derive(Clone, Debug)]
pub struct DsaPoly {
    pub coeffs: [i32; N],
}

impl Default for DsaPoly {
    fn default() -> Self {
        Self::zero()
    }
}

impl DsaPoly {
    /// Create a zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: [0i32; N] }
    }
}

/// A vector of ML-DSA polynomials.
#[derive(Clone, Debug)]
pub struct DsaPolyVec {
    pub polys: Vec<DsaPoly>,
}

impl DsaPolyVec {
    /// Create a new polynomial vector of given dimension.
    pub fn new(dim: usize) -> Self {
        Self {
            polys: (0..dim).map(|_| DsaPoly::zero()).collect(),
        }
    }

    /// Get the dimension.
    pub fn len(&self) -> usize {
        self.polys.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.polys.is_empty()
    }
}

/// A matrix of ML-DSA polynomials (k rows x l columns).
#[derive(Clone, Debug)]
pub struct DsaPolyMat {
    pub rows: Vec<DsaPolyVec>,
}

impl DsaPolyMat {
    /// Create a new k x l zero matrix.
    pub fn new(k: usize, l: usize) -> Self {
        Self {
            rows: (0..k).map(|_| DsaPolyVec::new(l)).collect(),
        }
    }
}

// =============================================================================
// Sampling Functions
// =============================================================================

/// Expand the public matrix A from a seed (FIPS 204 Algorithm 32, RejNTTPoly).
///
/// For each matrix entry A\[i\]\[j\], uses SHAKE128(rho || j || i) as an XOF and
/// performs rejection sampling: reads 3 bytes at a time, extracts a 23-bit
/// candidate coefficient, and accepts it if it is less than Q. The resulting
/// polynomials are in the NTT domain.
///
/// # Arguments
///
/// * `rho` - 32-byte seed
/// * `k` - Number of matrix rows
/// * `l` - Number of matrix columns
///
/// # Returns
///
/// A k x l matrix of polynomials in NTT domain
pub fn expand_a(rho: &[u8; 32], k: usize, l: usize) -> DsaPolyMat {
    let mut mat = DsaPolyMat::new(k, l);

    for i in 0..k {
        for j in 0..l {
            // SHAKE128(rho || j_byte || i_byte)
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            seed[32] = j as u8;
            seed[33] = i as u8;
            let mut xof = Shake128Xof::new(&seed);

            let mut ctr = 0usize;
            while ctr < N {
                let mut buf = [0u8; 3];
                xof.read(&mut buf);

                // Extract 23-bit candidate
                let coeff = (buf[0] as i32)
                    | ((buf[1] as i32) << 8)
                    | ((buf[2] as i32) << 16);
                let coeff = coeff & 0x7F_FFFF;

                if coeff < Q {
                    mat.rows[i].polys[j].coeffs[ctr] = coeff;
                    ctr += 1;
                }
            }
        }
    }

    mat
}

/// Expand secret vectors s1 and s2 from a seed (FIPS 204 Algorithm 33, RejBoundedPoly).
///
/// Uses SHAKE256(sigma || nonce) for each polynomial, where nonce is a 2-byte
/// little-endian u16. s1 uses nonces 0..l-1 and s2 uses nonces l..l+k-1.
///
/// Rejection sampling with bounded nibbles:
/// - eta=2: accept nibble z if z < 5, coefficient = 2 - z
/// - eta=4: accept nibble z if z < 9, coefficient = 4 - z
///
/// # Arguments
///
/// * `sigma` - 64-byte seed
/// * `l` - Dimension of s1
/// * `k` - Dimension of s2
/// * `eta` - Coefficient bound
///
/// # Returns
///
/// A tuple (s1, s2) of polynomial vectors with coefficients in [-eta, eta]
pub fn expand_s(
    sigma: &[u8; 64],
    l: usize,
    k: usize,
    eta: usize,
) -> (DsaPolyVec, DsaPolyVec) {
    let mut s1 = DsaPolyVec::new(l);
    let mut s2 = DsaPolyVec::new(k);

    // Sample s1 polynomials with nonces 0..l-1
    for i in 0..l {
        rej_bounded_poly(&mut s1.polys[i], sigma, i as u16, eta);
    }

    // Sample s2 polynomials with nonces l..l+k-1
    for i in 0..k {
        rej_bounded_poly(&mut s2.polys[i], sigma, (l + i) as u16, eta);
    }

    (s1, s2)
}

/// Sample a single polynomial via rejection bounded sampling.
///
/// Uses SHAKE256(seed || nonce_le) and reads bytes, splitting each byte into
/// two nibbles. Each nibble is tested against the bound (2*eta+1) and accepted
/// nibbles are mapped to coefficients via eta - nibble.
fn rej_bounded_poly(poly: &mut DsaPoly, seed: &[u8; 64], nonce: u16, eta: usize) {
    let nonce_bytes = nonce.to_le_bytes();
    let mut input = [0u8; 66];
    input[..64].copy_from_slice(seed);
    input[64] = nonce_bytes[0];
    input[65] = nonce_bytes[1];
    let mut xof = Shake256Xof::new(&input);

    let bound = match eta {
        2 => 5u8,  // accept if < 5 (values 0..4)
        4 => 9u8,  // accept if < 9 (values 0..8)
        _ => panic!("Unsupported eta value: {}", eta),
    };

    let mut ctr = 0usize;
    while ctr < N {
        let mut byte = [0u8; 1];
        xof.read(&mut byte);
        let b = byte[0];

        let z0 = b & 0x0F;
        let z1 = b >> 4;

        if z0 < bound {
            poly.coeffs[ctr] = eta as i32 - z0 as i32;
            ctr += 1;
        }
        if ctr < N && z1 < bound {
            poly.coeffs[ctr] = eta as i32 - z1 as i32;
            ctr += 1;
        }
    }
}

/// Expand the masking vector y from a seed (FIPS 204 Algorithm 34).
///
/// For each polynomial i in 0..l, uses SHAKE256(rho_prime || kappa_le) where
/// kappa value = kappa + i (as u16, little-endian).
///
/// Bit-packing depends on gamma1:
/// - gamma1 = 2^17: 18 bits per coefficient, 4 coefficients from 9 bytes
/// - gamma1 = 2^19: 20 bits per coefficient, 2 coefficients from 5 bytes
///
/// Each unpacked value v is mapped to gamma1 - v.
///
/// # Arguments
///
/// * `rho_prime` - 64-byte seed
/// * `kappa` - Starting nonce value
/// * `l` - Number of polynomials
/// * `gamma1` - Masking range parameter
///
/// # Returns
///
/// A polynomial vector with coefficients in [-(gamma1-1), gamma1]
pub fn expand_mask(
    rho_prime: &[u8; 64],
    kappa: u16,
    l: usize,
    gamma1: i32,
) -> DsaPolyVec {
    let mut vec = DsaPolyVec::new(l);

    for i in 0..l {
        let nonce = kappa + i as u16;
        let nonce_bytes = nonce.to_le_bytes();
        let mut input = [0u8; 66];
        input[..64].copy_from_slice(rho_prime);
        input[64] = nonce_bytes[0];
        input[65] = nonce_bytes[1];

        if gamma1 == (1 << 17) {
            // 18 bits per coefficient, 576 bytes total = 256 * 18 / 8
            let bytes = crate::primitives::sha3::shake256(&input, 576);
            unpack_gamma1_17(&bytes, &mut vec.polys[i].coeffs);
        } else if gamma1 == (1 << 19) {
            // 20 bits per coefficient, 640 bytes total = 256 * 20 / 8
            let bytes = crate::primitives::sha3::shake256(&input, 640);
            unpack_gamma1_19(&bytes, &mut vec.polys[i].coeffs);
        } else {
            panic!("Unsupported gamma1 value: {}", gamma1);
        }
    }

    vec
}

/// Unpack coefficients for gamma1 = 2^17 (18 bits per coefficient).
///
/// Reads 9 bytes at a time and extracts 4 coefficients, each 18 bits.
/// Each extracted value v is mapped to gamma1 - v.
fn unpack_gamma1_17(bytes: &[u8], coeffs: &mut [i32; N]) {
    let gamma1: i32 = 1 << 17;
    for i in 0..(N / 4) {
        let base = i * 9;
        let b = &bytes[base..base + 9];

        let a0 = (b[0] as i32)
            | ((b[1] as i32) << 8)
            | (((b[2] as i32) & 0x03) << 16);

        let a1 = ((b[2] as i32) >> 2)
            | ((b[3] as i32) << 6)
            | (((b[4] as i32) & 0x0F) << 14);

        let a2 = ((b[4] as i32) >> 4)
            | ((b[5] as i32) << 4)
            | (((b[6] as i32) & 0x3F) << 12);

        let a3 = ((b[6] as i32) >> 6)
            | ((b[7] as i32) << 2)
            | ((b[8] as i32) << 10);

        coeffs[4 * i] = gamma1 - a0;
        coeffs[4 * i + 1] = gamma1 - a1;
        coeffs[4 * i + 2] = gamma1 - a2;
        coeffs[4 * i + 3] = gamma1 - a3;
    }
}

/// Unpack coefficients for gamma1 = 2^19 (20 bits per coefficient).
///
/// Reads 5 bytes at a time and extracts 2 coefficients, each 20 bits.
/// Each extracted value v is mapped to gamma1 - v.
fn unpack_gamma1_19(bytes: &[u8], coeffs: &mut [i32; N]) {
    let gamma1: i32 = 1 << 19;
    for i in 0..(N / 2) {
        let base = i * 5;
        let b = &bytes[base..base + 5];

        let a0 = (b[0] as i32)
            | ((b[1] as i32) << 8)
            | (((b[2] as i32) & 0x0F) << 16);

        let a1 = ((b[2] as i32) >> 4)
            | ((b[3] as i32) << 4)
            | ((b[4] as i32) << 12);

        coeffs[2 * i] = gamma1 - a0;
        coeffs[2 * i + 1] = gamma1 - a1;
    }
}

/// Sample a challenge polynomial with exactly tau non-zero coefficients,
/// each being +/-1 (FIPS 204 Algorithm 31).
///
/// Uses SHAKE256(seed) as an XOF. The first 8 bytes provide a 64-bit sign
/// word. Then for each position i from 256-tau to 255, a byte j is read
/// from the XOF and rejected if j > i. Once accepted, coefficients are
/// swapped and the sign bit determines +/-1.
///
/// # Arguments
///
/// * `seed` - Challenge seed bytes
/// * `tau` - Number of non-zero coefficients
///
/// # Returns
///
/// A polynomial with exactly tau non-zero +/-1 coefficients
pub fn sample_in_ball(seed: &[u8], tau: usize) -> DsaPoly {
    let mut c = DsaPoly::zero();
    let mut xof = Shake256Xof::new(seed);

    // Read first 8 bytes as 64-bit sign word
    let mut sign_bytes = [0u8; 8];
    xof.read(&mut sign_bytes);
    let mut signs = u64::from_le_bytes(sign_bytes);

    for i in (N - tau)..N {
        // Rejection sample: read bytes until j <= i
        let j;
        loop {
            let mut byte = [0u8; 1];
            xof.read(&mut byte);
            if (byte[0] as usize) <= i {
                j = byte[0] as usize;
                break;
            }
        }

        c.coeffs[i] = c.coeffs[j];
        c.coeffs[j] = 1 - 2 * (signs & 1) as i32;
        signs >>= 1;
    }

    c
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_dsa::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, Q};
    use crate::primitives::ntt::mldsa_ntt_inv;

    // -------------------------------------------------------------------------
    // expand_a tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_expand_a_deterministic() {
        let rho = [0x42u8; 32];
        let a1 = expand_a(&rho, 4, 4);
        let a2 = expand_a(&rho, 4, 4);

        for i in 0..4 {
            for j in 0..4 {
                assert_eq!(
                    a1.rows[i].polys[j].coeffs,
                    a2.rows[i].polys[j].coeffs,
                    "expand_a not deterministic at ({}, {})",
                    i,
                    j,
                );
            }
        }
    }

    #[test]
    fn test_expand_a_coefficients_in_range() {
        let rho = [0xABu8; 32];
        for &(k, l) in &[(4, 4), (6, 5), (8, 7)] {
            let a = expand_a(&rho, k, l);
            assert_eq!(a.rows.len(), k);
            for i in 0..k {
                assert_eq!(a.rows[i].polys.len(), l);
                for j in 0..l {
                    for (idx, &coeff) in a.rows[i].polys[j].coeffs.iter().enumerate() {
                        assert!(
                            coeff >= 0 && coeff < Q,
                            "expand_a coeff {} at [{},{}][{}] out of [0, Q)",
                            coeff,
                            i,
                            j,
                            idx,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_expand_a_correct_dimensions() {
        let rho = [0x00u8; 32];
        let a = expand_a(&rho, 6, 5);
        assert_eq!(a.rows.len(), 6, "Expected 6 rows");
        for row in &a.rows {
            assert_eq!(row.polys.len(), 5, "Expected 5 columns");
        }
    }

    #[test]
    fn test_expand_a_different_seeds() {
        let rho1 = [0x01u8; 32];
        let rho2 = [0x02u8; 32];
        let a1 = expand_a(&rho1, 4, 4);
        let a2 = expand_a(&rho2, 4, 4);

        // At least one coefficient should differ
        let mut found_diff = false;
        'outer: for i in 0..4 {
            for j in 0..4 {
                for idx in 0..N {
                    if a1.rows[i].polys[j].coeffs[idx] != a2.rows[i].polys[j].coeffs[idx] {
                        found_diff = true;
                        break 'outer;
                    }
                }
            }
        }
        assert!(found_diff, "Different seeds produced identical matrices");
    }

    #[test]
    fn test_expand_a_ntt_domain() {
        // The output of expand_a should be in NTT domain.
        // Running inverse NTT should produce coefficients that look different
        // from the original NTT-domain values (verifying it's actually in NTT form).
        let rho = [0x55u8; 32];
        let a = expand_a(&rho, 4, 4);
        let mut poly = a.rows[0].polys[0].coeffs;
        let ntt_coeffs = poly;

        mldsa_ntt_inv(&mut poly);

        // After invNTT, at least some coefficients should differ from the NTT form
        let mut differ_count = 0;
        for i in 0..N {
            if poly[i] != ntt_coeffs[i] {
                differ_count += 1;
            }
        }
        assert!(
            differ_count > N / 2,
            "invNTT barely changed coefficients -- A may not be in NTT domain"
        );
    }

    // -------------------------------------------------------------------------
    // expand_s tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_expand_s_deterministic() {
        let sigma = [0x13u8; 64];
        let (s1a, s2a) = expand_s(&sigma, 4, 4, 2);
        let (s1b, s2b) = expand_s(&sigma, 4, 4, 2);

        for i in 0..4 {
            assert_eq!(
                s1a.polys[i].coeffs, s1b.polys[i].coeffs,
                "expand_s s1 not deterministic at {}",
                i,
            );
            assert_eq!(
                s2a.polys[i].coeffs, s2b.polys[i].coeffs,
                "expand_s s2 not deterministic at {}",
                i,
            );
        }
    }

    #[test]
    fn test_expand_s_coefficients_in_range_eta2() {
        let sigma = [0xCDu8; 64];
        let (s1, s2) = expand_s(&sigma, 4, 4, 2);

        for i in 0..4 {
            for (idx, &coeff) in s1.polys[i].coeffs.iter().enumerate() {
                assert!(
                    coeff >= -2 && coeff <= 2,
                    "s1[{}][{}] = {} not in [-2, 2]",
                    i,
                    idx,
                    coeff,
                );
            }
            for (idx, &coeff) in s2.polys[i].coeffs.iter().enumerate() {
                assert!(
                    coeff >= -2 && coeff <= 2,
                    "s2[{}][{}] = {} not in [-2, 2]",
                    i,
                    idx,
                    coeff,
                );
            }
        }
    }

    #[test]
    fn test_expand_s_coefficients_in_range_eta4() {
        let sigma = [0xEFu8; 64];
        let (s1, s2) = expand_s(&sigma, 5, 6, 4);

        for i in 0..5 {
            for (idx, &coeff) in s1.polys[i].coeffs.iter().enumerate() {
                assert!(
                    coeff >= -4 && coeff <= 4,
                    "s1[{}][{}] = {} not in [-4, 4]",
                    i,
                    idx,
                    coeff,
                );
            }
        }
        for i in 0..6 {
            for (idx, &coeff) in s2.polys[i].coeffs.iter().enumerate() {
                assert!(
                    coeff >= -4 && coeff <= 4,
                    "s2[{}][{}] = {} not in [-4, 4]",
                    i,
                    idx,
                    coeff,
                );
            }
        }
    }

    #[test]
    fn test_expand_s_correct_dimensions() {
        let sigma = [0x00u8; 64];

        let (s1, s2) = expand_s(&sigma, 4, 4, 2);
        assert_eq!(s1.len(), 4);
        assert_eq!(s2.len(), 4);

        let (s1, s2) = expand_s(&sigma, 5, 6, 4);
        assert_eq!(s1.len(), 5);
        assert_eq!(s2.len(), 6);

        let (s1, s2) = expand_s(&sigma, 7, 8, 2);
        assert_eq!(s1.len(), 7);
        assert_eq!(s2.len(), 8);
    }

    #[test]
    fn test_expand_s_all_param_sets() {
        let sigma = [0x77u8; 64];

        // ML-DSA-44: l=4, k=4, eta=2
        let (s1, s2) = expand_s(&sigma, ML_DSA_44.l, ML_DSA_44.k, ML_DSA_44.eta);
        assert_eq!(s1.len(), 4);
        assert_eq!(s2.len(), 4);

        // ML-DSA-65: l=5, k=6, eta=4
        let (s1, s2) = expand_s(&sigma, ML_DSA_65.l, ML_DSA_65.k, ML_DSA_65.eta);
        assert_eq!(s1.len(), 5);
        assert_eq!(s2.len(), 6);

        // ML-DSA-87: l=7, k=8, eta=2
        let (s1, s2) = expand_s(&sigma, ML_DSA_87.l, ML_DSA_87.k, ML_DSA_87.eta);
        assert_eq!(s1.len(), 7);
        assert_eq!(s2.len(), 8);
    }

    // -------------------------------------------------------------------------
    // expand_mask tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_expand_mask_deterministic() {
        let rho_prime = [0x99u8; 64];
        let y1 = expand_mask(&rho_prime, 0, 4, 1 << 17);
        let y2 = expand_mask(&rho_prime, 0, 4, 1 << 17);

        for i in 0..4 {
            assert_eq!(
                y1.polys[i].coeffs, y2.polys[i].coeffs,
                "expand_mask not deterministic at {}",
                i,
            );
        }
    }

    #[test]
    fn test_expand_mask_coefficients_gamma1_17() {
        let rho_prime = [0xAAu8; 64];
        let gamma1: i32 = 1 << 17;
        let y = expand_mask(&rho_prime, 0, 4, gamma1);

        assert_eq!(y.len(), 4);
        for i in 0..4 {
            for (idx, &coeff) in y.polys[i].coeffs.iter().enumerate() {
                assert!(
                    coeff >= -(gamma1 - 1) && coeff <= gamma1,
                    "mask[{}][{}] = {} not in [{}, {}]",
                    i,
                    idx,
                    coeff,
                    -(gamma1 - 1),
                    gamma1,
                );
            }
        }
    }

    #[test]
    fn test_expand_mask_coefficients_gamma1_19() {
        let rho_prime = [0xBBu8; 64];
        let gamma1: i32 = 1 << 19;
        let y = expand_mask(&rho_prime, 0, 5, gamma1);

        assert_eq!(y.len(), 5);
        for i in 0..5 {
            for (idx, &coeff) in y.polys[i].coeffs.iter().enumerate() {
                assert!(
                    coeff >= -(gamma1 - 1) && coeff <= gamma1,
                    "mask[{}][{}] = {} not in [{}, {}]",
                    i,
                    idx,
                    coeff,
                    -(gamma1 - 1),
                    gamma1,
                );
            }
        }
    }

    #[test]
    fn test_expand_mask_correct_dimensions() {
        let rho_prime = [0x00u8; 64];

        let y = expand_mask(&rho_prime, 0, 4, 1 << 17);
        assert_eq!(y.len(), 4);

        let y = expand_mask(&rho_prime, 0, 5, 1 << 19);
        assert_eq!(y.len(), 5);

        let y = expand_mask(&rho_prime, 0, 7, 1 << 19);
        assert_eq!(y.len(), 7);
    }

    #[test]
    fn test_expand_mask_different_kappa() {
        let rho_prime = [0x33u8; 64];
        let y1 = expand_mask(&rho_prime, 0, 4, 1 << 17);
        let y2 = expand_mask(&rho_prime, 4, 4, 1 << 17);

        // Different kappa should produce different vectors
        let mut found_diff = false;
        for i in 0..4 {
            for idx in 0..N {
                if y1.polys[i].coeffs[idx] != y2.polys[i].coeffs[idx] {
                    found_diff = true;
                    break;
                }
            }
            if found_diff {
                break;
            }
        }
        assert!(found_diff, "Different kappa values produced identical masks");
    }

    // -------------------------------------------------------------------------
    // sample_in_ball tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sample_in_ball_deterministic() {
        let seed = [0x42u8; 32];
        let c1 = sample_in_ball(&seed, 39);
        let c2 = sample_in_ball(&seed, 39);

        assert_eq!(c1.coeffs, c2.coeffs, "sample_in_ball not deterministic");
    }

    #[test]
    fn test_sample_in_ball_exactly_tau_nonzero() {
        for &tau in &[39, 49, 60] {
            let seed = [tau as u8; 32];
            let c = sample_in_ball(&seed, tau);

            let nonzero_count = c.coeffs.iter().filter(|&&x| x != 0).count();
            assert_eq!(
                nonzero_count, tau,
                "Expected exactly {} non-zero coefficients, got {}",
                tau, nonzero_count,
            );
        }
    }

    #[test]
    fn test_sample_in_ball_all_pm1() {
        let seed = [0xFFu8; 32];
        let c = sample_in_ball(&seed, 49);

        for (idx, &coeff) in c.coeffs.iter().enumerate() {
            assert!(
                coeff == 0 || coeff == 1 || coeff == -1,
                "sample_in_ball coeff {} at index {} is not in {{-1, 0, 1}}",
                coeff,
                idx,
            );
        }
    }

    #[test]
    fn test_sample_in_ball_different_seeds() {
        let seed1 = [0x01u8; 32];
        let seed2 = [0x02u8; 32];
        let c1 = sample_in_ball(&seed1, 39);
        let c2 = sample_in_ball(&seed2, 39);

        let mut found_diff = false;
        for i in 0..N {
            if c1.coeffs[i] != c2.coeffs[i] {
                found_diff = true;
                break;
            }
        }
        assert!(
            found_diff,
            "Different seeds produced identical challenge polynomials"
        );
    }

    #[test]
    fn test_sample_in_ball_all_tau_values() {
        // Test with all three ML-DSA tau values
        for &tau in &[ML_DSA_44.tau, ML_DSA_65.tau, ML_DSA_87.tau] {
            let seed = [0xABu8; 64]; // Use a longer seed
            let c = sample_in_ball(&seed, tau);

            let nonzero_count = c.coeffs.iter().filter(|&&x| x != 0).count();
            assert_eq!(nonzero_count, tau);

            for &coeff in &c.coeffs {
                assert!(coeff == 0 || coeff == 1 || coeff == -1);
            }
        }
    }

    #[test]
    fn test_sample_in_ball_has_both_signs() {
        // With tau >= 39, we should almost certainly see both +1 and -1
        let seed = [0x73u8; 32];
        let c = sample_in_ball(&seed, 60);

        let pos_count = c.coeffs.iter().filter(|&&x| x == 1).count();
        let neg_count = c.coeffs.iter().filter(|&&x| x == -1).count();

        assert!(pos_count > 0, "Expected at least one +1 coefficient");
        assert!(neg_count > 0, "Expected at least one -1 coefficient");
        assert_eq!(pos_count + neg_count, 60);
    }
}
