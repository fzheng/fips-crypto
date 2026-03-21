//! ML-DSA Key Generation -- FIPS 204 Algorithm 1 (ML-DSA.KeyGen)
//!
//! Generates a public key (pk) and secret key (sk) for ML-DSA.
//!
//! The key generation process:
//! 1. Generate (or accept) 32 bytes of randomness xi
//! 2. Derive (rho, rho', K) = SHAKE256(xi || k || l, 128)
//! 3. Expand matrix A from rho (in NTT domain)
//! 4. Sample secret vectors s1, s2 from rho'
//! 5. Compute t = A * NTT(s1) + s2
//! 6. Split t into (t1, t0) via Power2Round
//! 7. Encode pk = rho || pack(t1) and sk = rho || K || tr || pack(s1) || pack(s2) || pack(t0)

use crate::ml_dsa::params::*;
use crate::ml_dsa::polynomial::*;
use crate::ml_dsa::sampling;
use crate::primitives::random::random_bytes;
use crate::primitives::sha3::shake256;
use wasm_bindgen::JsError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA key pair
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaKeyPair {
    /// Public key
    pub pk: Vec<u8>,
    /// Secret key
    pub sk: Vec<u8>,
}

/// Convert a sampling::DsaPolyVec to a polynomial::DsaPolyVec
fn convert_polyvec(src: &sampling::DsaPolyVec) -> DsaPolyVec {
    let mut dst = DsaPolyVec::new(src.len());
    for i in 0..src.len() {
        dst.polys[i].coeffs = src.polys[i].coeffs;
    }
    dst
}

/// Convert a sampling::DsaPolyMat to a polynomial::DsaPolyMat
fn convert_polymat(src: &sampling::DsaPolyMat) -> DsaPolyMat {
    let k = src.rows.len();
    let l = src.rows[0].len();
    let mut dst = DsaPolyMat::new(k, l);
    for i in 0..k {
        for j in 0..l {
            dst.rows[i].polys[j].coeffs = src.rows[i].polys[j].coeffs;
        }
    }
    dst
}

/// ML-DSA key generation -- FIPS 204 Algorithm 1 (ML-DSA.KeyGen).
///
/// # Arguments
/// * `seed` - Optional 32-byte seed for deterministic key generation (for testing).
/// * `params` - The ML-DSA parameter set to use
///
/// # Returns
/// A key pair containing the public key and secret key
pub fn ml_dsa_keygen(
    seed: Option<&[u8]>,
    params: &MlDsaParams,
) -> Result<MlDsaKeyPair, JsError> {
    // 1. Generate or accept 32-byte seed xi
    let mut xi = [0u8; 32];
    match seed {
        Some(s) if s.len() >= 32 => xi.copy_from_slice(&s[..32]),
        Some(s) => {
            return Err(JsError::new(&format!(
                "Seed must be at least 32 bytes, got {}",
                s.len()
            )));
        }
        None => {
            random_bytes(&mut xi)
                .map_err(|_| JsError::new("Failed to generate random bytes"))?;
        }
    }

    // 2. (rho, rho', K) = H(xi || k || l) using SHAKE256, 128 bytes output
    let mut h_input = Vec::with_capacity(34);
    h_input.extend_from_slice(&xi);
    h_input.push(params.k as u8);
    h_input.push(params.l as u8);
    let h_output = shake256(&h_input, 128);
    let rho: [u8; 32] = h_output[0..32].try_into().unwrap();
    let rho_prime: [u8; 64] = h_output[32..96].try_into().unwrap();
    let k_seed: [u8; 32] = h_output[96..128].try_into().unwrap();

    // 3. A_hat = ExpandA(rho) -- already in NTT domain
    let a_hat_sampling = sampling::expand_a(&rho, params.k, params.l);
    let a_hat = convert_polymat(&a_hat_sampling);

    // 4. (s1, s2) = ExpandS(rho', l, k, eta)
    let (s1_sampling, s2_sampling) =
        sampling::expand_s(&rho_prime, params.l, params.k, params.eta);
    let s1 = convert_polyvec(&s1_sampling);
    let s2 = convert_polyvec(&s2_sampling);

    // 5. s1_hat = NTT(s1)
    let mut s1_hat = s1.clone();
    s1_hat.to_ntt();

    // 6. t = A_hat * s1_hat (in NTT domain), then invNTT + s2
    // pointwise_mul introduces R^{-1}, invNTT introduces R, so they cancel
    let mut t = a_hat.mul_vec(&s1_hat);
    t.from_ntt();
    t.reduce();
    t = t.add(&s2);

    // 7. (t1, t0) = Power2Round(t)
    // First reduce t to [0, Q) for proper Power2Round
    t.reduce();
    let mut t1_vec = DsaPolyVec::new(params.k);
    let mut t0_vec = DsaPolyVec::new(params.k);
    for i in 0..params.k {
        let (t1i, t0i) = t.polys[i].power2round();
        t1_vec.polys[i] = t1i;
        t0_vec.polys[i] = t0i;
    }

    // 8. pk = rho || pack_t1(t1)
    let mut pk = Vec::with_capacity(params.pk_bytes);
    pk.extend_from_slice(&rho);
    pk.extend_from_slice(&t1_vec.to_bytes_t1());

    // 9. tr = SHAKE256(pk, 64) -- public key hash
    let tr = shake256(&pk, 64);

    // 10. sk = rho || K || tr || pack_eta(s1) || pack_eta(s2) || pack_t0(t0)
    let mut sk = Vec::with_capacity(params.sk_bytes);
    sk.extend_from_slice(&rho);
    sk.extend_from_slice(&k_seed);
    sk.extend_from_slice(&tr);
    sk.extend_from_slice(&s1.to_bytes_eta(params.eta));
    sk.extend_from_slice(&s2.to_bytes_eta(params.eta));
    sk.extend_from_slice(&t0_vec.to_bytes_t0());

    Ok(MlDsaKeyPair { pk, sk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_dsa::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};

    #[test]
    fn test_keygen_mldsa44_sizes() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        assert_eq!(
            keypair.pk.len(),
            ML_DSA_44.pk_bytes,
            "ML-DSA-44 pk size mismatch"
        );
        assert_eq!(
            keypair.sk.len(),
            ML_DSA_44.sk_bytes,
            "ML-DSA-44 sk size mismatch"
        );
    }

    #[test]
    fn test_keygen_mldsa65_sizes() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_65).unwrap();
        assert_eq!(
            keypair.pk.len(),
            ML_DSA_65.pk_bytes,
            "ML-DSA-65 pk size mismatch"
        );
        assert_eq!(
            keypair.sk.len(),
            ML_DSA_65.sk_bytes,
            "ML-DSA-65 sk size mismatch"
        );
    }

    #[test]
    fn test_keygen_mldsa87_sizes() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_87).unwrap();
        assert_eq!(
            keypair.pk.len(),
            ML_DSA_87.pk_bytes,
            "ML-DSA-87 pk size mismatch"
        );
        assert_eq!(
            keypair.sk.len(),
            ML_DSA_87.sk_bytes,
            "ML-DSA-87 sk size mismatch"
        );
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [0x55u8; 32];
        let keypair1 = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let keypair2 = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        assert_eq!(keypair1.pk, keypair2.pk, "Deterministic keygen pk mismatch");
        assert_eq!(keypair1.sk, keypair2.sk, "Deterministic keygen sk mismatch");
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];
        let keypair1 = ml_dsa_keygen(Some(&seed1), &ML_DSA_44).unwrap();
        let keypair2 = ml_dsa_keygen(Some(&seed2), &ML_DSA_44).unwrap();
        assert_ne!(keypair1.pk, keypair2.pk, "Different seeds gave same pk");
        assert_ne!(keypair1.sk, keypair2.sk, "Different seeds gave same sk");
    }

    #[test]
    fn test_keygen_random() {
        // Random keygen should produce valid-sized outputs
        let keypair = ml_dsa_keygen(None, &ML_DSA_44).unwrap();
        assert_eq!(keypair.pk.len(), ML_DSA_44.pk_bytes);
        assert_eq!(keypair.sk.len(), ML_DSA_44.sk_bytes);
    }

    #[test]
    #[should_panic]
    fn test_keygen_seed_too_short() {
        let short_seed = [0x42u8; 16];
        let _ = ml_dsa_keygen(Some(&short_seed), &ML_DSA_44);
    }

    #[test]
    fn test_keygen_pk_has_rho() {
        // First 32 bytes of pk should be rho
        let seed = [0x77u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();

        // Derive rho from seed the same way keygen does
        let mut h_input = Vec::with_capacity(34);
        h_input.extend_from_slice(&seed);
        h_input.push(ML_DSA_44.k as u8);
        h_input.push(ML_DSA_44.l as u8);
        let h_output = shake256(&h_input, 128);
        let rho = &h_output[0..32];

        assert_eq!(
            &keypair.pk[..32],
            rho,
            "First 32 bytes of pk should be rho"
        );
        assert_eq!(
            &keypair.sk[..32],
            rho,
            "First 32 bytes of sk should be rho"
        );
    }

    #[test]
    fn test_keygen_sk_contains_tr() {
        // sk should contain tr = SHAKE256(pk, 64) at bytes 64..128
        let seed = [0x99u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let tr = shake256(&keypair.pk, 64);
        assert_eq!(
            &keypair.sk[64..128],
            &tr[..],
            "sk should contain tr at offset 64"
        );
    }
}
