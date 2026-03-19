//! ML-KEM Key Generation (Algorithm 15 in FIPS 203)
//!
//! Generates an encapsulation key (public key) and decapsulation key (secret key).

use crate::ml_kem::params::MlKemParams;
use crate::ml_kem::MlKemKeyPair;
use crate::primitives::polynomial::{Poly, PolyMat, PolyVec};
use crate::primitives::random::random_bytes;
use crate::primitives::sha3::{g, h};
use wasm_bindgen::JsError;

/// ML-KEM key generation
///
/// Generates an encapsulation key (ek) and decapsulation key (dk).
///
/// # Arguments
/// * `seed` - Optional 64-byte seed for deterministic key generation (for testing)
/// * `params` - The ML-KEM parameter set to use
///
/// # Returns
/// A key pair containing the encapsulation key and decapsulation key
pub fn ml_kem_keygen<const K: usize>(
    seed: Option<&[u8]>,
    params: &MlKemParams,
) -> Result<MlKemKeyPair, JsError> {
    // Get or generate the 64-byte seed (d || z)
    let mut d_z = [0u8; 64];
    match seed {
        Some(s) if s.len() >= 64 => {
            d_z.copy_from_slice(&s[..64]);
        }
        Some(s) => {
            return Err(JsError::new(&format!(
                "Seed must be at least 64 bytes, got {}",
                s.len()
            )));
        }
        None => {
            random_bytes(&mut d_z).map_err(|_| JsError::new("Failed to generate random bytes"))?;
        }
    }

    // Split into d (32 bytes) and z (32 bytes)
    let d = &d_z[..32];
    let z = &d_z[32..64];

    // Generate internal keys using K-PKE.KeyGen
    let (ek_pke, dk_pke) = k_pke_keygen::<K>(d, params)?;

    // Compute H(ek)
    let h_ek = h(&ek_pke);

    // Construct the encapsulation key (just the PKE public key)
    let ek = ek_pke.clone();

    // Construct the decapsulation key: dk_pke || ek || H(ek) || z
    let mut dk = Vec::with_capacity(params.dk_bytes);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek_pke);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);

    Ok(MlKemKeyPair { ek, dk })
}

/// K-PKE Key Generation (Algorithm 13 in FIPS 203)
///
/// Generates the internal PKE key pair used by ML-KEM.
fn k_pke_keygen<const K: usize>(
    d: &[u8],
    params: &MlKemParams,
) -> Result<(Vec<u8>, Vec<u8>), JsError> {
    // (ρ, σ) ← G(d)
    let g_output = g(d);
    let rho = &g_output[..32];
    let sigma = &g_output[32..64];

    // Sample matrix A from ρ (in NTT form)
    let a_hat = PolyMat::sample_uniform(rho, K, false);

    // Sample secret vector s
    let mut s = PolyVec::new(K);
    for i in 0..K {
        s.polys[i] = Poly::sample_cbd(sigma, i as u8, params.eta1);
    }

    // Sample error vector e
    let mut e = PolyVec::new(K);
    for i in 0..K {
        e.polys[i] = Poly::sample_cbd(sigma, (K + i) as u8, params.eta1);
    }

    // Convert s to NTT form
    let mut s_hat = s.clone();
    s_hat.to_ntt();

    // Convert e to NTT form
    let mut e_hat = e.clone();
    e_hat.to_ntt();

    // Compute t = A * s + e (in NTT form)
    // mul_vec uses basemul which introduces R^{-1}; to_mont cancels it
    let mut t_hat = a_hat.mul_vec(&s_hat);
    t_hat.to_mont();
    t_hat = t_hat.add(&e_hat);
    t_hat.reduce();

    // Encode public key: t || ρ
    let mut ek_pke = t_hat.to_bytes();
    ek_pke.extend_from_slice(rho);

    // Encode secret key: s (in NTT form)
    let dk_pke = s_hat.to_bytes();

    Ok((ek_pke, dk_pke))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem::params::{ML_KEM_512, ML_KEM_768, ML_KEM_1024, MLKEM512_K, MLKEM768_K, MLKEM1024_K};

    #[test]
    fn test_keygen_mlkem512() {
        let keypair = ml_kem_keygen::<MLKEM512_K>(None, &ML_KEM_512).unwrap();
        assert_eq!(keypair.ek.len(), ML_KEM_512.ek_bytes);
        assert_eq!(keypair.dk.len(), ML_KEM_512.dk_bytes);
    }

    #[test]
    fn test_keygen_mlkem768() {
        let keypair = ml_kem_keygen::<MLKEM768_K>(None, &ML_KEM_768).unwrap();
        assert_eq!(keypair.ek.len(), ML_KEM_768.ek_bytes);
        assert_eq!(keypair.dk.len(), ML_KEM_768.dk_bytes);
    }

    #[test]
    fn test_keygen_mlkem1024() {
        let keypair = ml_kem_keygen::<MLKEM1024_K>(None, &ML_KEM_1024).unwrap();
        assert_eq!(keypair.ek.len(), ML_KEM_1024.ek_bytes);
        assert_eq!(keypair.dk.len(), ML_KEM_1024.dk_bytes);
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [0x42u8; 64];
        let keypair1 = ml_kem_keygen::<MLKEM768_K>(Some(&seed), &ML_KEM_768).unwrap();
        let keypair2 = ml_kem_keygen::<MLKEM768_K>(Some(&seed), &ML_KEM_768).unwrap();
        assert_eq!(keypair1.ek, keypair2.ek);
        assert_eq!(keypair1.dk, keypair2.dk);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [0x42u8; 64];
        let seed2 = [0x43u8; 64];
        let keypair1 = ml_kem_keygen::<MLKEM768_K>(Some(&seed1), &ML_KEM_768).unwrap();
        let keypair2 = ml_kem_keygen::<MLKEM768_K>(Some(&seed2), &ML_KEM_768).unwrap();
        assert_ne!(keypair1.ek, keypair2.ek);
        assert_ne!(keypair1.dk, keypair2.dk);
    }
}
