//! ML-KEM Key Generation -- FIPS 203 Algorithm 16 (ML-KEM.KeyGen_internal)
//!
//! Generates an encapsulation key (public key) and decapsulation key (secret key).
//!
//! The key generation process:
//! 1. Generate (or accept) 64 bytes of randomness: d (32 bytes) || z (32 bytes)
//! 2. Run K-PKE.KeyGen(d) to produce the internal PKE keypair (ek_pke, dk_pke)
//! 3. Construct the ML-KEM decapsulation key as: dk_pke || ek || H(ek) || z
//!    - dk_pke: the serialized secret vector s_hat (in NTT form)
//!    - ek: the public encapsulation key (t_hat || rho)
//!    - H(ek): SHA3-256 hash of ek, used during decapsulation
//!    - z: implicit rejection randomness, used to derive a pseudorandom
//!      shared secret when ciphertext validation fails (CCA security)

use crate::ml_kem::params::MlKemParams;
use crate::ml_kem::MlKemKeyPair;
use crate::primitives::polynomial::{Poly, PolyMat, PolyVec};
use crate::primitives::random::random_bytes;
use crate::primitives::sha3::{g, h};
use wasm_bindgen::JsError;

/// ML-KEM key generation -- FIPS 203 Algorithm 16 (ML-KEM.KeyGen_internal).
///
/// Generates an encapsulation key (ek) and decapsulation key (dk).
///
/// # Arguments
/// * `seed` - Optional 64-byte seed for deterministic key generation (for testing).
///            The first 32 bytes are `d` (used by K-PKE.KeyGen), and the last 32
///            bytes are `z` (implicit rejection randomness).
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
    // This structure allows decapsulation to:
    // - Decrypt with dk_pke
    // - Re-encrypt with ek for ciphertext comparison
    // - Use H(ek) in the G hash derivation
    // - Use z for implicit rejection
    let mut dk = Vec::with_capacity(params.dk_bytes);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek_pke);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);

    Ok(MlKemKeyPair { ek, dk })
}

/// K-PKE Key Generation -- FIPS 203 Algorithm 13 (K-PKE.KeyGen).
///
/// Generates the internal PKE key pair used by ML-KEM:
/// 1. Derive (rho, sigma) = G(d) where rho seeds matrix A, sigma seeds secrets
/// 2. Sample matrix A_hat from rho (already in NTT form via SampleNTT)
/// 3. Sample secret vector s and error vector e using CBD_eta1(sigma, ...)
/// 4. Compute t_hat = A_hat * s_hat + e_hat in NTT domain
/// 5. Encode ek = t_hat || rho and dk = s_hat
///
/// The to_mont() call after mul_vec is critical: basemul computes
/// a_i * b_i * R^{-1} for each coefficient pair, so A * s has an extra
/// R^{-1} factor. Calling to_mont() multiplies every coefficient by R
/// (via fqmul with R^2), which cancels the R^{-1}. This ensures
/// t_hat = A * s + e is in proper NTT form, consistent with the
/// representation of A and e.
fn k_pke_keygen<const K: usize>(
    d: &[u8],
    params: &MlKemParams,
) -> Result<(Vec<u8>, Vec<u8>), JsError> {
    // (rho, sigma) <- G(d)
    let g_output = g(d);
    let rho = &g_output[..32];
    let sigma = &g_output[32..64];

    // Sample matrix A from rho (in NTT form)
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

    // Encode public key: t || rho
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
    use crate::primitives::sha3::h;

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

    #[test]
    #[should_panic]
    fn test_keygen_seed_too_short() {
        // A 32-byte seed should be rejected (need at least 64)
        // JsError::new panics on non-wasm targets, so we expect a panic
        let short_seed = [0x42u8; 32];
        let _ = ml_kem_keygen::<MLKEM768_K>(Some(&short_seed), &ML_KEM_768);
    }

    #[test]
    fn test_keygen_dk_structure() {
        // Verify dk = dk_pke || ek || H(ek) || z
        let seed = [0x55u8; 64];
        let z = &seed[32..64];
        let keypair = ml_kem_keygen::<MLKEM768_K>(Some(&seed), &ML_KEM_768).unwrap();

        let dk = &keypair.dk;
        let ek = &keypair.ek;
        let k = MLKEM768_K;

        let dk_pke_len = 384 * k;
        let ek_len = ML_KEM_768.ek_bytes;

        // Verify total length
        assert_eq!(dk.len(), dk_pke_len + ek_len + 32 + 32);

        // Verify ek is embedded in dk
        let ek_in_dk = &dk[dk_pke_len..dk_pke_len + ek_len];
        assert_eq!(ek_in_dk, ek.as_slice(), "ek should be embedded in dk");

        // Verify H(ek) is correct
        let h_ek_in_dk = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
        let computed_h_ek = h(ek);
        assert_eq!(h_ek_in_dk, &computed_h_ek, "H(ek) mismatch in dk");

        // Verify z is at the end
        let z_in_dk = &dk[dk_pke_len + ek_len + 32..];
        assert_eq!(z_in_dk, z, "z mismatch in dk");
    }

    #[test]
    fn test_keygen_ek_has_rho() {
        // Verify last 32 bytes of ek match rho (derived from G(d))
        let seed = [0x77u8; 64];
        let d = &seed[..32];
        let keypair = ml_kem_keygen::<MLKEM768_K>(Some(&seed), &ML_KEM_768).unwrap();

        // rho is the first 32 bytes of G(d)
        use crate::primitives::sha3::g;
        let g_output = g(d);
        let rho = &g_output[..32];

        // Last 32 bytes of ek should be rho
        let ek_rho = &keypair.ek[keypair.ek.len() - 32..];
        assert_eq!(ek_rho, rho, "Last 32 bytes of ek should be rho");
    }
}
