//! ML-KEM Encapsulation (Algorithm 17 in FIPS 203)
//!
//! Generates a shared secret and ciphertext from a public key.

use crate::ml_kem::params::MlKemParams;
use crate::ml_kem::MlKemEncapsulation;
use crate::primitives::polynomial::{Poly, PolyMat, PolyVec};
use crate::primitives::random::random_bytes;
use crate::primitives::sha3::{g, h};
use wasm_bindgen::JsError;

/// ML-KEM Encapsulation
///
/// Generates a shared secret and ciphertext using the recipient's public key.
///
/// # Arguments
/// * `ek` - The encapsulation key (public key)
/// * `seed` - Optional 32-byte seed for deterministic encapsulation (for testing)
/// * `params` - The ML-KEM parameter set
///
/// # Returns
/// The ciphertext and shared secret
pub fn ml_kem_encapsulate<const K: usize>(
    ek: &[u8],
    seed: Option<&[u8]>,
    params: &MlKemParams,
) -> Result<MlKemEncapsulation, JsError> {
    // Validate encapsulation key length
    if ek.len() != params.ek_bytes {
        return Err(JsError::new(&format!(
            "Invalid encapsulation key length: expected {}, got {}",
            params.ek_bytes,
            ek.len()
        )));
    }

    // Generate or use provided randomness m
    let mut m = [0u8; 32];
    match seed {
        Some(s) if s.len() >= 32 => {
            m.copy_from_slice(&s[..32]);
        }
        Some(s) => {
            return Err(JsError::new(&format!(
                "Seed must be at least 32 bytes, got {}",
                s.len()
            )));
        }
        None => {
            random_bytes(&mut m).map_err(|_| JsError::new("Failed to generate random bytes"))?;
        }
    }

    // Compute H(ek)
    let h_ek = h(ek);

    // (K, r) ← G(m || H(ek))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m);
    g_input[32..].copy_from_slice(&h_ek);
    let g_output = g(&g_input);
    let shared_secret: [u8; 32] = g_output[..32].try_into().unwrap();
    let r = &g_output[32..64];

    // c ← K-PKE.Encrypt(ek, m, r)
    let ciphertext = k_pke_encrypt::<K>(ek, &m, r, params)?;

    Ok(MlKemEncapsulation {
        ciphertext,
        shared_secret,
    })
}

/// K-PKE Encryption (Algorithm 14 in FIPS 203)
///
/// Encrypts a message using the PKE public key.
pub(crate) fn k_pke_encrypt<const K: usize>(
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8],
    params: &MlKemParams,
) -> Result<Vec<u8>, JsError> {
    // Parse public key: t || ρ
    let t_bytes = &ek[..384 * K];
    let rho = &ek[384 * K..];

    // Decode t
    let t_hat = PolyVec::from_bytes(t_bytes, K);

    // Sample matrix A^T from ρ
    let a_hat_t = PolyMat::sample_uniform(rho, K, true);

    // Sample r vector
    let mut r_vec = PolyVec::new(K);
    for i in 0..K {
        r_vec.polys[i] = Poly::sample_cbd(r, i as u8, params.eta1);
    }

    // Sample e1 vector
    let mut e1 = PolyVec::new(K);
    for i in 0..K {
        e1.polys[i] = Poly::sample_cbd(r, (K + i) as u8, params.eta2);
    }

    // Sample e2 polynomial
    let e2 = Poly::sample_cbd(r, (2 * K) as u8, params.eta2);

    // Convert r to NTT form
    let mut r_hat = r_vec.clone();
    r_hat.to_ntt();

    // Compute u = A^T * r + e1
    let mut u = a_hat_t.mul_vec(&r_hat);
    u.from_ntt();
    u = u.add(&e1);
    u.reduce();

    // Decode message to polynomial
    let mu = decode_message(m);

    // Compute v = t^T * r + e2 + μ
    let mut v = t_hat.inner_product(&r_hat);
    v.from_ntt();
    v = v.add(&e2);
    v = v.add(&mu);
    v.reduce();

    // Compress and encode ciphertext
    let c1 = u.compress(params.du);
    let c2 = v.compress(params.dv);

    let mut ciphertext = Vec::with_capacity(params.ct_bytes);
    ciphertext.extend_from_slice(&c1);
    ciphertext.extend_from_slice(&c2);

    Ok(ciphertext)
}

/// Decode a 32-byte message to a polynomial
/// Each bit of the message maps to a coefficient: 0 → 0, 1 → ⌈q/2⌉
fn decode_message(m: &[u8; 32]) -> Poly {
    let mut poly = Poly::zero();
    let half_q = (crate::primitives::ntt::MLKEM_Q + 1) / 2;

    for i in 0..32 {
        for j in 0..8 {
            let bit = (m[i] >> j) & 1;
            poly.coeffs[8 * i + j] = if bit == 1 { half_q as i16 } else { 0 };
        }
    }

    poly
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem::keygen::ml_kem_keygen;
    use crate::ml_kem::params::{ML_KEM_512, ML_KEM_768, ML_KEM_1024, MLKEM512_K, MLKEM768_K, MLKEM1024_K};

    #[test]
    fn test_encapsulate_mlkem512() {
        let keypair = ml_kem_keygen::<MLKEM512_K>(None, &ML_KEM_512).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM512_K>(&keypair.ek, None, &ML_KEM_512).unwrap();
        assert_eq!(encap.ciphertext.len(), ML_KEM_512.ct_bytes);
        assert_eq!(encap.shared_secret.len(), 32);
    }

    #[test]
    fn test_encapsulate_mlkem768() {
        let keypair = ml_kem_keygen::<MLKEM768_K>(None, &ML_KEM_768).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM768_K>(&keypair.ek, None, &ML_KEM_768).unwrap();
        assert_eq!(encap.ciphertext.len(), ML_KEM_768.ct_bytes);
        assert_eq!(encap.shared_secret.len(), 32);
    }

    #[test]
    fn test_encapsulate_mlkem1024() {
        let keypair = ml_kem_keygen::<MLKEM1024_K>(None, &ML_KEM_1024).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM1024_K>(&keypair.ek, None, &ML_KEM_1024).unwrap();
        assert_eq!(encap.ciphertext.len(), ML_KEM_1024.ct_bytes);
        assert_eq!(encap.shared_secret.len(), 32);
    }

    #[test]
    fn test_deterministic_encapsulation() {
        let keypair = ml_kem_keygen::<MLKEM768_K>(None, &ML_KEM_768).unwrap();
        let seed = [0x42u8; 32];

        let encap1 = ml_kem_encapsulate::<MLKEM768_K>(&keypair.ek, Some(&seed), &ML_KEM_768).unwrap();
        let encap2 = ml_kem_encapsulate::<MLKEM768_K>(&keypair.ek, Some(&seed), &ML_KEM_768).unwrap();

        assert_eq!(encap1.ciphertext, encap2.ciphertext);
        assert_eq!(encap1.shared_secret, encap2.shared_secret);
    }

    #[test]
    fn test_decode_message() {
        // All zeros message
        let m_zeros = [0u8; 32];
        let poly_zeros = decode_message(&m_zeros);
        for &coeff in &poly_zeros.coeffs {
            assert_eq!(coeff, 0);
        }

        // All ones message
        let m_ones = [0xFFu8; 32];
        let poly_ones = decode_message(&m_ones);
        let half_q = (crate::primitives::ntt::MLKEM_Q + 1) / 2;
        for &coeff in &poly_ones.coeffs {
            assert_eq!(coeff, half_q as i16);
        }
    }
}
