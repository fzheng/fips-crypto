//! ML-KEM Decapsulation (Algorithm 18 in FIPS 203)
//!
//! Recovers the shared secret from a ciphertext using the secret key.
//! Implements implicit rejection to prevent chosen-ciphertext attacks.

use crate::ml_kem::encapsulate::k_pke_encrypt;
use crate::ml_kem::params::MlKemParams;
use crate::primitives::polynomial::{Poly, PolyVec};
use crate::primitives::sha3::{g, j};
use wasm_bindgen::JsError;

/// ML-KEM Decapsulation
///
/// Decapsulates a ciphertext to recover the shared secret.
/// Implements implicit rejection for CCA security.
///
/// # Arguments
/// * `dk` - The decapsulation key (secret key)
/// * `c` - The ciphertext
/// * `params` - The ML-KEM parameter set
///
/// # Returns
/// The 32-byte shared secret
pub fn ml_kem_decapsulate<const K: usize>(
    dk: &[u8],
    c: &[u8],
    params: &MlKemParams,
) -> Result<[u8; 32], JsError> {
    // Validate key and ciphertext lengths
    if dk.len() != params.dk_bytes {
        return Err(JsError::new(&format!(
            "Invalid decapsulation key length: expected {}, got {}",
            params.dk_bytes,
            dk.len()
        )));
    }
    if c.len() != params.ct_bytes {
        return Err(JsError::new(&format!(
            "Invalid ciphertext length: expected {}, got {}",
            params.ct_bytes,
            c.len()
        )));
    }

    // Parse decapsulation key: dk_pke || ek || H(ek) || z
    let dk_pke_len = 384 * K;
    let ek_len = params.ek_bytes;

    let dk_pke = &dk[..dk_pke_len];
    let ek = &dk[dk_pke_len..dk_pke_len + ek_len];
    let h_ek = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
    let z = &dk[dk_pke_len + ek_len + 32..];

    // m' ← K-PKE.Decrypt(dk_pke, c)
    let m_prime = k_pke_decrypt::<K>(dk_pke, c, params)?;

    // (K', r') ← G(m' || H(ek))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(h_ek);
    let g_output = g(&g_input);
    let k_prime = &g_output[..32];
    let r_prime = &g_output[32..64];

    // K̄ ← J(z || c)
    let mut j_input = Vec::with_capacity(32 + c.len());
    j_input.extend_from_slice(z);
    j_input.extend_from_slice(c);
    let k_bar = j(&j_input, 32);

    // c' ← K-PKE.Encrypt(ek, m', r')
    let c_prime = k_pke_encrypt::<K>(ek, &m_prime, r_prime, params)?;

    // Implicit rejection: if c ≠ c', return K̄ instead of K'
    // This must be done in constant time to avoid timing attacks
    let mut shared_secret = [0u8; 32];
    let ciphertexts_equal = constant_time_eq(c, &c_prime);

    for i in 0..32 {
        shared_secret[i] = constant_time_select(ciphertexts_equal, k_prime[i], k_bar[i]);
    }

    Ok(shared_secret)
}

/// K-PKE Decryption (Algorithm 15 in FIPS 203)
///
/// Decrypts a ciphertext using the PKE secret key.
fn k_pke_decrypt<const K: usize>(
    dk_pke: &[u8],
    c: &[u8],
    params: &MlKemParams,
) -> Result<[u8; 32], JsError> {
    // Decode secret key s
    let s_hat = PolyVec::from_bytes(dk_pke, K);

    // Parse ciphertext: c1 || c2
    let c1_bytes = params.du * K * 32; // N * du * k / 8
    let c1 = &c[..c1_bytes];
    let c2 = &c[c1_bytes..];

    // Decompress c1 to get u
    let mut u = PolyVec::decompress(c1, K, params.du);

    // Decompress c2 to get v
    let v = Poly::decompress(c2, params.dv);

    // Convert u to NTT form
    u.to_ntt();

    // Compute w = v - s^T * u
    let mut s_t_u = s_hat.inner_product(&u);
    s_t_u.from_ntt();
    let w = v.sub(&s_t_u);

    // Encode w to message
    let m = encode_message(&w);

    Ok(m)
}

/// Encode a polynomial to a 32-byte message
/// Each coefficient is rounded to 0 or 1 based on proximity to 0 or ⌈q/2⌉
fn encode_message(poly: &Poly) -> [u8; 32] {
    let mut m = [0u8; 32];
    let q = crate::primitives::ntt::MLKEM_Q;

    for i in 0..256 {
        // Normalize coefficient to [0, q)
        let coeff = (poly.coeffs[i] as i32).rem_euclid(q);

        // Compress to 1 bit: round(2x/q) mod 2
        let bit = ((coeff * 2 + q / 2) / q) & 1;

        m[i / 8] |= (bit as u8) << (i % 8);
    }

    m
}

/// Constant-time comparison of two byte slices
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    // Returns 1 if equal, 0 if not
    ((diff as i16 - 1) >> 8) as u8 & 1
}

/// Constant-time conditional select
#[inline]
fn constant_time_select(condition: u8, a: u8, b: u8) -> u8 {
    // If condition == 1, return a; else return b
    let mask = (condition as i8).wrapping_neg() as u8;
    (a & mask) | (b & !mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem::encapsulate::ml_kem_encapsulate;
    use crate::ml_kem::keygen::ml_kem_keygen;
    use crate::ml_kem::params::{
        ML_KEM_512, ML_KEM_768, ML_KEM_1024, MLKEM512_K, MLKEM768_K, MLKEM1024_K,
    };

    #[test]
    fn test_roundtrip_mlkem512() {
        let keypair = ml_kem_keygen::<MLKEM512_K>(None, &ML_KEM_512).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM512_K>(&keypair.ek, None, &ML_KEM_512).unwrap();
        let decapped = ml_kem_decapsulate::<MLKEM512_K>(&keypair.dk, &encap.ciphertext, &ML_KEM_512).unwrap();
        assert_eq!(encap.shared_secret, decapped);
    }

    #[test]
    fn test_roundtrip_mlkem768() {
        let keypair = ml_kem_keygen::<MLKEM768_K>(None, &ML_KEM_768).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM768_K>(&keypair.ek, None, &ML_KEM_768).unwrap();
        let decapped = ml_kem_decapsulate::<MLKEM768_K>(&keypair.dk, &encap.ciphertext, &ML_KEM_768).unwrap();
        assert_eq!(encap.shared_secret, decapped);
    }

    #[test]
    fn test_roundtrip_mlkem1024() {
        let keypair = ml_kem_keygen::<MLKEM1024_K>(None, &ML_KEM_1024).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM1024_K>(&keypair.ek, None, &ML_KEM_1024).unwrap();
        let decapped = ml_kem_decapsulate::<MLKEM1024_K>(&keypair.dk, &encap.ciphertext, &ML_KEM_1024).unwrap();
        assert_eq!(encap.shared_secret, decapped);
    }

    #[test]
    fn test_deterministic_roundtrip() {
        let key_seed = [0x42u8; 64];
        let encap_seed = [0x43u8; 32];

        let keypair = ml_kem_keygen::<MLKEM768_K>(Some(&key_seed), &ML_KEM_768).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM768_K>(&keypair.ek, Some(&encap_seed), &ML_KEM_768).unwrap();
        let decapped = ml_kem_decapsulate::<MLKEM768_K>(&keypair.dk, &encap.ciphertext, &ML_KEM_768).unwrap();

        assert_eq!(encap.shared_secret, decapped);
    }

    #[test]
    fn test_implicit_rejection() {
        let keypair = ml_kem_keygen::<MLKEM768_K>(None, &ML_KEM_768).unwrap();
        let encap = ml_kem_encapsulate::<MLKEM768_K>(&keypair.ek, None, &ML_KEM_768).unwrap();

        // Corrupt the ciphertext
        let mut corrupted_ct = encap.ciphertext.clone();
        corrupted_ct[0] ^= 0xFF;

        // Decapsulation should return a different (pseudorandom) shared secret
        let decapped = ml_kem_decapsulate::<MLKEM768_K>(&keypair.dk, &corrupted_ct, &ML_KEM_768).unwrap();

        // The decapped secret should NOT match the original (with overwhelming probability)
        assert_ne!(encap.shared_secret, decapped);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert_eq!(constant_time_eq(&a, &b), 1);
        assert_eq!(constant_time_eq(&a, &c), 0);
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(1, 0xAA, 0xBB), 0xAA);
        assert_eq!(constant_time_select(0, 0xAA, 0xBB), 0xBB);
    }
}
