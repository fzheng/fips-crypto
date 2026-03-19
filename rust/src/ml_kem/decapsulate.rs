//! ML-KEM Decapsulation -- FIPS 203 Algorithm 18 (ML-KEM.Decaps_internal)
//!
//! Recovers the shared secret from a ciphertext using the secret key.
//! Implements implicit rejection to prevent chosen-ciphertext attacks:
//! if the ciphertext is invalid (i.e., re-encryption doesn't match),
//! a pseudorandom value derived from z is returned instead of an error,
//! ensuring an attacker cannot distinguish valid from invalid ciphertexts.

use crate::ml_kem::encapsulate::k_pke_encrypt;
use crate::ml_kem::params::MlKemParams;
use crate::primitives::polynomial::{Poly, PolyVec};
use crate::primitives::sha3::{g, j};
use wasm_bindgen::JsError;

/// ML-KEM Decapsulation -- FIPS 203 Algorithm 18 (ML-KEM.Decaps_internal).
///
/// Decapsulates a ciphertext to recover the shared secret.
/// Implements implicit rejection for CCA security.
///
/// Steps:
/// 1. Parse dk as dk_pke || ek || H(ek) || z
/// 2. Decrypt: m' = K-PKE.Decrypt(dk_pke, c)
/// 3. Derive (K', r') = G(m' || H(ek))
/// 4. Re-encrypt: c' = K-PKE.Encrypt(ek, m', r')
/// 5. Compute rejection key: K_bar = J(z || c)
/// 6. Return K' if c == c' (valid), else return K_bar (implicit rejection)
///    -- the comparison and selection are done in constant time
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

    // m' <- K-PKE.Decrypt(dk_pke, c)
    let m_prime = k_pke_decrypt::<K>(dk_pke, c, params)?;

    // (K', r') <- G(m' || H(ek))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(h_ek);
    let g_output = g(&g_input);
    let k_prime = &g_output[..32];
    let r_prime = &g_output[32..64];

    // K_bar <- J(z || c)
    let mut j_input = Vec::with_capacity(32 + c.len());
    j_input.extend_from_slice(z);
    j_input.extend_from_slice(c);
    let k_bar = j(&j_input, 32);

    // c' <- K-PKE.Encrypt(ek, m', r')
    let c_prime = k_pke_encrypt::<K>(ek, &m_prime, r_prime, params)?;

    // Implicit rejection: if c != c', return K_bar instead of K'
    // This must be done in constant time to avoid timing attacks
    let mut shared_secret = [0u8; 32];
    let ciphertexts_equal = constant_time_eq(c, &c_prime);

    for i in 0..32 {
        shared_secret[i] = constant_time_select(ciphertexts_equal, k_prime[i], k_bar[i]);
    }

    Ok(shared_secret)
}

/// K-PKE Decryption -- FIPS 203 Algorithm 16 (K-PKE.Decrypt).
///
/// Decrypts a ciphertext using the PKE secret key to recover the original message.
///
/// Steps:
/// 1. Decode s_hat from dk_pke (secret vector in NTT form)
/// 2. Parse ciphertext as c1 || c2
/// 3. Decompress u = Decompress(c1, d_u) and v = Decompress(c2, d_v)
/// 4. Compute w = v - NTT^{-1}(s_hat^T * NTT(u))
/// 5. Recover message m = Compress_q(w, 1) via encode_message
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

    // Encode w to message: applies Compress_q(w_i, 1) to each coefficient
    let m = encode_message(&w);

    Ok(m)
}

/// Encode a polynomial to a 32-byte message.
///
/// Applies Compress_q(x, 1) to each coefficient: computes round(2x/q) mod 2,
/// which maps coefficients near 0 to bit 0 and coefficients near q/2 to bit 1.
///
/// The formula used is: bit = ((coeff * 2 + q/2) / q) & 1
/// This is equivalent to Compress_q(x, 1) = round(2^1 / q * x) mod 2^1.
/// Each coefficient produces one bit, packed 8 per byte (LSB first).
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

/// Constant-time comparison of two byte slices.
///
/// Returns 1 if the slices are equal, 0 otherwise.
/// Runs in time proportional to the length of the slices, regardless
/// of where (or whether) they differ.
///
/// Implementation: XORs all corresponding bytes and ORs the results into
/// a single accumulator `diff`. If diff == 0, slices are equal.
/// The expression ((diff as i16 - 1) >> 8) & 1 maps:
///   diff == 0  ->  (0 - 1) >> 8 = (-1) >> 8 = 0xFF (arithmetic shift) -> & 1 = 1
///   diff != 0  ->  (diff - 1) >> 8 = 0 (for any diff in 1..255)        -> & 1 = 0
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

/// Constant-time conditional select.
///
/// Returns a if condition == 1, or b if condition == 0.
/// Must not be called with any other condition value.
///
/// Implementation: creates a mask from the condition by negating it:
///   condition = 1  ->  mask = wrapping_neg(1) = 0xFF (all bits set)
///   condition = 0  ->  mask = wrapping_neg(0) = 0x00 (no bits set)
/// Then: (a & mask) | (b & !mask) selects a when mask=0xFF, b when mask=0x00.
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

    #[test]
    #[should_panic]
    fn test_decapsulate_invalid_dk_length() {
        // Wrong dk length should return an error
        // JsError::new panics on non-wasm targets, so we expect a panic
        let short_dk = vec![0u8; 100];
        let dummy_ct = vec![0u8; ML_KEM_768.ct_bytes];
        let _ = ml_kem_decapsulate::<MLKEM768_K>(&short_dk, &dummy_ct, &ML_KEM_768);
    }

    #[test]
    #[should_panic]
    fn test_decapsulate_invalid_ct_length() {
        // Wrong ciphertext length should return an error
        // JsError::new panics on non-wasm targets, so we expect a panic
        let keypair = ml_kem_keygen::<MLKEM768_K>(None, &ML_KEM_768).unwrap();
        let short_ct = vec![0u8; 100];
        let _ = ml_kem_decapsulate::<MLKEM768_K>(&keypair.dk, &short_ct, &ML_KEM_768);
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        // Slices of different lengths should return 0
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert_eq!(constant_time_eq(&a, &b), 0);
        assert_eq!(constant_time_eq(&b, &a), 0);
    }

    #[test]
    fn test_constant_time_eq_empty() {
        // Two empty slices should be considered equal
        let empty: [u8; 0] = [];
        assert_eq!(constant_time_eq(&empty, &empty), 1);

        // Empty vs non-empty should be not equal
        let non_empty = [1u8];
        assert_eq!(constant_time_eq(&empty, &non_empty), 0);
    }

    #[test]
    fn test_constant_time_select_all_values() {
        // Test that constant_time_select works for all possible byte values
        for a_val in 0..=255u8 {
            assert_eq!(
                constant_time_select(1, a_val, 0),
                a_val,
                "select(1, {}, 0) should be {}", a_val, a_val
            );
            assert_eq!(
                constant_time_select(0, 0, a_val),
                a_val,
                "select(0, 0, {}) should be {}", a_val, a_val
            );
        }
        // Also verify crossover for a representative sample
        assert_eq!(constant_time_select(1, 0x00, 0xFF), 0x00);
        assert_eq!(constant_time_select(0, 0x00, 0xFF), 0xFF);
        assert_eq!(constant_time_select(1, 0xFF, 0x00), 0xFF);
        assert_eq!(constant_time_select(0, 0xFF, 0x00), 0x00);
    }

    #[test]
    fn test_decode_encode_roundtrip() {
        // Test encode_message directly with known polynomial values

        // A polynomial with all-zero coefficients should encode to all-zero message
        let zero_poly = Poly::zero();
        let m_from_zero = encode_message(&zero_poly);
        assert_eq!(m_from_zero, [0u8; 32], "Encoding zero polynomial should give all-zero message");

        // A polynomial with all coefficients = ceil(q/2) = 1665 should encode to all-ones
        let mut ones_poly = Poly::zero();
        let half_q = (crate::primitives::ntt::MLKEM_Q + 1) / 2;
        for i in 0..256 {
            ones_poly.coeffs[i] = half_q as i16;
        }
        let m_from_ones = encode_message(&ones_poly);
        assert_eq!(m_from_ones, [0xFFu8; 32], "Encoding ceil(q/2) polynomial should give all-one message");
    }
}
