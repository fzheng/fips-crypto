//! SLH-DSA Verification — FIPS 205 Algorithm 19 (slh_verify)
//!
//! Verifies an SLH-DSA signature against a public key and message.

use crate::slh_dsa::address::{Adrs, AdrsType};
use crate::slh_dsa::fors;
use crate::slh_dsa::hash::h_msg;
use crate::slh_dsa::hypertree;
use crate::slh_dsa::params::SlhDsaParams;
use crate::slh_dsa::sign::split_digest;

/// FIPS 205 Algorithm 19: SLH-DSA Verification.
///
/// Returns true if the signature is valid for the given message and public key.
pub fn slh_dsa_verify(
    pk: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
    params: &SlhDsaParams,
) -> Result<bool, String> {
    let n = params.n;

    if pk.len() != params.pk_bytes {
        return Err(format!(
            "Invalid public key length: expected {}, got {}",
            params.pk_bytes,
            pk.len()
        ));
    }

    if signature.len() != params.sig_bytes {
        return Err(format!(
            "Invalid signature length: expected {}, got {}",
            params.sig_bytes,
            signature.len()
        ));
    }

    if context.len() > 255 {
        return Err(format!(
            "Context must be at most 255 bytes, got {}",
            context.len()
        ));
    }

    // Parse PK = PK.seed || PK.root
    let pk_seed = &pk[..n];
    let pk_root = &pk[n..2 * n];

    // Parse signature = R || SIG_FORS || SIG_HT
    let r = &signature[..n];
    let fors_sig_size = params.k * (1 + params.a) * n;
    let sig_fors = &signature[n..n + fors_sig_size];
    let sig_ht = &signature[n + fors_sig_size..];

    // M' = 0x00 || len(ctx) || ctx || message
    let mut m_prime = Vec::with_capacity(2 + context.len() + message.len());
    m_prime.push(0x00); // domain separator for pure SLH-DSA
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(message);

    // Compute message digest
    let digest = h_msg(r, pk_seed, pk_root, &m_prime, params);
    let (md, idx_tree, idx_leaf) = split_digest(&digest, params);

    // Recover FORS public key from FORS signature
    let mut fors_adrs = Adrs::new();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(idx_tree);
    fors_adrs.set_type(AdrsType::ForsTree);
    fors_adrs.set_key_pair_address(idx_leaf);
    let pk_fors = fors::fors_pk_from_sig(sig_fors, &md, pk_seed, &mut fors_adrs, params);

    // Verify hypertree signature over FORS public key
    let valid = hypertree::ht_verify(&pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root, params);

    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::keygen::slh_dsa_keygen;
    use crate::slh_dsa::sign::slh_dsa_sign;
    use crate::slh_dsa::params::*;

    #[test]
    fn test_sign_verify_roundtrip_shake_128f() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHAKE_128F).unwrap();
        let msg = b"Hello, SLH-DSA!";
        let sig = slh_dsa_sign(&kp.sk, msg, &[], &SLH_DSA_SHAKE_128F).unwrap();
        let valid = slh_dsa_verify(&kp.pk, msg, &sig, &[], &SLH_DSA_SHAKE_128F).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHAKE_128F).unwrap();
        let msg = b"correct message";
        let sig = slh_dsa_sign(&kp.sk, msg, &[], &SLH_DSA_SHAKE_128F).unwrap();
        let valid = slh_dsa_verify(&kp.pk, b"wrong message", &sig, &[], &SLH_DSA_SHAKE_128F).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_corrupted_signature() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHAKE_128F).unwrap();
        let msg = b"test";
        let mut sig = slh_dsa_sign(&kp.sk, msg, &[], &SLH_DSA_SHAKE_128F).unwrap();
        sig[100] ^= 0xFF; // flip a byte
        let valid = slh_dsa_verify(&kp.pk, msg, &sig, &[], &SLH_DSA_SHAKE_128F).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_with_context() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHAKE_128F).unwrap();
        let msg = b"context test";
        let ctx = b"my-app-v1";
        let sig = slh_dsa_sign(&kp.sk, msg, ctx, &SLH_DSA_SHAKE_128F).unwrap();

        // Correct context: valid
        let valid = slh_dsa_verify(&kp.pk, msg, &sig, ctx, &SLH_DSA_SHAKE_128F).unwrap();
        assert!(valid);

        // Wrong context: invalid
        let valid = slh_dsa_verify(&kp.pk, msg, &sig, b"wrong-ctx", &SLH_DSA_SHAKE_128F).unwrap();
        assert!(!valid);

        // No context: invalid
        let valid = slh_dsa_verify(&kp.pk, msg, &sig, &[], &SLH_DSA_SHAKE_128F).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_invalid_pk_length() {
        let result = slh_dsa_verify(&[0u8; 10], b"msg", &[0u8; 17088], &[], &SLH_DSA_SHAKE_128F);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_sig_length() {
        let pk = [0u8; 32];
        let result = slh_dsa_verify(&pk, b"msg", &[0u8; 100], &[], &SLH_DSA_SHAKE_128F);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_verify_sha2_128f() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHA2_128F).unwrap();
        let msg = b"SHA2 test";
        let sig = slh_dsa_sign(&kp.sk, msg, &[], &SLH_DSA_SHA2_128F).unwrap();
        assert_eq!(sig.len(), SLH_DSA_SHA2_128F.sig_bytes);
        let valid = slh_dsa_verify(&kp.pk, msg, &sig, &[], &SLH_DSA_SHA2_128F).unwrap();
        assert!(valid);
    }
}
