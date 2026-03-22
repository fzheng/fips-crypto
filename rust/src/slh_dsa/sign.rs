//! SLH-DSA Signing — FIPS 205 Algorithm 18 (slh_sign)
//!
//! Signs a message using the SLH-DSA secret key.
//!
//! The signature consists of:
//! 1. R (randomizer, n bytes)
//! 2. FORS signature (k * (1 + a) * n bytes)
//! 3. Hypertree signature (d * (len + hp) * n bytes)

use crate::slh_dsa::address::{Adrs, AdrsType};
use crate::slh_dsa::fors;
use crate::slh_dsa::hash::{h_msg, prf_msg};
use crate::slh_dsa::hypertree;
use crate::slh_dsa::params::SlhDsaParams;
use crate::primitives::random::random_bytes;
use zeroize::Zeroize;

/// FIPS 205 Algorithm 18: SLH-DSA Signing.
///
/// Signs `message` with `sk` under the given parameter set.
/// An optional `context` (max 255 bytes) can be provided per FIPS 205.
pub fn slh_dsa_sign(
    sk: &[u8],
    message: &[u8],
    context: &[u8],
    params: &SlhDsaParams,
) -> Result<Vec<u8>, String> {
    let n = params.n;

    if sk.len() != params.sk_bytes {
        return Err(format!(
            "Invalid secret key length: expected {}, got {}",
            params.sk_bytes,
            sk.len()
        ));
    }

    if context.len() > 255 {
        return Err(format!(
            "Context must be at most 255 bytes, got {}",
            context.len()
        ));
    }

    // Parse SK = SK.seed || SK.prf || PK.seed || PK.root
    let sk_seed = &sk[..n];
    let sk_prf = &sk[n..2 * n];
    let pk_seed = &sk[2 * n..3 * n];
    let pk_root = &sk[3 * n..4 * n];

    // Generate randomizer R = PRF_msg(SK.prf, OptRand, M')
    // OptRand = random n bytes (hedged signing)
    let mut opt_rand = vec![0u8; n];
    random_bytes(&mut opt_rand)
        .map_err(|_| "Failed to generate random bytes".to_string())?;

    // M' = 0x01 || len(ctx) || ctx || message  (pure signing with context)
    // Per FIPS 205 Section 9.2
    let mut m_prime = Vec::with_capacity(2 + context.len() + message.len());
    m_prime.push(0x00); // domain separator for pure SLH-DSA
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(message);

    let r = prf_msg(sk_prf, &opt_rand, &m_prime, params);

    // Compute message digest: digest = H_msg(R, PK.seed, PK.root, M')
    let digest = h_msg(&r, pk_seed, pk_root, &m_prime, params);

    // Split digest into FORS message (md), tree index, and leaf index
    // md = first floor(k*a / 8) bytes
    // tree index and leaf index from remaining bytes
    let (md, idx_tree, idx_leaf) = split_digest(&digest, params);

    // Set up FORS address
    let mut fors_adrs = Adrs::new();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(idx_tree);
    fors_adrs.set_type(AdrsType::ForsTree);
    fors_adrs.set_key_pair_address(idx_leaf);

    // FORS signature
    let sig_fors = fors::fors_sign(&md, sk_seed, pk_seed, &mut fors_adrs, params);

    // Compute FORS public key (needed as message for hypertree)
    let mut fors_pk_adrs = Adrs::new();
    fors_pk_adrs.set_layer_address(0);
    fors_pk_adrs.set_tree_address(idx_tree);
    fors_pk_adrs.set_type(AdrsType::ForsTree);
    fors_pk_adrs.set_key_pair_address(idx_leaf);
    let pk_fors = fors::fors_pk_from_sig(&sig_fors, &md, pk_seed, &mut fors_pk_adrs, params);

    // Hypertree signature over FORS public key
    let sig_ht = hypertree::ht_sign(&pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, params);

    // Assemble full signature: R || SIG_FORS || SIG_HT
    let mut sig = Vec::with_capacity(params.sig_bytes);
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&sig_fors);
    sig.extend_from_slice(&sig_ht);

    // Zeroize sensitive intermediates
    opt_rand.zeroize();
    m_prime.zeroize();

    Ok(sig)
}

/// Split the H_msg digest into (md, idx_tree, idx_leaf).
///
/// Per FIPS 205:
/// - md: first ceil(k*a / 8) bytes — message for FORS
/// - idx_tree: next bits, masked to (h - h/d) bits
/// - idx_leaf: next bits, masked to (h/d) bits
pub fn split_digest(digest: &[u8], params: &SlhDsaParams) -> (Vec<u8>, u64, u32) {
    let ka_bytes = (params.k * params.a + 7) / 8;
    let md = digest[..ka_bytes].to_vec();

    // Tree and leaf index bits from the remaining digest bytes
    let tree_bits = params.h - params.hp; // total tree height minus per-layer height
    let leaf_bits = params.hp;

    // Read tree index (big-endian) from digest bytes after md
    let tree_bytes = (tree_bits + 7) / 8;
    let leaf_bytes = (leaf_bits + 7) / 8;

    let mut idx_tree: u64 = 0;
    for i in 0..tree_bytes {
        if ka_bytes + i < digest.len() {
            idx_tree = (idx_tree << 8) | digest[ka_bytes + i] as u64;
        }
    }
    // Mask to tree_bits
    if tree_bits < 64 {
        idx_tree &= (1u64 << tree_bits) - 1;
    }

    let mut idx_leaf: u32 = 0;
    for i in 0..leaf_bytes {
        if ka_bytes + tree_bytes + i < digest.len() {
            idx_leaf = (idx_leaf << 8) | digest[ka_bytes + tree_bytes + i] as u32;
        }
    }
    // Mask to leaf_bits
    if leaf_bits < 32 {
        idx_leaf &= (1u32 << leaf_bits) - 1;
    }

    (md, idx_tree, idx_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::keygen::slh_dsa_keygen;
    use crate::slh_dsa::params::*;

    #[test]
    fn test_sign_shake_128f_size() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHAKE_128F).unwrap();
        let msg = b"test message";
        let sig = slh_dsa_sign(&kp.sk, msg, &[], &SLH_DSA_SHAKE_128F).unwrap();
        assert_eq!(sig.len(), SLH_DSA_SHAKE_128F.sig_bytes);
    }

    #[test]
    fn test_sign_invalid_sk_length() {
        let result = slh_dsa_sign(&[0u8; 10], b"msg", &[], &SLH_DSA_SHAKE_128F);
        assert!(result.is_err());
    }

    #[test]
    fn test_split_digest() {
        let params = &SLH_DSA_SHAKE_128F;
        let digest = vec![0xABu8; params.m];
        let (md, _tree, _leaf) = split_digest(&digest, params);
        let expected_md_len = (params.k * params.a + 7) / 8;
        assert_eq!(md.len(), expected_md_len);
    }
}
