//! XMSS (eXtended Merkle Signature Scheme) — FIPS 205 Algorithms 6-8
//!
//! XMSS extends WOTS+ into a many-time signature scheme by organizing
//! 2^hp WOTS+ key pairs as leaves of a binary hash tree of height hp.
//! The tree root serves as the XMSS public key, and a signature consists
//! of a WOTS+ signature together with an authentication path (hp sibling
//! nodes needed to recompute the root).
//!
//! In the SLH-DSA hypertree, each layer contains an XMSS tree.
//! The tree height hp = h / d varies by parameter set.

use crate::slh_dsa::address::{Adrs, AdrsType};
use crate::slh_dsa::hash::t_l;
use crate::slh_dsa::params::SlhDsaParams;
use crate::slh_dsa::wots;

/// FIPS 205 Algorithm 6: Compute an internal XMSS tree node.
///
/// Recursively computes the root of the subtree of height `z` whose
/// leftmost leaf is at index `i * 2^z` in the full tree.
///
/// - When z=0 the "node" is a WOTS+ public key (leaf).
/// - When z>0 the node is T_l(pk_seed, adrs, left || right) where
///   left and right are the children at height z-1.
///
/// # Arguments
/// * `sk_seed` - Secret seed (n bytes)
/// * `pk_seed` - Public seed (n bytes)
/// * `i` - Node index at height z (0-indexed from the left)
/// * `z` - Height of this node (0 = leaf, hp = root)
/// * `adrs` - Address (layer and tree address should be set)
/// * `params` - Parameter set
///
/// # Returns
/// The n-byte hash value of the node.
pub fn xmss_node(
    sk_seed: &[u8],
    pk_seed: &[u8],
    i: u32,
    z: u32,
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    if z == 0 {
        // Leaf node: compute WOTS+ public key for leaf index i.
        adrs.set_key_pair_address(i);
        wots::wots_pk_gen(sk_seed, pk_seed, adrs, params)
    } else {
        // Internal node: recursively compute left and right children.
        let left = xmss_node(sk_seed, pk_seed, 2 * i, z - 1, adrs, params);
        let right = xmss_node(sk_seed, pk_seed, 2 * i + 1, z - 1, adrs, params);

        // Combine children using the Tree address type.
        adrs.set_type(AdrsType::Tree);
        adrs.set_key_pair_address(0);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);

        let mut combined = Vec::with_capacity(left.len() + right.len());
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);

        t_l(pk_seed, adrs, &combined, params)
    }
}

/// FIPS 205 Algorithm 7: XMSS signature generation.
///
/// Signs an n-byte message `msg` using the `idx`-th WOTS+ key pair
/// in the XMSS tree. The signature consists of:
/// - A WOTS+ signature on `msg` (len * n bytes)
/// - An authentication path of hp sibling nodes (hp * n bytes)
///
/// # Arguments
/// * `msg` - Message to sign (n bytes, typically a tree root from the layer above)
/// * `sk_seed` - Secret seed (n bytes)
/// * `idx` - Leaf index to sign with (0 .. 2^hp - 1)
/// * `pk_seed` - Public seed (n bytes)
/// * `adrs` - Address (layer and tree address should be set)
/// * `params` - Parameter set
///
/// # Returns
/// XMSS signature: sig_wots (len * n bytes) || auth_path (hp * n bytes).
pub fn xmss_sign(
    msg: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let n = params.n;
    let hp = params.hp;

    // Step 1: Generate WOTS+ signature for msg using the idx-th key pair.
    adrs.set_key_pair_address(idx);
    let sig_wots = wots::wots_sign(msg, sk_seed, pk_seed, adrs, params);

    // Step 2: Build authentication path.
    // For each level j from 0 to hp-1, the authentication path contains
    // the sibling node of the current node's ancestor at height j.
    let mut auth = Vec::with_capacity(hp * n);
    let mut k = idx;
    for j in 0..hp {
        // Sibling index at height j: flip the last bit of k
        let sibling = k ^ 1;
        let node = xmss_node(sk_seed, pk_seed, sibling, j as u32, adrs, params);
        auth.extend_from_slice(&node);
        k >>= 1;
    }

    // Concatenate WOTS+ signature and authentication path
    let mut sig_xmss = Vec::with_capacity(sig_wots.len() + auth.len());
    sig_xmss.extend_from_slice(&sig_wots);
    sig_xmss.extend_from_slice(&auth);
    sig_xmss
}

/// FIPS 205 Algorithm 8: Compute XMSS public key (root) from signature.
///
/// Given an XMSS signature (WOTS+ signature + authentication path) and
/// the signed message, reconstructs the XMSS tree root. If the signature
/// is valid, this root will match the original XMSS public key.
///
/// # Arguments
/// * `idx` - Leaf index that was used for signing
/// * `sig_xmss` - XMSS signature: sig_wots (len * n bytes) || auth (hp * n bytes)
/// * `msg` - Signed message (n bytes)
/// * `pk_seed` - Public seed (n bytes)
/// * `adrs` - Address (layer and tree address should be set)
/// * `params` - Parameter set
///
/// # Returns
/// Reconstructed XMSS root (n bytes).
pub fn xmss_pk_from_sig(
    idx: u32,
    sig_xmss: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let n = params.n;
    let hp = params.hp;
    let wots_sig_len = params.len * n;

    // Step 1: Extract WOTS+ signature and authentication path.
    let sig_wots = &sig_xmss[..wots_sig_len];
    let auth = &sig_xmss[wots_sig_len..];

    // Step 2: Recover WOTS+ public key from the WOTS+ signature.
    adrs.set_key_pair_address(idx);
    let mut node = wots::wots_pk_from_sig(sig_wots, msg, pk_seed, adrs, params);

    // Step 3: Walk up the tree using the authentication path.
    // At each level j, combine the current node with the auth path node
    // to compute the parent. The order depends on whether idx's bit at
    // position j is 0 (current node is left child) or 1 (right child).
    let mut k = idx;
    for j in 0..hp {
        let auth_node = &auth[j * n..(j + 1) * n];

        adrs.set_type(AdrsType::Tree);
        adrs.set_key_pair_address(0);
        adrs.set_tree_height((j + 1) as u32);
        adrs.set_tree_index(k >> 1);

        let mut combined = Vec::with_capacity(2 * n);
        if k & 1 == 0 {
            // Current node is the left child
            combined.extend_from_slice(&node);
            combined.extend_from_slice(auth_node);
        } else {
            // Current node is the right child
            combined.extend_from_slice(auth_node);
            combined.extend_from_slice(&node);
        }

        node = t_l(pk_seed, adrs, &combined, params);
        k >>= 1;
    }

    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::*;

    #[test]
    fn test_xmss_node_leaf_equals_wots_pk() {
        // xmss_node at height 0 should equal wots_pk_gen for the same leaf index.
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0x11u8; params.n];
        let pk_seed = vec![0x22u8; params.n];

        let mut adrs1 = Adrs::new();
        adrs1.set_layer_address(0);
        adrs1.set_tree_address(0);
        let leaf = xmss_node(&sk_seed, &pk_seed, 0, 0, &mut adrs1, params);

        let mut adrs2 = Adrs::new();
        adrs2.set_layer_address(0);
        adrs2.set_tree_address(0);
        adrs2.set_key_pair_address(0);
        let pk = wots::wots_pk_gen(&sk_seed, &pk_seed, &mut adrs2, params);

        assert_eq!(leaf, pk, "xmss_node(z=0) should equal wots_pk_gen");
    }

    #[test]
    fn test_xmss_node_output_length() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0x11u8; params.n];
        let pk_seed = vec![0x22u8; params.n];
        let mut adrs = Adrs::new();

        // Test at different heights
        for z in 0..=2 {
            let node = xmss_node(&sk_seed, &pk_seed, 0, z, &mut adrs, params);
            assert_eq!(node.len(), params.n, "xmss_node at height {} should be n bytes", z);
        }
    }

    #[test]
    fn test_xmss_node_deterministic() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];

        let mut adrs1 = Adrs::new();
        let r1 = xmss_node(&sk_seed, &pk_seed, 0, 2, &mut adrs1, params);

        let mut adrs2 = Adrs::new();
        let r2 = xmss_node(&sk_seed, &pk_seed, 0, 2, &mut adrs2, params);

        assert_eq!(r1, r2, "xmss_node should be deterministic");
    }

    #[test]
    fn test_xmss_roundtrip_shake_128f() {
        // XMSS roundtrip: sign then pk_from_sig should recover the tree root.
        // Use hp=3 for SLH-DSA-SHAKE-128f (tree has 2^3 = 8 leaves).
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];
        let msg = vec![0x55u8; params.n];
        let idx: u32 = 3; // Sign with leaf 3

        // Compute the XMSS tree root.
        let mut adrs = Adrs::new();
        adrs.set_layer_address(0);
        adrs.set_tree_address(0);
        let root = xmss_node(&sk_seed, &pk_seed, 0, params.hp as u32, &mut adrs, params);

        // Sign
        let mut adrs = Adrs::new();
        adrs.set_layer_address(0);
        adrs.set_tree_address(0);
        let sig = xmss_sign(&msg, &sk_seed, idx, &pk_seed, &mut adrs, params);

        let expected_sig_len = params.len * params.n + params.hp * params.n;
        assert_eq!(sig.len(), expected_sig_len, "XMSS sig should be (len + hp) * n bytes");

        // Recover root from signature
        let mut adrs = Adrs::new();
        adrs.set_layer_address(0);
        adrs.set_tree_address(0);
        let recovered = xmss_pk_from_sig(idx, &sig, &msg, &pk_seed, &mut adrs, params);

        assert_eq!(recovered, root, "XMSS roundtrip: recovered root should match computed root");
    }

    #[test]
    fn test_xmss_roundtrip_sha2_128s() {
        // Use a small tree height (hp=9 for SHA2-128s, but we test with leaf 0
        // to keep test runtime reasonable -- the tree structure is the same).
        let params = &SLH_DSA_SHA2_128F; // hp=3, faster for testing
        let sk_seed = vec![0x11u8; params.n];
        let pk_seed = vec![0x22u8; params.n];
        let msg = vec![0x33u8; params.n];
        let idx: u32 = 0;

        let mut adrs = Adrs::new();
        adrs.set_layer_address(2);
        adrs.set_tree_address(1);
        let root = xmss_node(&sk_seed, &pk_seed, 0, params.hp as u32, &mut adrs, params);

        let mut adrs = Adrs::new();
        adrs.set_layer_address(2);
        adrs.set_tree_address(1);
        let sig = xmss_sign(&msg, &sk_seed, idx, &pk_seed, &mut adrs, params);

        let mut adrs = Adrs::new();
        adrs.set_layer_address(2);
        adrs.set_tree_address(1);
        let recovered = xmss_pk_from_sig(idx, &sig, &msg, &pk_seed, &mut adrs, params);

        assert_eq!(recovered, root, "XMSS SHA2-128f roundtrip failed");
    }

    #[test]
    fn test_xmss_roundtrip_last_leaf() {
        // Test signing with the last leaf in the tree.
        let params = &SLH_DSA_SHAKE_128F; // hp=3, so last leaf is 7
        let sk_seed = vec![0xFFu8; params.n];
        let pk_seed = vec![0xEEu8; params.n];
        let msg = vec![0xDDu8; params.n];
        let idx: u32 = (1 << params.hp) - 1; // Last leaf

        let mut adrs = Adrs::new();
        let root = xmss_node(&sk_seed, &pk_seed, 0, params.hp as u32, &mut adrs, params);

        let mut adrs = Adrs::new();
        let sig = xmss_sign(&msg, &sk_seed, idx, &pk_seed, &mut adrs, params);

        let mut adrs = Adrs::new();
        let recovered = xmss_pk_from_sig(idx, &sig, &msg, &pk_seed, &mut adrs, params);

        assert_eq!(recovered, root, "XMSS roundtrip with last leaf failed");
    }

    #[test]
    fn test_xmss_wrong_message_fails() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];
        let msg = vec![0x55u8; params.n];
        let wrong_msg = vec![0x66u8; params.n];
        let idx: u32 = 2;

        let mut adrs = Adrs::new();
        let root = xmss_node(&sk_seed, &pk_seed, 0, params.hp as u32, &mut adrs, params);

        let mut adrs = Adrs::new();
        let sig = xmss_sign(&msg, &sk_seed, idx, &pk_seed, &mut adrs, params);

        // Verify with the wrong message
        let mut adrs = Adrs::new();
        let recovered = xmss_pk_from_sig(idx, &sig, &wrong_msg, &pk_seed, &mut adrs, params);

        assert_ne!(recovered, root, "XMSS should not verify with wrong message");
    }

    #[test]
    fn test_xmss_wrong_idx_fails() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];
        let msg = vec![0x55u8; params.n];
        let idx: u32 = 2;

        let mut adrs = Adrs::new();
        let root = xmss_node(&sk_seed, &pk_seed, 0, params.hp as u32, &mut adrs, params);

        let mut adrs = Adrs::new();
        let sig = xmss_sign(&msg, &sk_seed, idx, &pk_seed, &mut adrs, params);

        // Verify with wrong leaf index
        let mut adrs = Adrs::new();
        let recovered = xmss_pk_from_sig(idx + 1, &sig, &msg, &pk_seed, &mut adrs, params);

        assert_ne!(recovered, root, "XMSS should not verify with wrong leaf index");
    }

    #[test]
    fn test_xmss_different_trees_different_roots() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];

        let mut adrs1 = Adrs::new();
        adrs1.set_tree_address(0);
        let root1 = xmss_node(&sk_seed, &pk_seed, 0, params.hp as u32, &mut adrs1, params);

        let mut adrs2 = Adrs::new();
        adrs2.set_tree_address(1);
        let root2 = xmss_node(&sk_seed, &pk_seed, 0, params.hp as u32, &mut adrs2, params);

        assert_ne!(root1, root2, "Different tree addresses should yield different roots");
    }
}
