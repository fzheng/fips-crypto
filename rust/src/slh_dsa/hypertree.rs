//! Hypertree — FIPS 205 Algorithms 15-16
//!
//! The hypertree is a certification tree of d layers of XMSS trees.
//! Each XMSS tree has height hp = h/d, and the hypertree has a total
//! height of h. Layer 0 is the bottom (closest to the FORS signatures)
//! and layer d-1 is the top, whose root is the SLH-DSA public key.
//!
//! Signing traverses from layer 0 up to layer d-1, producing one XMSS
//! signature per layer. Verification replays the same traversal and
//! checks that the final recovered root matches the public key.

use crate::slh_dsa::address::Adrs;
use crate::slh_dsa::params::SlhDsaParams;
use crate::slh_dsa::xmss;

// =============================================================================
// Hypertree Signing — Algorithm 15
// =============================================================================

/// FIPS 205 Algorithm 15: Hypertree signing.
///
/// Signs a message `msg` (typically a FORS public key) using the
/// hypertree. The caller provides `idx_tree` (which tree at layer 0)
/// and `idx_leaf` (which leaf within that tree).
///
/// Returns the concatenation of d XMSS signatures, each of size
/// (len + hp) * n bytes, for a total of d * (len + hp) * n bytes.
pub fn ht_sign(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let d = params.d;
    let hp = params.hp;
    let n = params.n;
    let xmss_sig_size = (params.len + hp) * n;

    let mut sig_ht = Vec::with_capacity(d * xmss_sig_size);

    // Layer 0
    let mut adrs = Adrs::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    let sig_0 = xmss::xmss_sign(msg, sk_seed, idx_leaf, pk_seed, &mut adrs, params);
    sig_ht.extend_from_slice(&sig_0);

    // Compute the root that the verifier would recover at layer 0
    let mut root = xmss::xmss_pk_from_sig(idx_leaf, &sig_0, msg, pk_seed, &mut adrs, params);

    // Layers 1 through d-1
    let mut tree = idx_tree;
    for layer in 1..d {
        // The leaf index for this layer is the lower hp bits of tree
        let leaf = (tree & ((1u64 << hp) - 1)) as u32;
        // Shift tree address right by hp
        tree >>= hp;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(tree);

        let sig_layer = xmss::xmss_sign(&root, sk_seed, leaf, pk_seed, &mut adrs, params);
        sig_ht.extend_from_slice(&sig_layer);

        root = xmss::xmss_pk_from_sig(leaf, &sig_layer, &root, pk_seed, &mut adrs, params);
    }

    sig_ht
}

// =============================================================================
// Hypertree Verification — Algorithm 16
// =============================================================================

/// FIPS 205 Algorithm 16: Hypertree signature verification.
///
/// Verifies a hypertree signature `sig_ht` over `msg` against the
/// root public key `pk_root`. Returns true if and only if the
/// recovered root at the top layer matches `pk_root`.
pub fn ht_verify(
    msg: &[u8],
    sig_ht: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8],
    params: &SlhDsaParams,
) -> bool {
    let d = params.d;
    let hp = params.hp;
    let n = params.n;
    let xmss_sig_size = (params.len + hp) * n;

    // Layer 0
    let sig_0 = &sig_ht[..xmss_sig_size];
    let mut adrs = Adrs::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    let mut root = xmss::xmss_pk_from_sig(idx_leaf, sig_0, msg, pk_seed, &mut adrs, params);

    // Layers 1 through d-1
    let mut tree = idx_tree;
    for layer in 1..d {
        let leaf = (tree & ((1u64 << hp) - 1)) as u32;
        tree >>= hp;

        let sig_layer =
            &sig_ht[layer * xmss_sig_size..(layer + 1) * xmss_sig_size];

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(tree);

        root = xmss::xmss_pk_from_sig(leaf, sig_layer, &root, pk_seed, &mut adrs, params);
    }

    root == pk_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::SLH_DSA_SHAKE_128F;
    use crate::slh_dsa::xmss;

    /// Helper: compute the hypertree root from sk_seed and pk_seed.
    ///
    /// The root is the XMSS root at layer d-1, tree address 0.
    /// We compute it bottom-up by evaluating xmss_node at the top of
    /// each layer. For the test we just need the top-layer root, which
    /// is xmss_node(sk_seed, 0, hp, pk_seed, adrs) at layer d-1,
    /// tree 0. But computing the full hypertree root correctly requires
    /// knowledge of which tree addresses are used, so instead we use a
    /// sign-then-recover approach.
    fn compute_ht_root(
        sk_seed: &[u8],
        pk_seed: &[u8],
        params: &SlhDsaParams,
    ) -> Vec<u8> {
        // The hypertree root is the XMSS root at the topmost layer (d-1),
        // tree address 0. We compute it by signing an arbitrary message
        // with idx_tree=0, idx_leaf=0, then extracting the root the
        // sign function computed internally.
        //
        // Actually, the simplest approach: compute xmss_node at layer d-1.
        let mut adrs = Adrs::new();
        adrs.set_layer_address((params.d - 1) as u32);
        adrs.set_tree_address(0);
        xmss::xmss_node(sk_seed, pk_seed, 0, params.hp as u32, &mut adrs, params)
    }

    #[test]
    fn test_ht_sign_output_size() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;
        let d = params.d;
        let hp = params.hp;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];
        let msg = vec![0xCCu8; n];

        let sig = ht_sign(&msg, &sk_seed, &pk_seed, 0, 0, params);
        let expected_size = d * (params.len + hp) * n;
        assert_eq!(sig.len(), expected_size);
    }

    #[test]
    fn test_ht_sign_verify_roundtrip_trivial() {
        // Use idx_tree=0, idx_leaf=0 for simplest case
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];
        let msg = vec![0xCCu8; n];

        // Compute the hypertree root
        let pk_root = compute_ht_root(&sk_seed, &pk_seed, params);

        // Sign
        let sig = ht_sign(&msg, &sk_seed, &pk_seed, 0, 0, params);

        // Verify
        let valid = ht_verify(&msg, &sig, &pk_seed, 0, 0, &pk_root, params);
        assert!(valid, "Hypertree signature must verify with correct root");
    }

    #[test]
    fn test_ht_sign_verify_roundtrip_nonzero_leaf() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;

        let sk_seed = vec![0x11u8; n];
        let pk_seed = vec![0x22u8; n];
        let msg = vec![0x33u8; n];

        let pk_root = compute_ht_root(&sk_seed, &pk_seed, params);

        // Use a non-zero leaf index (must be < 2^hp)
        let idx_leaf = 3u32;
        let sig = ht_sign(&msg, &sk_seed, &pk_seed, 0, idx_leaf, params);
        let valid = ht_verify(&msg, &sig, &pk_seed, 0, idx_leaf, &pk_root, params);
        assert!(valid, "Hypertree signature must verify with non-zero leaf index");
    }

    #[test]
    fn test_ht_verify_rejects_wrong_message() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];
        let msg = vec![0xCCu8; n];
        let wrong_msg = vec![0xDDu8; n];

        let pk_root = compute_ht_root(&sk_seed, &pk_seed, params);
        let sig = ht_sign(&msg, &sk_seed, &pk_seed, 0, 0, params);

        let valid = ht_verify(&wrong_msg, &sig, &pk_seed, 0, 0, &pk_root, params);
        assert!(!valid, "Hypertree verification must reject wrong message");
    }

    #[test]
    fn test_ht_verify_rejects_tampered_signature() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];
        let msg = vec![0xCCu8; n];

        let pk_root = compute_ht_root(&sk_seed, &pk_seed, params);
        let mut sig = ht_sign(&msg, &sk_seed, &pk_seed, 0, 0, params);

        // Tamper with the signature
        sig[0] ^= 0xFF;

        let valid = ht_verify(&msg, &sig, &pk_seed, 0, 0, &pk_root, params);
        assert!(!valid, "Hypertree verification must reject tampered signature");
    }

    #[test]
    fn test_ht_verify_rejects_wrong_root() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];
        let msg = vec![0xCCu8; n];

        let mut wrong_root = compute_ht_root(&sk_seed, &pk_seed, params);
        wrong_root[0] ^= 0xFF; // corrupt the root

        let sig = ht_sign(&msg, &sk_seed, &pk_seed, 0, 0, params);

        let valid = ht_verify(&msg, &sig, &pk_seed, 0, 0, &wrong_root, params);
        assert!(!valid, "Hypertree verification must reject wrong public key root");
    }
}
