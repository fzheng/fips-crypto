//! FORS (Forest of Random Subsets) — FIPS 205 Algorithms 10-14
//!
//! FORS is a few-time signature scheme used within SLH-DSA to sign
//! the message digest. It consists of k independent binary trees, each
//! of height a. The message digest is split into k a-bit indices, each
//! selecting a leaf from one tree.
//!
//! The FORS signature reveals one secret value per tree plus an
//! authentication path of a sibling nodes, allowing the verifier to
//! reconstruct each tree root. The k roots are then compressed into a
//! single FORS public key using T_l.

use crate::slh_dsa::address::{Adrs, AdrsType};
use crate::slh_dsa::hash::{prf, t_l};
use crate::slh_dsa::params::SlhDsaParams;

// =============================================================================
// Helper: bit extraction
// =============================================================================

/// Extract k values of a bits each from the message digest md.
///
/// Bits are read in big-endian order: the first a bits of md become
/// indices\[0\], the next a bits become indices\[1\], and so on.
fn extract_indices(md: &[u8], k: usize, a: usize) -> Vec<u32> {
    let mut indices = Vec::with_capacity(k);
    for i in 0..k {
        let bit_offset = i * a;
        let mut val: u32 = 0;
        for b in 0..a {
            let total_bit = bit_offset + b;
            let byte_idx = total_bit / 8;
            let bit_idx = 7 - (total_bit % 8); // big-endian within each byte
            let bit = ((md[byte_idx] >> bit_idx) & 1) as u32;
            val = (val << 1) | bit;
        }
        indices.push(val);
    }
    indices
}

// =============================================================================
// FORS Secret Key Generation — Algorithm 10
// =============================================================================

/// FIPS 205 Algorithm 10: Generate a FORS secret value.
///
/// Returns the n-byte secret value at position `idx` within the FORS
/// instance identified by the current ADRS (which carries the key pair
/// address set by the caller).
///
/// `idx` is the global leaf index: for tree j with leaf offset i, the
/// global index is j * 2^a + i.
pub fn fors_sk_gen(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    idx: u32,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let kp = adrs.get_key_pair_address();
    adrs.set_type(AdrsType::ForsPrf);
    adrs.set_key_pair_address(kp);
    adrs.set_tree_height(0);
    adrs.set_tree_index(idx);
    prf(pk_seed, sk_seed, adrs, params)
}

// =============================================================================
// FORS Tree Node Computation — Algorithm 11
// =============================================================================

/// FIPS 205 Algorithm 11: Compute a FORS tree node.
///
/// Computes the node at height `z` and global index `i`. The global
/// indexing scheme is the same as for leaves: at height 0, indices run
/// from j * 2^a to (j+1) * 2^a - 1 for tree j. At height z, indices
/// run from j * 2^(a-z) to (j+1) * 2^(a-z) - 1.
///
/// At height 0 the node is the hash of the corresponding secret value;
/// at higher levels it is the hash of the concatenation of its two
/// children.
pub fn fors_node(
    sk_seed: &[u8],
    pk_seed: &[u8],
    i: u32,
    z: u32,
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    if z == 0 {
        // Leaf node: hash of the secret value
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs, i, params);
        let kp = adrs.get_key_pair_address();
        adrs.set_type(AdrsType::ForsTree);
        adrs.set_key_pair_address(kp);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        t_l(pk_seed, adrs, &sk, params)
    } else {
        // Internal node: hash of left || right children
        let left = fors_node(sk_seed, pk_seed, 2 * i, z - 1, adrs, params);
        let right = fors_node(sk_seed, pk_seed, 2 * i + 1, z - 1, adrs, params);
        let kp = adrs.get_key_pair_address();
        adrs.set_type(AdrsType::ForsTree);
        adrs.set_key_pair_address(kp);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        let mut concat = Vec::with_capacity(left.len() + right.len());
        concat.extend_from_slice(&left);
        concat.extend_from_slice(&right);
        t_l(pk_seed, adrs, &concat, params)
    }
}

// =============================================================================
// FORS Signature Generation — Algorithm 12
// =============================================================================

/// FIPS 205 Algorithm 12: FORS signature generation.
///
/// The message digest `md` is split into k chunks of a bits each.
/// For each chunk j, the signature includes:
/// 1. The secret value at the selected leaf (global index j * 2^a + idx).
/// 2. An authentication path of a sibling nodes (one per tree level).
///
/// The total FORS signature size is k * (1 + a) * n bytes.
pub fn fors_sign(
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let k = params.k;
    let a = params.a;
    let n = params.n;
    let indices = extract_indices(md, k, a);

    let mut sig = Vec::with_capacity(k * (1 + a) * n);

    for j in 0..k {
        let idx = indices[j];

        // Secret value: global leaf index = j * 2^a + idx
        let global_leaf = (j as u32) * (1u32 << a) + idx;
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs, global_leaf, params);
        sig.extend_from_slice(&sk);

        // Authentication path: a sibling nodes, one per level
        for l in 0..a {
            // At height l, the index of the ancestor of our leaf within
            // tree j is (idx >> l). Its sibling is (idx >> l) ^ 1.
            // The global index at height l is:
            //   j * 2^(a-l) + sibling_index_within_tree
            let sibling = (idx >> l) ^ 1;
            let global_idx = (j as u32) * (1u32 << (a - l)) + sibling;
            let auth_node =
                fors_node(sk_seed, pk_seed, global_idx, l as u32, adrs, params);
            sig.extend_from_slice(&auth_node);
        }
    }

    sig
}

// =============================================================================
// FORS Public Key from Signature — Algorithm 13
// =============================================================================

/// FIPS 205 Algorithm 13: Compute FORS public key from signature.
///
/// Recovers the k tree roots from the FORS signature and compresses
/// them into a single n-byte FORS public key using T_l with the
/// ForsRoots address type.
pub fn fors_pk_from_sig(
    sig_fors: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let k = params.k;
    let a = params.a;
    let n = params.n;
    let indices = extract_indices(md, k, a);

    let mut roots = Vec::with_capacity(k * n);
    let sig_tree_size = (1 + a) * n; // bytes per tree in the signature

    for j in 0..k {
        let tree_sig = &sig_fors[j * sig_tree_size..(j + 1) * sig_tree_size];
        let sk_val = &tree_sig[..n];
        let auth = &tree_sig[n..];

        let idx = indices[j];

        // Hash the secret value to get the leaf node
        let global_leaf = (j as u32) * (1u32 << a) + idx;
        let kp = adrs.get_key_pair_address();
        adrs.set_type(AdrsType::ForsTree);
        adrs.set_key_pair_address(kp);
        adrs.set_tree_height(0);
        adrs.set_tree_index(global_leaf);
        let mut node = t_l(pk_seed, adrs, sk_val, params);

        // Walk up the tree using the authentication path
        for l in 0..a {
            let auth_node = &auth[l * n..(l + 1) * n];

            // Parent global index at height (l+1)
            let parent_global = (j as u32) * (1u32 << (a - l - 1)) + (idx >> (l + 1));
            adrs.set_tree_height((l + 1) as u32);
            adrs.set_tree_index(parent_global);

            // Determine ordering: if bit l of idx is 0, our node is the
            // left child and the auth node is the right child.
            let mut concat = Vec::with_capacity(2 * n);
            if (idx >> l) & 1 == 0 {
                concat.extend_from_slice(&node);
                concat.extend_from_slice(auth_node);
            } else {
                concat.extend_from_slice(auth_node);
                concat.extend_from_slice(&node);
            }
            node = t_l(pk_seed, adrs, &concat, params);
        }

        roots.extend_from_slice(&node);
    }

    // Compress k roots into a single FORS public key
    let kp = adrs.get_key_pair_address();
    adrs.set_type(AdrsType::ForsRoots);
    adrs.set_key_pair_address(kp);
    adrs.set_tree_height(0);
    adrs.set_tree_index(0);
    t_l(pk_seed, adrs, &roots, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::SLH_DSA_SHAKE_128F;

    #[test]
    fn test_extract_indices_basic() {
        // 6-bit values from a byte sequence
        // Byte 0: 0b1101_0110, Byte 1: 0b1010_0011, Byte 2: 0b0000_1111
        // First 6 bits: 1 1 0 1 0 1 => 0b110101 = 53
        // Next 6 bits:  1 0 1 0 1 0 => 0b101010 = 42
        let md = [0b1101_0110, 0b1010_0011, 0b0000_1111];
        let indices = extract_indices(&md, 2, 6);
        assert_eq!(indices[0], 53);
        assert_eq!(indices[1], 42);
    }

    #[test]
    fn test_extract_indices_full_byte() {
        // When a=8, each index is a full byte
        let md = [0xAB, 0xCD, 0xEF];
        let indices = extract_indices(&md, 3, 8);
        assert_eq!(indices[0], 0xAB);
        assert_eq!(indices[1], 0xCD);
        assert_eq!(indices[2], 0xEF);
    }

    #[test]
    fn test_extract_indices_single_bit() {
        // When a=1, each index is a single bit
        let md = [0b1010_0000];
        let indices = extract_indices(&md, 4, 1);
        assert_eq!(indices[0], 1);
        assert_eq!(indices[1], 0);
        assert_eq!(indices[2], 1);
        assert_eq!(indices[3], 0);
    }

    #[test]
    fn test_fors_sk_gen_deterministic() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0x42u8; params.n];
        let pk_seed = vec![0x13u8; params.n];

        let mut adrs1 = Adrs::new();
        adrs1.set_key_pair_address(7);
        let sk1 = fors_sk_gen(&sk_seed, &pk_seed, &mut adrs1, 0, params);

        let mut adrs2 = Adrs::new();
        adrs2.set_key_pair_address(7);
        let sk2 = fors_sk_gen(&sk_seed, &pk_seed, &mut adrs2, 0, params);

        assert_eq!(sk1, sk2);
        assert_eq!(sk1.len(), params.n);
    }

    #[test]
    fn test_fors_sk_gen_different_indices() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0x42u8; params.n];
        let pk_seed = vec![0x13u8; params.n];
        let mut adrs = Adrs::new();

        let sk0 = fors_sk_gen(&sk_seed, &pk_seed, &mut adrs, 0, params);
        let sk1 = fors_sk_gen(&sk_seed, &pk_seed, &mut adrs, 1, params);
        assert_ne!(sk0, sk1);
    }

    #[test]
    fn test_fors_node_leaf() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0x11u8; params.n];
        let pk_seed = vec![0x22u8; params.n];
        let mut adrs = Adrs::new();

        let node = fors_node(&sk_seed, &pk_seed, 0, 0, &mut adrs, params);
        assert_eq!(node.len(), params.n);
    }

    #[test]
    fn test_fors_node_internal() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0x11u8; params.n];
        let pk_seed = vec![0x22u8; params.n];
        let mut adrs = Adrs::new();

        // Height 1 node is the hash of two leaf children
        let node = fors_node(&sk_seed, &pk_seed, 0, 1, &mut adrs, params);
        assert_eq!(node.len(), params.n);
    }

    #[test]
    fn test_fors_node_consistency() {
        // fors_node(i, 1) should equal T_l(pk_seed, adrs,
        //   fors_node(2i, 0) || fors_node(2i+1, 0))
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0x11u8; params.n];
        let pk_seed = vec![0x22u8; params.n];

        let mut adrs = Adrs::new();
        let parent = fors_node(&sk_seed, &pk_seed, 5, 1, &mut adrs, params);

        let mut adrs2 = Adrs::new();
        let left = fors_node(&sk_seed, &pk_seed, 10, 0, &mut adrs2, params);
        let mut adrs3 = Adrs::new();
        let right = fors_node(&sk_seed, &pk_seed, 11, 0, &mut adrs3, params);

        let mut concat = Vec::new();
        concat.extend_from_slice(&left);
        concat.extend_from_slice(&right);

        let mut adrs4 = Adrs::new();
        adrs4.set_type(AdrsType::ForsTree);
        adrs4.set_tree_height(1);
        adrs4.set_tree_index(5);
        let expected = t_l(&pk_seed, &adrs4, &concat, params);

        assert_eq!(parent, expected);
    }

    #[test]
    fn test_fors_sign_output_size() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;
        let k = params.k;
        let a = params.a;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];

        let md_len = (k * a + 7) / 8;
        let md = vec![0x55u8; md_len];

        let mut adrs = Adrs::new();
        let sig = fors_sign(&md, &sk_seed, &pk_seed, &mut adrs, params);
        assert_eq!(sig.len(), k * (1 + a) * n);
    }

    #[test]
    fn test_fors_sign_verify_roundtrip() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;
        let k = params.k;
        let a = params.a;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];

        // Create a message digest of sufficient length
        let md_len = (k * a + 7) / 8;
        let md = vec![0x55u8; md_len];

        let mut adrs = Adrs::new();
        adrs.set_layer_address(0);
        adrs.set_tree_address(0);
        adrs.set_key_pair_address(0);

        // Sign
        let sig = fors_sign(&md, &sk_seed, &pk_seed, &mut adrs, params);

        // Recover public key from signature
        let mut adrs2 = Adrs::new();
        adrs2.set_key_pair_address(0);
        let pk_from_sig = fors_pk_from_sig(&sig, &md, &pk_seed, &mut adrs2, params);
        assert_eq!(pk_from_sig.len(), n);

        // Compute the expected public key directly by building all k tree roots.
        // The root of tree j is fors_node(j, a) since at height a the global
        // index of the single root for tree j is j (from the recursion:
        // root at height a has index j, its children at height a-1 have
        // indices 2j and 2j+1, ..., down to height 0 with indices
        // j*2^a .. (j+1)*2^a - 1).
        let mut roots = Vec::with_capacity(k * n);
        for j in 0..k {
            let mut adrs_j = Adrs::new();
            adrs_j.set_key_pair_address(0);
            let root = fors_node(&sk_seed, &pk_seed, j as u32, a as u32, &mut adrs_j, params);
            roots.extend_from_slice(&root);
        }

        let mut adrs_roots = Adrs::new();
        adrs_roots.set_type(AdrsType::ForsRoots);
        adrs_roots.set_key_pair_address(0);
        let pk_expected = t_l(&pk_seed, &adrs_roots, &roots, params);

        assert_eq!(
            pk_from_sig, pk_expected,
            "FORS public key recovered from signature must match directly computed public key"
        );
    }

    #[test]
    fn test_fors_tampered_sig_produces_different_pk() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;
        let k = params.k;
        let a = params.a;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];

        let md_len = (k * a + 7) / 8;
        let md = vec![0x55u8; md_len];

        let mut adrs = Adrs::new();
        adrs.set_key_pair_address(0);
        let sig = fors_sign(&md, &sk_seed, &pk_seed, &mut adrs, params);

        // Get the correct public key
        let mut adrs2 = Adrs::new();
        adrs2.set_key_pair_address(0);
        let pk_correct = fors_pk_from_sig(&sig, &md, &pk_seed, &mut adrs2, params);

        // Tamper with the signature (flip a byte in the first secret value)
        let mut tampered = sig.clone();
        tampered[0] ^= 0xFF;

        let mut adrs3 = Adrs::new();
        adrs3.set_key_pair_address(0);
        let pk_tampered = fors_pk_from_sig(&tampered, &md, &pk_seed, &mut adrs3, params);

        assert_ne!(
            pk_correct, pk_tampered,
            "Tampered signature must produce a different public key"
        );
    }

    #[test]
    fn test_fors_wrong_message_produces_different_pk() {
        let params = &SLH_DSA_SHAKE_128F;
        let n = params.n;
        let k = params.k;
        let a = params.a;

        let sk_seed = vec![0xAAu8; n];
        let pk_seed = vec![0xBBu8; n];

        let md_len = (k * a + 7) / 8;
        let md1 = vec![0x55u8; md_len];
        let md2 = vec![0x66u8; md_len];

        let mut adrs = Adrs::new();
        adrs.set_key_pair_address(0);
        let sig = fors_sign(&md1, &sk_seed, &pk_seed, &mut adrs, params);

        // Verify with correct message
        let mut adrs2 = Adrs::new();
        adrs2.set_key_pair_address(0);
        let pk1 = fors_pk_from_sig(&sig, &md1, &pk_seed, &mut adrs2, params);

        // Verify with wrong message
        let mut adrs3 = Adrs::new();
        adrs3.set_key_pair_address(0);
        let pk2 = fors_pk_from_sig(&sig, &md2, &pk_seed, &mut adrs3, params);

        assert_ne!(
            pk1, pk2,
            "Different message digests must produce different public keys"
        );
    }
}