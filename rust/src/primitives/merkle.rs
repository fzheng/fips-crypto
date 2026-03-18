//! Merkle tree operations for SLH-DSA (FIPS 205)
//!
//! Implements binary Merkle trees used in hash-based signatures.
//! Used for XMSS and Hypertree constructions in SPHINCS+.

use crate::primitives::sha3::{sha3_256, shake256};

/// Hash two nodes to compute parent node (SHA-256 variant)
pub fn hash_node_sha256(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    sha3_256(&input)
}

/// Hash two nodes to compute parent node (SHAKE256 variant)
pub fn hash_node_shake256(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    let output = shake256(&input, 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&output);
    result
}

/// Authentication path in a Merkle tree
#[derive(Clone, Debug)]
pub struct AuthPath {
    pub nodes: Vec<[u8; 32]>,
}

impl AuthPath {
    /// Create a new authentication path
    pub fn new(height: usize) -> Self {
        Self {
            nodes: vec![[0u8; 32]; height],
        }
    }

    /// Get the path length
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.nodes.len() * 32);
        for node in &self.nodes {
            result.extend_from_slice(node);
        }
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8], height: usize) -> Self {
        let mut nodes = Vec::with_capacity(height);
        for i in 0..height {
            let mut node = [0u8; 32];
            node.copy_from_slice(&data[i * 32..(i + 1) * 32]);
            nodes.push(node);
        }
        Self { nodes }
    }
}

/// Compute root from leaf and authentication path
pub fn compute_root(
    leaf: &[u8; 32],
    leaf_index: usize,
    auth_path: &AuthPath,
    hash_fn: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> [u8; 32] {
    let mut current = *leaf;
    let mut index = leaf_index;

    for node in &auth_path.nodes {
        if index & 1 == 0 {
            // Current node is left child
            current = hash_fn(&current, node);
        } else {
            // Current node is right child
            current = hash_fn(node, &current);
        }
        index >>= 1;
    }

    current
}

/// Verify that a leaf is part of a tree with the given root
pub fn verify_path(
    leaf: &[u8; 32],
    leaf_index: usize,
    auth_path: &AuthPath,
    root: &[u8; 32],
    hash_fn: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> bool {
    let computed_root = compute_root(leaf, leaf_index, auth_path, hash_fn);
    constant_time_eq(&computed_root, root)
}

/// Simple Merkle tree builder (for testing and small trees)
pub struct MerkleTree {
    /// All nodes in the tree, layer by layer (leaves first)
    nodes: Vec<Vec<[u8; 32]>>,
    /// Height of the tree
    height: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaves
    pub fn from_leaves(
        leaves: &[[u8; 32]],
        hash_fn: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    ) -> Self {
        assert!(leaves.len().is_power_of_two(), "Number of leaves must be a power of 2");
        let height = (leaves.len() as f64).log2() as usize;

        let mut nodes = Vec::with_capacity(height + 1);
        nodes.push(leaves.to_vec());

        // Build layers bottom-up
        for layer in 0..height {
            let prev_layer = &nodes[layer];
            let mut new_layer = Vec::with_capacity(prev_layer.len() / 2);

            for i in (0..prev_layer.len()).step_by(2) {
                let parent = hash_fn(&prev_layer[i], &prev_layer[i + 1]);
                new_layer.push(parent);
            }

            nodes.push(new_layer);
        }

        Self { nodes, height }
    }

    /// Get the root of the tree
    pub fn root(&self) -> [u8; 32] {
        self.nodes[self.height][0]
    }

    /// Get the authentication path for a leaf
    pub fn auth_path(&self, leaf_index: usize) -> AuthPath {
        let mut path = AuthPath::new(self.height);
        let mut index = leaf_index;

        for layer in 0..self.height {
            let sibling_index = index ^ 1;
            path.nodes[layer] = self.nodes[layer][sibling_index];
            index >>= 1;
        }

        path
    }

    /// Get tree height
    pub fn height(&self) -> usize {
        self.height
    }

    /// Get number of leaves
    pub fn num_leaves(&self) -> usize {
        self.nodes[0].len()
    }
}

/// Constant-time comparison of two byte arrays
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_basic() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();

        let tree = MerkleTree::from_leaves(&leaves, hash_node_sha256);

        assert_eq!(tree.height(), 2);
        assert_eq!(tree.num_leaves(), 4);

        // Verify all leaves
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.auth_path(i);
            assert!(verify_path(leaf, i, &path, &tree.root(), hash_node_sha256));
        }
    }

    #[test]
    fn test_merkle_tree_large() {
        let leaves: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                sha3_256(&leaf)
            })
            .collect();

        let tree = MerkleTree::from_leaves(&leaves, hash_node_sha256);

        assert_eq!(tree.height(), 4);

        // Verify random leaves
        for i in [0, 5, 10, 15] {
            let path = tree.auth_path(i);
            assert!(verify_path(&leaves[i], i, &path, &tree.root(), hash_node_sha256));
        }
    }

    #[test]
    fn test_invalid_proof_fails() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();

        let tree = MerkleTree::from_leaves(&leaves, hash_node_sha256);

        // Get path for leaf 0
        let path = tree.auth_path(0);

        // Try to verify with wrong leaf
        let mut wrong_leaf = leaves[0];
        wrong_leaf[0] = 255;

        assert!(!verify_path(&wrong_leaf, 0, &path, &tree.root(), hash_node_sha256));
    }

    #[test]
    fn test_auth_path_serialization() {
        let mut path = AuthPath::new(3);
        for i in 0..3 {
            path.nodes[i][0] = i as u8;
        }

        let bytes = path.to_bytes();
        let restored = AuthPath::from_bytes(&bytes, 3);

        for i in 0..3 {
            assert_eq!(path.nodes[i], restored.nodes[i]);
        }
    }
}
