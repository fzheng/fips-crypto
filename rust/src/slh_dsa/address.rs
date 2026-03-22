//! SLH-DSA Address Structure — FIPS 205 Section 4.2
//!
//! A 32-byte address (ADRS) used to domain-separate all hash calls.
//! Different address types are used for different operations
//! (WOTS+ hashing, WOTS+ key compression, FORS tree, etc.).
//!
//! Byte layout for SHAKE (32-byte, per NIST reference implementation):
//!   Byte  3:    layer address
//!   Bytes 8-15: tree address (8 bytes, big-endian)
//!   Byte  19:   type
//!   Bytes 20-23: key pair address (4 bytes, big-endian)
//!   Byte  27:   chain address / tree height
//!   Bytes 28-31: tree index (4 bytes, big-endian)
//!   Byte  31:   hash address (overlaps with tree index last byte)
//!
//! For SHA2, a compressed 22-byte ADRSc is used (see to_sha2_compressed).

use zeroize::Zeroize;

/// Address types per FIPS 205 Table 2.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum AdrsType {
    /// WOTS+ hash address
    WotsHash = 0,
    /// WOTS+ public key compression
    WotsPk = 1,
    /// Hash tree address (XMSS internal nodes)
    Tree = 2,
    /// FORS tree address
    ForsTree = 3,
    /// FORS tree roots compression
    ForsRoots = 4,
    /// WOTS+ PRF key generation
    WotsPrf = 5,
    /// FORS PRF key generation
    ForsPrf = 6,
}

// SHAKE (32-byte) offsets per NIST reference implementation (shake_offsets.h)
const OFFSET_LAYER: usize = 3;
const OFFSET_TREE: usize = 8;
const OFFSET_TYPE: usize = 19;
const OFFSET_KP_ADDR: usize = 20;
const OFFSET_CHAIN_ADDR: usize = 27;  // also tree height
const OFFSET_TREE_INDEX: usize = 28;
const OFFSET_HASH_ADDR: usize = 31;

/// 32-byte ADRS (address) structure per FIPS 205.
#[derive(Clone, Zeroize)]
pub struct Adrs {
    bytes: [u8; 32],
}

impl Adrs {
    /// Create a new zero-initialized ADRS.
    pub fn new() -> Self {
        Adrs { bytes: [0u8; 32] }
    }

    /// Get the raw 32-byte address.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Set layer address (single byte at offset 3).
    pub fn set_layer_address(&mut self, layer: u32) {
        self.bytes[OFFSET_LAYER] = layer as u8;
    }

    /// Set tree address (8 bytes big-endian at offset 8).
    pub fn set_tree_address(&mut self, tree: u64) {
        self.bytes[OFFSET_TREE..OFFSET_TREE + 8].copy_from_slice(&tree.to_be_bytes());
    }

    /// Set address type (single byte at offset 19).
    /// Per NIST reference implementation, only the type byte is set —
    /// the caller is responsible for setting/clearing other fields.
    pub fn set_type(&mut self, addr_type: AdrsType) {
        self.bytes[OFFSET_TYPE] = addr_type as u8;
    }

    /// Set key pair address (4 bytes big-endian at offset 20).
    pub fn set_key_pair_address(&mut self, kp: u32) {
        self.bytes[OFFSET_KP_ADDR..OFFSET_KP_ADDR + 4].copy_from_slice(&kp.to_be_bytes());
    }

    /// Get key pair address (4 bytes big-endian at offset 20).
    pub fn get_key_pair_address(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[OFFSET_KP_ADDR],
            self.bytes[OFFSET_KP_ADDR + 1],
            self.bytes[OFFSET_KP_ADDR + 2],
            self.bytes[OFFSET_KP_ADDR + 3],
        ])
    }

    /// Set chain address (single byte at offset 27).
    pub fn set_chain_address(&mut self, chain: u32) {
        self.bytes[OFFSET_CHAIN_ADDR] = chain as u8;
    }

    /// Set hash address (single byte at offset 31).
    pub fn set_hash_address(&mut self, hash: u32) {
        self.bytes[OFFSET_HASH_ADDR] = hash as u8;
    }

    /// Set tree height (single byte at offset 27, same position as chain).
    pub fn set_tree_height(&mut self, height: u32) {
        self.bytes[OFFSET_CHAIN_ADDR] = height as u8;
    }

    /// Set tree index (4 bytes big-endian at offset 28).
    pub fn set_tree_index(&mut self, index: u32) {
        self.bytes[OFFSET_TREE_INDEX..OFFSET_TREE_INDEX + 4].copy_from_slice(&index.to_be_bytes());
    }

    /// Get tree index (4 bytes big-endian at offset 28).
    pub fn get_tree_index(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[OFFSET_TREE_INDEX],
            self.bytes[OFFSET_TREE_INDEX + 1],
            self.bytes[OFFSET_TREE_INDEX + 2],
            self.bytes[OFFSET_TREE_INDEX + 3],
        ])
    }

    /// Copy the address into a compressed form for SHA2 (22 bytes).
    /// Per FIPS 205 Section 10.1 / sha2_offsets.h:
    ///   Byte  0:    layer
    ///   Bytes 1-8:  tree address (8 bytes)
    ///   Byte  9:    type
    ///   Bytes 10-13: key pair (4 bytes)
    ///   Byte  17:   chain/height
    ///   Bytes 18-21: tree index (4 bytes)
    ///   Byte  21:   hash address
    pub fn to_sha2_compressed(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0] = self.bytes[OFFSET_LAYER];
        out[1..9].copy_from_slice(&self.bytes[OFFSET_TREE..OFFSET_TREE + 8]);
        out[9] = self.bytes[OFFSET_TYPE];
        out[10..14].copy_from_slice(&self.bytes[OFFSET_KP_ADDR..OFFSET_KP_ADDR + 4]);
        out[17] = self.bytes[OFFSET_CHAIN_ADDR];
        out[18..22].copy_from_slice(&self.bytes[OFFSET_TREE_INDEX..OFFSET_TREE_INDEX + 4]);
        // Note: hash_addr at byte 21 overlaps with tree_index last byte, same as 32-byte format
        out
    }
}

impl Default for Adrs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adrs_new_is_zeroed() {
        let adrs = Adrs::new();
        assert_eq!(adrs.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_adrs_set_layer() {
        let mut adrs = Adrs::new();
        adrs.set_layer_address(5);
        assert_eq!(adrs.bytes[OFFSET_LAYER], 5);
    }

    #[test]
    fn test_adrs_set_tree() {
        let mut adrs = Adrs::new();
        adrs.set_tree_address(0x0102030405060708);
        assert_eq!(&adrs.bytes[OFFSET_TREE..OFFSET_TREE + 8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_adrs_set_type_preserves_other_fields() {
        let mut adrs = Adrs::new();
        adrs.set_key_pair_address(42);
        adrs.set_type(AdrsType::WotsPrf);
        assert_eq!(adrs.bytes[OFFSET_TYPE], 5);
        // Key pair address should be preserved (not zeroed)
        assert_eq!(adrs.get_key_pair_address(), 42);
    }

    #[test]
    fn test_adrs_get_key_pair() {
        let mut adrs = Adrs::new();
        adrs.set_key_pair_address(1234);
        assert_eq!(adrs.get_key_pair_address(), 1234);
    }

    #[test]
    fn test_adrs_get_tree_index() {
        let mut adrs = Adrs::new();
        adrs.set_tree_index(5678);
        assert_eq!(adrs.get_tree_index(), 5678);
    }

    #[test]
    fn test_adrs_type_at_byte_19() {
        let mut adrs = Adrs::new();
        adrs.set_type(AdrsType::WotsPrf);
        assert_eq!(adrs.bytes[19], 5);
    }

    #[test]
    fn test_sha2_compressed_layout() {
        let mut adrs = Adrs::new();
        adrs.set_layer_address(3);
        adrs.set_type(AdrsType::ForsTree);
        let compressed = adrs.to_sha2_compressed();
        assert_eq!(compressed[0], 3); // layer
        assert_eq!(compressed[9], AdrsType::ForsTree as u8); // type
    }
}
