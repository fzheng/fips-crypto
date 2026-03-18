//! SHA-3 and SHAKE hash function wrappers
//!
//! Provides interfaces to SHA-3 family hash functions as required by
//! FIPS 203, 204, and 205:
//! - SHA3-256, SHA3-512
//! - SHAKE128, SHAKE256 (extendable-output functions)
//!
//! ## Author
//!
//! Feng Zheng (https://github.com/fzheng)

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake128, Shake256,
};

/// Compute SHA3-256 hash.
///
/// # Arguments
///
/// * `input` - The data to hash
///
/// # Returns
///
/// A 32-byte hash output
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

/// Compute SHA3-512 hash.
///
/// # Arguments
///
/// * `input` - The data to hash
///
/// # Returns
///
/// A 64-byte hash output
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

/// SHAKE128 extendable-output function.
///
/// # Arguments
///
/// * `input` - The data to hash
/// * `output_len` - Number of output bytes to generate
///
/// # Returns
///
/// A vector of `output_len` bytes
pub fn shake128(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// SHAKE256 extendable-output function.
///
/// # Arguments
///
/// * `input` - The data to hash
/// * `output_len` - Number of output bytes to generate
///
/// # Returns
///
/// A vector of `output_len` bytes
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// SHAKE128 XOF (Extendable Output Function) for streaming output.
///
/// This allows incremental reading of arbitrary-length output from
/// a SHAKE128 hash, which is useful for sampling operations in ML-KEM.
pub struct Shake128Xof {
    reader: sha3::Shake128Reader,
}

impl Shake128Xof {
    /// Create a new SHAKE128 XOF from input data.
    ///
    /// # Arguments
    ///
    /// * `input` - The seed data to absorb
    pub fn new(input: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        Update::update(&mut hasher, input);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Read bytes from the XOF
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }

    /// Squeeze a fixed number of bytes
    pub fn squeeze(&mut self, len: usize) -> Vec<u8> {
        let mut output = vec![0u8; len];
        self.reader.read(&mut output);
        output
    }
}

/// SHAKE256 XOF for streaming output.
///
/// This allows incremental reading of arbitrary-length output from
/// a SHAKE256 hash, which is useful for PRF operations in ML-KEM.
pub struct Shake256Xof {
    reader: sha3::Shake256Reader,
}

impl Shake256Xof {
    /// Create a new SHAKE256 XOF from input data.
    ///
    /// # Arguments
    ///
    /// * `input` - The seed data to absorb
    pub fn new(input: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        Update::update(&mut hasher, input);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Read bytes from the XOF
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }

    /// Squeeze a fixed number of bytes
    pub fn squeeze(&mut self, len: usize) -> Vec<u8> {
        let mut output = vec![0u8; len];
        self.reader.read(&mut output);
        output
    }
}

/// G function: SHA3-512 used in ML-KEM
#[inline]
pub fn g(input: &[u8]) -> [u8; 64] {
    sha3_512(input)
}

/// H function: SHA3-256 used in ML-KEM
#[inline]
pub fn h(input: &[u8]) -> [u8; 32] {
    sha3_256(input)
}

/// J function: SHAKE256 used in ML-KEM for implicit rejection
#[inline]
pub fn j(input: &[u8], output_len: usize) -> Vec<u8> {
    shake256(input, output_len)
}

/// PRF (Pseudo-Random Function): SHAKE256 used for sampling
#[inline]
pub fn prf(seed: &[u8], nonce: u8, output_len: usize) -> Vec<u8> {
    let mut input = seed.to_vec();
    input.push(nonce);
    shake256(&input, output_len)
}

/// XOF (Extendable Output Function): SHAKE128 for matrix sampling
#[inline]
pub fn xof(seed: &[u8], i: u8, j: u8) -> Shake128Xof {
    let mut input = seed.to_vec();
    input.push(j);
    input.push(i);
    Shake128Xof::new(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let input = b"test";
        let hash = sha3_256(input);
        assert_eq!(hash.len(), 32);
        // Known test vector
        let expected = [
            0x36, 0xf0, 0x28, 0x58, 0x0b, 0xb0, 0x2c, 0xc8,
            0x27, 0x2a, 0x9a, 0x02, 0x0f, 0x42, 0x00, 0xe3,
            0x46, 0xe2, 0x76, 0xae, 0x66, 0x4e, 0x45, 0xee,
            0x80, 0x74, 0x55, 0x74, 0xe2, 0xf5, 0xab, 0x80,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_shake128() {
        let input = b"test";
        let output = shake128(input, 32);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_shake256() {
        let input = b"test";
        let output = shake256(input, 64);
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_xof_streaming() {
        let seed = [0u8; 32];
        let mut xof = Shake128Xof::new(&seed);
        let out1 = xof.squeeze(16);
        let out2 = xof.squeeze(16);
        assert_eq!(out1.len(), 16);
        assert_eq!(out2.len(), 16);
        // Outputs should be different (streaming)
        assert_ne!(out1, out2);
    }
}
