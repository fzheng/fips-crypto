//! Cryptographically secure random number generation
//!
//! Uses the getrandom crate which provides OS-level entropy sources.
//! In WASM environments, this uses Web Crypto API's getRandomValues.

use getrandom::getrandom;
use zeroize::Zeroize;

/// Error type for random number generation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomError;

impl std::fmt::Display for RandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to generate random bytes")
    }
}

impl std::error::Error for RandomError {}

/// Fill a buffer with cryptographically secure random bytes
pub fn random_bytes(dest: &mut [u8]) -> Result<(), RandomError> {
    getrandom(dest).map_err(|_| RandomError)
}

/// Generate a fixed-size array of random bytes
pub fn random_array<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut arr = [0u8; N];
    random_bytes(&mut arr)?;
    Ok(arr)
}

/// A seed for deterministic key generation (for testing purposes)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Seed<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Seed<N> {
    /// Create a new seed from bytes
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Generate a random seed
    pub fn random() -> Result<Self, RandomError> {
        Ok(Self {
            bytes: random_array()?,
        })
    }

    /// Get the seed bytes
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> From<[u8; N]> for Seed<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> AsRef<[u8]> for Seed<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        random_bytes(&mut buf1).unwrap();
        random_bytes(&mut buf2).unwrap();
        // Two random outputs should be different (with overwhelming probability)
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_random_array() {
        let arr: [u8; 64] = random_array().unwrap();
        // Should not be all zeros
        assert!(arr.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_seed() {
        let seed = Seed::<32>::random().unwrap();
        assert_eq!(seed.as_bytes().len(), 32);
    }
}
