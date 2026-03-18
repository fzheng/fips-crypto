//! # Cryptographic Primitives
//!
//! This module provides the foundational cryptographic building blocks used
//! across all post-quantum algorithms in this library.
//!
//! ## Modules
//!
//! - **sha3**: SHA-3 family hash functions and SHAKE XOFs (FIPS 202)
//! - **ntt**: Number Theoretic Transform for efficient polynomial multiplication
//! - **polynomial**: Polynomial ring arithmetic in R_q = Z_q[X]/(X^n + 1)
//! - **merkle**: Merkle tree operations for hash-based signatures
//! - **random**: Cryptographically secure random number generation
//!
//! ## Mathematical Background
//!
//! ### Polynomial Rings
//!
//! ML-KEM and ML-DSA operate in the polynomial ring R_q = Z_q[X]/(X^n + 1) where:
//! - n = 256 (polynomial degree)
//! - q = 3329 for ML-KEM
//! - q = 8380417 for ML-DSA
//!
//! ### Number Theoretic Transform (NTT)
//!
//! The NTT is used to convert polynomial multiplication from O(n²) to O(n log n).
//! It's analogous to the FFT but works over finite fields instead of complex numbers.
//!
//! ### Hash Functions
//!
//! All algorithms use SHA-3 family functions (FIPS 202):
//! - SHA3-256, SHA3-512 for fixed-output hashing
//! - SHAKE128, SHAKE256 for extendable-output (XOF)
//!
//! ## Author
//!
//! Feng Zheng (https://github.com/fzheng)

// -----------------------------------------------------------------------------
// Sub-modules
// -----------------------------------------------------------------------------

/// SHA-3 and SHAKE hash function implementations.
///
/// Provides wrappers around the `sha3` crate for:
/// - SHA3-256 and SHA3-512 (fixed output)
/// - SHAKE128 and SHAKE256 (extendable output)
/// - Convenience functions (G, H, J, PRF, XOF) as defined in FIPS 203/204
pub mod sha3;

/// Number Theoretic Transform (NTT) implementation.
///
/// Provides forward and inverse NTT for efficient polynomial multiplication
/// in the ring R_q. Includes:
/// - Barrett reduction for modular arithmetic
/// - Montgomery multiplication for NTT operations
/// - Precomputed twiddle factors (powers of primitive roots)
pub mod ntt;

/// Polynomial ring arithmetic.
///
/// Implements operations in R_q = Z_q[X]/(X^n + 1):
/// - Addition, subtraction, multiplication
/// - NTT conversion (to/from NTT domain)
/// - Compression and decompression
/// - CBD sampling (centered binomial distribution)
/// - Uniform sampling via rejection
pub mod polynomial;

/// Merkle tree operations for SLH-DSA.
///
/// Provides binary Merkle tree construction and verification:
/// - Tree building from leaves
/// - Authentication path generation
/// - Root computation and verification
pub mod merkle;

/// Cryptographically secure random number generation.
///
/// Uses the `getrandom` crate which provides:
/// - OS-level entropy on native platforms
/// - Web Crypto API in WASM environments
pub mod random;

// -----------------------------------------------------------------------------
// Re-exports for convenience
// -----------------------------------------------------------------------------

pub use sha3::*;
pub use ntt::*;
pub use polynomial::*;
pub use random::*;
