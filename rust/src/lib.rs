//! # fips-crypto: Post-Quantum Cryptography Library
//!
//! A WebAssembly-based implementation of NIST post-quantum cryptography standards.
//!
//! ## Overview
//!
//! This library provides implementations of the following NIST FIPS standards:
//!
//! - **FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//!   - Derived from CRYSTALS-Kyber
//!   - Provides quantum-resistant key encapsulation
//!   - Three parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024
//!
//! - **FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//!   - Derived from CRYSTALS-Dilithium
//!   - Provides quantum-resistant digital signatures
//!   - Three parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87
//!
//! - **FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//!   - Derived from SPHINCS+
//!   - Based purely on hash functions (no lattice assumptions)
//!   - 12 parameter sets with SHA-2 and SHAKE variants
//!
//! ## Security Considerations
//!
//! - All secret key material is zeroized on drop using the `zeroize` crate
//! - Constant-time operations are used where possible to prevent timing attacks
//! - ML-KEM implements implicit rejection for CCA security
//!
//! ## Usage
//!
//! This crate is compiled to WebAssembly and used via JavaScript/TypeScript bindings.
//! See the npm package documentation for usage examples.
//!
//! ## Author
//!
//! Feng Zheng (https://github.com/fzheng)
//!
//! ## License
//!
//! MIT License

use wasm_bindgen::prelude::*;

// =============================================================================
// Module Declarations
// =============================================================================

/// Cryptographic primitives (SHA-3, NTT, polynomial arithmetic, etc.)
pub mod primitives;

/// ML-KEM implementation (FIPS 203)
pub mod ml_kem;

/// ML-DSA implementation (FIPS 204)
pub mod ml_dsa;

/// SLH-DSA implementation (FIPS 205)
pub mod slh_dsa;

// =============================================================================
// WASM Entry Points
// =============================================================================

/// Initialize the WASM module.
///
/// This function is called automatically when the WASM module is instantiated.
/// Currently a no-op, but reserved for future initialization needs.
#[wasm_bindgen(start)]
pub fn init() {
    // Reserved for future initialization
}

/// Get the library version string.
///
/// Returns the version from Cargo.toml (e.g., "0.1.0").
///
/// # Example (JavaScript)
///
/// ```javascript
/// import { version } from 'fips-crypto';
/// console.log('fips-crypto version:', version());
/// ```
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
