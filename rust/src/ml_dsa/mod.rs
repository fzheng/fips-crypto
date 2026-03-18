//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//!
//! Implementation of FIPS 204: Module-Lattice-Based Digital Signature Standard
//!
//! ML-DSA provides three parameter sets:
//! - ML-DSA-44: Security Category 2
//! - ML-DSA-65: Security Category 3 - Recommended for general use
//! - ML-DSA-87: Security Category 5
//!
//! TODO: Implementation coming in Phase 3

use wasm_bindgen::prelude::*;

/// ML-DSA-44 key generation (stub)
#[wasm_bindgen(js_name = mlDsa44KeyGen)]
pub fn ml_dsa_44_keygen(_seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    Err(JsError::new("ML-DSA-44 not yet implemented"))
}

/// ML-DSA-44 sign (stub)
#[wasm_bindgen(js_name = mlDsa44Sign)]
pub fn ml_dsa_44_sign(
    _secret_key: &[u8],
    _message: &[u8],
    _context: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsError> {
    Err(JsError::new("ML-DSA-44 not yet implemented"))
}

/// ML-DSA-44 verify (stub)
#[wasm_bindgen(js_name = mlDsa44Verify)]
pub fn ml_dsa_44_verify(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
    _context: Option<Vec<u8>>,
) -> Result<bool, JsError> {
    Err(JsError::new("ML-DSA-44 not yet implemented"))
}

/// ML-DSA-65 key generation (stub)
#[wasm_bindgen(js_name = mlDsa65KeyGen)]
pub fn ml_dsa_65_keygen(_seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    Err(JsError::new("ML-DSA-65 not yet implemented"))
}

/// ML-DSA-65 sign (stub)
#[wasm_bindgen(js_name = mlDsa65Sign)]
pub fn ml_dsa_65_sign(
    _secret_key: &[u8],
    _message: &[u8],
    _context: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsError> {
    Err(JsError::new("ML-DSA-65 not yet implemented"))
}

/// ML-DSA-65 verify (stub)
#[wasm_bindgen(js_name = mlDsa65Verify)]
pub fn ml_dsa_65_verify(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
    _context: Option<Vec<u8>>,
) -> Result<bool, JsError> {
    Err(JsError::new("ML-DSA-65 not yet implemented"))
}

/// ML-DSA-87 key generation (stub)
#[wasm_bindgen(js_name = mlDsa87KeyGen)]
pub fn ml_dsa_87_keygen(_seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    Err(JsError::new("ML-DSA-87 not yet implemented"))
}

/// ML-DSA-87 sign (stub)
#[wasm_bindgen(js_name = mlDsa87Sign)]
pub fn ml_dsa_87_sign(
    _secret_key: &[u8],
    _message: &[u8],
    _context: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsError> {
    Err(JsError::new("ML-DSA-87 not yet implemented"))
}

/// ML-DSA-87 verify (stub)
#[wasm_bindgen(js_name = mlDsa87Verify)]
pub fn ml_dsa_87_verify(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
    _context: Option<Vec<u8>>,
) -> Result<bool, JsError> {
    Err(JsError::new("ML-DSA-87 not yet implemented"))
}
