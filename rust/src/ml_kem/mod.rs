//! ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//!
//! Implementation of FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard.
//!
//! ML-KEM provides three parameter sets:
//! - ML-KEM-512: Security Category 1 (~AES-128)
//! - ML-KEM-768: Security Category 3 (~AES-192) - Recommended for general use
//! - ML-KEM-1024: Security Category 5 (~AES-256)
//!
//! ## Author
//!
//! Feng Zheng (https://github.com/fzheng)

pub mod params;
pub mod keygen;
pub mod encapsulate;
pub mod decapsulate;

pub use params::*;
pub use keygen::*;
pub use encapsulate::*;
pub use decapsulate::*;

use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Helper to convert JsValue error to JsError
fn js_err(e: JsValue) -> JsError {
    JsError::new(&format!("{:?}", e))
}

/// ML-KEM key pair
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemKeyPair {
    /// Encapsulation key (public key)
    pub ek: Vec<u8>,
    /// Decapsulation key (secret key)
    pub dk: Vec<u8>,
}

/// ML-KEM encapsulation result
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemEncapsulation {
    /// Ciphertext
    pub ciphertext: Vec<u8>,
    /// Shared secret (32 bytes)
    pub shared_secret: [u8; 32],
}

// ============================================================================
// WASM Bindings for ML-KEM-512
// ============================================================================

/// Generate ML-KEM-512 key pair
#[wasm_bindgen(js_name = mlKem512KeyGen)]
pub fn ml_kem_512_keygen(seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    let keypair = keygen::ml_kem_keygen::<{ params::MLKEM512_K }>(
        seed.as_deref(),
        &params::ML_KEM_512,
    )?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("publicKey"),
        &js_sys::Uint8Array::from(&keypair.ek[..]).into(),
    ).map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("secretKey"),
        &js_sys::Uint8Array::from(&keypair.dk[..]).into(),
    ).map_err(js_err)?;

    Ok(result.into())
}

/// ML-KEM-512 encapsulation.
///
/// Encapsulates a shared secret using the recipient's public key.
#[wasm_bindgen(js_name = mlKem512Encapsulate)]
pub fn ml_kem_512_encapsulate(
    public_key: &[u8],
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let encap = encapsulate::ml_kem_encapsulate::<{ params::MLKEM512_K }>(
        public_key,
        seed.as_deref(),
        &params::ML_KEM_512,
    )?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("ciphertext"),
        &js_sys::Uint8Array::from(&encap.ciphertext[..]).into(),
    ).map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("sharedSecret"),
        &js_sys::Uint8Array::from(&encap.shared_secret[..]).into(),
    ).map_err(js_err)?;

    Ok(result.into())
}

/// ML-KEM-512 decapsulation
#[wasm_bindgen(js_name = mlKem512Decapsulate)]
pub fn ml_kem_512_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let shared_secret = decapsulate::ml_kem_decapsulate::<{ params::MLKEM512_K }>(
        secret_key,
        ciphertext,
        &params::ML_KEM_512,
    )?;

    Ok(js_sys::Uint8Array::from(&shared_secret[..]))
}

// ============================================================================
// WASM Bindings for ML-KEM-768
// ============================================================================

/// Generate ML-KEM-768 key pair.
///
/// This is the recommended parameter set for most applications.
#[wasm_bindgen(js_name = mlKem768KeyGen)]
pub fn ml_kem_768_keygen(seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    let keypair = keygen::ml_kem_keygen::<{ params::MLKEM768_K }>(
        seed.as_deref(),
        &params::ML_KEM_768,
    )?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("publicKey"),
        &js_sys::Uint8Array::from(&keypair.ek[..]).into(),
    ).map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("secretKey"),
        &js_sys::Uint8Array::from(&keypair.dk[..]).into(),
    ).map_err(js_err)?;

    Ok(result.into())
}

/// ML-KEM-768 encapsulation.
///
/// Encapsulates a shared secret using the recipient's public key.
#[wasm_bindgen(js_name = mlKem768Encapsulate)]
pub fn ml_kem_768_encapsulate(
    public_key: &[u8],
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let encap = encapsulate::ml_kem_encapsulate::<{ params::MLKEM768_K }>(
        public_key,
        seed.as_deref(),
        &params::ML_KEM_768,
    )?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("ciphertext"),
        &js_sys::Uint8Array::from(&encap.ciphertext[..]).into(),
    ).map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("sharedSecret"),
        &js_sys::Uint8Array::from(&encap.shared_secret[..]).into(),
    ).map_err(js_err)?;

    Ok(result.into())
}

/// ML-KEM-768 decapsulation
#[wasm_bindgen(js_name = mlKem768Decapsulate)]
pub fn ml_kem_768_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let shared_secret = decapsulate::ml_kem_decapsulate::<{ params::MLKEM768_K }>(
        secret_key,
        ciphertext,
        &params::ML_KEM_768,
    )?;

    Ok(js_sys::Uint8Array::from(&shared_secret[..]))
}

// ============================================================================
// WASM Bindings for ML-KEM-1024
// ============================================================================

/// Generate ML-KEM-1024 key pair.
///
/// Provides the highest security level (Category 5, ~AES-256).
#[wasm_bindgen(js_name = mlKem1024KeyGen)]
pub fn ml_kem_1024_keygen(seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    let keypair = keygen::ml_kem_keygen::<{ params::MLKEM1024_K }>(
        seed.as_deref(),
        &params::ML_KEM_1024,
    )?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("publicKey"),
        &js_sys::Uint8Array::from(&keypair.ek[..]).into(),
    ).map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("secretKey"),
        &js_sys::Uint8Array::from(&keypair.dk[..]).into(),
    ).map_err(js_err)?;

    Ok(result.into())
}

/// ML-KEM-1024 encapsulation.
///
/// Encapsulates a shared secret using the recipient's public key.
#[wasm_bindgen(js_name = mlKem1024Encapsulate)]
pub fn ml_kem_1024_encapsulate(
    public_key: &[u8],
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let encap = encapsulate::ml_kem_encapsulate::<{ params::MLKEM1024_K }>(
        public_key,
        seed.as_deref(),
        &params::ML_KEM_1024,
    )?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("ciphertext"),
        &js_sys::Uint8Array::from(&encap.ciphertext[..]).into(),
    ).map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("sharedSecret"),
        &js_sys::Uint8Array::from(&encap.shared_secret[..]).into(),
    ).map_err(js_err)?;

    Ok(result.into())
}

/// ML-KEM-1024 decapsulation
#[wasm_bindgen(js_name = mlKem1024Decapsulate)]
pub fn ml_kem_1024_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let shared_secret = decapsulate::ml_kem_decapsulate::<{ params::MLKEM1024_K }>(
        secret_key,
        ciphertext,
        &params::ML_KEM_1024,
    )?;

    Ok(js_sys::Uint8Array::from(&shared_secret[..]))
}
