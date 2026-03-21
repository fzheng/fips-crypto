//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//!
//! Implementation of FIPS 204: Module-Lattice-Based Digital Signature Standard.
//!
//! ML-DSA provides three parameter sets:
//! - ML-DSA-44: Security Category 2
//! - ML-DSA-65: Security Category 3 - Recommended for general use
//! - ML-DSA-87: Security Category 5

pub mod params;
pub mod polynomial;
pub mod sampling;
pub mod keygen;
pub mod sign;
pub mod verify;

pub use params::*;
pub use keygen::*;
pub use sign::*;
pub use verify::*;

use wasm_bindgen::prelude::*;

/// Helper to convert JsValue error to JsError
fn js_err(e: JsValue) -> JsError {
    JsError::new(&format!("{:?}", e))
}

// ============================================================================
// WASM Bindings for ML-DSA-44
// ============================================================================

/// Generate ML-DSA-44 key pair
#[wasm_bindgen(js_name = mlDsa44KeyGen)]
pub fn ml_dsa_44_keygen(seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    let keypair = keygen::ml_dsa_keygen(seed.as_deref(), &params::ML_DSA_44)?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("publicKey"),
        &js_sys::Uint8Array::from(&keypair.pk[..]).into(),
    )
    .map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("secretKey"),
        &js_sys::Uint8Array::from(&keypair.sk[..]).into(),
    )
    .map_err(js_err)?;

    Ok(result.into())
}

/// ML-DSA-44 signing
#[wasm_bindgen(js_name = mlDsa44Sign)]
pub fn ml_dsa_44_sign(
    secret_key: &[u8],
    message: &[u8],
    context: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsError> {
    let ctx = context.as_deref().unwrap_or(&[]);
    let sig = sign::ml_dsa_sign(secret_key, message, ctx, &params::ML_DSA_44, None)?;
    Ok(js_sys::Uint8Array::from(&sig[..]))
}

/// ML-DSA-44 verification
#[wasm_bindgen(js_name = mlDsa44Verify)]
pub fn ml_dsa_44_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: Option<Vec<u8>>,
) -> Result<bool, JsError> {
    let ctx = context.as_deref().unwrap_or(&[]);
    verify::ml_dsa_verify(public_key, message, signature, ctx, &params::ML_DSA_44)
}

// ============================================================================
// WASM Bindings for ML-DSA-65
// ============================================================================

/// Generate ML-DSA-65 key pair.
///
/// This is the recommended parameter set for most applications.
#[wasm_bindgen(js_name = mlDsa65KeyGen)]
pub fn ml_dsa_65_keygen(seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    let keypair = keygen::ml_dsa_keygen(seed.as_deref(), &params::ML_DSA_65)?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("publicKey"),
        &js_sys::Uint8Array::from(&keypair.pk[..]).into(),
    )
    .map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("secretKey"),
        &js_sys::Uint8Array::from(&keypair.sk[..]).into(),
    )
    .map_err(js_err)?;

    Ok(result.into())
}

/// ML-DSA-65 signing
#[wasm_bindgen(js_name = mlDsa65Sign)]
pub fn ml_dsa_65_sign(
    secret_key: &[u8],
    message: &[u8],
    context: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsError> {
    let ctx = context.as_deref().unwrap_or(&[]);
    let sig = sign::ml_dsa_sign(secret_key, message, ctx, &params::ML_DSA_65, None)?;
    Ok(js_sys::Uint8Array::from(&sig[..]))
}

/// ML-DSA-65 verification
#[wasm_bindgen(js_name = mlDsa65Verify)]
pub fn ml_dsa_65_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: Option<Vec<u8>>,
) -> Result<bool, JsError> {
    let ctx = context.as_deref().unwrap_or(&[]);
    verify::ml_dsa_verify(public_key, message, signature, ctx, &params::ML_DSA_65)
}

// ============================================================================
// WASM Bindings for ML-DSA-87
// ============================================================================

/// Generate ML-DSA-87 key pair.
///
/// Provides the highest security level (Category 5).
#[wasm_bindgen(js_name = mlDsa87KeyGen)]
pub fn ml_dsa_87_keygen(seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
    let keypair = keygen::ml_dsa_keygen(seed.as_deref(), &params::ML_DSA_87)?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("publicKey"),
        &js_sys::Uint8Array::from(&keypair.pk[..]).into(),
    )
    .map_err(js_err)?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("secretKey"),
        &js_sys::Uint8Array::from(&keypair.sk[..]).into(),
    )
    .map_err(js_err)?;

    Ok(result.into())
}

/// ML-DSA-87 signing
#[wasm_bindgen(js_name = mlDsa87Sign)]
pub fn ml_dsa_87_sign(
    secret_key: &[u8],
    message: &[u8],
    context: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsError> {
    let ctx = context.as_deref().unwrap_or(&[]);
    let sig = sign::ml_dsa_sign(secret_key, message, ctx, &params::ML_DSA_87, None)?;
    Ok(js_sys::Uint8Array::from(&sig[..]))
}

/// ML-DSA-87 verification
#[wasm_bindgen(js_name = mlDsa87Verify)]
pub fn ml_dsa_87_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: Option<Vec<u8>>,
) -> Result<bool, JsError> {
    let ctx = context.as_deref().unwrap_or(&[]);
    verify::ml_dsa_verify(public_key, message, signature, ctx, &params::ML_DSA_87)
}
