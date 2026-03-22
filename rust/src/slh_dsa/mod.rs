//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//!
//! Implementation of FIPS 205: Stateless Hash-Based Digital Signature Standard.
//!
//! SLH-DSA provides 12 parameter sets combining:
//! - Hash functions: SHA-2 or SHAKE
//! - Security levels: 128, 192, 256
//! - Variants: 's' (small signatures) or 'f' (fast signing)

pub mod params;
pub mod address;
pub mod hash;
pub mod wots;
pub mod xmss;
pub mod fors;
pub mod hypertree;
pub mod keygen;
pub mod sign;
pub mod verify;

use wasm_bindgen::prelude::*;

/// Helper to convert JsValue error to JsError
fn js_err(e: JsValue) -> JsError {
    JsError::new(&format!("{:?}", e))
}

/// Macro to generate WASM bindings for an SLH-DSA parameter set.
/// Creates keygen, sign, and verify functions.
macro_rules! slh_dsa_wasm_bindings {
    ($keygen_name:ident, $sign_name:ident, $verify_name:ident,
     $js_keygen:literal, $js_sign:literal, $js_verify:literal,
     $params:expr) => {
        #[wasm_bindgen(js_name = $js_keygen)]
        pub fn $keygen_name(seed: Option<Vec<u8>>) -> Result<JsValue, JsError> {
            let keypair = keygen::slh_dsa_keygen(seed.as_deref(), &$params)
                .map_err(|e| JsError::new(&e))?;
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

        #[wasm_bindgen(js_name = $js_sign)]
        pub fn $sign_name(
            secret_key: &[u8],
            message: &[u8],
            context: Option<Vec<u8>>,
        ) -> Result<js_sys::Uint8Array, JsError> {
            let ctx = context.as_deref().unwrap_or(&[]);
            let sig = sign::slh_dsa_sign(secret_key, message, ctx, &$params)
                .map_err(|e| JsError::new(&e))?;
            Ok(js_sys::Uint8Array::from(&sig[..]))
        }

        #[wasm_bindgen(js_name = $js_verify)]
        pub fn $verify_name(
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
            context: Option<Vec<u8>>,
        ) -> Result<bool, JsError> {
            let ctx = context.as_deref().unwrap_or(&[]);
            verify::slh_dsa_verify(public_key, message, signature, ctx, &$params)
                .map_err(|e| JsError::new(&e))
        }
    };
}

// =============================================================================
// SHA2 Parameter Set Bindings
// =============================================================================

slh_dsa_wasm_bindings!(
    slh_dsa_sha2_128s_keygen, slh_dsa_sha2_128s_sign, slh_dsa_sha2_128s_verify,
    "slhDsaSha2_128sKeyGen", "slhDsaSha2_128sSign", "slhDsaSha2_128sVerify",
    params::SLH_DSA_SHA2_128S
);

slh_dsa_wasm_bindings!(
    slh_dsa_sha2_128f_keygen, slh_dsa_sha2_128f_sign, slh_dsa_sha2_128f_verify,
    "slhDsaSha2_128fKeyGen", "slhDsaSha2_128fSign", "slhDsaSha2_128fVerify",
    params::SLH_DSA_SHA2_128F
);

slh_dsa_wasm_bindings!(
    slh_dsa_sha2_192s_keygen, slh_dsa_sha2_192s_sign, slh_dsa_sha2_192s_verify,
    "slhDsaSha2_192sKeyGen", "slhDsaSha2_192sSign", "slhDsaSha2_192sVerify",
    params::SLH_DSA_SHA2_192S
);

slh_dsa_wasm_bindings!(
    slh_dsa_sha2_192f_keygen, slh_dsa_sha2_192f_sign, slh_dsa_sha2_192f_verify,
    "slhDsaSha2_192fKeyGen", "slhDsaSha2_192fSign", "slhDsaSha2_192fVerify",
    params::SLH_DSA_SHA2_192F
);

slh_dsa_wasm_bindings!(
    slh_dsa_sha2_256s_keygen, slh_dsa_sha2_256s_sign, slh_dsa_sha2_256s_verify,
    "slhDsaSha2_256sKeyGen", "slhDsaSha2_256sSign", "slhDsaSha2_256sVerify",
    params::SLH_DSA_SHA2_256S
);

slh_dsa_wasm_bindings!(
    slh_dsa_sha2_256f_keygen, slh_dsa_sha2_256f_sign, slh_dsa_sha2_256f_verify,
    "slhDsaSha2_256fKeyGen", "slhDsaSha2_256fSign", "slhDsaSha2_256fVerify",
    params::SLH_DSA_SHA2_256F
);

// =============================================================================
// SHAKE Parameter Set Bindings
// =============================================================================

slh_dsa_wasm_bindings!(
    slh_dsa_shake_128s_keygen, slh_dsa_shake_128s_sign, slh_dsa_shake_128s_verify,
    "slhDsaShake128sKeyGen", "slhDsaShake128sSign", "slhDsaShake128sVerify",
    params::SLH_DSA_SHAKE_128S
);

slh_dsa_wasm_bindings!(
    slh_dsa_shake_128f_keygen, slh_dsa_shake_128f_sign, slh_dsa_shake_128f_verify,
    "slhDsaShake128fKeyGen", "slhDsaShake128fSign", "slhDsaShake128fVerify",
    params::SLH_DSA_SHAKE_128F
);

slh_dsa_wasm_bindings!(
    slh_dsa_shake_192s_keygen, slh_dsa_shake_192s_sign, slh_dsa_shake_192s_verify,
    "slhDsaShake192sKeyGen", "slhDsaShake192sSign", "slhDsaShake192sVerify",
    params::SLH_DSA_SHAKE_192S
);

slh_dsa_wasm_bindings!(
    slh_dsa_shake_192f_keygen, slh_dsa_shake_192f_sign, slh_dsa_shake_192f_verify,
    "slhDsaShake192fKeyGen", "slhDsaShake192fSign", "slhDsaShake192fVerify",
    params::SLH_DSA_SHAKE_192F
);

slh_dsa_wasm_bindings!(
    slh_dsa_shake_256s_keygen, slh_dsa_shake_256s_sign, slh_dsa_shake_256s_verify,
    "slhDsaShake256sKeyGen", "slhDsaShake256sSign", "slhDsaShake256sVerify",
    params::SLH_DSA_SHAKE_256S
);

slh_dsa_wasm_bindings!(
    slh_dsa_shake_256f_keygen, slh_dsa_shake_256f_sign, slh_dsa_shake_256f_verify,
    "slhDsaShake256fKeyGen", "slhDsaShake256fSign", "slhDsaShake256fVerify",
    params::SLH_DSA_SHAKE_256F
);
