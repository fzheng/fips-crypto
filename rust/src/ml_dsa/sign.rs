//! ML-DSA Signing -- FIPS 204 Algorithm 2 (ML-DSA.Sign_internal)
//!
//! Signs a message using the ML-DSA secret key.
//!
//! The signing process uses a rejection loop:
//! 1. Parse the secret key components
//! 2. Compute mu = SHAKE256(tr || M') where M' includes domain separator + context + message
//! 3. Derive rho'' for mask generation from K, randomness, and mu
//! 4. In a rejection loop:
//!    a. Generate mask y = ExpandMask(rho'', kappa)
//!    b. Compute w = A*y, decompose into w1
//!    c. Compute challenge c from mu || pack_w1(w1)
//!    d. Compute z = y + c*s1, check norm
//!    e. Check additional conditions on w - c*s2 and c*t0
//!    f. Generate hint h, check weight
//!    g. If all checks pass, output signature

use crate::ml_dsa::params::*;
use crate::ml_dsa::polynomial::*;
use crate::ml_dsa::sampling;
use crate::primitives::random::random_bytes;
use crate::primitives::sha3::shake256;
use wasm_bindgen::JsError;
use zeroize::Zeroize;

/// Convert a sampling::DsaPolyMat to a polynomial::DsaPolyMat
fn convert_polymat(src: &sampling::DsaPolyMat) -> DsaPolyMat {
    let k = src.rows.len();
    let l = src.rows[0].len();
    let mut dst = DsaPolyMat::new(k, l);
    for i in 0..k {
        for j in 0..l {
            dst.rows[i].polys[j].coeffs = src.rows[i].polys[j].coeffs;
        }
    }
    dst
}

/// Convert a sampling::DsaPoly to a polynomial::DsaPoly
fn convert_poly(src: &sampling::DsaPoly) -> DsaPoly {
    let mut dst = DsaPoly::zero();
    dst.coeffs = src.coeffs;
    dst
}

/// Convert a sampling::DsaPolyVec to a polynomial::DsaPolyVec
fn convert_polyvec(src: &sampling::DsaPolyVec) -> DsaPolyVec {
    let mut dst = DsaPolyVec::new(src.len());
    for i in 0..src.len() {
        dst.polys[i].coeffs = src.polys[i].coeffs;
    }
    dst
}

/// ML-DSA signing -- FIPS 204 Algorithm 2 (ML-DSA.Sign_internal).
///
/// # Arguments
/// * `sk` - Secret key bytes
/// * `message` - Message to sign
/// * `context` - Context string (at most 255 bytes)
/// * `params` - The ML-DSA parameter set to use
/// * `rnd_override` - Optional 32-byte randomness override (for deterministic testing)
///
/// # Returns
/// The signature as a byte vector
pub fn ml_dsa_sign(
    sk: &[u8],
    message: &[u8],
    context: &[u8],
    params: &MlDsaParams,
    rnd_override: Option<&[u8; 32]>,
) -> Result<Vec<u8>, JsError> {
    if context.len() > 255 {
        return Err(JsError::new("Context must be at most 255 bytes"));
    }
    if sk.len() != params.sk_bytes {
        return Err(JsError::new(&format!(
            "Invalid secret key length: expected {}, got {}",
            params.sk_bytes,
            sk.len()
        )));
    }

    // Parse sk = rho || K || tr || s1 || s2 || t0
    let rho: [u8; 32] = sk[0..32].try_into().unwrap();
    let mut k_bytes: [u8; 32] = sk[32..64].try_into().unwrap();
    let tr: [u8; 64] = sk[64..128].try_into().unwrap();

    // Calculate sizes for eta packing
    let eta_poly_bytes = match params.eta {
        2 => 96,  // 3 bits * 256 / 8 = 96
        4 => 128, // 4 bits * 256 / 8 = 128
        _ => return Err(JsError::new("Unsupported eta")),
    };
    let s1_end = 128 + params.l * eta_poly_bytes;
    let s2_end = s1_end + params.k * eta_poly_bytes;

    let s1 = DsaPolyVec::from_bytes_eta(&sk[128..s1_end], params.l, params.eta);
    let s2 = DsaPolyVec::from_bytes_eta(&sk[s1_end..s2_end], params.k, params.eta);
    let t0 = DsaPolyVec::from_bytes_t0(&sk[s2_end..], params.k);

    // Precompute NTT forms
    let mut s1_hat = s1.clone();
    s1_hat.to_ntt();
    let mut s2_hat = s2.clone();
    s2_hat.to_ntt();
    let mut t0_hat = t0.clone();
    t0_hat.to_ntt();

    let a_hat_sampling = sampling::expand_a(&rho, params.k, params.l);
    let a_hat = convert_polymat(&a_hat_sampling);

    // mu = SHAKE256(tr || M'), where M' = 0x00 || len(ctx) || ctx || message
    let mut mu_input = Vec::new();
    mu_input.extend_from_slice(&tr);
    mu_input.push(0x00); // domain separator for pure ML-DSA
    mu_input.push(context.len() as u8);
    mu_input.extend_from_slice(context);
    mu_input.extend_from_slice(message);
    let mu = shake256(&mu_input, 64);

    // rnd = random 32 bytes (for randomized signing), or override for testing
    let mut rnd = [0u8; 32];
    match rnd_override {
        Some(r) => rnd.copy_from_slice(r),
        None => {
            random_bytes(&mut rnd)
                .map_err(|_| JsError::new("Failed to generate random bytes"))?;
        }
    }

    // rho'' = SHAKE256(K || rnd || mu, 64)
    let mut rho_pp_input = Vec::new();
    rho_pp_input.extend_from_slice(&k_bytes);
    rho_pp_input.extend_from_slice(&rnd);
    rho_pp_input.extend_from_slice(&mu);
    let mut rho_pp: [u8; 64] = shake256(&rho_pp_input, 64).try_into().unwrap();

    let beta = params.beta();
    let mut kappa: u16 = 0;

    // Rejection loop
    loop {
        // y = ExpandMask(rho'', kappa)
        let y_sampling = sampling::expand_mask(&rho_pp, kappa, params.l, params.gamma1);
        let y = convert_polyvec(&y_sampling);

        // w = A*y in NTT domain, then invNTT
        let mut y_hat = y.clone();
        y_hat.to_ntt();
        let mut w = a_hat.mul_vec(&y_hat);
        w.from_ntt();
        w.reduce();

        // w1 = HighBits(w)
        let mut w1 = DsaPolyVec::new(params.k);
        for i in 0..params.k {
            w1.polys[i] = w.polys[i].high_bits(params.gamma2);
        }

        // c_tilde = SHAKE256(mu || pack_w1(w1))
        let mut c_input = Vec::new();
        c_input.extend_from_slice(&mu);
        c_input.extend_from_slice(&w1.pack_w1(params.gamma2));
        let c_tilde = shake256(&c_input, params.c_tilde_bytes());

        // c = SampleInBall(c_tilde)
        let c_sampling = sampling::sample_in_ball(&c_tilde, params.tau);
        let c = convert_poly(&c_sampling);
        let mut c_hat = c.clone();
        c_hat.to_ntt();

        // z = y + c*s1
        // cs1 is reduced to centered form (-Q/2, Q/2] so z stays centered
        // for both the norm check and z packing to work correctly.
        let mut cs1 = DsaPolyVec::new(params.l);
        for i in 0..params.l {
            cs1.polys[i] = c_hat.pointwise_mul(&s1_hat.polys[i]);
            cs1.polys[i].from_ntt();
            cs1.polys[i].reduce_centered();
        }
        let z = y.add(&cs1);

        // Check ||z||_inf < gamma1 - beta
        if !z.check_norm(params.gamma1 - beta) {
            kappa += params.l as u16;
            continue;
        }

        // cs2 = c*s2, centered
        let mut cs2 = DsaPolyVec::new(params.k);
        for i in 0..params.k {
            cs2.polys[i] = c_hat.pointwise_mul(&s2_hat.polys[i]);
            cs2.polys[i].from_ntt();
            cs2.polys[i].reduce_centered();
        }

        // r0 = LowBits(w - cs2)
        let w_minus_cs2 = w.sub(&cs2);
        let mut r0 = DsaPolyVec::new(params.k);
        for i in 0..params.k {
            r0.polys[i] = w_minus_cs2.polys[i].low_bits(params.gamma2);
        }

        if !r0.check_norm(params.gamma2 - beta) {
            kappa += params.l as u16;
            continue;
        }

        // ct0 = c*t0, centered
        let mut ct0 = DsaPolyVec::new(params.k);
        for i in 0..params.k {
            ct0.polys[i] = c_hat.pointwise_mul(&t0_hat.polys[i]);
            ct0.polys[i].from_ntt();
            ct0.polys[i].reduce_centered();
        }

        if !ct0.check_norm(params.gamma2) {
            kappa += params.l as u16;
            continue;
        }

        // h = MakeHint(-ct0, w - cs2 + ct0)
        let w_cs2_ct0 = w_minus_cs2.add(&ct0);
        let mut hint = DsaPolyVec::new(params.k);
        let mut hint_ones = 0usize;
        let mut neg_ct0 = DsaPolyVec::new(params.k);
        for i in 0..params.k {
            for j in 0..N {
                neg_ct0.polys[i].coeffs[j] = -ct0.polys[i].coeffs[j];
            }
        }
        for i in 0..params.k {
            let (h_poly, count) =
                DsaPoly::make_hint(&neg_ct0.polys[i], &w_cs2_ct0.polys[i], params.gamma2);
            hint.polys[i] = h_poly;
            hint_ones += count;
        }

        if hint_ones > params.omega {
            kappa += params.l as u16;
            continue;
        }

        // Pack signature: c_tilde || z || hint
        let mut sig = Vec::with_capacity(params.sig_bytes);
        sig.extend_from_slice(&c_tilde);
        sig.extend_from_slice(&z.to_bytes_z(params.gamma1));

        // Encode hints: for each polynomial, list the positions of 1s
        encode_hints(&hint, params.k, params.omega, &mut sig);

        // Zeroize sensitive intermediate buffers before returning
        k_bytes.zeroize();
        rnd.zeroize();
        rho_pp_input.zeroize();
        rho_pp.zeroize();
        mu_input.zeroize();

        return Ok(sig);
    }
}

/// Encode hint vector into the signature per FIPS 204.
///
/// The hint encoding uses omega + k bytes:
/// - For each of the k polynomials, the positions of the non-zero coefficients
///   are listed sequentially
/// - The last k bytes contain the cumulative count of positions for each polynomial
fn encode_hints(hint: &DsaPolyVec, k: usize, omega: usize, sig: &mut Vec<u8>) {
    let mut hint_bytes = vec![0u8; omega + k];
    let mut idx = 0;
    for i in 0..k {
        for j in 0..N {
            if hint.polys[i].coeffs[j] != 0 {
                hint_bytes[idx] = j as u8;
                idx += 1;
            }
        }
        hint_bytes[omega + i] = idx as u8;
    }
    sig.extend_from_slice(&hint_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_dsa::keygen::ml_dsa_keygen;
    use crate::ml_dsa::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
    use crate::ml_dsa::verify::ml_dsa_verify;

    #[test]
    fn test_sign_mldsa44_output_size() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"test message";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_44, None).unwrap();
        assert_eq!(
            sig.len(),
            ML_DSA_44.sig_bytes,
            "ML-DSA-44 signature size mismatch"
        );
    }

    #[test]
    fn test_sign_mldsa65_output_size() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_65).unwrap();
        let message = b"test message";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_65, None).unwrap();
        assert_eq!(
            sig.len(),
            ML_DSA_65.sig_bytes,
            "ML-DSA-65 signature size mismatch"
        );
    }

    #[test]
    fn test_sign_mldsa87_output_size() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_87).unwrap();
        let message = b"test message";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_87, None).unwrap();
        assert_eq!(
            sig.len(),
            ML_DSA_87.sig_bytes,
            "ML-DSA-87 signature size mismatch"
        );
    }

    #[test]
    fn test_deterministic_sign() {
        let seed = [0x55u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"deterministic signing test";
        let rnd = [0u8; 32]; // Fix randomness for deterministic test
        let sig1 =
            ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_44, Some(&rnd)).unwrap();
        let sig2 =
            ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_44, Some(&rnd)).unwrap();
        assert_eq!(sig1, sig2, "Deterministic signing should produce identical signatures");
    }

    #[test]
    fn test_sign_verify_roundtrip_mldsa44() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"hello, ML-DSA!";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_44, None).unwrap();
        let valid = ml_dsa_verify(&keypair.pk, message, &sig, &[], &ML_DSA_44).unwrap();
        assert!(valid, "ML-DSA-44 sign/verify roundtrip failed");
    }

    #[test]
    fn test_sign_verify_roundtrip_mldsa65() {
        let seed = [0x43u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_65).unwrap();
        let message = b"hello, ML-DSA-65!";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_65, None).unwrap();
        let valid = ml_dsa_verify(&keypair.pk, message, &sig, &[], &ML_DSA_65).unwrap();
        assert!(valid, "ML-DSA-65 sign/verify roundtrip failed");
    }

    #[test]
    fn test_sign_verify_roundtrip_mldsa87() {
        let seed = [0x44u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_87).unwrap();
        let message = b"hello, ML-DSA-87!";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_87, None).unwrap();
        let valid = ml_dsa_verify(&keypair.pk, message, &sig, &[], &ML_DSA_87).unwrap();
        assert!(valid, "ML-DSA-87 sign/verify roundtrip failed");
    }

    #[test]
    fn test_sign_with_context() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"context test";
        let context = b"my-app-context";
        let sig = ml_dsa_sign(&keypair.sk, message, context, &ML_DSA_44, None).unwrap();
        let valid =
            ml_dsa_verify(&keypair.pk, message, &sig, context, &ML_DSA_44).unwrap();
        assert!(valid, "Sign/verify with context failed");
    }

    #[test]
    fn test_sign_empty_message() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_44, None).unwrap();
        let valid = ml_dsa_verify(&keypair.pk, message, &sig, &[], &ML_DSA_44).unwrap();
        assert!(valid, "Sign/verify with empty message failed");
    }
}
