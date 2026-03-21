//! ML-DSA Verification -- FIPS 204 Algorithm 3 (ML-DSA.Verify_internal)
//!
//! Verifies an ML-DSA signature against a message and public key.
//!
//! The verification process:
//! 1. Parse the public key (rho, t1) and signature (c_tilde, z, hints)
//! 2. Check ||z||_inf < gamma1 - beta
//! 3. Expand A from rho, compute mu from tr and message
//! 4. Compute w' = A*z - c*t1*2^d (in NTT domain)
//! 5. Apply UseHint to get w1'
//! 6. Recompute c_tilde' and compare with the signature's c_tilde

use crate::ml_dsa::params::*;
use crate::ml_dsa::polynomial::*;
use crate::ml_dsa::sampling;
use crate::primitives::sha3::shake256;
use wasm_bindgen::JsError;

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

/// ML-DSA verification -- FIPS 204 Algorithm 3 (ML-DSA.Verify_internal).
///
/// # Arguments
/// * `pk` - Public key bytes
/// * `message` - Message that was signed
/// * `signature` - Signature to verify
/// * `context` - Context string (at most 255 bytes)
/// * `params` - The ML-DSA parameter set to use
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
pub fn ml_dsa_verify(
    pk: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
    params: &MlDsaParams,
) -> Result<bool, JsError> {
    if context.len() > 255 {
        return Err(JsError::new("Context must be at most 255 bytes"));
    }
    if pk.len() != params.pk_bytes {
        return Err(JsError::new("Invalid public key length"));
    }
    if signature.len() != params.sig_bytes {
        return Err(JsError::new("Invalid signature length"));
    }

    // Parse pk = rho || t1
    let rho: [u8; 32] = pk[0..32].try_into().unwrap();
    let t1 = DsaPolyVec::from_bytes_t1(&pk[32..], params.k);

    // Parse signature = c_tilde || z || hints
    let c_tilde_len = params.c_tilde_bytes();
    let c_tilde = &signature[0..c_tilde_len];

    let z_byte_len = match params.gamma1 {
        g if g == (1 << 17) => params.l * 576,
        g if g == (1 << 19) => params.l * 640,
        _ => return Err(JsError::new("Unsupported gamma1")),
    };
    let z = DsaPolyVec::from_bytes_z(
        &signature[c_tilde_len..c_tilde_len + z_byte_len],
        params.l,
        params.gamma1,
    );

    // Decode hints
    let hint_bytes = &signature[c_tilde_len + z_byte_len..];
    let hint = decode_hints(hint_bytes, params.k, params.omega)?;

    // Check ||z||_inf < gamma1 - beta
    let beta = params.beta();
    if !z.check_norm(params.gamma1 - beta) {
        return Ok(false);
    }

    // A_hat = ExpandA(rho)
    let a_hat_sampling = sampling::expand_a(&rho, params.k, params.l);
    let a_hat = convert_polymat(&a_hat_sampling);

    // tr = SHAKE256(pk, 64)
    let tr = shake256(pk, 64);

    // mu = SHAKE256(tr || M')
    let mut mu_input = Vec::new();
    mu_input.extend_from_slice(&tr);
    mu_input.push(0x00);
    mu_input.push(context.len() as u8);
    mu_input.extend_from_slice(context);
    mu_input.extend_from_slice(message);
    let mu = shake256(&mu_input, 64);

    // c = SampleInBall(c_tilde)
    let c_sampling = sampling::sample_in_ball(c_tilde, params.tau);
    let c = convert_poly(&c_sampling);
    let mut c_hat = c.clone();
    c_hat.to_ntt();

    // w_approx = A*z - c*t1*2^d (in NTT domain)
    let mut z_hat = z.clone();
    z_hat.to_ntt();
    let az = a_hat.mul_vec(&z_hat);

    // c * t1 * 2^d: scale t1 by 2^d, convert to NTT, multiply by c_hat
    let mut t1_scaled = t1.clone();
    for i in 0..params.k {
        for j in 0..N {
            t1_scaled.polys[i].coeffs[j] <<= D;
        }
    }
    t1_scaled.to_ntt();

    let mut ct1 = DsaPolyVec::new(params.k);
    for i in 0..params.k {
        ct1.polys[i] = c_hat.pointwise_mul(&t1_scaled.polys[i]);
    }

    let w_approx_hat = az.sub(&ct1);
    let mut w_approx = w_approx_hat;
    w_approx.from_ntt();
    w_approx.reduce();

    // w1' = UseHint(hint, w_approx)
    let mut w1_prime = DsaPolyVec::new(params.k);
    for i in 0..params.k {
        w1_prime.polys[i] = w_approx.polys[i].use_hint(&hint.polys[i], params.gamma2);
    }

    // c_tilde' = SHAKE256(mu || pack_w1(w1'))
    let mut c_input = Vec::new();
    c_input.extend_from_slice(&mu);
    c_input.extend_from_slice(&w1_prime.pack_w1(params.gamma2));
    let c_tilde_prime = shake256(&c_input, params.c_tilde_bytes());

    Ok(c_tilde == c_tilde_prime)
}

/// Decode hint vector from signature bytes.
///
/// The hint encoding uses omega + k bytes. For each of the k polynomials,
/// the positions of non-zero coefficients are listed sequentially, and
/// the last k bytes contain cumulative position counts.
fn decode_hints(bytes: &[u8], k: usize, omega: usize) -> Result<DsaPolyVec, JsError> {
    let mut hint = DsaPolyVec::new(k);
    let mut idx = 0;
    for i in 0..k {
        let end = bytes[omega + i] as usize;
        if end < idx || end > omega {
            return Err(JsError::new("Invalid hint encoding"));
        }
        for j in idx..end {
            if j > idx && bytes[j] <= bytes[j - 1] {
                return Err(JsError::new("Invalid hint encoding"));
            }
            hint.polys[i].coeffs[bytes[j] as usize] = 1;
        }
        idx = end;
    }
    // Verify remaining bytes between idx and omega are zero
    for j in idx..omega {
        if bytes[j] != 0 {
            return Err(JsError::new("Invalid hint encoding"));
        }
    }
    Ok(hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_dsa::keygen::ml_dsa_keygen;
    use crate::ml_dsa::params::ML_DSA_44;
    use crate::ml_dsa::sign::ml_dsa_sign;

    #[test]
    fn test_verify_rejects_corrupted_signature() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"test message";
        let mut sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_44, None).unwrap();

        // Corrupt the signature
        sig[10] ^= 0xFF;

        let valid = ml_dsa_verify(&keypair.pk, message, &sig, &[], &ML_DSA_44).unwrap();
        assert!(!valid, "Corrupted signature should not verify");
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"correct message";
        let sig = ml_dsa_sign(&keypair.sk, message, &[], &ML_DSA_44, None).unwrap();

        let wrong_message = b"wrong message";
        let valid =
            ml_dsa_verify(&keypair.pk, wrong_message, &sig, &[], &ML_DSA_44).unwrap();
        assert!(!valid, "Wrong message should not verify");
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];
        let keypair1 = ml_dsa_keygen(Some(&seed1), &ML_DSA_44).unwrap();
        let keypair2 = ml_dsa_keygen(Some(&seed2), &ML_DSA_44).unwrap();
        let message = b"test message";
        let sig = ml_dsa_sign(&keypair1.sk, message, &[], &ML_DSA_44, None).unwrap();

        let valid =
            ml_dsa_verify(&keypair2.pk, message, &sig, &[], &ML_DSA_44).unwrap();
        assert!(!valid, "Wrong key should not verify");
    }

    #[test]
    fn test_verify_rejects_wrong_context() {
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let message = b"test message";
        let context = b"context-a";
        let sig =
            ml_dsa_sign(&keypair.sk, message, context, &ML_DSA_44, None).unwrap();

        let wrong_context = b"context-b";
        let valid = ml_dsa_verify(&keypair.pk, message, &sig, wrong_context, &ML_DSA_44)
            .unwrap();
        assert!(!valid, "Wrong context should not verify");
    }

    #[test]
    #[should_panic]
    fn test_verify_rejects_invalid_pk_length() {
        // JsError::new panics on non-wasm targets, so we expect a panic
        let _ = ml_dsa_verify(&[0u8; 100], b"test", &[0u8; 2420], &[], &ML_DSA_44);
    }

    #[test]
    #[should_panic]
    fn test_verify_rejects_invalid_sig_length() {
        // JsError::new panics on non-wasm targets, so we expect a panic
        let seed = [0x42u8; 32];
        let keypair = ml_dsa_keygen(Some(&seed), &ML_DSA_44).unwrap();
        let _ = ml_dsa_verify(&keypair.pk, b"test", &[0u8; 100], &[], &ML_DSA_44);
    }
}
