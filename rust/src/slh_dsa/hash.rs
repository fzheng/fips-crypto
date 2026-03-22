//! SLH-DSA Tweakable Hash Functions — FIPS 205 Sections 10-11
//!
//! Provides the four core hash functions used throughout SLH-DSA:
//! - T_l: tweakable hash (parameterized by public seed and address)
//! - PRF: pseudorandom function for secret key derivation
//! - PRF_msg: pseudorandom function for message randomization
//! - H_msg: message hash producing the digest and tree/leaf indices
//!
//! Two instantiations are provided:
//! - SHAKE: uses SHAKE256 for everything (FIPS 205 Section 11)
//! - SHA2: uses SHA-256/SHA-512 + HMAC + MGF1 (FIPS 205 Section 10)

use crate::slh_dsa::address::Adrs;
use crate::slh_dsa::params::{HashFamily, SlhDsaParams};

use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

// =============================================================================
// Public API — dispatches to the correct hash family
// =============================================================================

/// T_l: tweakable hash function.
/// FIPS 205 Alg 1 building block — used for WOTS+ chain steps, tree node
/// computation, and public key compression.
pub fn t_l(pk_seed: &[u8], adrs: &Adrs, m: &[u8], params: &SlhDsaParams) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake_t_l(pk_seed, adrs, m, params.n),
        HashFamily::Sha2 => sha2_t_l(pk_seed, adrs, m, params.n),
    }
}

/// PRF: pseudorandom function for secret value generation.
/// Used to derive WOTS+ secret keys and FORS secret values from sk_seed.
pub fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, params: &SlhDsaParams) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake_prf(pk_seed, sk_seed, adrs, params.n),
        HashFamily::Sha2 => sha2_prf(pk_seed, sk_seed, adrs, params.n),
    }
}

/// PRF_msg: pseudorandom function for message randomization.
/// Generates the randomizer R for hedged signing.
pub fn prf_msg(
    sk_prf: &[u8],
    opt_rand: &[u8],
    msg: &[u8],
    params: &SlhDsaParams,
) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake_prf_msg(sk_prf, opt_rand, msg, params.n),
        HashFamily::Sha2 => sha2_prf_msg(sk_prf, opt_rand, msg, params.n),
    }
}

/// H_msg: message digest function.
/// Produces the m-byte digest used to derive FORS message indices and
/// the tree address / leaf index for hypertree signing.
pub fn h_msg(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    params: &SlhDsaParams,
) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake_h_msg(r, pk_seed, pk_root, msg, params.m),
        HashFamily::Sha2 => sha2_h_msg(r, pk_seed, pk_root, msg, params.n, params.m),
    }
}

// =============================================================================
// SHAKE Instantiation — FIPS 205 Section 11
// =============================================================================

fn shake256_output(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = sha3::Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// T_l^SHAKE(PK.seed, ADRS, M) = SHAKE256(PK.seed || ADRS || M, 8n)
fn shake_t_l(pk_seed: &[u8], adrs: &Adrs, m: &[u8], n: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(pk_seed.len() + 32 + m.len());
    input.extend_from_slice(pk_seed);
    input.extend_from_slice(adrs.as_bytes());
    input.extend_from_slice(m);
    shake256_output(&input, n)
}

/// PRF^SHAKE(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
fn shake_prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, n: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(pk_seed.len() + 32 + sk_seed.len());
    input.extend_from_slice(pk_seed);
    input.extend_from_slice(adrs.as_bytes());
    input.extend_from_slice(sk_seed);
    shake256_output(&input, n)
}

/// PRF_msg^SHAKE(SK.prf, OptRand, M) = SHAKE256(SK.prf || OptRand || M, 8n)
fn shake_prf_msg(sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], n: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(sk_prf.len() + opt_rand.len() + msg.len());
    input.extend_from_slice(sk_prf);
    input.extend_from_slice(opt_rand);
    input.extend_from_slice(msg);
    shake256_output(&input, n)
}

/// H_msg^SHAKE(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)
fn shake_h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8], m: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(r.len() + pk_seed.len() + pk_root.len() + msg.len());
    input.extend_from_slice(r);
    input.extend_from_slice(pk_seed);
    input.extend_from_slice(pk_root);
    input.extend_from_slice(msg);
    shake256_output(&input, m)
}

// =============================================================================
// SHA2 Instantiation — FIPS 205 Section 10
// =============================================================================

/// MGF1-SHA-256: Mask Generation Function (RFC 8017 B.2.1) using SHA-256.
fn mgf1_sha256(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while output.len() < out_len {
        let mut hasher = Sha256::new();
        Sha2Digest::update(&mut hasher, seed);
        Sha2Digest::update(&mut hasher, &counter.to_be_bytes());
        output.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    output.truncate(out_len);
    output
}

/// MGF1-SHA-512: Mask Generation Function using SHA-512.
fn mgf1_sha512(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while output.len() < out_len {
        let mut hasher = Sha512::new();
        Sha2Digest::update(&mut hasher, seed);
        Sha2Digest::update(&mut hasher, &counter.to_be_bytes());
        output.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    output.truncate(out_len);
    output
}

/// T_l^SHA2 (simple variant): uses SHA-256 or SHA-512 depending on n and input size.
///
/// Per FIPS 205 Section 10.1:
/// - F (single n-byte input): always SHA-256, padded to 64-byte block
/// - H/T_l (multi-block input, n>16): SHA-512, padded to 128-byte block
/// - H/T_l (multi-block input, n=16): SHA-256, padded to 64-byte block
fn sha2_t_l(pk_seed: &[u8], adrs: &Adrs, m: &[u8], n: usize) -> Vec<u8> {
    let adrs_c = adrs.to_sha2_compressed();

    // For single-block input (F function) or n=16: use SHA-256
    if m.len() <= n || n == 16 {
        let padding = vec![0u8; 64 - n]; // SHA-256 block size (64) - n
        let mut hasher = Sha256::new();
        Sha2Digest::update(&mut hasher, pk_seed);
        Sha2Digest::update(&mut hasher, &padding);
        Sha2Digest::update(&mut hasher, &adrs_c);
        Sha2Digest::update(&mut hasher, m);
        hasher.finalize()[..n].to_vec()
    } else {
        // Multi-block input with n=24 or n=32: use SHA-512
        let padding = vec![0u8; 128 - n]; // SHA-512 block size (128) - n
        let mut hasher = Sha512::new();
        Sha2Digest::update(&mut hasher, pk_seed);
        Sha2Digest::update(&mut hasher, &padding);
        Sha2Digest::update(&mut hasher, &adrs_c);
        Sha2Digest::update(&mut hasher, m);
        hasher.finalize()[..n].to_vec()
    }
}

/// PRF^SHA2: SHA-256-based PRF (always SHA-256 regardless of n).
/// Per FIPS 205 Section 10.1, PRF uses h0 (SHA-256) for all security levels.
/// PRF = SHA-256(PK.seed || padding_256 || ADRSc || SK.seed)[0:n]
fn sha2_prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, n: usize) -> Vec<u8> {
    let adrs_c = adrs.to_sha2_compressed();
    let padding = vec![0u8; 64 - n]; // SHA-256 block size - n
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, pk_seed);
    Sha2Digest::update(&mut hasher, &padding);
    Sha2Digest::update(&mut hasher, &adrs_c);
    Sha2Digest::update(&mut hasher, sk_seed);
    hasher.finalize()[..n].to_vec()
}

/// PRF_msg^SHA2: HMAC-based message PRF.
/// For n=16: first n bytes of HMAC-SHA-256(SK.prf, OptRand || M)
/// For n=24,32: first n bytes of HMAC-SHA-512(SK.prf, OptRand || M)
fn sha2_prf_msg(sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], n: usize) -> Vec<u8> {
    if n == 16 {
        let mut mac = HmacSha256::new_from_slice(sk_prf)
            .expect("HMAC key length is valid");
        Mac::update(&mut mac, opt_rand);
        Mac::update(&mut mac, msg);
        mac.finalize().into_bytes()[..n].to_vec()
    } else {
        let mut mac = HmacSha512::new_from_slice(sk_prf)
            .expect("HMAC key length is valid");
        Mac::update(&mut mac, opt_rand);
        Mac::update(&mut mac, msg);
        mac.finalize().into_bytes()[..n].to_vec()
    }
}

/// H_msg^SHA2: message hash using MGF1.
/// For n=16: MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
/// For n=24,32: MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m)
fn sha2_h_msg(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    n: usize,
    m: usize,
) -> Vec<u8> {
    if n == 16 {
        // Inner hash: SHA-256(R || PK.seed || PK.root || M)
        let mut hasher = Sha256::new();
        Sha2Digest::update(&mut hasher, r);
        Sha2Digest::update(&mut hasher, pk_seed);
        Sha2Digest::update(&mut hasher, pk_root);
        Sha2Digest::update(&mut hasher, msg);
        let inner = hasher.finalize();

        // MGF1-SHA-256(R || PK.seed || inner, m)
        let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + 32);
        seed.extend_from_slice(r);
        seed.extend_from_slice(pk_seed);
        seed.extend_from_slice(&inner);
        mgf1_sha256(&seed, m)
    } else {
        // Inner hash: SHA-512(R || PK.seed || PK.root || M)
        let mut hasher = Sha512::new();
        Sha2Digest::update(&mut hasher, r);
        Sha2Digest::update(&mut hasher, pk_seed);
        Sha2Digest::update(&mut hasher, pk_root);
        Sha2Digest::update(&mut hasher, msg);
        let inner = hasher.finalize();

        // MGF1-SHA-512(R || PK.seed || inner, m)
        let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + 64);
        seed.extend_from_slice(r);
        seed.extend_from_slice(pk_seed);
        seed.extend_from_slice(&inner);
        mgf1_sha512(&seed, m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::*;

    #[test]
    fn test_shake_t_l_output_length() {
        let pk_seed = [0u8; 16];
        let adrs = Adrs::new();
        let m = [1u8; 16];
        let out = t_l(&pk_seed, &adrs, &m, &SLH_DSA_SHAKE_128F);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn test_sha2_t_l_output_length() {
        let pk_seed = [0u8; 16];
        let adrs = Adrs::new();
        let m = [1u8; 16];
        let out = t_l(&pk_seed, &adrs, &m, &SLH_DSA_SHA2_128F);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn test_shake_prf_output_length() {
        let pk_seed = [0u8; 32];
        let sk_seed = [0u8; 32];
        let adrs = Adrs::new();
        let out = prf(&pk_seed, &sk_seed, &adrs, &SLH_DSA_SHAKE_256S);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn test_sha2_prf_output_length() {
        let pk_seed = [0u8; 32];
        let sk_seed = [0u8; 32];
        let adrs = Adrs::new();
        let out = prf(&pk_seed, &sk_seed, &adrs, &SLH_DSA_SHA2_256S);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn test_prf_msg_output_length() {
        for p in &[SLH_DSA_SHAKE_128F, SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_256S, SLH_DSA_SHA2_256S] {
            let sk_prf = vec![0u8; p.n];
            let opt_rand = vec![0u8; p.n];
            let msg = b"test message";
            let out = prf_msg(&sk_prf, &opt_rand, msg, p);
            assert_eq!(out.len(), p.n, "prf_msg output length for {}", p.name);
        }
    }

    #[test]
    fn test_h_msg_output_length() {
        for p in &[SLH_DSA_SHAKE_128F, SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_256S, SLH_DSA_SHA2_256S] {
            let r = vec![0u8; p.n];
            let pk_seed = vec![0u8; p.n];
            let pk_root = vec![0u8; p.n];
            let msg = b"test message";
            let out = h_msg(&r, &pk_seed, &pk_root, msg, p);
            assert_eq!(out.len(), p.m, "h_msg output length for {}", p.name);
        }
    }

    #[test]
    fn test_deterministic_shake() {
        let pk = [42u8; 16];
        let adrs = Adrs::new();
        let m = [1u8; 16];
        let out1 = shake_t_l(&pk, &adrs, &m, 16);
        let out2 = shake_t_l(&pk, &adrs, &m, 16);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_different_adrs_different_output() {
        let pk = [42u8; 16];
        let m = [1u8; 16];
        let mut adrs1 = Adrs::new();
        let mut adrs2 = Adrs::new();
        adrs2.set_layer_address(1);
        let out1 = t_l(&pk, &adrs1, &m, &SLH_DSA_SHAKE_128F);
        let out2 = t_l(&pk, &adrs2, &m, &SLH_DSA_SHAKE_128F);
        assert_ne!(out1, out2);
    }
}
