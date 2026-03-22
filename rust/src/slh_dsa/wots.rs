//! WOTS+ One-Time Signature — FIPS 205 Algorithms 1-5
//!
//! WOTS+ (Winternitz One-Time Signature Plus) is the base signature scheme
//! used within each XMSS tree. It signs an n-byte message digest by:
//!
//! 1. Splitting the digest into base-w (w=16) nibbles
//! 2. Computing a checksum over the nibbles
//! 3. Generating `len` secret values from SK.seed via PRF
//! 4. Iterating the tweakable hash (chain function) for each nibble value
//!
//! The scheme provides one-time unforgeability: each WOTS+ key pair must
//! only be used to sign a single message.

use crate::slh_dsa::address::{Adrs, AdrsType};
use crate::slh_dsa::hash::{prf, t_l};
use crate::slh_dsa::params::SlhDsaParams;

/// FIPS 205 Algorithm 1: Chaining function.
///
/// Iterates the tweakable hash function F (implemented as `t_l`) `s` times,
/// starting from step `i`. The address hash_address is set to the current
/// step index on each iteration.
///
/// # Arguments
/// * `x` - Input value (n bytes)
/// * `i` - Starting step index
/// * `s` - Number of steps to iterate
/// * `pk_seed` - Public seed
/// * `adrs` - Address (chain_address and hash_address fields are modified)
/// * `params` - Parameter set
///
/// # Returns
/// The chained value after s applications of F (n bytes).
pub fn chain(
    x: &[u8],
    i: u32,
    s: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    // FIPS 205 Algorithm 1, step 1-5
    if s == 0 {
        return x.to_vec();
    }

    let mut tmp = x.to_vec();
    for j in i..(i + s) {
        adrs.set_hash_address(j);
        tmp = t_l(pk_seed, adrs, &tmp, params);
    }
    tmp
}

/// Convert an n-byte message to base-w representation with appended checksum.
///
/// FIPS 205 Algorithm 2: base_2^b conversion combined with checksum.
///
/// Since w=16 (lg_w=4), each byte of `msg` yields two nibbles (high then low).
/// The checksum ensures that an attacker cannot forge a signature by only
/// increasing chain values.
///
/// # Arguments
/// * `msg` - Input message (n bytes)
/// * `params` - Parameter set (provides len1, len2, w)
///
/// # Returns
/// A vector of len1 + len2 values, each in `[0, w-1]`.
pub fn base_w_with_checksum(msg: &[u8], params: &SlhDsaParams) -> Vec<u32> {
    let w = params.w() as u32;
    let len1 = params.len1;
    let len2 = params.len2;

    // Step 1: Split message bytes into base-w (nibble) digits.
    // For lg_w=4, each byte gives 2 nibbles: high nibble first, then low nibble.
    let mut base_w = Vec::with_capacity(len1 + len2);
    for i in 0..len1 {
        let byte_idx = i / 2;
        if i % 2 == 0 {
            // High nibble
            base_w.push((msg[byte_idx] >> 4) as u32);
        } else {
            // Low nibble
            base_w.push((msg[byte_idx] & 0x0F) as u32);
        }
    }

    // Step 2: Compute checksum = sum(w - 1 - msg[i]) for all len1 values.
    let mut checksum: u32 = 0;
    for i in 0..len1 {
        checksum += w - 1 - base_w[i];
    }

    // Step 3: Left-shift checksum per FIPS 205:
    //   csum <<= (8 - ((len2 * lg_w) % 8)) % 8
    let shift = (8 - ((len2 * params.lg_w) % 8)) % 8;
    checksum <<= shift;

    // Step 4: Convert checksum to bytes (big-endian), then extract len2
    // base-w digits using the same bit-extraction as the message nibbles.
    let cs_byte_len = (len2 * params.lg_w + 7) / 8;
    let cs_bytes = &checksum.to_be_bytes()[4 - cs_byte_len..];
    for i in 0..len2 {
        let bit_offset = i * params.lg_w;
        let mut val: u32 = 0;
        for b in 0..params.lg_w {
            let total_bit = bit_offset + b;
            let byte_idx = total_bit / 8;
            let bit_idx = 7 - (total_bit % 8);
            let bit = ((cs_bytes[byte_idx] >> bit_idx) & 1) as u32;
            val = (val << 1) | bit;
        }
        base_w.push(val);
    }

    base_w
}

/// FIPS 205 Algorithm 3: Generate a WOTS+ public key.
///
/// Generates `len` secret values using PRF, chains each one w-1 times,
/// then compresses the resulting `len` chain endpoints into a single
/// n-byte public key using T_l.
///
/// # Arguments
/// * `sk_seed` - Secret seed (n bytes)
/// * `pk_seed` - Public seed (n bytes)
/// * `adrs` - Address (key_pair_address should already be set)
/// * `params` - Parameter set
///
/// # Returns
/// WOTS+ public key (n bytes).
pub fn wots_pk_gen(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let n = params.n;
    let w_minus_1 = (params.w() - 1) as u32;

    // Step 1: Generate len secret values using PRF with WotsPrf address type.
    let mut tmp = Vec::with_capacity(params.len * n);
    let sk_adrs_kp = adrs.get_key_pair_address();

    // Generate secret keys and chain them
    for i in 0..params.len {
        // Generate secret value sk[i]
        adrs.set_type(AdrsType::WotsPrf);
        adrs.set_key_pair_address(sk_adrs_kp);
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);
        let sk_i = prf(pk_seed, sk_seed, adrs, params);

        // Step 2: Chain each secret value w-1 times using WotsHash address type.
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_key_pair_address(sk_adrs_kp);
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);
        let endpoint = chain(&sk_i, 0, w_minus_1, pk_seed, adrs, params);
        tmp.extend_from_slice(&endpoint);
    }

    // Step 3: Compress all chain endpoints with T_l using WotsPk address type.
    adrs.set_type(AdrsType::WotsPk);
    adrs.set_key_pair_address(sk_adrs_kp);
    adrs.set_chain_address(0);
    adrs.set_hash_address(0);
    t_l(pk_seed, adrs, &tmp, params)
}

/// FIPS 205 Algorithm 4: WOTS+ signature generation.
///
/// Signs an n-byte message digest by:
/// 1. Converting the message to base-w with checksum
/// 2. Generating secret values via PRF
/// 3. Chaining each value msg[i] times
///
/// # Arguments
/// * `msg` - Message digest to sign (n bytes)
/// * `sk_seed` - Secret seed (n bytes)
/// * `pk_seed` - Public seed (n bytes)
/// * `adrs` - Address (key_pair_address should already be set)
/// * `params` - Parameter set
///
/// # Returns
/// WOTS+ signature (len * n bytes).
pub fn wots_sign(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let n = params.n;
    let sk_adrs_kp = adrs.get_key_pair_address();

    // Step 1: Convert message to base-w with checksum.
    let base_w = base_w_with_checksum(msg, params);

    // Step 2-3: For each chain, generate the secret value and chain msg[i] times.
    let mut sig = Vec::with_capacity(params.len * n);
    for i in 0..params.len {
        // Generate secret value sk[i]
        adrs.set_type(AdrsType::WotsPrf);
        adrs.set_key_pair_address(sk_adrs_kp);
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);
        let sk_i = prf(pk_seed, sk_seed, adrs, params);

        // Chain sk[i] for msg[i] steps
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_key_pair_address(sk_adrs_kp);
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);
        let sig_i = chain(&sk_i, 0, base_w[i], pk_seed, adrs, params);
        sig.extend_from_slice(&sig_i);
    }

    sig
}

/// FIPS 205 Algorithm 5: Compute WOTS+ public key from signature.
///
/// Given a WOTS+ signature and the original message digest, reconstructs
/// the public key by completing the remaining chain steps for each chain.
///
/// # Arguments
/// * `sig` - WOTS+ signature (len * n bytes)
/// * `msg` - Message digest (n bytes)
/// * `pk_seed` - Public seed (n bytes)
/// * `adrs` - Address (key_pair_address should already be set)
/// * `params` - Parameter set
///
/// # Returns
/// Recovered WOTS+ public key (n bytes). If the signature is valid,
/// this will match the original public key.
pub fn wots_pk_from_sig(
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
) -> Vec<u8> {
    let n = params.n;
    let w_minus_1 = (params.w() - 1) as u32;
    let sk_adrs_kp = adrs.get_key_pair_address();

    // Step 1: Convert message to base-w with checksum.
    let base_w = base_w_with_checksum(msg, params);

    // Step 2: For each chain, complete the remaining (w-1-msg[i]) steps.
    let mut tmp = Vec::with_capacity(params.len * n);
    for i in 0..params.len {
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_key_pair_address(sk_adrs_kp);
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);

        let sig_i = &sig[i * n..(i + 1) * n];
        let remaining = w_minus_1 - base_w[i];
        let endpoint = chain(sig_i, base_w[i], remaining, pk_seed, adrs, params);
        tmp.extend_from_slice(&endpoint);
    }

    // Step 3: Compress all chain endpoints with T_l using WotsPk address type.
    adrs.set_type(AdrsType::WotsPk);
    adrs.set_key_pair_address(sk_adrs_kp);
    adrs.set_chain_address(0);
    adrs.set_hash_address(0);
    t_l(pk_seed, adrs, &tmp, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::*;

    #[test]
    fn test_base_w_with_checksum_length() {
        // For SLH-DSA-SHAKE-128f: len1=8, len2=3, len=11
        let params = &SLH_DSA_SHAKE_128F;
        let msg = vec![0xABu8; params.n];
        let bw = base_w_with_checksum(&msg, params);
        assert_eq!(bw.len(), params.len, "base_w length should be len1 + len2");
    }

    #[test]
    fn test_base_w_values_in_range() {
        let params = &SLH_DSA_SHAKE_128F;
        let msg = vec![0x3Cu8; params.n];
        let bw = base_w_with_checksum(&msg, params);
        let w = params.w() as u32;
        for (i, &val) in bw.iter().enumerate() {
            assert!(val < w, "base_w[{}] = {} should be < w={}", i, val, w);
        }
    }

    #[test]
    fn test_base_w_nibble_extraction() {
        // With lg_w=4, byte 0xAB should give nibbles [0xA, 0xB]
        let params = &SLH_DSA_SHAKE_128F;
        let mut msg = vec![0u8; params.n];
        msg[0] = 0xAB;
        let bw = base_w_with_checksum(&msg, params);
        assert_eq!(bw[0], 0xA, "High nibble of 0xAB should be 0xA");
        assert_eq!(bw[1], 0xB, "Low nibble of 0xAB should be 0xB");
    }

    #[test]
    fn test_base_w_checksum_all_zeros() {
        // All-zero message: each nibble is 0, checksum = len1 * (w-1)
        let params = &SLH_DSA_SHAKE_128F;
        let msg = vec![0u8; params.n];
        let bw = base_w_with_checksum(&msg, params);
        // First len1 values should all be 0
        for i in 0..params.len1 {
            assert_eq!(bw[i], 0, "All-zero msg: nibble {} should be 0", i);
        }
    }

    #[test]
    fn test_base_w_checksum_all_max() {
        // All-0xFF message: each nibble is 15, checksum = 0
        let params = &SLH_DSA_SHAKE_128F;
        let msg = vec![0xFFu8; params.n];
        let bw = base_w_with_checksum(&msg, params);
        // First len1 values should all be 15
        for i in 0..params.len1 {
            assert_eq!(bw[i], 15, "All-0xFF msg: nibble {} should be 15", i);
        }
        // Checksum digits should all be 0
        for i in params.len1..params.len {
            assert_eq!(bw[i], 0, "All-max msg: checksum digit {} should be 0", i);
        }
    }

    #[test]
    fn test_chain_zero_steps() {
        let params = &SLH_DSA_SHAKE_128F;
        let pk_seed = vec![0u8; params.n];
        let mut adrs = Adrs::new();
        let x = vec![42u8; params.n];
        let result = chain(&x, 0, 0, &pk_seed, &mut adrs, params);
        assert_eq!(result, x, "chain with s=0 should return input unchanged");
    }

    #[test]
    fn test_chain_deterministic() {
        let params = &SLH_DSA_SHAKE_128F;
        let pk_seed = vec![1u8; params.n];
        let mut adrs1 = Adrs::new();
        let mut adrs2 = Adrs::new();
        let x = vec![42u8; params.n];
        let r1 = chain(&x, 0, 3, &pk_seed, &mut adrs1, params);
        let r2 = chain(&x, 0, 3, &pk_seed, &mut adrs2, params);
        assert_eq!(r1, r2, "chain should be deterministic");
    }

    #[test]
    fn test_chain_composition() {
        // chain(x, 0, 3) == chain(chain(x, 0, 1), 1, 2)
        let params = &SLH_DSA_SHAKE_128F;
        let pk_seed = vec![1u8; params.n];
        let x = vec![42u8; params.n];

        let mut adrs = Adrs::new();
        let full = chain(&x, 0, 3, &pk_seed, &mut adrs, params);

        let mut adrs = Adrs::new();
        let partial1 = chain(&x, 0, 1, &pk_seed, &mut adrs, params);
        let mut adrs = Adrs::new();
        let partial2 = chain(&partial1, 1, 2, &pk_seed, &mut adrs, params);

        assert_eq!(full, partial2, "chain composition should be consistent");
    }

    #[test]
    fn test_wots_roundtrip_shake_128f() {
        // WOTS+ roundtrip: sign, then pk_from_sig should yield the same pk as pk_gen.
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];
        let msg = vec![0x55u8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_layer_address(0);
        adrs.set_tree_address(0);
        adrs.set_key_pair_address(0);

        // Generate public key
        let pk = wots_pk_gen(&sk_seed, &pk_seed, &mut adrs.clone(), params);
        assert_eq!(pk.len(), params.n, "WOTS+ pk should be n bytes");

        // Sign
        let sig = wots_sign(&msg, &sk_seed, &pk_seed, &mut adrs.clone(), params);
        assert_eq!(sig.len(), params.len * params.n, "WOTS+ sig should be len*n bytes");

        // Recover pk from signature
        let pk_recovered = wots_pk_from_sig(&sig, &msg, &pk_seed, &mut adrs.clone(), params);
        assert_eq!(pk_recovered, pk, "WOTS+ roundtrip: recovered pk should match generated pk");
    }

    #[test]
    fn test_wots_roundtrip_sha2_128s() {
        let params = &SLH_DSA_SHA2_128S;
        let sk_seed = vec![0x11u8; params.n];
        let pk_seed = vec![0x22u8; params.n];
        let msg = vec![0x33u8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_layer_address(1);
        adrs.set_tree_address(5);
        adrs.set_key_pair_address(3);

        let pk = wots_pk_gen(&sk_seed, &pk_seed, &mut adrs.clone(), params);
        let sig = wots_sign(&msg, &sk_seed, &pk_seed, &mut adrs.clone(), params);
        let pk_recovered = wots_pk_from_sig(&sig, &msg, &pk_seed, &mut adrs.clone(), params);

        assert_eq!(pk_recovered, pk, "WOTS+ SHA2-128s roundtrip failed");
    }

    #[test]
    fn test_wots_roundtrip_shake_256s() {
        let params = &SLH_DSA_SHAKE_256S;
        let sk_seed = vec![0xCCu8; params.n];
        let pk_seed = vec![0xDDu8; params.n];
        let msg = vec![0xEEu8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_key_pair_address(7);

        let pk = wots_pk_gen(&sk_seed, &pk_seed, &mut adrs.clone(), params);
        let sig = wots_sign(&msg, &sk_seed, &pk_seed, &mut adrs.clone(), params);
        let pk_recovered = wots_pk_from_sig(&sig, &msg, &pk_seed, &mut adrs.clone(), params);

        assert_eq!(pk_recovered, pk, "WOTS+ SHAKE-256s roundtrip failed");
    }

    #[test]
    fn test_wots_wrong_message_fails() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];
        let msg = vec![0x55u8; params.n];
        let wrong_msg = vec![0x66u8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_key_pair_address(0);

        let pk = wots_pk_gen(&sk_seed, &pk_seed, &mut adrs.clone(), params);
        let sig = wots_sign(&msg, &sk_seed, &pk_seed, &mut adrs.clone(), params);
        let pk_wrong = wots_pk_from_sig(&sig, &wrong_msg, &pk_seed, &mut adrs.clone(), params);

        assert_ne!(pk_wrong, pk, "WOTS+ should not verify with wrong message");
    }

    #[test]
    fn test_wots_different_keypairs_different_pks() {
        let params = &SLH_DSA_SHAKE_128F;
        let sk_seed = vec![0xAAu8; params.n];
        let pk_seed = vec![0xBBu8; params.n];

        let mut adrs1 = Adrs::new();
        adrs1.set_key_pair_address(0);
        let pk1 = wots_pk_gen(&sk_seed, &pk_seed, &mut adrs1, params);

        let mut adrs2 = Adrs::new();
        adrs2.set_key_pair_address(1);
        let pk2 = wots_pk_gen(&sk_seed, &pk_seed, &mut adrs2, params);

        assert_ne!(pk1, pk2, "Different key pair addresses should yield different public keys");
    }
}
