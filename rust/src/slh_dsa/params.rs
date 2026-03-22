//! SLH-DSA Parameter Sets — FIPS 205 Table 1
//!
//! Defines all 12 SLH-DSA parameter sets across two hash families
//! (SHA2 and SHAKE) and three security levels (128, 192, 256),
//! each with fast (f) and small (s) variants.

/// Hash family used by an SLH-DSA parameter set.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashFamily {
    Sha2,
    Shake,
}

/// SLH-DSA parameter set per FIPS 205 Table 1.
#[derive(Clone, Debug)]
pub struct SlhDsaParams {
    pub name: &'static str,
    pub hash: HashFamily,
    /// Security parameter in bytes (n): hash output length
    pub n: usize,
    /// Total tree height h
    pub h: usize,
    /// Number of hypertree layers d
    pub d: usize,
    /// Height of each XMSS tree: h' = h / d
    pub hp: usize,
    /// FORS tree height
    pub a: usize,
    /// Number of FORS trees
    pub k: usize,
    /// Winternitz parameter log2(w)
    pub lg_w: usize,
    /// WOTS+ message length (len1)
    pub len1: usize,
    /// WOTS+ checksum length (len2)
    pub len2: usize,
    /// WOTS+ total chains: len = len1 + len2
    pub len: usize,
    /// Message digest length in bytes
    pub m: usize,
    /// Public key size in bytes
    pub pk_bytes: usize,
    /// Secret key size in bytes
    pub sk_bytes: usize,
    /// Signature size in bytes
    pub sig_bytes: usize,
}

impl SlhDsaParams {
    /// Winternitz parameter w = 2^lg_w (always 16 for FIPS 205)
    pub const fn w(&self) -> usize {
        1 << self.lg_w
    }
}

// =============================================================================
// SHA2 Parameter Sets
// =============================================================================

/// SLH-DSA-SHA2-128s: 128-bit security, small signatures
pub const SLH_DSA_SHA2_128S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHA2-128s",
    hash: HashFamily::Sha2,
    n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14,
    lg_w: 4, len1: 32, len2: 3, len: 35, m: 30,
    pk_bytes: 32, sk_bytes: 64, sig_bytes: 7856,
};

/// SLH-DSA-SHA2-128f: 128-bit security, fast signing
pub const SLH_DSA_SHA2_128F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHA2-128f",
    hash: HashFamily::Sha2,
    n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33,
    lg_w: 4, len1: 32, len2: 3, len: 35, m: 34,
    pk_bytes: 32, sk_bytes: 64, sig_bytes: 17088,
};

/// SLH-DSA-SHA2-192s: 192-bit security, small signatures
pub const SLH_DSA_SHA2_192S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHA2-192s",
    hash: HashFamily::Sha2,
    n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17,
    lg_w: 4, len1: 48, len2: 3, len: 51, m: 39,
    pk_bytes: 48, sk_bytes: 96, sig_bytes: 16224,
};

/// SLH-DSA-SHA2-192f: 192-bit security, fast signing
pub const SLH_DSA_SHA2_192F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHA2-192f",
    hash: HashFamily::Sha2,
    n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33,
    lg_w: 4, len1: 48, len2: 3, len: 51, m: 42,
    pk_bytes: 48, sk_bytes: 96, sig_bytes: 35664,
};

/// SLH-DSA-SHA2-256s: 256-bit security, small signatures
pub const SLH_DSA_SHA2_256S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHA2-256s",
    hash: HashFamily::Sha2,
    n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22,
    lg_w: 4, len1: 64, len2: 3, len: 67, m: 47,
    pk_bytes: 64, sk_bytes: 128, sig_bytes: 29792,
};

/// SLH-DSA-SHA2-256f: 256-bit security, fast signing
pub const SLH_DSA_SHA2_256F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHA2-256f",
    hash: HashFamily::Sha2,
    n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35,
    lg_w: 4, len1: 64, len2: 3, len: 67, m: 49,
    pk_bytes: 64, sk_bytes: 128, sig_bytes: 49856,
};

// =============================================================================
// SHAKE Parameter Sets
// =============================================================================

/// SLH-DSA-SHAKE-128s: 128-bit security, small signatures
pub const SLH_DSA_SHAKE_128S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-128s",
    hash: HashFamily::Shake,
    n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14,
    lg_w: 4, len1: 32, len2: 3, len: 35, m: 30,
    pk_bytes: 32, sk_bytes: 64, sig_bytes: 7856,
};

/// SLH-DSA-SHAKE-128f: 128-bit security, fast signing
pub const SLH_DSA_SHAKE_128F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-128f",
    hash: HashFamily::Shake,
    n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33,
    lg_w: 4, len1: 32, len2: 3, len: 35, m: 34,
    pk_bytes: 32, sk_bytes: 64, sig_bytes: 17088,
};

/// SLH-DSA-SHAKE-192s: 192-bit security, small signatures
pub const SLH_DSA_SHAKE_192S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-192s",
    hash: HashFamily::Shake,
    n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17,
    lg_w: 4, len1: 48, len2: 3, len: 51, m: 39,
    pk_bytes: 48, sk_bytes: 96, sig_bytes: 16224,
};

/// SLH-DSA-SHAKE-192f: 192-bit security, fast signing
pub const SLH_DSA_SHAKE_192F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-192f",
    hash: HashFamily::Shake,
    n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33,
    lg_w: 4, len1: 48, len2: 3, len: 51, m: 42,
    pk_bytes: 48, sk_bytes: 96, sig_bytes: 35664,
};

/// SLH-DSA-SHAKE-256s: 256-bit security, small signatures
pub const SLH_DSA_SHAKE_256S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-256s",
    hash: HashFamily::Shake,
    n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22,
    lg_w: 4, len1: 64, len2: 3, len: 67, m: 47,
    pk_bytes: 64, sk_bytes: 128, sig_bytes: 29792,
};

/// SLH-DSA-SHAKE-256f: 256-bit security, fast signing
pub const SLH_DSA_SHAKE_256F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-256f",
    hash: HashFamily::Shake,
    n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35,
    lg_w: 4, len1: 64, len2: 3, len: 67, m: 49,
    pk_bytes: 64, sk_bytes: 128, sig_bytes: 49856,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_consistency() {
        let all = [
            &SLH_DSA_SHA2_128S, &SLH_DSA_SHA2_128F,
            &SLH_DSA_SHA2_192S, &SLH_DSA_SHA2_192F,
            &SLH_DSA_SHA2_256S, &SLH_DSA_SHA2_256F,
            &SLH_DSA_SHAKE_128S, &SLH_DSA_SHAKE_128F,
            &SLH_DSA_SHAKE_192S, &SLH_DSA_SHAKE_192F,
            &SLH_DSA_SHAKE_256S, &SLH_DSA_SHAKE_256F,
        ];
        for p in &all {
            // h = d * hp
            assert_eq!(p.h, p.d * p.hp, "{}: h != d * hp", p.name);
            // len = len1 + len2
            assert_eq!(p.len, p.len1 + p.len2, "{}: len != len1 + len2", p.name);
            // pk = 2n, sk = 4n
            assert_eq!(p.pk_bytes, 2 * p.n, "{}: pk_bytes != 2n", p.name);
            assert_eq!(p.sk_bytes, 4 * p.n, "{}: sk_bytes != 4n", p.name);
            // w = 16 (lg_w = 4)
            assert_eq!(p.w(), 16, "{}: w != 16", p.name);
        }
    }

    #[test]
    fn test_signature_sizes() {
        // FIPS 205 sig = (1 + k*(1+a) + h + d*len) * n
        let all_with_expected: &[(&SlhDsaParams, usize)] = &[
            (&SLH_DSA_SHA2_128S, 7856), (&SLH_DSA_SHA2_128F, 17088),
            (&SLH_DSA_SHA2_192S, 16224), (&SLH_DSA_SHA2_192F, 35664),
            (&SLH_DSA_SHA2_256S, 29792), (&SLH_DSA_SHA2_256F, 49856),
        ];
        for (p, expected) in all_with_expected {
            assert_eq!(p.sig_bytes, *expected, "{}", p.name);
        }
    }
}
