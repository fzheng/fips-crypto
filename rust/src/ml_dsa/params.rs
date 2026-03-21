//! ML-DSA parameter sets as defined in FIPS 204
//!
//! Three parameter sets are defined:
//! - ML-DSA-44: k=4, l=4, Security Category 2
//! - ML-DSA-65: k=6, l=5, Security Category 3 (recommended)
//! - ML-DSA-87: k=8, l=7, Security Category 5

/// Polynomial degree
pub const N: usize = 256;

/// ML-DSA modulus q = 2^23 - 2^13 + 1
pub const Q: i32 = 8380417;

/// Number of dropped bits from t
pub const D: usize = 13;

/// Parameter set configuration for ML-DSA
#[derive(Clone, Copy, Debug)]
pub struct MlDsaParams {
    /// Name of the parameter set
    pub name: &'static str,
    /// Matrix rows
    pub k: usize,
    /// Matrix columns
    pub l: usize,
    /// Secret key coefficient bound
    pub eta: usize,
    /// Number of ±1 coefficients in challenge polynomial
    pub tau: usize,
    /// Masking range: coefficients in [-(gamma1-1), gamma1]
    pub gamma1: i32,
    /// Decomposition parameter for w
    pub gamma2: i32,
    /// Maximum number of 1s in hint
    pub omega: usize,
    /// Collision strength in bits (lambda)
    pub lambda: usize,
    /// NIST security category
    pub security_category: usize,
    /// Public key size in bytes
    pub pk_bytes: usize,
    /// Secret key size in bytes
    pub sk_bytes: usize,
    /// Signature size in bytes
    pub sig_bytes: usize,
}

impl MlDsaParams {
    /// beta = tau * eta (rejection bound)
    pub const fn beta(&self) -> i32 {
        (self.tau * self.eta) as i32
    }

    /// Challenge seed length in bytes (lambda / 4)
    pub const fn c_tilde_bytes(&self) -> usize {
        self.lambda / 4
    }
}

/// ML-DSA-44 parameters
pub const ML_DSA_44: MlDsaParams = MlDsaParams {
    name: "ML-DSA-44",
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    gamma1: 1 << 17,    // 2^17 = 131072
    gamma2: (Q - 1) / 88,  // 95232
    omega: 80,
    lambda: 128,
    security_category: 2,
    pk_bytes: 1312,     // 32 + 320*4
    sk_bytes: 2560,     // 32+32+64 + 32*((4+4)*bitlen(4) + 13*4) = 32+32+64 + 32*(8*3+52) = 128 + 32*76 = 128+2432 = 2560
    sig_bytes: 2420,    // 32 + 4*576 + 80+4 = 32 + 2304 + 84 = 2420
};

/// ML-DSA-65 parameters (recommended)
pub const ML_DSA_65: MlDsaParams = MlDsaParams {
    name: "ML-DSA-65",
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    gamma1: 1 << 19,    // 2^19 = 524288
    gamma2: (Q - 1) / 32,  // 261888
    omega: 55,
    lambda: 192,
    security_category: 3,
    pk_bytes: 1952,     // 32 + 320*6
    sk_bytes: 4032,
    sig_bytes: 3309,    // 48 + 5*640 + 55+6 = 3309
};

/// ML-DSA-87 parameters
pub const ML_DSA_87: MlDsaParams = MlDsaParams {
    name: "ML-DSA-87",
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    gamma1: 1 << 19,    // 2^19 = 524288
    gamma2: (Q - 1) / 32,  // 261888
    omega: 75,
    lambda: 256,
    security_category: 5,
    pk_bytes: 2592,     // 32 + 320*8
    sk_bytes: 4896,
    sig_bytes: 4627,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa44_sizes() {
        assert_eq!(ML_DSA_44.pk_bytes, 1312);
        assert_eq!(ML_DSA_44.sk_bytes, 2560);
        assert_eq!(ML_DSA_44.sig_bytes, 2420);
    }

    #[test]
    fn test_mldsa65_sizes() {
        assert_eq!(ML_DSA_65.pk_bytes, 1952);
        assert_eq!(ML_DSA_65.sk_bytes, 4032);
        assert_eq!(ML_DSA_65.sig_bytes, 3309);
    }

    #[test]
    fn test_mldsa87_sizes() {
        assert_eq!(ML_DSA_87.pk_bytes, 2592);
        assert_eq!(ML_DSA_87.sk_bytes, 4896);
        assert_eq!(ML_DSA_87.sig_bytes, 4627);
    }

    #[test]
    fn test_beta_values() {
        assert_eq!(ML_DSA_44.beta(), 78);   // 39 * 2
        assert_eq!(ML_DSA_65.beta(), 196);  // 49 * 4
        assert_eq!(ML_DSA_87.beta(), 120);  // 60 * 2
    }

    #[test]
    fn test_gamma2_values() {
        assert_eq!(ML_DSA_44.gamma2, 95232);
        assert_eq!(ML_DSA_65.gamma2, 261888);
        assert_eq!(ML_DSA_87.gamma2, 261888);
    }

    #[test]
    fn test_c_tilde_bytes() {
        assert_eq!(ML_DSA_44.c_tilde_bytes(), 32);
        assert_eq!(ML_DSA_65.c_tilde_bytes(), 48);
        assert_eq!(ML_DSA_87.c_tilde_bytes(), 64);
    }

    #[test]
    fn test_pk_size_formula() {
        // pk = 32 + 320*k
        assert_eq!(ML_DSA_44.pk_bytes, 32 + 320 * 4);
        assert_eq!(ML_DSA_65.pk_bytes, 32 + 320 * 6);
        assert_eq!(ML_DSA_87.pk_bytes, 32 + 320 * 8);
    }
}
