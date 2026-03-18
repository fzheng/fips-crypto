//! ML-KEM parameter sets as defined in FIPS 203
//!
//! Three parameter sets are defined:
//! - ML-KEM-512: k=2, Security Category 1
//! - ML-KEM-768: k=3, Security Category 3 (recommended)
//! - ML-KEM-1024: k=4, Security Category 5

/// ML-KEM-512 dimension
pub const MLKEM512_K: usize = 2;

/// ML-KEM-768 dimension
pub const MLKEM768_K: usize = 3;

/// ML-KEM-1024 dimension
pub const MLKEM1024_K: usize = 4;

/// Polynomial degree
pub const N: usize = 256;

/// Modulus q
pub const Q: i32 = 3329;

/// Parameter set configuration
#[derive(Clone, Copy, Debug)]
pub struct MlKemParams {
    /// Name of the parameter set
    pub name: &'static str,
    /// Module dimension k
    pub k: usize,
    /// η₁ for secret key sampling
    pub eta1: usize,
    /// η₂ for noise sampling
    pub eta2: usize,
    /// d_u compression parameter for ciphertext u
    pub du: usize,
    /// d_v compression parameter for ciphertext v
    pub dv: usize,
    /// NIST security category
    pub security_category: usize,
    /// Encapsulation key (public key) size in bytes
    pub ek_bytes: usize,
    /// Decapsulation key (secret key) size in bytes
    pub dk_bytes: usize,
    /// Ciphertext size in bytes
    pub ct_bytes: usize,
    /// Shared secret size in bytes (always 32)
    pub ss_bytes: usize,
}

impl MlKemParams {
    /// Calculate encapsulation key size: 384k + 32
    pub const fn ek_size(k: usize) -> usize {
        384 * k + 32
    }

    /// Calculate decapsulation key size: 768k + 96
    pub const fn dk_size(k: usize) -> usize {
        768 * k + 96
    }

    /// Calculate ciphertext size: 32(d_u * k + d_v)
    pub const fn ct_size(k: usize, du: usize, dv: usize) -> usize {
        32 * (du * k + dv)
    }
}

/// ML-KEM-512 parameters
pub const ML_KEM_512: MlKemParams = MlKemParams {
    name: "ML-KEM-512",
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    security_category: 1,
    ek_bytes: MlKemParams::ek_size(2),  // 800
    dk_bytes: MlKemParams::dk_size(2),  // 1632
    ct_bytes: MlKemParams::ct_size(2, 10, 4),  // 768
    ss_bytes: 32,
};

/// ML-KEM-768 parameters (recommended)
pub const ML_KEM_768: MlKemParams = MlKemParams {
    name: "ML-KEM-768",
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    security_category: 3,
    ek_bytes: MlKemParams::ek_size(3),  // 1184
    dk_bytes: MlKemParams::dk_size(3),  // 2400
    ct_bytes: MlKemParams::ct_size(3, 10, 4),  // 1088
    ss_bytes: 32,
};

/// ML-KEM-1024 parameters
pub const ML_KEM_1024: MlKemParams = MlKemParams {
    name: "ML-KEM-1024",
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    security_category: 5,
    ek_bytes: MlKemParams::ek_size(4),  // 1568
    dk_bytes: MlKemParams::dk_size(4),  // 3168
    ct_bytes: MlKemParams::ct_size(4, 11, 5),  // 1568
    ss_bytes: 32,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem512_sizes() {
        assert_eq!(ML_KEM_512.ek_bytes, 800);
        assert_eq!(ML_KEM_512.dk_bytes, 1632);
        assert_eq!(ML_KEM_512.ct_bytes, 768);
    }

    #[test]
    fn test_mlkem768_sizes() {
        assert_eq!(ML_KEM_768.ek_bytes, 1184);
        assert_eq!(ML_KEM_768.dk_bytes, 2400);
        assert_eq!(ML_KEM_768.ct_bytes, 1088);
    }

    #[test]
    fn test_mlkem1024_sizes() {
        assert_eq!(ML_KEM_1024.ek_bytes, 1568);
        assert_eq!(ML_KEM_1024.dk_bytes, 3168);
        assert_eq!(ML_KEM_1024.ct_bytes, 1568);
    }
}
