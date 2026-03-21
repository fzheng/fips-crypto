//! Polynomial arithmetic for ML-DSA (FIPS 204)
//!
//! Implements polynomial operations in the ring R_q = Z_q[X]/(X^n + 1)
//! where q = 8380417 for ML-DSA and n = 256.
//!
//! Key operations and their FIPS 204 references:
//! - Power2Round (Algorithm 35): split t into (t1, t0) for public key compression
//! - Decompose (Algorithm 36): decompose w into high and low bits
//! - HighBits / LowBits (Algorithms 37/38): extract high/low parts of decomposition
//! - MakeHint / UseHint (Algorithms 39/40): hint generation and application
//! - Bit packing functions for t1, t0, eta, z, w1 encoding

use crate::ml_dsa::params::{D, N, Q};
use crate::primitives::ntt::{
    mldsa_caddq, mldsa_ntt, mldsa_ntt_inv, mldsa_pointwise_mul, mldsa_reduce32,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// DsaPoly
// ============================================================================

/// A polynomial in R_q with i32 coefficients for ML-DSA (q = 8380417)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DsaPoly {
    pub coeffs: [i32; N],
}

impl Default for DsaPoly {
    fn default() -> Self {
        Self::zero()
    }
}

impl DsaPoly {
    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self { coeffs: [0i32; N] }
    }

    /// Add two polynomials
    pub fn add(&self, other: &DsaPoly) -> DsaPoly {
        let mut result = [0i32; N];
        for i in 0..N {
            result[i] = self.coeffs[i] + other.coeffs[i];
        }
        DsaPoly { coeffs: result }
    }

    /// Subtract two polynomials
    pub fn sub(&self, other: &DsaPoly) -> DsaPoly {
        let mut result = [0i32; N];
        for i in 0..N {
            result[i] = self.coeffs[i] - other.coeffs[i];
        }
        DsaPoly { coeffs: result }
    }

    /// Convert to NTT representation in-place
    pub fn to_ntt(&mut self) {
        mldsa_ntt(&mut self.coeffs);
    }

    /// Convert from NTT representation in-place
    pub fn from_ntt(&mut self) {
        mldsa_ntt_inv(&mut self.coeffs);
    }

    /// Pointwise multiplication in NTT domain (element-wise Montgomery multiply)
    pub fn pointwise_mul(&self, other: &DsaPoly) -> DsaPoly {
        DsaPoly {
            coeffs: mldsa_pointwise_mul(&self.coeffs, &other.coeffs),
        }
    }

    /// Reduce all coefficients to [0, Q) via mldsa_reduce32 + mldsa_caddq
    pub fn reduce(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = mldsa_reduce32(*coeff);
            *coeff = mldsa_caddq(*coeff);
        }
    }

    /// Reduce all coefficients to centered representation (-Q/2, Q/2]
    /// via mldsa_reduce32 only (no caddq shift).
    /// Used when coefficients need to stay centered, e.g., for z packing.
    pub fn reduce_centered(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = mldsa_reduce32(*coeff);
        }
    }

    /// Compute the infinity norm: max |coeff| centered around 0.
    ///
    /// For each coefficient c, if c > (Q-1)/2 then use Q - c instead.
    /// Returns the maximum absolute value.
    pub fn infinity_norm(&self) -> i32 {
        let half_q = (Q - 1) / 2;
        let mut max_val = 0i32;
        for &c in &self.coeffs {
            // Center around 0: if c > (Q-1)/2, use Q - c
            let centered = if c > half_q { Q - c } else { c };
            // Take absolute value (handles negative coefficients)
            let abs_val = centered.abs();
            if abs_val > max_val {
                max_val = abs_val;
            }
        }
        max_val
    }

    /// Check if the infinity norm is strictly less than bound
    pub fn check_norm(&self, bound: i32) -> bool {
        self.infinity_norm() < bound
    }

    /// FIPS 204 Algorithm 35: Power2Round
    ///
    /// Splits t into (t1, t0) where t = t1 * 2^d + t0, with d = 13.
    /// For each coefficient r:
    ///   t1 = (r + (1 << (d-1)) - 1) >> d
    ///   t0 = r - (t1 << d)
    /// Centers t0 in [-(2^(d-1)-1), 2^(d-1)]
    pub fn power2round(&self) -> (DsaPoly, DsaPoly) {
        let mut t1 = DsaPoly::zero();
        let mut t0 = DsaPoly::zero();
        let d = D as u32;

        for i in 0..N {
            let r = self.coeffs[i];
            // t1 = (r + (1 << (d-1)) - 1) >> d
            t1.coeffs[i] = (r + (1 << (d - 1)) - 1) >> d;
            // t0 = r - t1 * 2^d
            t0.coeffs[i] = r - (t1.coeffs[i] << d);
        }

        (t1, t0)
    }

    /// FIPS 204 Algorithm 36: Decompose
    ///
    /// Decomposes r into (r1, r0) such that r = r1 * 2*gamma2 + r0.
    /// r0 = r mod± (2*gamma2); if r - r0 == Q-1 then r1=0, r0=r0-1
    /// else r1 = (r - r0) / (2*gamma2).
    pub fn decompose(&self, gamma2: i32) -> (DsaPoly, DsaPoly) {
        let mut r1 = DsaPoly::zero();
        let mut r0 = DsaPoly::zero();

        for i in 0..N {
            let (hi, lo) = decompose_coeff(self.coeffs[i], gamma2);
            r1.coeffs[i] = hi;
            r0.coeffs[i] = lo;
        }

        (r1, r0)
    }

    /// Extract high bits of decompose (first element)
    pub fn high_bits(&self, gamma2: i32) -> DsaPoly {
        let (r1, _) = self.decompose(gamma2);
        r1
    }

    /// Extract low bits of decompose (second element)
    pub fn low_bits(&self, gamma2: i32) -> DsaPoly {
        let (_, r0) = self.decompose(gamma2);
        r0
    }

    /// FIPS 204 Algorithm 39: MakeHint
    ///
    /// hint[i] = 1 if high_bits(r[i], gamma2) != high_bits(r[i]+z[i], gamma2), else 0.
    /// Returns (hint polynomial, count of 1s).
    pub fn make_hint(z: &DsaPoly, r: &DsaPoly, gamma2: i32) -> (DsaPoly, usize) {
        let mut hint = DsaPoly::zero();
        let mut count = 0usize;

        for i in 0..N {
            let (r1, _) = decompose_coeff(r.coeffs[i], gamma2);
            let sum = (r.coeffs[i] + z.coeffs[i]).rem_euclid(Q);
            let (r1_sum, _) = decompose_coeff(sum, gamma2);
            if r1 != r1_sum {
                hint.coeffs[i] = 1;
                count += 1;
            }
        }

        (hint, count)
    }

    /// FIPS 204 Algorithm 40: UseHint
    ///
    /// If hint=0, return r1 from decompose(self).
    /// If hint=1, adjust r1: if r0 > 0 then (r1+1) mod m, else (r1-1) mod m,
    /// where m = (Q-1) / (2*gamma2).
    pub fn use_hint(&self, hint: &DsaPoly, gamma2: i32) -> DsaPoly {
        let m = (Q - 1) / (2 * gamma2);
        let mut result = DsaPoly::zero();

        for i in 0..N {
            let (r1, r0) = decompose_coeff(self.coeffs[i], gamma2);
            if hint.coeffs[i] == 0 {
                result.coeffs[i] = r1;
            } else if r0 > 0 {
                result.coeffs[i] = (r1 + 1).rem_euclid(m);
            } else {
                result.coeffs[i] = (r1 - 1).rem_euclid(m);
            }
        }

        result
    }

    // ========================================================================
    // Bit packing functions
    // ========================================================================

    /// Pack t1 coefficients: 10 bits per coefficient, 320 bytes total.
    /// Coefficients are in [0, 2^10).
    pub fn pack_t1(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 320];
        for i in 0..N / 4 {
            let c0 = self.coeffs[4 * i] as u32;
            let c1 = self.coeffs[4 * i + 1] as u32;
            let c2 = self.coeffs[4 * i + 2] as u32;
            let c3 = self.coeffs[4 * i + 3] as u32;

            buf[5 * i] = c0 as u8;
            buf[5 * i + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
            buf[5 * i + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
            buf[5 * i + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
            buf[5 * i + 4] = (c3 >> 2) as u8;
        }
        buf
    }

    /// Unpack t1 coefficients from 320 bytes (10 bits per coefficient)
    pub fn unpack_t1(bytes: &[u8]) -> DsaPoly {
        let mut poly = DsaPoly::zero();
        for i in 0..N / 4 {
            let b0 = bytes[5 * i] as u32;
            let b1 = bytes[5 * i + 1] as u32;
            let b2 = bytes[5 * i + 2] as u32;
            let b3 = bytes[5 * i + 3] as u32;
            let b4 = bytes[5 * i + 4] as u32;

            poly.coeffs[4 * i] = (b0 | (b1 << 8)) as i32 & 0x3FF;
            poly.coeffs[4 * i + 1] = ((b1 >> 2) | (b2 << 6)) as i32 & 0x3FF;
            poly.coeffs[4 * i + 2] = ((b2 >> 4) | (b3 << 4)) as i32 & 0x3FF;
            poly.coeffs[4 * i + 3] = ((b3 >> 6) | (b4 << 2)) as i32 & 0x3FF;
        }
        poly
    }

    /// Pack t0 coefficients: 13 bits per coefficient, 416 bytes total.
    /// Coefficients are centered around 2^(d-1): stored as (1 << (D-1)) - coeff
    /// to make them positive, then encoded with 13 bits each.
    pub fn pack_t0(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 416];
        for i in 0..N / 8 {
            let mut vals = [0u32; 8];
            for j in 0..8 {
                // Map from centered representation to positive: (1 << (D-1)) - coeff
                vals[j] = ((1i32 << (D - 1)) - self.coeffs[8 * i + j]) as u32;
            }

            buf[13 * i] = vals[0] as u8;
            buf[13 * i + 1] = ((vals[0] >> 8) | (vals[1] << 5)) as u8;
            buf[13 * i + 2] = (vals[1] >> 3) as u8;
            buf[13 * i + 3] = ((vals[1] >> 11) | (vals[2] << 2)) as u8;
            buf[13 * i + 4] = ((vals[2] >> 6) | (vals[3] << 7)) as u8;
            buf[13 * i + 5] = (vals[3] >> 1) as u8;
            buf[13 * i + 6] = ((vals[3] >> 9) | (vals[4] << 4)) as u8;
            buf[13 * i + 7] = (vals[4] >> 4) as u8;
            buf[13 * i + 8] = ((vals[4] >> 12) | (vals[5] << 1)) as u8;
            buf[13 * i + 9] = ((vals[5] >> 7) | (vals[6] << 6)) as u8;
            buf[13 * i + 10] = (vals[6] >> 2) as u8;
            buf[13 * i + 11] = ((vals[6] >> 10) | (vals[7] << 3)) as u8;
            buf[13 * i + 12] = (vals[7] >> 5) as u8;
        }
        buf
    }

    /// Unpack t0 coefficients from 416 bytes (13 bits per coefficient)
    pub fn unpack_t0(bytes: &[u8]) -> DsaPoly {
        let mut poly = DsaPoly::zero();
        for i in 0..N / 8 {
            let b = |idx: usize| bytes[13 * i + idx] as u32;

            let mut vals = [0u32; 8];
            vals[0] = b(0) | (b(1) << 8);
            vals[0] &= 0x1FFF;
            vals[1] = (b(1) >> 5) | (b(2) << 3) | (b(3) << 11);
            vals[1] &= 0x1FFF;
            vals[2] = (b(3) >> 2) | (b(4) << 6);
            vals[2] &= 0x1FFF;
            vals[3] = (b(4) >> 7) | (b(5) << 1) | (b(6) << 9);
            vals[3] &= 0x1FFF;
            vals[4] = (b(6) >> 4) | (b(7) << 4) | (b(8) << 12);
            vals[4] &= 0x1FFF;
            vals[5] = (b(8) >> 1) | (b(9) << 7);
            vals[5] &= 0x1FFF;
            vals[6] = (b(9) >> 6) | (b(10) << 2) | (b(11) << 10);
            vals[6] &= 0x1FFF;
            vals[7] = (b(11) >> 3) | (b(12) << 5);
            vals[7] &= 0x1FFF;

            for j in 0..8 {
                // Map from positive back to centered: (1 << (D-1)) - val
                poly.coeffs[8 * i + j] = (1i32 << (D - 1)) - vals[j] as i32;
            }
        }
        poly
    }

    /// Pack eta-bounded coefficients.
    /// For eta=2: 3 bits per coeff, 96 bytes. Each coeff in [-2, 2] stored as eta - coeff.
    /// For eta=4: 4 bits per coeff, 128 bytes. Each coeff in [-4, 4] stored as eta - coeff.
    pub fn pack_eta(&self, eta: usize) -> Vec<u8> {
        match eta {
            2 => {
                let mut buf = vec![0u8; 96];
                for i in 0..N / 8 {
                    let mut vals = [0u8; 8];
                    for j in 0..8 {
                        vals[j] = (eta as i32 - self.coeffs[8 * i + j]) as u8;
                    }
                    buf[3 * i] = vals[0] | (vals[1] << 3) | (vals[2] << 6);
                    buf[3 * i + 1] = (vals[2] >> 2) | (vals[3] << 1) | (vals[4] << 4) | (vals[5] << 7);
                    buf[3 * i + 2] = (vals[5] >> 1) | (vals[6] << 2) | (vals[7] << 5);
                }
                buf
            }
            4 => {
                let mut buf = vec![0u8; 128];
                for i in 0..N / 2 {
                    let c0 = (eta as i32 - self.coeffs[2 * i]) as u8;
                    let c1 = (eta as i32 - self.coeffs[2 * i + 1]) as u8;
                    buf[i] = c0 | (c1 << 4);
                }
                buf
            }
            _ => panic!("Unsupported eta value: {}", eta),
        }
    }

    /// Unpack eta-bounded coefficients.
    /// For eta=2: 3 bits per coeff, 96 bytes.
    /// For eta=4: 4 bits per coeff, 128 bytes.
    pub fn unpack_eta(bytes: &[u8], eta: usize) -> DsaPoly {
        let mut poly = DsaPoly::zero();
        match eta {
            2 => {
                for i in 0..N / 8 {
                    let b0 = bytes[3 * i];
                    let b1 = bytes[3 * i + 1];
                    let b2 = bytes[3 * i + 2];

                    let mut vals = [0u8; 8];
                    vals[0] = b0 & 7;
                    vals[1] = (b0 >> 3) & 7;
                    vals[2] = ((b0 >> 6) | (b1 << 2)) & 7;
                    vals[3] = (b1 >> 1) & 7;
                    vals[4] = (b1 >> 4) & 7;
                    vals[5] = ((b1 >> 7) | (b2 << 1)) & 7;
                    vals[6] = (b2 >> 2) & 7;
                    vals[7] = (b2 >> 5) & 7;

                    for j in 0..8 {
                        poly.coeffs[8 * i + j] = eta as i32 - vals[j] as i32;
                    }
                }
            }
            4 => {
                for i in 0..N / 2 {
                    let c0 = bytes[i] & 0x0F;
                    let c1 = bytes[i] >> 4;
                    poly.coeffs[2 * i] = eta as i32 - c0 as i32;
                    poly.coeffs[2 * i + 1] = eta as i32 - c1 as i32;
                }
            }
            _ => panic!("Unsupported eta value: {}", eta),
        }
        poly
    }

    /// Pack z coefficients: encode z in [-(gamma1-1), gamma1].
    /// For gamma1 = 2^17: 18 bits/coeff = 576 bytes.
    /// For gamma1 = 2^19: 20 bits/coeff = 640 bytes.
    pub fn pack_z(&self, gamma1: i32) -> Vec<u8> {
        match gamma1 {
            // gamma1 = 2^17, 18 bits per coefficient
            g if g == (1 << 17) => {
                let mut buf = vec![0u8; 576];
                for i in 0..N / 4 {
                    let mut vals = [0u32; 4];
                    for j in 0..4 {
                        vals[j] = (gamma1 - self.coeffs[4 * i + j]) as u32;
                    }

                    buf[9 * i] = vals[0] as u8;
                    buf[9 * i + 1] = (vals[0] >> 8) as u8;
                    buf[9 * i + 2] = ((vals[0] >> 16) | (vals[1] << 2)) as u8;
                    buf[9 * i + 3] = (vals[1] >> 6) as u8;
                    buf[9 * i + 4] = ((vals[1] >> 14) | (vals[2] << 4)) as u8;
                    buf[9 * i + 5] = (vals[2] >> 4) as u8;
                    buf[9 * i + 6] = ((vals[2] >> 12) | (vals[3] << 6)) as u8;
                    buf[9 * i + 7] = (vals[3] >> 2) as u8;
                    buf[9 * i + 8] = (vals[3] >> 10) as u8;
                }
                buf
            }
            // gamma1 = 2^19, 20 bits per coefficient
            g if g == (1 << 19) => {
                let mut buf = vec![0u8; 640];
                for i in 0..N / 2 {
                    let v0 = (gamma1 - self.coeffs[2 * i]) as u32;
                    let v1 = (gamma1 - self.coeffs[2 * i + 1]) as u32;

                    buf[5 * i] = v0 as u8;
                    buf[5 * i + 1] = (v0 >> 8) as u8;
                    buf[5 * i + 2] = ((v0 >> 16) | (v1 << 4)) as u8;
                    buf[5 * i + 3] = (v1 >> 4) as u8;
                    buf[5 * i + 4] = (v1 >> 12) as u8;
                }
                buf
            }
            _ => panic!("Unsupported gamma1 value: {}", gamma1),
        }
    }

    /// Unpack z coefficients.
    /// For gamma1 = 2^17: 18 bits/coeff from 576 bytes.
    /// For gamma1 = 2^19: 20 bits/coeff from 640 bytes.
    pub fn unpack_z(bytes: &[u8], gamma1: i32) -> DsaPoly {
        let mut poly = DsaPoly::zero();
        match gamma1 {
            g if g == (1 << 17) => {
                for i in 0..N / 4 {
                    let b = |idx: usize| bytes[9 * i + idx] as u32;

                    let mut vals = [0u32; 4];
                    vals[0] = b(0) | (b(1) << 8) | (b(2) << 16);
                    vals[0] &= 0x3FFFF;
                    vals[1] = (b(2) >> 2) | (b(3) << 6) | (b(4) << 14);
                    vals[1] &= 0x3FFFF;
                    vals[2] = (b(4) >> 4) | (b(5) << 4) | (b(6) << 12);
                    vals[2] &= 0x3FFFF;
                    vals[3] = (b(6) >> 6) | (b(7) << 2) | (b(8) << 10);
                    vals[3] &= 0x3FFFF;

                    for j in 0..4 {
                        poly.coeffs[4 * i + j] = gamma1 - vals[j] as i32;
                    }
                }
            }
            g if g == (1 << 19) => {
                for i in 0..N / 2 {
                    let b = |idx: usize| bytes[5 * i + idx] as u32;

                    let v0 = b(0) | (b(1) << 8) | (b(2) << 16);
                    let v0 = v0 & 0xFFFFF;
                    let v1 = (b(2) >> 4) | (b(3) << 4) | (b(4) << 12);
                    let v1 = v1 & 0xFFFFF;

                    poly.coeffs[2 * i] = gamma1 - v0 as i32;
                    poly.coeffs[2 * i + 1] = gamma1 - v1 as i32;
                }
            }
            _ => panic!("Unsupported gamma1 value: {}", gamma1),
        }
        poly
    }

    /// Pack w1 coefficients.
    /// For gamma2 = (Q-1)/88: w1 in [0, 43], 6 bits/coeff = 192 bytes.
    /// For gamma2 = (Q-1)/32: w1 in [0, 15], 4 bits/coeff = 128 bytes.
    pub fn pack_w1(&self, gamma2: i32) -> Vec<u8> {
        if gamma2 == (Q - 1) / 88 {
            // 6 bits per coefficient, 192 bytes
            let mut buf = vec![0u8; 192];
            for i in 0..N / 4 {
                let c0 = self.coeffs[4 * i] as u32;
                let c1 = self.coeffs[4 * i + 1] as u32;
                let c2 = self.coeffs[4 * i + 2] as u32;
                let c3 = self.coeffs[4 * i + 3] as u32;

                buf[3 * i] = (c0 | (c1 << 6)) as u8;
                buf[3 * i + 1] = ((c1 >> 2) | (c2 << 4)) as u8;
                buf[3 * i + 2] = ((c2 >> 4) | (c3 << 2)) as u8;
            }
            buf
        } else if gamma2 == (Q - 1) / 32 {
            // 4 bits per coefficient, 128 bytes
            let mut buf = vec![0u8; 128];
            for i in 0..N / 2 {
                let c0 = self.coeffs[2 * i] as u8;
                let c1 = self.coeffs[2 * i + 1] as u8;
                buf[i] = c0 | (c1 << 4);
            }
            buf
        } else {
            panic!("Unsupported gamma2 value: {}", gamma2);
        }
    }
}

// ============================================================================
// Helper: decompose a single coefficient (FIPS 204 Algorithm 36)
// ============================================================================

/// Decompose a single coefficient r into (r1, r0) such that
/// r = r1 * 2*gamma2 + r0 (mod Q).
///
/// r0 = r mod± (2*gamma2). If r - r0 == Q - 1 then r1 = 0 and r0 -= 1,
/// otherwise r1 = (r - r0) / (2*gamma2).
#[inline]
fn decompose_coeff(a: i32, gamma2: i32) -> (i32, i32) {
    // Ensure a is in [0, Q)
    let r = a.rem_euclid(Q);

    // r0 = r mod± (2*gamma2)
    let two_gamma2 = 2 * gamma2;
    let mut r0 = r.rem_euclid(two_gamma2);
    if r0 > gamma2 {
        r0 -= two_gamma2;
    }

    if r - r0 == Q - 1 {
        // Edge case: r1 would overflow, so set r1 = 0 and adjust r0
        (0, r0 - 1)
    } else {
        let r1 = (r - r0) / two_gamma2;
        (r1, r0)
    }
}

// ============================================================================
// DsaPolyVec
// ============================================================================

/// A vector of DsaPoly polynomials
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DsaPolyVec {
    pub polys: Vec<DsaPoly>,
}

impl DsaPolyVec {
    /// Create a new polynomial vector of given length
    pub fn new(len: usize) -> Self {
        Self {
            polys: vec![DsaPoly::zero(); len],
        }
    }

    /// Get the dimension
    pub fn len(&self) -> usize {
        self.polys.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.polys.is_empty()
    }

    /// Add two polynomial vectors
    pub fn add(&self, other: &DsaPolyVec) -> DsaPolyVec {
        assert_eq!(self.len(), other.len());
        DsaPolyVec {
            polys: self
                .polys
                .iter()
                .zip(other.polys.iter())
                .map(|(a, b)| a.add(b))
                .collect(),
        }
    }

    /// Subtract two polynomial vectors
    pub fn sub(&self, other: &DsaPolyVec) -> DsaPolyVec {
        assert_eq!(self.len(), other.len());
        DsaPolyVec {
            polys: self
                .polys
                .iter()
                .zip(other.polys.iter())
                .map(|(a, b)| a.sub(b))
                .collect(),
        }
    }

    /// Convert all polynomials to NTT form
    pub fn to_ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.to_ntt();
        }
    }

    /// Convert all polynomials from NTT form
    pub fn from_ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.from_ntt();
        }
    }

    /// Reduce all coefficients in all polynomials to [0, Q)
    pub fn reduce(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.reduce();
        }
    }

    /// Reduce all coefficients in all polynomials to centered form (-Q/2, Q/2]
    pub fn reduce_centered(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.reduce_centered();
        }
    }

    /// Inner product of two polynomial vectors in NTT domain
    /// (sum of pointwise multiplications)
    pub fn pointwise_acc(a: &DsaPolyVec, b: &DsaPolyVec) -> DsaPoly {
        assert_eq!(a.len(), b.len());
        let mut result = DsaPoly::zero();
        for (pa, pb) in a.polys.iter().zip(b.polys.iter()) {
            let prod = pa.pointwise_mul(pb);
            result = result.add(&prod);
        }
        result
    }

    /// Check if all polynomials have infinity norm < bound
    pub fn check_norm(&self, bound: i32) -> bool {
        self.polys.iter().all(|p| p.check_norm(bound))
    }

    /// Pack all polys with pack_eta
    pub fn to_bytes_eta(&self, eta: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for poly in &self.polys {
            result.extend(poly.pack_eta(eta));
        }
        result
    }

    /// Unpack polynomial vector from eta-encoded bytes
    pub fn from_bytes_eta(bytes: &[u8], len: usize, eta: usize) -> DsaPolyVec {
        let bytes_per_poly = match eta {
            2 => 96,
            4 => 128,
            _ => panic!("Unsupported eta value: {}", eta),
        };
        let mut polys = Vec::with_capacity(len);
        for i in 0..len {
            polys.push(DsaPoly::unpack_eta(
                &bytes[i * bytes_per_poly..(i + 1) * bytes_per_poly],
                eta,
            ));
        }
        DsaPolyVec { polys }
    }

    /// Pack all polys with pack_t0
    pub fn to_bytes_t0(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for poly in &self.polys {
            result.extend(poly.pack_t0());
        }
        result
    }

    /// Unpack polynomial vector from t0-encoded bytes
    pub fn from_bytes_t0(bytes: &[u8], len: usize) -> DsaPolyVec {
        let bytes_per_poly = 416;
        let mut polys = Vec::with_capacity(len);
        for i in 0..len {
            polys.push(DsaPoly::unpack_t0(
                &bytes[i * bytes_per_poly..(i + 1) * bytes_per_poly],
            ));
        }
        DsaPolyVec { polys }
    }

    /// Pack all polys with pack_t1
    pub fn to_bytes_t1(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for poly in &self.polys {
            result.extend(poly.pack_t1());
        }
        result
    }

    /// Unpack polynomial vector from t1-encoded bytes
    pub fn from_bytes_t1(bytes: &[u8], len: usize) -> DsaPolyVec {
        let bytes_per_poly = 320;
        let mut polys = Vec::with_capacity(len);
        for i in 0..len {
            polys.push(DsaPoly::unpack_t1(
                &bytes[i * bytes_per_poly..(i + 1) * bytes_per_poly],
            ));
        }
        DsaPolyVec { polys }
    }

    /// Pack all polys with pack_z
    pub fn to_bytes_z(&self, gamma1: i32) -> Vec<u8> {
        let mut result = Vec::new();
        for poly in &self.polys {
            result.extend(poly.pack_z(gamma1));
        }
        result
    }

    /// Unpack polynomial vector from z-encoded bytes
    pub fn from_bytes_z(bytes: &[u8], len: usize, gamma1: i32) -> DsaPolyVec {
        let bytes_per_poly = match gamma1 {
            g if g == (1 << 17) => 576,
            g if g == (1 << 19) => 640,
            _ => panic!("Unsupported gamma1 value: {}", gamma1),
        };
        let mut polys = Vec::with_capacity(len);
        for i in 0..len {
            polys.push(DsaPoly::unpack_z(
                &bytes[i * bytes_per_poly..(i + 1) * bytes_per_poly],
                gamma1,
            ));
        }
        DsaPolyVec { polys }
    }

    /// Pack all polys with pack_w1
    pub fn pack_w1(&self, gamma2: i32) -> Vec<u8> {
        let mut result = Vec::new();
        for poly in &self.polys {
            result.extend(poly.pack_w1(gamma2));
        }
        result
    }
}

// ============================================================================
// DsaPolyMat
// ============================================================================

/// A k x l matrix of polynomials (k rows, each row has l polys)
pub struct DsaPolyMat {
    pub rows: Vec<DsaPolyVec>,
}

impl DsaPolyMat {
    /// Create a new zero matrix with k rows and l columns
    pub fn new(k: usize, l: usize) -> Self {
        Self {
            rows: (0..k).map(|_| DsaPolyVec::new(l)).collect(),
        }
    }

    /// Matrix-vector multiply in NTT domain: result[i] = sum_j(rows[i][j] * v[j])
    pub fn mul_vec(&self, v: &DsaPolyVec) -> DsaPolyVec {
        let k = self.rows.len();
        let mut result = DsaPolyVec::new(k);
        for i in 0..k {
            result.polys[i] = DsaPolyVec::pointwise_acc(&self.rows[i], v);
        }
        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add_sub() {
        let mut a = DsaPoly::zero();
        let mut b = DsaPoly::zero();
        for i in 0..N {
            a.coeffs[i] = i as i32;
            b.coeffs[i] = (N - i) as i32;
        }

        let c = a.add(&b);
        for i in 0..N {
            assert_eq!(c.coeffs[i], N as i32);
        }

        let d = c.sub(&b);
        for i in 0..N {
            assert_eq!(d.coeffs[i], i as i32);
        }
    }

    #[test]
    fn test_infinity_norm() {
        let mut p = DsaPoly::zero();
        p.coeffs[0] = 100;
        p.coeffs[1] = -50;
        p.coeffs[2] = 200;
        assert_eq!(p.infinity_norm(), 200);

        // Test centering: coefficient close to Q should wrap
        let mut p2 = DsaPoly::zero();
        p2.coeffs[0] = Q - 1; // Should center to 1
        assert_eq!(p2.infinity_norm(), 1);

        let mut p3 = DsaPoly::zero();
        p3.coeffs[0] = (Q - 1) / 2 + 1; // Just over half -> Q - val
        let expected = Q - ((Q - 1) / 2 + 1);
        assert_eq!(p3.infinity_norm(), expected);
    }

    #[test]
    fn test_check_norm() {
        let mut p = DsaPoly::zero();
        p.coeffs[0] = 100;
        assert!(p.check_norm(101));
        assert!(!p.check_norm(100));
        assert!(!p.check_norm(50));
    }

    #[test]
    fn test_power2round_roundtrip() {
        // Verify: t1 * 2^D + t0 == t for coefficients in [0, Q)
        let mut t = DsaPoly::zero();
        let mut val: u32 = 12345;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            t.coeffs[i] = ((val >> 16) as i32).rem_euclid(Q);
        }

        let (t1, t0) = t.power2round();

        for i in 0..N {
            let reconstructed = (t1.coeffs[i] << D) + t0.coeffs[i];
            assert_eq!(
                reconstructed, t.coeffs[i],
                "power2round roundtrip failed at index {}: t={}, t1={}, t0={}, reconstructed={}",
                i, t.coeffs[i], t1.coeffs[i], t0.coeffs[i], reconstructed
            );
        }

        // Verify t0 is centered in [-(2^(D-1)-1), 2^(D-1)]
        let half = 1i32 << (D - 1);
        for i in 0..N {
            assert!(
                t0.coeffs[i] >= -(half - 1) && t0.coeffs[i] <= half,
                "t0[{}] = {} not in [{}, {}]",
                i,
                t0.coeffs[i],
                -(half - 1),
                half
            );
        }
    }

    #[test]
    fn test_decompose_roundtrip() {
        // Verify: r1 * 2*gamma2 + r0 == r (mod Q) for both gamma2 values
        for &gamma2 in &[(Q - 1) / 88, (Q - 1) / 32] {
            let mut poly = DsaPoly::zero();
            let mut val: u32 = 54321;
            for i in 0..N {
                val = val.wrapping_mul(1103515245).wrapping_add(12345);
                poly.coeffs[i] = ((val >> 16) as i32).rem_euclid(Q);
            }

            let (r1, r0) = poly.decompose(gamma2);

            for i in 0..N {
                let r = poly.coeffs[i].rem_euclid(Q);
                let reconstructed = (r1.coeffs[i] * 2 * gamma2 + r0.coeffs[i]).rem_euclid(Q);
                assert_eq!(
                    reconstructed, r,
                    "decompose roundtrip failed at index {} (gamma2={}): r={}, r1={}, r0={}, reconstructed={}",
                    i, gamma2, r, r1.coeffs[i], r0.coeffs[i], reconstructed
                );
            }
        }
    }

    #[test]
    fn test_decompose_edge_case_q_minus_1() {
        // When r = Q-1, decompose should handle the edge case
        let gamma2 = (Q - 1) / 88;
        let mut poly = DsaPoly::zero();
        poly.coeffs[0] = Q - 1;

        let (r1, r0) = poly.decompose(gamma2);

        // r - r0 should equal Q-1, so r1 should be 0, r0 adjusted
        assert_eq!(r1.coeffs[0], 0, "r1 should be 0 for r=Q-1");
        // Verify reconstruction: r1 * 2*gamma2 + r0 mod Q should give Q-1 mod Q = Q-1
        let reconstructed = (r1.coeffs[0] * 2 * gamma2 + r0.coeffs[0]).rem_euclid(Q);
        assert_eq!(
            reconstructed,
            Q - 1,
            "decompose edge case Q-1 failed: r0={}, reconstructed={}",
            r0.coeffs[0],
            reconstructed
        );
    }

    #[test]
    fn test_pack_unpack_t1() {
        let mut poly = DsaPoly::zero();
        let mut val: u32 = 99999;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            poly.coeffs[i] = ((val >> 16) % 1024) as i32; // [0, 2^10)
        }

        let packed = poly.pack_t1();
        assert_eq!(packed.len(), 320);

        let unpacked = DsaPoly::unpack_t1(&packed);
        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "pack_t1 roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_pack_unpack_t0() {
        let mut poly = DsaPoly::zero();
        let half = 1i32 << (D - 1); // 4096
        let mut val: u32 = 77777;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            // t0 is centered in [-(2^(D-1)-1), 2^(D-1)] = [-4095, 4096]
            let range = 2 * half; // 8192
            poly.coeffs[i] = ((val >> 16) % range as u32) as i32 - (half - 1);
        }

        let packed = poly.pack_t0();
        assert_eq!(packed.len(), 416);

        let unpacked = DsaPoly::unpack_t0(&packed);
        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "pack_t0 roundtrip failed at index {}: orig={}, got={}",
                i, poly.coeffs[i], unpacked.coeffs[i]
            );
        }
    }

    #[test]
    fn test_pack_unpack_eta2() {
        let mut poly = DsaPoly::zero();
        let mut val: u32 = 11111;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            poly.coeffs[i] = ((val >> 16) % 5) as i32 - 2; // [-2, 2]
        }

        let packed = poly.pack_eta(2);
        assert_eq!(packed.len(), 96);

        let unpacked = DsaPoly::unpack_eta(&packed, 2);
        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "pack_eta(2) roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_pack_unpack_eta4() {
        let mut poly = DsaPoly::zero();
        let mut val: u32 = 22222;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            poly.coeffs[i] = ((val >> 16) % 9) as i32 - 4; // [-4, 4]
        }

        let packed = poly.pack_eta(4);
        assert_eq!(packed.len(), 128);

        let unpacked = DsaPoly::unpack_eta(&packed, 4);
        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "pack_eta(4) roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_pack_unpack_z_gamma1_2_17() {
        let gamma1 = 1i32 << 17; // 131072
        let mut poly = DsaPoly::zero();
        let mut val: u32 = 33333;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            // z in [-(gamma1-1), gamma1]
            let range = 2 * gamma1;
            poly.coeffs[i] = ((val >> 16) % range as u32) as i32 - (gamma1 - 1);
        }

        let packed = poly.pack_z(gamma1);
        assert_eq!(packed.len(), 576);

        let unpacked = DsaPoly::unpack_z(&packed, gamma1);
        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "pack_z(2^17) roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_pack_unpack_z_gamma1_2_19() {
        let gamma1 = 1i32 << 19; // 524288
        let mut poly = DsaPoly::zero();
        let mut val: u32 = 44444;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            // z in [-(gamma1-1), gamma1]
            let range = 2 * gamma1;
            poly.coeffs[i] = ((val >> 16) % range as u32) as i32 - (gamma1 - 1);
        }

        let packed = poly.pack_z(gamma1);
        assert_eq!(packed.len(), 640);

        let unpacked = DsaPoly::unpack_z(&packed, gamma1);
        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "pack_z(2^19) roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_pack_w1_gamma2_q88() {
        let gamma2 = (Q - 1) / 88; // 95232
        let mut poly = DsaPoly::zero();
        let mut val: u32 = 55555;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            poly.coeffs[i] = ((val >> 16) % 44) as i32; // [0, 43]
        }

        let packed = poly.pack_w1(gamma2);
        assert_eq!(packed.len(), 192);

        // Verify we can unpack manually (6 bits per coeff)
        for i in 0..N / 4 {
            let b0 = packed[3 * i] as u32;
            let b1 = packed[3 * i + 1] as u32;
            let b2 = packed[3 * i + 2] as u32;

            let c0 = (b0 & 0x3F) as i32;
            let c1 = (((b0 >> 6) | (b1 << 2)) & 0x3F) as i32;
            let c2 = (((b1 >> 4) | (b2 << 4)) & 0x3F) as i32;
            let c3 = ((b2 >> 2) & 0x3F) as i32;

            assert_eq!(poly.coeffs[4 * i], c0, "w1 pack (q/88) at {}", 4 * i);
            assert_eq!(poly.coeffs[4 * i + 1], c1, "w1 pack (q/88) at {}", 4 * i + 1);
            assert_eq!(poly.coeffs[4 * i + 2], c2, "w1 pack (q/88) at {}", 4 * i + 2);
            assert_eq!(poly.coeffs[4 * i + 3], c3, "w1 pack (q/88) at {}", 4 * i + 3);
        }
    }

    #[test]
    fn test_pack_w1_gamma2_q32() {
        let gamma2 = (Q - 1) / 32; // 261888
        let mut poly = DsaPoly::zero();
        let mut val: u32 = 66666;
        for i in 0..N {
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            poly.coeffs[i] = ((val >> 16) % 16) as i32; // [0, 15]
        }

        let packed = poly.pack_w1(gamma2);
        assert_eq!(packed.len(), 128);

        // Verify we can unpack manually (4 bits per coeff)
        for i in 0..N / 2 {
            let c0 = (packed[i] & 0x0F) as i32;
            let c1 = (packed[i] >> 4) as i32;
            assert_eq!(poly.coeffs[2 * i], c0, "w1 pack (q/32) at {}", 2 * i);
            assert_eq!(poly.coeffs[2 * i + 1], c1, "w1 pack (q/32) at {}", 2 * i + 1);
        }
    }

    #[test]
    fn test_polyvec_add_sub() {
        let len = 4;
        let mut a = DsaPolyVec::new(len);
        let mut b = DsaPolyVec::new(len);

        for p in 0..len {
            for i in 0..N {
                a.polys[p].coeffs[i] = ((p * 100 + i * 7) % Q as usize) as i32;
                b.polys[p].coeffs[i] = ((p * 200 + i * 11 + 50) % Q as usize) as i32;
            }
        }

        let sum = a.add(&b);
        let diff = sum.sub(&b);

        for p in 0..len {
            for i in 0..N {
                assert_eq!(
                    diff.polys[p].coeffs[i], a.polys[p].coeffs[i],
                    "(a+b)-b != a at poly {}, index {}",
                    p, i
                );
            }
        }
    }

    #[test]
    fn test_polyvec_check_norm() {
        let mut v = DsaPolyVec::new(3);
        v.polys[0].coeffs[0] = 100;
        v.polys[1].coeffs[0] = 200;
        v.polys[2].coeffs[0] = 50;

        assert!(v.check_norm(201));
        assert!(!v.check_norm(200));
        assert!(!v.check_norm(100));
    }

    #[test]
    fn test_polyvec_bytes_eta_roundtrip() {
        let len = 4;
        for &eta in &[2usize, 4] {
            let mut v = DsaPolyVec::new(len);
            let mut val: u32 = 88888;
            let range = 2 * eta + 1;
            for p in 0..len {
                for i in 0..N {
                    val = val.wrapping_mul(1103515245).wrapping_add(12345);
                    v.polys[p].coeffs[i] = ((val >> 16) % range as u32) as i32 - eta as i32;
                }
            }

            let bytes = v.to_bytes_eta(eta);
            let unpacked = DsaPolyVec::from_bytes_eta(&bytes, len, eta);

            for p in 0..len {
                for i in 0..N {
                    assert_eq!(
                        v.polys[p].coeffs[i], unpacked.polys[p].coeffs[i],
                        "polyvec eta={} roundtrip failed at poly {}, index {}",
                        eta, p, i
                    );
                }
            }
        }
    }

    #[test]
    fn test_polyvec_bytes_t0_roundtrip() {
        let len = 4;
        let half = 1i32 << (D - 1);
        let mut v = DsaPolyVec::new(len);
        let mut val: u32 = 11223;
        for p in 0..len {
            for i in 0..N {
                val = val.wrapping_mul(1103515245).wrapping_add(12345);
                let range = 2 * half;
                v.polys[p].coeffs[i] = ((val >> 16) % range as u32) as i32 - (half - 1);
            }
        }

        let bytes = v.to_bytes_t0();
        let unpacked = DsaPolyVec::from_bytes_t0(&bytes, len);

        for p in 0..len {
            for i in 0..N {
                assert_eq!(
                    v.polys[p].coeffs[i], unpacked.polys[p].coeffs[i],
                    "polyvec t0 roundtrip failed at poly {}, index {}",
                    p, i
                );
            }
        }
    }

    #[test]
    fn test_polyvec_bytes_t1_roundtrip() {
        let len = 4;
        let mut v = DsaPolyVec::new(len);
        let mut val: u32 = 33445;
        for p in 0..len {
            for i in 0..N {
                val = val.wrapping_mul(1103515245).wrapping_add(12345);
                v.polys[p].coeffs[i] = ((val >> 16) % 1024) as i32;
            }
        }

        let bytes = v.to_bytes_t1();
        let unpacked = DsaPolyVec::from_bytes_t1(&bytes, len);

        for p in 0..len {
            for i in 0..N {
                assert_eq!(
                    v.polys[p].coeffs[i], unpacked.polys[p].coeffs[i],
                    "polyvec t1 roundtrip failed at poly {}, index {}",
                    p, i
                );
            }
        }
    }

    #[test]
    fn test_polyvec_bytes_z_roundtrip() {
        for &gamma1 in &[1i32 << 17, 1i32 << 19] {
            let len = 4;
            let mut v = DsaPolyVec::new(len);
            let mut val: u32 = 55667;
            for p in 0..len {
                for i in 0..N {
                    val = val.wrapping_mul(1103515245).wrapping_add(12345);
                    let range = 2 * gamma1;
                    v.polys[p].coeffs[i] =
                        ((val >> 16) % range as u32) as i32 - (gamma1 - 1);
                }
            }

            let bytes = v.to_bytes_z(gamma1);
            let unpacked = DsaPolyVec::from_bytes_z(&bytes, len, gamma1);

            for p in 0..len {
                for i in 0..N {
                    assert_eq!(
                        v.polys[p].coeffs[i], unpacked.polys[p].coeffs[i],
                        "polyvec z (gamma1={}) roundtrip failed at poly {}, index {}",
                        gamma1, p, i
                    );
                }
            }
        }
    }

    #[test]
    fn test_make_hint_use_hint() {
        // Key property: use_hint(r+z, hint) == high_bits(r+z)
        // where hint = make_hint(z, r)
        for &gamma2 in &[(Q - 1) / 88, (Q - 1) / 32] {
            let mut r = DsaPoly::zero();
            let mut z = DsaPoly::zero();
            let mut val: u32 = 77889;
            for i in 0..N {
                val = val.wrapping_mul(1103515245).wrapping_add(12345);
                r.coeffs[i] = ((val >> 16) as i32).rem_euclid(Q);
                val = val.wrapping_mul(1103515245).wrapping_add(12345);
                // z is small so that r+z doesn't wrap badly
                z.coeffs[i] = ((val >> 16) % (2 * gamma2 as u32)) as i32 - gamma2;
            }

            let (hint, count) = DsaPoly::make_hint(&z, &r, gamma2);

            // Verify count matches number of 1s
            let actual_count: usize = hint.coeffs.iter().filter(|&&c| c == 1).count();
            assert_eq!(count, actual_count, "make_hint count mismatch");

            // Verify use_hint gives the correct high bits of r+z
            let mut r_plus_z = DsaPoly::zero();
            for i in 0..N {
                r_plus_z.coeffs[i] = (r.coeffs[i] + z.coeffs[i]).rem_euclid(Q);
            }

            let result = r.use_hint(&hint, gamma2);
            let expected = r_plus_z.high_bits(gamma2);

            for i in 0..N {
                assert_eq!(
                    result.coeffs[i], expected.coeffs[i],
                    "use_hint mismatch at index {} (gamma2={}): hint={}, r={}, z={}, r+z={}",
                    i, gamma2, hint.coeffs[i], r.coeffs[i], z.coeffs[i], r_plus_z.coeffs[i]
                );
            }
        }
    }

    #[test]
    fn test_dsapolymat_mul_vec() {
        // Test matrix-vector multiplication with zero vector gives zero result
        let k = 4;
        let l = 4;
        let mat = DsaPolyMat::new(k, l);
        let v = DsaPolyVec::new(l);

        let result = mat.mul_vec(&v);
        assert_eq!(result.len(), k);
        for p in 0..k {
            for i in 0..N {
                assert_eq!(result.polys[p].coeffs[i], 0);
            }
        }
    }

    #[test]
    fn test_reduce() {
        let mut p = DsaPoly::zero();
        // Set some large coefficients
        p.coeffs[0] = Q + 100;
        p.coeffs[1] = 2 * Q + 50;
        p.coeffs[2] = -100;

        p.reduce();

        // All coefficients should be in [0, Q)
        for i in 0..N {
            assert!(
                p.coeffs[i] >= 0 && p.coeffs[i] < Q,
                "reduce() failed at index {}: got {}",
                i, p.coeffs[i]
            );
        }

        // Check specific values for congruence
        assert_eq!(p.coeffs[0], 100);
        assert_eq!(p.coeffs[1], 50);
        assert_eq!(p.coeffs[2], Q - 100);
    }

    #[test]
    fn test_ntt_roundtrip_dsapoly() {
        // Verify NTT roundtrip works at the DsaPoly level
        let mut p = DsaPoly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32 * 37) % Q;
        }
        let original = p.clone();

        p.to_ntt();
        p.from_ntt();

        // NTT roundtrip introduces a Montgomery factor R = 2^32 mod Q = 4193792
        const R_MOD_Q: i64 = 4193792;
        for i in 0..N {
            let expected = ((original.coeffs[i] as i64) * R_MOD_Q).rem_euclid(Q as i64) as i32;
            let got = p.coeffs[i].rem_euclid(Q);
            assert_eq!(
                got, expected,
                "DsaPoly NTT roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_pointwise_mul_zero() {
        let mut a = DsaPoly::zero();
        let b = DsaPoly::zero();
        for i in 0..N {
            a.coeffs[i] = (i as i32 * 13) % Q;
        }
        a.to_ntt();

        let c = a.pointwise_mul(&b);
        for i in 0..N {
            assert_eq!(
                c.coeffs[i].rem_euclid(Q),
                0,
                "pointwise_mul with zero non-zero at index {}",
                i
            );
        }
    }

    #[test]
    fn test_polyvec_pointwise_acc() {
        // Test that pointwise_acc of zero vectors gives zero
        let len = 5;
        let a = DsaPolyVec::new(len);
        let b = DsaPolyVec::new(len);
        let result = DsaPolyVec::pointwise_acc(&a, &b);
        for i in 0..N {
            assert_eq!(result.coeffs[i], 0);
        }
    }

    #[test]
    fn test_power2round_specific_values() {
        // Test power2round with specific known values
        let mut p = DsaPoly::zero();
        p.coeffs[0] = 0;
        p.coeffs[1] = 1 << D; // Exactly 2^D
        p.coeffs[2] = (1 << D) - 1; // 2^D - 1

        let (t1, t0) = p.power2round();

        // r=0: t1 = (0 + 4095) >> 13 = 0, t0 = 0
        assert_eq!(t1.coeffs[0], 0);
        assert_eq!(t0.coeffs[0], 0);

        // r=8192: t1 = (8192 + 4095) >> 13 = 12287 >> 13 = 1, t0 = 8192 - 8192 = 0
        assert_eq!(t1.coeffs[1], 1);
        assert_eq!(t0.coeffs[1], 0);

        // r=8191: t1 = (8191 + 4095) >> 13 = 12286 >> 13 = 1, t0 = 8191 - 8192 = -1
        assert_eq!(t1.coeffs[2], 1);
        assert_eq!(t0.coeffs[2], -1);
    }

    #[test]
    fn test_decompose_low_bits_range() {
        // Verify r0 is in the correct range: |r0| <= gamma2
        for &gamma2 in &[(Q - 1) / 88, (Q - 1) / 32] {
            let mut poly = DsaPoly::zero();
            let mut val: u32 = 98765;
            for i in 0..N {
                val = val.wrapping_mul(1103515245).wrapping_add(12345);
                poly.coeffs[i] = ((val >> 16) as i32).rem_euclid(Q);
            }

            let (_, r0) = poly.decompose(gamma2);

            for i in 0..N {
                assert!(
                    r0.coeffs[i].abs() <= gamma2,
                    "decompose r0[{}] = {} out of range (gamma2={})",
                    i, r0.coeffs[i], gamma2
                );
            }
        }
    }
}
