//! Polynomial arithmetic for lattice-based cryptography (FIPS 203)
//!
//! Implements polynomial operations in the ring R_q = Z_q[X]/(X^n + 1)
//! where q = 3329 for ML-KEM and n = 256.
//!
//! Key operations and their FIPS 203 references:
//! - SampleNTT (Algorithm 7): rejection sampling from XOF to sample A
//! - SamplePolyCBD (Algorithm 8): centered binomial distribution sampling
//! - ByteEncode / ByteDecode (Algorithms 5/6): 12-bit coefficient encoding
//! - Compress / Decompress (Section 4.2.1): lossy coefficient compression

use crate::primitives::ntt::{
    mlkem_barrett_reduce, mlkem_basemul, mlkem_ntt, mlkem_ntt_inv, mlkem_to_mont, MLKEM_Q, N,
};
use crate::primitives::sha3::{prf, xof};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A polynomial in R_q with coefficients in [0, q)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self { coeffs: [0i16; N] }
    }

    /// Create a polynomial from coefficients
    pub fn from_coeffs(coeffs: [i16; N]) -> Self {
        Self { coeffs }
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0i16; N];
        for i in 0..N {
            result[i] = self.coeffs[i] + other.coeffs[i];
        }
        Self { coeffs: result }
    }

    /// Subtract two polynomials
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0i16; N];
        for i in 0..N {
            result[i] = self.coeffs[i] - other.coeffs[i];
        }
        Self { coeffs: result }
    }

    /// Fully reduce all coefficients to the canonical range [0, q).
    ///
    /// Applies Barrett reduction to get close to [0, q), then uses
    /// conditional addition/subtraction (via arithmetic right shift
    /// to extract the sign bit) to normalize:
    ///   1. Add q if coefficient is negative (sign bit is 1)
    ///   2. Subtract q unconditionally
    ///   3. Add q again if result went negative
    /// This guarantees all coefficients end up in [0, q).
    pub fn reduce(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            // Barrett reduce first to get close to [0, q)
            *coeff = mlkem_barrett_reduce(*coeff as i32);
            // Conditional subtraction/addition to normalize to [0, q)
            let mut c = *coeff;
            c += (c >> 15) & (MLKEM_Q as i16); // add q if negative
            c -= MLKEM_Q as i16;
            c += (c >> 15) & (MLKEM_Q as i16); // add q if negative
            *coeff = c;
        }
    }

    /// Convert to NTT representation
    pub fn to_ntt(&mut self) {
        mlkem_ntt(&mut self.coeffs);
    }

    /// Convert from NTT representation
    pub fn from_ntt(&mut self) {
        mlkem_ntt_inv(&mut self.coeffs);
    }

    /// Convert all coefficients to Montgomery form by multiplying each by R mod q.
    ///
    /// Internally calls fqmul(coeff, R^2 mod q) which computes
    /// coeff * R^2 * R^{-1} = coeff * R mod q.
    ///
    /// This is used after basemul-based products (e.g., A * s) to cancel the
    /// extra R^{-1} factor that basemul introduces. After to_mont(), the result
    /// is in proper NTT form with the correct Montgomery scaling.
    pub fn to_mont(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = mlkem_to_mont(*coeff);
        }
    }

    /// Multiply two polynomials in NTT domain
    pub fn basemul(&self, other: &Self) -> Self {
        Self {
            coeffs: mlkem_basemul(&self.coeffs, &other.coeffs),
        }
    }

    /// Sample a polynomial using centered binomial distribution (CBD).
    ///
    /// FIPS 203 Algorithm 8 (SamplePolyCBD_eta).
    ///
    /// Uses PRF(seed, nonce) to generate pseudorandom bytes, then applies
    /// the CBD_eta distribution. Each coefficient is the difference of two
    /// sums of eta random bits, giving values in [-eta, eta].
    /// - eta=2: coefficients in [-2, 2], uses 4 bits per coefficient
    /// - eta=3: coefficients in [-3, 3], uses 6 bits per coefficient
    pub fn sample_cbd(seed: &[u8], nonce: u8, eta: usize) -> Self {
        let mut poly = Self::zero();
        let bytes_needed = 64 * eta;
        let buf = prf(seed, nonce, bytes_needed);

        match eta {
            2 => sample_cbd2(&buf, &mut poly.coeffs),
            3 => sample_cbd3(&buf, &mut poly.coeffs),
            _ => panic!("Unsupported eta value: {}", eta),
        }

        poly
    }

    /// Sample a polynomial uniformly from R_q using rejection sampling.
    ///
    /// FIPS 203 Algorithm 7 (SampleNTT).
    ///
    /// Generates coefficients by reading 3 bytes at a time from XOF(seed || i || j)
    /// and extracting two 12-bit candidate values d1 and d2. Each candidate is
    /// accepted if d1 < q (or d2 < q), otherwise rejected. This rejection sampling
    /// ensures a uniform distribution over [0, q).
    ///
    /// Used for sampling the public matrix A in NTT form.
    pub fn sample_uniform(seed: &[u8], i: u8, j: u8) -> Self {
        let mut poly = Self::zero();
        let mut xof = xof(seed, i, j);

        let mut ctr = 0usize;
        while ctr < N {
            let mut buf = [0u8; 3];
            xof.read(&mut buf);

            let d1 = ((buf[0] as u16) | ((buf[1] as u16 & 0x0F) << 8)) as i16;
            let d2 = (((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4)) as i16;

            if d1 < MLKEM_Q as i16 {
                poly.coeffs[ctr] = d1;
                ctr += 1;
            }
            if ctr < N && d2 < MLKEM_Q as i16 {
                poly.coeffs[ctr] = d2;
                ctr += 1;
            }
        }

        poly
    }

    /// Compress polynomial coefficients to d bits.
    ///
    /// FIPS 203 Section 4.2.1: Compress_q(x, d) = round(2^d / q * x) mod 2^d.
    ///
    /// This is a lossy operation that maps each coefficient from [0, q) to [0, 2^d).
    /// The rounding minimizes the error |Decompress(Compress(x)) - x|.
    pub fn compress(&self, d: usize) -> Vec<u8> {
        let mut result = Vec::new();

        match d {
            1 => {
                // Pack 8 coefficients per byte
                for chunk in self.coeffs.chunks(8) {
                    let mut byte = 0u8;
                    for (i, &coeff) in chunk.iter().enumerate() {
                        let compressed = compress_coeff(coeff, 1);
                        byte |= (compressed as u8) << i;
                    }
                    result.push(byte);
                }
            }
            4 => {
                // Pack 2 coefficients per byte
                for chunk in self.coeffs.chunks(2) {
                    let c0 = compress_coeff(chunk[0], 4) as u8;
                    let c1 = compress_coeff(chunk[1], 4) as u8;
                    result.push(c0 | (c1 << 4));
                }
            }
            5 => {
                // Pack 8 coefficients into 5 bytes
                for chunk in self.coeffs.chunks(8) {
                    let mut vals = [0u8; 8];
                    for (i, &coeff) in chunk.iter().enumerate() {
                        vals[i] = compress_coeff(coeff, 5) as u8;
                    }
                    result.push(vals[0] | (vals[1] << 5));
                    result.push((vals[1] >> 3) | (vals[2] << 2) | (vals[3] << 7));
                    result.push((vals[3] >> 1) | (vals[4] << 4));
                    result.push((vals[4] >> 4) | (vals[5] << 1) | (vals[6] << 6));
                    result.push((vals[6] >> 2) | (vals[7] << 3));
                }
            }
            10 => {
                // Pack 4 coefficients into 5 bytes
                for chunk in self.coeffs.chunks(4) {
                    let mut vals = [0u16; 4];
                    for (i, &coeff) in chunk.iter().enumerate() {
                        vals[i] = compress_coeff(coeff, 10) as u16;
                    }
                    result.push(vals[0] as u8);
                    result.push(((vals[0] >> 8) | (vals[1] << 2)) as u8);
                    result.push(((vals[1] >> 6) | (vals[2] << 4)) as u8);
                    result.push(((vals[2] >> 4) | (vals[3] << 6)) as u8);
                    result.push((vals[3] >> 2) as u8);
                }
            }
            11 => {
                // Pack 8 coefficients into 11 bytes
                for chunk in self.coeffs.chunks(8) {
                    let mut vals = [0u16; 8];
                    for (i, &coeff) in chunk.iter().enumerate() {
                        vals[i] = compress_coeff(coeff, 11) as u16;
                    }
                    result.push(vals[0] as u8);
                    result.push(((vals[0] >> 8) | (vals[1] << 3)) as u8);
                    result.push(((vals[1] >> 5) | (vals[2] << 6)) as u8);
                    result.push((vals[2] >> 2) as u8);
                    result.push(((vals[2] >> 10) | (vals[3] << 1)) as u8);
                    result.push(((vals[3] >> 7) | (vals[4] << 4)) as u8);
                    result.push(((vals[4] >> 4) | (vals[5] << 7)) as u8);
                    result.push((vals[5] >> 1) as u8);
                    result.push(((vals[5] >> 9) | (vals[6] << 2)) as u8);
                    result.push(((vals[6] >> 6) | (vals[7] << 5)) as u8);
                    result.push((vals[7] >> 3) as u8);
                }
            }
            _ => panic!("Unsupported compression factor d={}", d),
        }

        result
    }

    /// Decompress polynomial coefficients from d bits.
    ///
    /// FIPS 203 Section 4.2.1: Decompress_q(x, d) = round(q / 2^d * x).
    ///
    /// Inverse of Compress (approximately). Maps each d-bit value back to
    /// a coefficient in [0, q). The round-trip error is bounded by
    /// |Decompress(Compress(x)) - x| <= ceil(q / 2^{d+1}).
    pub fn decompress(data: &[u8], d: usize) -> Self {
        let mut poly = Self::zero();

        match d {
            1 => {
                for (i, &byte) in data.iter().enumerate() {
                    for j in 0..8 {
                        let idx = i * 8 + j;
                        if idx < N {
                            poly.coeffs[idx] = decompress_coeff(((byte >> j) & 1) as i16, 1);
                        }
                    }
                }
            }
            4 => {
                for (i, &byte) in data.iter().enumerate() {
                    let idx = i * 2;
                    if idx < N {
                        poly.coeffs[idx] = decompress_coeff((byte & 0x0F) as i16, 4);
                    }
                    if idx + 1 < N {
                        poly.coeffs[idx + 1] = decompress_coeff((byte >> 4) as i16, 4);
                    }
                }
            }
            5 => {
                let mut idx = 0;
                for chunk in data.chunks(5) {
                    if chunk.len() < 5 || idx >= N {
                        break;
                    }
                    let vals = [
                        chunk[0] & 0x1F,
                        ((chunk[0] >> 5) | (chunk[1] << 3)) & 0x1F,
                        (chunk[1] >> 2) & 0x1F,
                        ((chunk[1] >> 7) | (chunk[2] << 1)) & 0x1F,
                        ((chunk[2] >> 4) | (chunk[3] << 4)) & 0x1F,
                        (chunk[3] >> 1) & 0x1F,
                        ((chunk[3] >> 6) | (chunk[4] << 2)) & 0x1F,
                        chunk[4] >> 3,
                    ];
                    for v in vals {
                        if idx < N {
                            poly.coeffs[idx] = decompress_coeff(v as i16, 5);
                            idx += 1;
                        }
                    }
                }
            }
            10 => {
                let mut idx = 0;
                for chunk in data.chunks(5) {
                    if chunk.len() < 5 || idx >= N {
                        break;
                    }
                    let vals = [
                        (chunk[0] as u16) | ((chunk[1] as u16 & 0x03) << 8),
                        ((chunk[1] as u16) >> 2) | ((chunk[2] as u16 & 0x0F) << 6),
                        ((chunk[2] as u16) >> 4) | ((chunk[3] as u16 & 0x3F) << 4),
                        ((chunk[3] as u16) >> 6) | ((chunk[4] as u16) << 2),
                    ];
                    for v in vals {
                        if idx < N {
                            poly.coeffs[idx] = decompress_coeff((v & 0x3FF) as i16, 10);
                            idx += 1;
                        }
                    }
                }
            }
            11 => {
                let mut idx = 0;
                for chunk in data.chunks(11) {
                    if chunk.len() < 11 || idx >= N {
                        break;
                    }
                    let vals = [
                        (chunk[0] as u16) | ((chunk[1] as u16 & 0x07) << 8),
                        ((chunk[1] as u16) >> 3) | ((chunk[2] as u16 & 0x3F) << 5),
                        ((chunk[2] as u16) >> 6) | ((chunk[3] as u16) << 2) | ((chunk[4] as u16 & 0x01) << 10),
                        ((chunk[4] as u16) >> 1) | ((chunk[5] as u16 & 0x0F) << 7),
                        ((chunk[5] as u16) >> 4) | ((chunk[6] as u16 & 0x7F) << 4),
                        ((chunk[6] as u16) >> 7) | ((chunk[7] as u16) << 1) | ((chunk[8] as u16 & 0x03) << 9),
                        ((chunk[8] as u16) >> 2) | ((chunk[9] as u16 & 0x1F) << 6),
                        ((chunk[9] as u16) >> 5) | ((chunk[10] as u16) << 3),
                    ];
                    for v in vals {
                        if idx < N {
                            poly.coeffs[idx] = decompress_coeff((v & 0x7FF) as i16, 11);
                            idx += 1;
                        }
                    }
                }
            }
            _ => panic!("Unsupported decompression factor d={}", d),
        }

        poly
    }

    /// Encode polynomial to bytes using 12 bits per coefficient.
    ///
    /// FIPS 203 ByteEncode_12 (Algorithm 5 with d=12): packs each pair of
    /// 12-bit coefficients (c0, c1) into 3 bytes as:
    ///     byte0 = c0[7:0]
    ///     byte1 = c0[11:8] | c1[3:0] << 4
    ///     byte2 = c1[11:4]
    ///
    /// Produces 384 bytes for a 256-coefficient polynomial.
    pub fn to_bytes(&self) -> [u8; 384] {
        let mut result = [0u8; 384];
        for i in 0..N / 2 {
            let c0 = self.coeffs[2 * i] as u16;
            let c1 = self.coeffs[2 * i + 1] as u16;
            result[3 * i] = c0 as u8;
            result[3 * i + 1] = ((c0 >> 8) | (c1 << 4)) as u8;
            result[3 * i + 2] = (c1 >> 4) as u8;
        }
        result
    }

    /// Decode polynomial from bytes using 12 bits per coefficient.
    ///
    /// FIPS 203 ByteDecode_12 (Algorithm 6 with d=12): unpacks each group
    /// of 3 bytes into two 12-bit coefficients. Inverse of `to_bytes`.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut poly = Self::zero();
        for i in 0..N / 2 {
            poly.coeffs[2 * i] = ((data[3 * i] as u16) | ((data[3 * i + 1] as u16 & 0x0F) << 8)) as i16;
            poly.coeffs[2 * i + 1] = (((data[3 * i + 1] as u16) >> 4) | ((data[3 * i + 2] as u16) << 4)) as i16;
        }
        poly
    }
}

/// Compress a single coefficient to d bits.
///
/// FIPS 203 Section 4.2.1: Compress_q(x, d) = round(2^d / q * x) mod 2^d.
/// Implemented as: ((x << d) + q/2) / q, which rounds to nearest integer.
#[inline]
fn compress_coeff(x: i16, d: usize) -> i32 {
    // Normalize to [0, q)
    let x = (x as i32).rem_euclid(MLKEM_Q);
    let two_d = 1i32 << d;
    // Compute round((2^d / q) * x) mod 2^d
    ((((x as i64) << d) + (MLKEM_Q as i64 / 2)) / (MLKEM_Q as i64)) as i32 & (two_d - 1)
}

/// Decompress a d-bit value back to a coefficient.
///
/// FIPS 203 Section 4.2.1: Decompress_q(x, d) = round(q / 2^d * x).
/// Implemented as: (x * q + 2^{d-1}) / 2^d, which rounds to nearest integer.
#[inline]
fn decompress_coeff(x: i16, d: usize) -> i16 {
    let x = x as i32;
    let q = MLKEM_Q;
    let two_d = 1i32 << d;
    // Compute round((q / 2^d) * x)
    (((x * q) + (two_d / 2)) / two_d) as i16
}

/// Sample coefficients using CBD with eta=2.
///
/// FIPS 203 Algorithm 8 (SamplePolyCBD_eta) with eta=2.
/// Reads 4 bytes at a time, extracts pairs of 2-bit sums, and computes
/// their difference to produce coefficients in [-2, 2].
fn sample_cbd2(buf: &[u8], coeffs: &mut [i16; N]) {
    for i in 0..N / 8 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);

        let d = t & 0x55555555;
        let e = (t >> 1) & 0x55555555;
        let f = d + e;

        for j in 0..8 {
            let a = ((f >> (4 * j)) & 0x3) as i16;
            let b = ((f >> (4 * j + 2)) & 0x3) as i16;
            coeffs[8 * i + j] = a - b;
        }
    }
}

/// Sample coefficients using CBD with eta=3.
///
/// FIPS 203 Algorithm 8 (SamplePolyCBD_eta) with eta=3.
/// Reads 3 bytes at a time, extracts triples of bits, sums them, and
/// computes their difference to produce coefficients in [-3, 3].
fn sample_cbd3(buf: &[u8], coeffs: &mut [i16; N]) {
    for i in 0..N / 4 {
        let t = u32::from_le_bytes([buf[3 * i], buf[3 * i + 1], buf[3 * i + 2], 0]);

        let d = t & 0x00249249;
        let e = (t >> 1) & 0x00249249;
        let f = (t >> 2) & 0x00249249;
        let g = d + e + f;

        for j in 0..4 {
            let a = ((g >> (6 * j)) & 0x7) as i16;
            let b = ((g >> (6 * j + 3)) & 0x7) as i16;
            coeffs[4 * i + j] = a - b;
        }
    }
}

/// A vector of k polynomials
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PolyVec {
    pub polys: Vec<Poly>,
}

impl PolyVec {
    /// Create a new polynomial vector of size k
    pub fn new(k: usize) -> Self {
        Self {
            polys: vec![Poly::zero(); k],
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
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        Self {
            polys: self
                .polys
                .iter()
                .zip(other.polys.iter())
                .map(|(a, b)| a.add(b))
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

    /// Convert all polynomials to Montgomery form
    pub fn to_mont(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.to_mont();
        }
    }

    /// Reduce all coefficients
    pub fn reduce(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.reduce();
        }
    }

    /// Inner product of two polynomial vectors in NTT domain
    pub fn inner_product(&self, other: &Self) -> Poly {
        assert_eq!(self.len(), other.len());
        let mut result = Poly::zero();
        for (a, b) in self.polys.iter().zip(other.polys.iter()) {
            let prod = a.basemul(b);
            result = result.add(&prod);
        }
        result
    }

    /// Encode to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.len() * 384);
        for poly in &self.polys {
            result.extend_from_slice(&poly.to_bytes());
        }
        result
    }

    /// Decode from bytes
    pub fn from_bytes(data: &[u8], k: usize) -> Self {
        let mut polys = Vec::with_capacity(k);
        for i in 0..k {
            polys.push(Poly::from_bytes(&data[i * 384..(i + 1) * 384]));
        }
        Self { polys }
    }

    /// Compress polynomial vector
    pub fn compress(&self, d: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for poly in &self.polys {
            result.extend(poly.compress(d));
        }
        result
    }

    /// Decompress polynomial vector
    pub fn decompress(data: &[u8], k: usize, d: usize) -> Self {
        let bytes_per_poly = N * d / 8;
        let mut polys = Vec::with_capacity(k);
        for i in 0..k {
            polys.push(Poly::decompress(
                &data[i * bytes_per_poly..(i + 1) * bytes_per_poly],
                d,
            ));
        }
        Self { polys }
    }
}

/// A k x k matrix of polynomials
pub struct PolyMat {
    pub rows: Vec<PolyVec>,
}

impl PolyMat {
    /// Create a new k x k matrix
    pub fn new(k: usize) -> Self {
        Self {
            rows: vec![PolyVec::new(k); k],
        }
    }

    /// Sample matrix A from seed (already in NTT form)
    pub fn sample_uniform(seed: &[u8], k: usize, transpose: bool) -> Self {
        let mut mat = Self::new(k);
        for i in 0..k {
            for j in 0..k {
                let (ii, jj) = if transpose { (j, i) } else { (i, j) };
                mat.rows[i].polys[j] = Poly::sample_uniform(seed, ii as u8, jj as u8);
            }
        }
        mat
    }

    /// Multiply matrix by vector (matrix and vector must be in NTT form)
    pub fn mul_vec(&self, v: &PolyVec) -> PolyVec {
        let k = self.rows.len();
        let mut result = PolyVec::new(k);
        for i in 0..k {
            result.polys[i] = self.rows[i].inner_product(v);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add_sub() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = i as i16;
            b.coeffs[i] = (N - i) as i16;
        }

        let c = a.add(&b);
        for i in 0..N {
            assert_eq!(c.coeffs[i], N as i16);
        }

        let d = c.sub(&b);
        for i in 0..N {
            assert_eq!(d.coeffs[i], i as i16);
        }
    }

    #[test]
    fn test_compress_decompress() {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = ((i * 13) % MLKEM_Q as usize) as i16;
        }

        for d in [1, 4, 5, 10, 11] {
            let compressed = poly.compress(d);
            let decompressed = Poly::decompress(&compressed, d);

            // Check that decompression is close to original
            for i in 0..N {
                let orig = poly.coeffs[i] as i32;
                let dec = decompressed.coeffs[i] as i32;
                // The error should be bounded by q / 2^(d+1)
                let max_error = (MLKEM_Q + (1 << d)) / (1 << (d + 1));
                let diff = (orig - dec).rem_euclid(MLKEM_Q);
                let error = diff.min(MLKEM_Q - diff);
                assert!(
                    error <= max_error,
                    "d={}, i={}, orig={}, dec={}, error={}, max_error={}",
                    d,
                    i,
                    orig,
                    dec,
                    error,
                    max_error,
                );
            }
        }
    }

    #[test]
    fn test_byte_encoding() {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = ((i * 17) % MLKEM_Q as usize) as i16;
        }

        let bytes = poly.to_bytes();
        let decoded = Poly::from_bytes(&bytes);

        for i in 0..N {
            assert_eq!(poly.coeffs[i], decoded.coeffs[i]);
        }
    }

    #[test]
    fn test_sample_cbd() {
        let seed = [0u8; 32];
        let poly = Poly::sample_cbd(&seed, 0, 2);

        // CBD with eta=2 should produce coefficients in [-2, 2]
        for &coeff in &poly.coeffs {
            assert!(coeff >= -2 && coeff <= 2);
        }
    }

    #[test]
    fn test_sample_uniform() {
        let seed = [0u8; 32];
        let poly = Poly::sample_uniform(&seed, 0, 0);

        // All coefficients should be in [0, q)
        for &coeff in &poly.coeffs {
            assert!(coeff >= 0 && coeff < MLKEM_Q as i16);
        }
    }

    #[test]
    fn test_poly_reduce_normalizes() {
        // Coefficients in [-q, 2q] should all map to [0, q) after reduce()
        let mut poly = Poly::zero();
        let test_values: [i16; 8] = [
            0, 1, -1, MLKEM_Q as i16 - 1, -(MLKEM_Q as i16),
            MLKEM_Q as i16, MLKEM_Q as i16 + 1, 2 * MLKEM_Q as i16 - 1,
        ];
        // Fill polynomial with test values repeating
        for i in 0..N {
            poly.coeffs[i] = test_values[i % test_values.len()];
        }

        // Store original values for congruence check
        let originals: Vec<i32> = poly.coeffs.iter().map(|&c| c as i32).collect();

        poly.reduce();

        for i in 0..N {
            assert!(
                poly.coeffs[i] >= 0 && poly.coeffs[i] < MLKEM_Q as i16,
                "reduce() failed for original value {}: got {}",
                originals[i], poly.coeffs[i]
            );
            // Check congruence
            assert_eq!(
                (poly.coeffs[i] as i32).rem_euclid(MLKEM_Q),
                originals[i].rem_euclid(MLKEM_Q),
                "reduce() broke congruence for {}",
                originals[i]
            );
        }
    }

    #[test]
    fn test_compress_decompress_d1_exhaustive() {
        // Test all 3329 possible inputs for d=1 compression
        for x in 0..MLKEM_Q as i16 {
            let compressed = compress_coeff(x, 1);
            assert!(compressed == 0 || compressed == 1,
                "Compress_q({}, 1) = {} not in {{0, 1}}", x, compressed);

            let decompressed = decompress_coeff(compressed as i16, 1);
            // For d=1: 0 -> 0, 1 -> ceil(q/2) = 1665
            if compressed == 0 {
                assert_eq!(decompressed, 0, "Decompress(0, 1) should be 0");
            } else {
                assert_eq!(decompressed, 1665, "Decompress(1, 1) should be 1665");
            }

            // Check round-trip error is bounded
            let orig = x as i32;
            let dec = decompressed as i32;
            let diff = (orig - dec).rem_euclid(MLKEM_Q);
            let error = diff.min(MLKEM_Q - diff);
            let max_error = (MLKEM_Q + 2) / 4; // q / 2^(1+1) rounded up
            assert!(error <= max_error,
                "Round-trip error for x={}: error={} > max_error={}", x, error, max_error);
        }
    }

    #[test]
    fn test_sample_cbd3() {
        // CBD eta=3 should produce coefficients in [-3, 3]
        let seed = [0xABu8; 32];
        let poly = Poly::sample_cbd(&seed, 0, 3);

        for (i, &coeff) in poly.coeffs.iter().enumerate() {
            assert!(
                coeff >= -3 && coeff <= 3,
                "CBD3 coefficient {} at index {} out of range [-3, 3]",
                coeff, i
            );
        }
    }

    #[test]
    fn test_sample_cbd_deterministic() {
        // Same seed and nonce should produce the same polynomial
        let seed = [0x42u8; 32];
        let poly1 = Poly::sample_cbd(&seed, 5, 2);
        let poly2 = Poly::sample_cbd(&seed, 5, 2);

        for i in 0..N {
            assert_eq!(poly1.coeffs[i], poly2.coeffs[i],
                "CBD not deterministic at index {}", i);
        }

        // Different nonce should produce different polynomial
        let poly3 = Poly::sample_cbd(&seed, 6, 2);
        let mut all_same = true;
        for i in 0..N {
            if poly1.coeffs[i] != poly3.coeffs[i] {
                all_same = false;
                break;
            }
        }
        assert!(!all_same, "Different nonces produced identical polynomials");
    }

    #[test]
    fn test_sample_uniform_range() {
        // All coefficients from sample_uniform should be in [0, q)
        let seeds: Vec<[u8; 32]> = vec![[0u8; 32], [0xFFu8; 32], [0x42u8; 32]];
        for seed in &seeds {
            for i in 0..3u8 {
                for j in 0..3u8 {
                    let poly = Poly::sample_uniform(seed, i, j);
                    for (idx, &coeff) in poly.coeffs.iter().enumerate() {
                        assert!(
                            coeff >= 0 && coeff < MLKEM_Q as i16,
                            "sample_uniform coeff {} at index {} out of [0, q) for seed {:?}, i={}, j={}",
                            coeff, idx, &seed[..4], i, j
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_byte_encoding_roundtrip_random() {
        // Test with pseudo-random coefficients that to_bytes/from_bytes is lossless
        let mut poly = Poly::zero();
        let mut val: u32 = 12345;
        for i in 0..N {
            // Simple LCG for deterministic "random" values
            val = val.wrapping_mul(1103515245).wrapping_add(12345);
            poly.coeffs[i] = ((val >> 16) % MLKEM_Q as u32) as i16;
        }

        let bytes = poly.to_bytes();
        let decoded = Poly::from_bytes(&bytes);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], decoded.coeffs[i],
                "Byte encoding roundtrip failed at index {}", i
            );
        }
    }

    #[test]
    fn test_polyvec_add_sub_inverse() {
        // (a + b) - b should equal a
        let k = 3;
        let mut a = PolyVec::new(k);
        let mut b = PolyVec::new(k);

        for p in 0..k {
            for i in 0..N {
                a.polys[p].coeffs[i] = ((p * 100 + i * 7) % MLKEM_Q as usize) as i16;
                b.polys[p].coeffs[i] = ((p * 200 + i * 11 + 50) % MLKEM_Q as usize) as i16;
            }
        }

        let sum = a.add(&b);

        // (a + b) - b
        let mut diff = PolyVec::new(k);
        for p in 0..k {
            diff.polys[p] = sum.polys[p].sub(&b.polys[p]);
        }

        for p in 0..k {
            for i in 0..N {
                assert_eq!(
                    diff.polys[p].coeffs[i], a.polys[p].coeffs[i],
                    "(a+b)-b != a at poly {}, index {}", p, i
                );
            }
        }
    }

    #[test]
    fn test_to_mont_conversion() {
        // to_mont should multiply each coefficient by R mod q
        // We verify by checking that fqmul(to_mont(a), 1) = a mod q
        // (since fqmul computes x*y*R^{-1}, fqmul(a*R, 1) = a*R*R^{-1} = a)
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = (i as i16 * 13) % (MLKEM_Q as i16);
        }
        let original: Vec<i16> = poly.coeffs.to_vec();

        poly.to_mont();

        for i in 0..N {
            // Coefficients should have changed (unless original was 0)
            if original[i] != 0 {
                assert_ne!(
                    poly.coeffs[i], original[i],
                    "to_mont did not change coefficient at index {}", i
                );
            }
            // Verify: fqmul(mont_coeff, 1) should give back original mod q
            use crate::primitives::ntt::mlkem_fqmul;
            let recovered = mlkem_fqmul(poly.coeffs[i], 1);
            assert_eq!(
                (recovered as i32).rem_euclid(MLKEM_Q),
                (original[i] as i32).rem_euclid(MLKEM_Q),
                "to_mont roundtrip failed at index {}", i
            );
        }
    }
}
