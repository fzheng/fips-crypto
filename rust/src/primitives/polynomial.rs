//! Polynomial arithmetic for lattice-based cryptography
//!
//! Implements polynomial operations in the ring R_q = Z_q[X]/(X^n + 1)
//! where q = 3329 for ML-KEM and n = 256.

use crate::primitives::ntt::{
    mlkem_barrett_reduce, mlkem_basemul, mlkem_ntt, mlkem_ntt_inv, MLKEM_Q, N,
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

    /// Reduce all coefficients modulo q
    pub fn reduce(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = mlkem_barrett_reduce(*coeff as i32);
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

    /// Multiply two polynomials in NTT domain
    pub fn basemul(&self, other: &Self) -> Self {
        Self {
            coeffs: mlkem_basemul(&self.coeffs, &other.coeffs),
        }
    }

    /// Sample a polynomial using centered binomial distribution (CBD)
    /// with η (eta) determining the distribution width
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

    /// Sample a polynomial uniformly from R_q using rejection sampling
    /// Used for sampling the matrix A
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

    /// Compress polynomial coefficients to d bits
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

    /// Decompress polynomial coefficients from d bits
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

    /// Encode polynomial to bytes (12 bits per coefficient)
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

    /// Decode polynomial from bytes (12 bits per coefficient)
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut poly = Self::zero();
        for i in 0..N / 2 {
            poly.coeffs[2 * i] = ((data[3 * i] as u16) | ((data[3 * i + 1] as u16 & 0x0F) << 8)) as i16;
            poly.coeffs[2 * i + 1] = (((data[3 * i + 1] as u16) >> 4) | ((data[3 * i + 2] as u16) << 4)) as i16;
        }
        poly
    }
}

/// Compress a coefficient to d bits
#[inline]
fn compress_coeff(x: i16, d: usize) -> i32 {
    let x = x as i32;
    let q = MLKEM_Q;
    let two_d = 1i32 << d;
    // Compute round((2^d / q) * x) mod 2^d
    ((((x as i64) << d) + (q as i64 / 2)) / (q as i64)) as i32 & (two_d - 1)
}

/// Decompress a d-bit value back to a coefficient
#[inline]
fn decompress_coeff(x: i16, d: usize) -> i16 {
    let x = x as i32;
    let q = MLKEM_Q;
    let two_d = 1i32 << d;
    // Compute round((q / 2^d) * x)
    (((x * q) + (two_d / 2)) / two_d) as i16
}

/// Sample coefficients using CBD with η=2
fn sample_cbd2(buf: &[u8], coeffs: &mut [i16; N]) {
    for i in 0..N / 4 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);

        let d = t & 0x55555555;
        let e = (t >> 1) & 0x55555555;
        let f = d + e;

        for j in 0..4 {
            let a = ((f >> (8 * j)) & 0x3) as i16;
            let b = ((f >> (8 * j + 2)) & 0x3) as i16;
            coeffs[4 * i + j] = a - b;
        }
    }
}

/// Sample coefficients using CBD with η=3
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

/// A k×k matrix of polynomials
pub struct PolyMat {
    pub rows: Vec<PolyVec>,
}

impl PolyMat {
    /// Create a new k×k matrix
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
                let max_error = MLKEM_Q / (1 << d);
                let error = (orig - dec).abs().min((orig - dec + MLKEM_Q).abs());
                assert!(
                    error <= max_error,
                    "d={}, i={}, orig={}, dec={}, error={}",
                    d,
                    i,
                    orig,
                    dec,
                    error
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

        // CBD with η=2 should produce coefficients in [-2, 2]
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
}
