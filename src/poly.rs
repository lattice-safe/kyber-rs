//! Polynomial operations for Kyber.

use crate::cbd;
use crate::ntt;
use crate::params::{KyberMode, N, Q32};
use crate::reduce::{barrett_reduce, montgomery_reduce};
use crate::symmetric;

/// A polynomial with N=256 i16 coefficients.
#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0i16; N] }
    }
}

impl Poly {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply NTT followed by Barrett reduction (matches C poly_ntt).
    pub fn ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
        self.reduce();
    }

    /// Apply inverse NTT.
    pub fn invntt_tomont(&mut self) {
        ntt::invntt(&mut self.coeffs);
    }

    /// Barrett reduce all coefficients.
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = barrett_reduce(*c);
        }
    }

    /// Add two polynomials.
    pub fn add(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i] + b.coeffs[i];
        }
    }

    /// Subtract: self = a - b.
    pub fn sub(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i] - b.coeffs[i];
        }
    }

    /// Multiply by 2^16 mod q for Montgomery domain conversion.
    pub fn tomont(&mut self) {
        let f = (1i64 << 32) % (Q32 as i64);
        for c in self.coeffs.iter_mut() {
            *c = montgomery_reduce((*c as i32) * (f as i32));
        }
    }

    /// Base multiplication in NTT domain.
    pub fn basemul_montgomery(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N / 4 {
            ntt::basemul(
                &mut self.coeffs[4 * i..4 * i + 2],
                &a.coeffs[4 * i..4 * i + 2],
                &b.coeffs[4 * i..4 * i + 2],
                ntt::ZETAS[64 + i],
            );
            ntt::basemul(
                &mut self.coeffs[4 * i + 2..4 * i + 4],
                &a.coeffs[4 * i + 2..4 * i + 4],
                &b.coeffs[4 * i + 2..4 * i + 4],
                -ntt::ZETAS[64 + i],
            );
        }
    }

    /// Sample noise polynomial with given eta.
    pub fn getnoise(seed: &[u8; 32], nonce: u8, eta: usize) -> Self {
        let buf_len = eta * N / 4;
        let mut buf = alloc::vec![0u8; buf_len];
        symmetric::prf(&mut buf, seed, nonce);
        let mut p = Poly::new();
        cbd::poly_cbd(&mut p.coeffs, &buf, eta);
        p
    }

    /// Serialize polynomial to bytes (full 12-bit packed).
    pub fn tobytes(&self, r: &mut [u8]) {
        for i in 0..N / 2 {
            let mut t0 = self.coeffs[2 * i] as u16;
            let mut t1 = self.coeffs[2 * i + 1] as u16;
            if (t0 as i16) < 0 {
                t0 = t0.wrapping_add(Q32 as u16);
            }
            if (t1 as i16) < 0 {
                t1 = t1.wrapping_add(Q32 as u16);
            }
            r[3 * i] = t0 as u8;
            r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
            r[3 * i + 2] = (t1 >> 4) as u8;
        }
    }

    /// Deserialize polynomial from bytes (12-bit packed).
    pub fn frombytes(a: &[u8]) -> Self {
        let mut p = Poly::new();
        for i in 0..N / 2 {
            p.coeffs[2 * i] =
                ((u16::from(a[3 * i]) | (u16::from(a[3 * i + 1]) << 8)) & 0xFFF) as i16;
            p.coeffs[2 * i + 1] =
                ((u16::from(a[3 * i + 1]) >> 4) | (u16::from(a[3 * i + 2]) << 4)) as i16;
        }
        p
    }

    /// Convert message bytes to polynomial.
    pub fn frommsg(msg: &[u8; 32]) -> Self {
        let mut p = Poly::new();
        for i in 0..N / 8 {
            for j in 0..8 {
                let mask = -(((msg[i] >> j) & 1) as i16);
                p.coeffs[8 * i + j] = mask & ((Q32 as i16 + 1) / 2);
            }
        }
        p
    }

    /// Convert polynomial to message bytes.
    pub fn tomsg(&self, msg: &mut [u8; 32]) {
        for i in 0..N / 8 {
            msg[i] = 0;
            for j in 0..8 {
                let mut t = self.coeffs[8 * i + j];
                // Freeze
                t += (t >> 15) & (Q32 as i16);
                // (t << 1) + Q/2) / Q & 1
                let val = (((t as u16) << 1).wrapping_add(Q32 as u16 / 2)) / (Q32 as u16) & 1;
                msg[i] |= (val as u8) << j;
            }
        }
    }

    /// Compress polynomial for ciphertext (d bits).
    pub fn compress(&self, r: &mut [u8], mode: KyberMode) {
        let mut t = [0u8; 8];
        match mode.poly_compressed_bytes() {
            128 => {
                // d=4
                for i in 0..N / 8 {
                    for j in 0..8 {
                        let mut u = self.coeffs[8 * i + j] as i16;
                        u += (u >> 15) & (Q32 as i16);
                        t[j] = ((((u as u32) << 4) + Q32 as u32 / 2) / Q32 as u32 & 15) as u8;
                    }
                    r[4 * i] = t[0] | (t[1] << 4);
                    r[4 * i + 1] = t[2] | (t[3] << 4);
                    r[4 * i + 2] = t[4] | (t[5] << 4);
                    r[4 * i + 3] = t[6] | (t[7] << 4);
                }
            }
            160 => {
                // d=5
                for i in 0..N / 8 {
                    for j in 0..8 {
                        let mut u = self.coeffs[8 * i + j] as i16;
                        u += (u >> 15) & (Q32 as i16);
                        t[j] = ((((u as u32) << 5) + Q32 as u32 / 2) / Q32 as u32 & 31) as u8;
                    }
                    r[5 * i] = t[0] | (t[1] << 5);
                    r[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
                    r[5 * i + 2] = (t[3] >> 1) | (t[4] << 4);
                    r[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
                    r[5 * i + 4] = (t[6] >> 2) | (t[7] << 3);
                }
            }
            _ => unreachable!(),
        }
    }

    /// Decompress polynomial from ciphertext.
    pub fn decompress(a: &[u8], mode: KyberMode) -> Self {
        let mut p = Poly::new();
        match mode.poly_compressed_bytes() {
            128 => {
                for i in 0..N / 2 {
                    p.coeffs[2 * i] = ((((a[i] & 15) as u32 * Q32 as u32) + 8) >> 4) as i16;
                    p.coeffs[2 * i + 1] = ((((a[i] >> 4) as u32 * Q32 as u32) + 8) >> 4) as i16;
                }
            }
            160 => {
                let mut t = [0u8; 8];
                for i in 0..N / 8 {
                    t[0] = a[5 * i] & 0x1F;
                    t[1] = (a[5 * i] >> 5) | ((a[5 * i + 1] << 3) & 0x1F);
                    t[2] = (a[5 * i + 1] >> 2) & 0x1F;
                    t[3] = (a[5 * i + 1] >> 7) | ((a[5 * i + 2] << 1) & 0x1F);
                    t[4] = (a[5 * i + 2] >> 4) | ((a[5 * i + 3] << 4) & 0x1F);
                    t[5] = (a[5 * i + 3] >> 1) & 0x1F;
                    t[6] = (a[5 * i + 3] >> 6) | ((a[5 * i + 4] << 2) & 0x1F);
                    t[7] = a[5 * i + 4] >> 3;
                    for j in 0..8 {
                        p.coeffs[8 * i + j] = (((t[j] as u32 * Q32 as u32) + 16) >> 5) as i16;
                    }
                }
            }
            _ => unreachable!(),
        }
        p
    }
}
