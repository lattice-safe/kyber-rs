//! Vector of polynomials for Kyber.

use crate::params::{KyberMode, N, POLYBYTES, Q32};
use crate::poly::Poly;
use alloc::vec::Vec;
use zeroize::Zeroize;

/// A vector of K polynomials.
#[derive(Clone, Zeroize)]
pub struct PolyVec {
    pub vec: Vec<Poly>,
}

impl PolyVec {
    pub fn new(k: usize) -> Self {
        Self {
            vec: (0..k).map(|_| Poly::new()).collect(),
        }
    }

    pub fn ntt(&mut self) {
        for p in self.vec.iter_mut() {
            p.ntt();
        }
    }

    pub fn invntt_tomont(&mut self) {
        for p in self.vec.iter_mut() {
            p.invntt_tomont();
        }
    }

    pub fn reduce(&mut self) {
        for p in self.vec.iter_mut() {
            p.reduce();
        }
    }

    pub fn add(&mut self, a: &PolyVec, b: &PolyVec) {
        for i in 0..self.vec.len() {
            self.vec[i].add(&a.vec[i], &b.vec[i]);
        }
    }

    /// Inner product in NTT domain with Montgomery reduction.
    pub fn basemul_acc_montgomery(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
        let mut t = Poly::new();
        r.basemul_montgomery(&a.vec[0], &b.vec[0]);
        for i in 1..a.vec.len() {
            t.basemul_montgomery(&a.vec[i], &b.vec[i]);
            for j in 0..N {
                r.coeffs[j] += t.coeffs[j];
            }
        }
        r.reduce();
    }

    /// Serialize polyvec to bytes.
    pub fn tobytes(&self, r: &mut [u8]) {
        for i in 0..self.vec.len() {
            self.vec[i].tobytes(&mut r[i * POLYBYTES..(i + 1) * POLYBYTES]);
        }
    }

    /// Deserialize polyvec from bytes.
    pub fn frombytes(a: &[u8], k: usize) -> Self {
        let mut pv = PolyVec::new(k);
        for i in 0..k {
            pv.vec[i] = Poly::frombytes(&a[i * POLYBYTES..(i + 1) * POLYBYTES]);
        }
        pv
    }

    /// Compress polyvec for ciphertext.
    pub fn compress(&self, r: &mut [u8], mode: KyberMode) {
        let k = mode.k();
        match mode.polyvec_compressed_bytes() / k {
            352 => {
                // d=11
                let mut idx = 0;
                for i in 0..k {
                    for j in 0..N / 8 {
                        let mut t = [0u16; 8];
                        for (m, tm) in t.iter_mut().enumerate() {
                            let mut u = self.vec[i].coeffs[8 * j + m];
                            u += (u >> 15) & (Q32 as i16);
                            *tm =
                                (((((u as u32) << 11) + Q32 as u32 / 2) / Q32 as u32) & 0x7FF) as u16;
                        }
                        r[idx] = t[0] as u8;
                        r[idx + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                        r[idx + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                        r[idx + 3] = (t[2] >> 2) as u8;
                        r[idx + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                        r[idx + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                        r[idx + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                        r[idx + 7] = (t[5] >> 1) as u8;
                        r[idx + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                        r[idx + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                        r[idx + 10] = (t[7] >> 3) as u8;
                        idx += 11;
                    }
                }
            }
            320 => {
                // d=10
                let mut idx = 0;
                for i in 0..k {
                    for j in 0..N / 4 {
                        let mut t = [0u16; 4];
                        for (m, tm) in t.iter_mut().enumerate() {
                            let mut u = self.vec[i].coeffs[4 * j + m];
                            u += (u >> 15) & (Q32 as i16);
                            *tm =
                                (((((u as u32) << 10) + Q32 as u32 / 2) / Q32 as u32) & 0x3FF) as u16;
                        }
                        r[idx] = t[0] as u8;
                        r[idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                        r[idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                        r[idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                        r[idx + 4] = (t[3] >> 2) as u8;
                        idx += 5;
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    /// Decompress polyvec from ciphertext.
    pub fn decompress(a: &[u8], mode: KyberMode) -> Self {
        let k = mode.k();
        let mut pv = PolyVec::new(k);
        match mode.polyvec_compressed_bytes() / k {
            352 => {
                let mut idx = 0;
                for i in 0..k {
                    for j in 0..N / 8 {
                        let mut t = [0u16; 8];
                        t[0] = (u16::from(a[idx]) | (u16::from(a[idx + 1]) << 8)) & 0x7FF;
                        t[1] =
                            ((u16::from(a[idx + 1]) >> 3) | (u16::from(a[idx + 2]) << 5)) & 0x7FF;
                        t[2] = ((u16::from(a[idx + 2]) >> 6)
                            | (u16::from(a[idx + 3]) << 2)
                            | (u16::from(a[idx + 4]) << 10))
                            & 0x7FF;
                        t[3] =
                            ((u16::from(a[idx + 4]) >> 1) | (u16::from(a[idx + 5]) << 7)) & 0x7FF;
                        t[4] =
                            ((u16::from(a[idx + 5]) >> 4) | (u16::from(a[idx + 6]) << 4)) & 0x7FF;
                        t[5] = ((u16::from(a[idx + 6]) >> 7)
                            | (u16::from(a[idx + 7]) << 1)
                            | (u16::from(a[idx + 8]) << 9))
                            & 0x7FF;
                        t[6] =
                            ((u16::from(a[idx + 8]) >> 2) | (u16::from(a[idx + 9]) << 6)) & 0x7FF;
                        t[7] =
                            ((u16::from(a[idx + 9]) >> 5) | (u16::from(a[idx + 10]) << 3)) & 0x7FF;
                        idx += 11;
                        for (m, &tm) in t.iter().enumerate() {
                            pv.vec[i].coeffs[8 * j + m] =
                                (((tm as u32) * Q32 as u32 + 1024) >> 11) as i16;
                        }
                    }
                }
            }
            320 => {
                let mut idx = 0;
                for i in 0..k {
                    for j in 0..N / 4 {
                        let mut t = [0u16; 4];
                        t[0] = (u16::from(a[idx]) | (u16::from(a[idx + 1]) << 8)) & 0x3FF;
                        t[1] =
                            ((u16::from(a[idx + 1]) >> 2) | (u16::from(a[idx + 2]) << 6)) & 0x3FF;
                        t[2] =
                            ((u16::from(a[idx + 2]) >> 4) | (u16::from(a[idx + 3]) << 4)) & 0x3FF;
                        t[3] =
                            ((u16::from(a[idx + 3]) >> 6) | (u16::from(a[idx + 4]) << 2)) & 0x3FF;
                        idx += 5;
                        for (m, &tm) in t.iter().enumerate() {
                            pv.vec[i].coeffs[4 * j + m] =
                                (((tm as u32) * Q32 as u32 + 512) >> 10) as i16;
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        pv
    }
}
