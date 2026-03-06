//! Centered Binomial Distribution sampling (CBD) for noise polynomials.

use crate::params::N;

fn load32_le(x: &[u8]) -> u32 {
    u32::from(x[0]) | (u32::from(x[1]) << 8) | (u32::from(x[2]) << 16) | (u32::from(x[3]) << 24)
}

fn load24_le(x: &[u8]) -> u32 {
    u32::from(x[0]) | (u32::from(x[1]) << 8) | (u32::from(x[2]) << 16)
}

/// CBD with eta=2.
pub fn cbd2(r: &mut [i16; N], buf: &[u8]) {
    for i in 0..N / 8 {
        let t = load32_le(&buf[4 * i..]);
        let d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r[8 * i + j] = a - b;
        }
    }
}

/// CBD with eta=3 (only used for Kyber-512).
pub fn cbd3(r: &mut [i16; N], buf: &[u8]) {
    for i in 0..N / 4 {
        let t = load24_le(&buf[3 * i..]);
        let d = (t & 0x00249249) + ((t >> 1) & 0x00249249) + ((t >> 2) & 0x00249249);
        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r[4 * i + j] = a - b;
        }
    }
}

/// CBD dispatcher based on eta value.
pub fn poly_cbd(r: &mut [i16; N], buf: &[u8], eta: usize) {
    match eta {
        2 => cbd2(r, buf),
        3 => cbd3(r, buf),
        _ => panic!("unsupported eta: {}", eta),
    }
}
