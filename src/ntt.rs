//! Number-theoretic transform for Kyber (q=3329, N=256).

use crate::params::N;
use crate::reduce::{barrett_reduce, fqmul};

/// Pre-computed zetas in Montgomery domain (from C reference).
pub const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// Forward NTT. Input in standard order, output in bit-reversed order.
pub fn ntt(r: &mut [i16; N]) {
    let mut k: usize = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT. Input in bit-reversed order, output in standard order.
/// Multiplies by Montgomery factor 2^16.
pub fn invntt(r: &mut [i16; N]) {
    let f: i16 = 1441; // mont^2/128
    let mut k: usize = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = fqmul(zeta, r[j + len] - t);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in r.iter_mut() {
        *coeff = fqmul(*coeff, f);
    }
}

/// Base multiplication in Zq[X]/(X^2-zeta).
pub fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]) + fqmul(a[1], b[0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_roundtrip() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = (i as i16 * 13 + 7) % 3329;
            b[i] = a[i];
        }
        ntt(&mut a);
        invntt(&mut a);
        // After NTT-INTT, result should be original * R mod q
        for i in 0..N {
            let r = ((a[i] as i32).rem_euclid(3329)) as i16;
            let expected = (((b[i] as i32) * ((1i32 << 16) % 3329)).rem_euclid(3329)) as i16;
            assert_eq!(r, expected, "mismatch at index {}", i);
        }
    }
}
