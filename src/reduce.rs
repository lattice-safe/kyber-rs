//! Montgomery and Barrett reduction for Kyber (q=3329, R=2^16).

use crate::params::Q32;

/// Montgomery reduction: given a 32-bit integer a, compute
/// 16-bit integer congruent to a * R^{-1} mod q, where R=2^16.
#[inline]
pub fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(-3327i16); // (a mod 2^16) * QINV mod 2^16
    ((a - (t as i32) * Q32) >> 16) as i16
}

/// Multiplication followed by Montgomery reduction.
#[inline]
pub fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

/// Barrett reduction: centered representative mod q in {-(q-1)/2,...,(q-1)/2}.
#[inline]
pub fn barrett_reduce(a: i16) -> i16 {
    let v: i16 = ((1i32 << 26) / Q32 + 1) as i16; // ≈ 20159
    let t = (((v as i32) * (a as i32) + (1 << 25)) >> 26) as i16;
    a - t * (Q32 as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce() {
        // mont_reduce(a * R) should give a mod q
        let a = 1234i16;
        let mont_r: i32 = 1 << 16;
        let result = montgomery_reduce((a as i32) * mont_r);
        // Result should be congruent to a mod q
        let r = ((result as i32 % 3329) + 3329) % 3329;
        let expected = ((a as i32 % 3329) + 3329) % 3329;
        assert_eq!(r, expected);
    }

    #[test]
    fn test_barrett_reduce() {
        for a in -10000i16..10000 {
            let r = barrett_reduce(a);
            assert!(
                r > -(3329 / 2 + 1) && r < 3329 / 2 + 1,
                "barrett_reduce({}) = {} out of range",
                a,
                r
            );
            assert_eq!(
                (r as i32).rem_euclid(3329),
                (a as i32).rem_euclid(3329),
                "barrett_reduce({}) = {} wrong residue",
                a,
                r
            );
        }
    }
}
