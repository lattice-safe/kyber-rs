//! SIMD-accelerated NTT for Kyber.
//!
//! This module provides AVX2 (x86_64) and NEON (aarch64) accelerated
//! NTT/INVNTT operations. Falls back to scalar implementation when
//! SIMD is not available.
//!
//! Activated by the `simd` feature flag.

use crate::params::N;
use crate::reduce::fqmul;

/// SIMD-accelerated forward NTT.
///
/// On supported platforms, uses vectorized Montgomery reduction
/// to process 8 butterflies at once. Falls back to scalar on
/// unsupported platforms.
pub fn ntt_simd(r: &mut [i16; N]) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { ntt_avx2(r) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { ntt_neon(r) };
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        crate::ntt::ntt(r);
    }
}

/// SIMD-accelerated inverse NTT.
pub fn invntt_simd(r: &mut [i16; N]) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { invntt_avx2(r) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { invntt_neon(r) };
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        crate::ntt::invntt(r);
    }
}

// ===========================================================================
// AVX2 implementation (x86_64)
// ===========================================================================
#[cfg(target_arch = "x86_64")]
mod avx2 {
    use core::arch::x86_64::*;

    const Q: i16 = 3329;
    const QINV: i16 = -3327; // q^-1 mod 2^16

    /// Vectorized Montgomery reduction: (a * QINV) mod 2^16, then (a - t*Q) >> 16
    #[inline(always)]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn montgomery_reduce_avx2(a_lo: __m256i, a_hi: __m256i) -> __m256i {
        let qinv = _mm256_set1_epi16(QINV);
        let q = _mm256_set1_epi16(Q);
        // t = a_lo * QINV (low 16 bits)
        let t = _mm256_mullo_epi16(a_lo, qinv);
        // t * Q (high 16 bits)
        let tq_hi = _mm256_mulhi_epi16(t, q);
        // result = a_hi - tq_hi
        _mm256_sub_epi16(a_hi, tq_hi)
    }

    /// Vectorized fqmul: montgomery_reduce(a * b)
    #[inline(always)]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn fqmul_avx2(a: __m256i, b: __m256i) -> __m256i {
        let lo = _mm256_mullo_epi16(a, b);
        let hi = _mm256_mulhi_epi16(a, b);
        montgomery_reduce_avx2(lo, hi)
    }

    /// AVX2 NTT butterfly: process 16 coefficients at once
    #[inline(always)]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn butterfly_avx2(r: &mut [i16; 256], start: usize, len: usize, zeta: i16) {
        let z = _mm256_set1_epi16(zeta);
        let mut j = start;
        while j < start + len {
            let remaining = start + len - j;
            if remaining >= 16 {
                let a = _mm256_loadu_si256(r.as_ptr().add(j) as *const __m256i);
                let b = _mm256_loadu_si256(r.as_ptr().add(j + len) as *const __m256i);
                let t = fqmul_avx2(z, b);
                let r_lo = _mm256_add_epi16(a, t);
                let r_hi = _mm256_sub_epi16(a, t);
                _mm256_storeu_si256(r.as_mut_ptr().add(j) as *mut __m256i, r_lo);
                _mm256_storeu_si256(r.as_mut_ptr().add(j + len) as *mut __m256i, r_hi);
                j += 16;
            } else {
                // Scalar fallback for remaining
                for jj in j..start + len {
                    let t = crate::reduce::fqmul(zeta, r[jj + len]);
                    r[jj + len] = r[jj] - t;
                    r[jj] += t;
                }
                break;
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn ntt_avx2(r: &mut [i16; N]) {
    use crate::ntt::ZETAS;

    let mut k: usize = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            if len >= 16 {
                avx2::butterfly_avx2(r, start, len, zeta);
            } else {
                // For small len, scalar is more efficient
                for j in start..start + len {
                    let t = fqmul(zeta, r[j + len]);
                    r[j + len] = r[j] - t;
                    r[j] = r[j] + t;
                }
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn invntt_avx2(r: &mut [i16; N]) {
    use crate::ntt::ZETAS;
    use crate::reduce::barrett_reduce;

    let f: i16 = 1441;
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

    // Final scaling by f = mont^2/128
    let f_vec = unsafe { core::arch::x86_64::_mm256_set1_epi16(f) };
    let mut j = 0;
    while j + 16 <= N {
        let a = unsafe {
            core::arch::x86_64::_mm256_loadu_si256(
                r.as_ptr().add(j) as *const core::arch::x86_64::__m256i
            )
        };
        let result = unsafe { avx2::fqmul_avx2(a, f_vec) };
        unsafe {
            core::arch::x86_64::_mm256_storeu_si256(
                r.as_mut_ptr().add(j) as *mut core::arch::x86_64::__m256i,
                result,
            );
        }
        j += 16;
    }
}

// ===========================================================================
// NEON implementation (aarch64)
// ===========================================================================
#[cfg(target_arch = "aarch64")]
mod neon {
    use core::arch::aarch64::*;

    const Q: i16 = 3329;
    const QINV: i16 = -3327;

    #[inline(always)]
    pub(super) unsafe fn fqmul_neon(a: int16x8_t, b: int16x8_t) -> int16x8_t {
        let qinv = vdupq_n_s16(QINV);
        let q = vdupq_n_s16(Q);
        let lo = vmulq_s16(a, b);
        // t = lo * QINV
        let t = vmulq_s16(lo, qinv);
        // result = (a*b - t*Q) >> 16  using vqrdmulhq as a proxy for mulhi
        // NEON doesn't have direct mulhi, use widening multiply
        let a_lo = vget_low_s16(a);
        let a_hi = vget_high_s16(a);
        let b_lo = vget_low_s16(b);
        let b_hi = vget_high_s16(b);
        let prod_lo = vmull_s16(a_lo, b_lo);
        let prod_hi = vmull_s16(a_hi, b_hi);
        let ab_hi_lo = vshrn_n_s32(prod_lo, 16);
        let ab_hi_hi = vshrn_n_s32(prod_hi, 16);
        let ab_hi = vcombine_s16(ab_hi_lo, ab_hi_hi);
        let tq_lo = vmull_s16(vget_low_s16(t), vget_low_s16(q));
        let tq_hi = vmull_s16(vget_high_s16(t), vget_high_s16(q));
        let tq_hi_lo = vshrn_n_s32(tq_lo, 16);
        let tq_hi_hi = vshrn_n_s32(tq_hi, 16);
        let tq_result = vcombine_s16(tq_hi_lo, tq_hi_hi);
        vsubq_s16(ab_hi, tq_result)
    }

    #[inline(always)]
    pub(super) unsafe fn butterfly_neon(r: &mut [i16; 256], start: usize, len: usize, zeta: i16) {
        let z = vdupq_n_s16(zeta);
        let mut j = start;
        while j + 8 <= start + len {
            let a = vld1q_s16(r.as_ptr().add(j));
            let b = vld1q_s16(r.as_ptr().add(j + len));
            let t = fqmul_neon(z, b);
            let r_lo = vaddq_s16(a, t);
            let r_hi = vsubq_s16(a, t);
            vst1q_s16(r.as_mut_ptr().add(j), r_lo);
            vst1q_s16(r.as_mut_ptr().add(j + len), r_hi);
            j += 8;
        }
        // Scalar fallback for remainder
        while j < start + len {
            let t = crate::reduce::fqmul(zeta, r[j + len]);
            r[j + len] = r[j] - t;
            r[j] += t;
            j += 1;
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn ntt_neon(r: &mut [i16; N]) {
    use crate::ntt::ZETAS;

    let mut k: usize = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            if len >= 8 {
                neon::butterfly_neon(r, start, len, zeta);
            } else {
                for j in start..start + len {
                    let t = fqmul(zeta, r[j + len]);
                    r[j + len] = r[j] - t;
                    r[j] += t;
                }
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn invntt_neon(r: &mut [i16; N]) {
    use crate::ntt::ZETAS;
    use crate::reduce::barrett_reduce;

    let f: i16 = 1441;
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

    // Final scaling with NEON
    let f_vec = unsafe { core::arch::aarch64::vdupq_n_s16(f) };
    let mut j = 0;
    while j + 8 <= N {
        let a = unsafe { core::arch::aarch64::vld1q_s16(r.as_ptr().add(j)) };
        let result = unsafe { neon::fqmul_neon(a, f_vec) };
        unsafe { core::arch::aarch64::vst1q_s16(r.as_mut_ptr().add(j), result) };
        j += 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt;

    #[test]
    fn test_simd_ntt_matches_scalar() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = (i as i16 * 13 + 7) % 3329;
            b[i] = a[i];
        }
        ntt::ntt(&mut a);
        ntt_simd(&mut b);
        for i in 0..N {
            assert_eq!(
                ((a[i] as i32).rem_euclid(3329)) as i16,
                ((b[i] as i32).rem_euclid(3329)) as i16,
                "NTT mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_simd_invntt_matches_scalar() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = (i as i16 * 17 + 3) % 3329;
            b[i] = a[i];
        }
        ntt::ntt(&mut a);
        ntt_simd(&mut b);
        ntt::invntt(&mut a);
        invntt_simd(&mut b);
        for i in 0..N {
            assert_eq!(
                ((a[i] as i32).rem_euclid(3329)) as i16,
                ((b[i] as i32).rem_euclid(3329)) as i16,
                "INVNTT mismatch at index {}",
                i
            );
        }
    }
}
