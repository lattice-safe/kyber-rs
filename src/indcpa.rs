//! IND-CPA public-key encryption (core Kyber PKE).

use crate::params::{KyberMode, N};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::symmetric::{self, XofState};
use alloc::vec;

/// Rejection sampling: sample uniform mod q from XOF output.
fn rej_uniform(r: &mut [i16], buf: &[u8]) -> usize {
    let mut ctr = 0;
    let mut pos = 0;
    let len = r.len();
    let buflen = buf.len();
    while ctr < len && pos + 3 <= buflen {
        let val0 = (u16::from(buf[pos]) | (u16::from(buf[pos + 1]) << 8)) & 0xFFF;
        let val1 = ((u16::from(buf[pos + 1]) >> 4) | (u16::from(buf[pos + 2]) << 4)) & 0xFFF;
        pos += 3;
        if val0 < 3329 {
            r[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < len && val1 < 3329 {
            r[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

const XOF_BLOCKBYTES: usize = 168; // SHAKE128 rate

/// Generate matrix A (or transpose) from seed.
pub fn gen_matrix(mode: KyberMode, seed: &[u8; 32], transposed: bool) -> alloc::vec::Vec<PolyVec> {
    let k = mode.k();
    let gen_nblocks = ((12 * N / 8 * (1 << 12) / 3329) + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;

    let mut a: alloc::vec::Vec<PolyVec> = (0..k).map(|_| PolyVec::new(k)).collect();

    for i in 0..k {
        for j in 0..k {
            let (si, sj) = if transposed { (i, j) } else { (j, i) };
            let mut state = XofState::absorb(seed, si as u8, sj as u8);
            let mut buf = vec![0u8; gen_nblocks * XOF_BLOCKBYTES];
            state.squeeze(&mut buf);
            let mut ctr = rej_uniform(&mut a[i].vec[j].coeffs, &buf);
            while ctr < N {
                let mut extra = [0u8; XOF_BLOCKBYTES];
                state.squeeze(&mut extra);
                ctr += rej_uniform(&mut a[i].vec[j].coeffs[ctr..], &extra);
            }
        }
    }
    a
}

/// IND-CPA key generation (deterministic).
pub fn keypair_derand(
    mode: KyberMode,
    coins: &[u8; 32],
) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
    let k = mode.k();

    // Hash coins || K
    let mut buf = [0u8; 64];
    let mut seed_input = [0u8; 33];
    seed_input[..32].copy_from_slice(coins);
    seed_input[32] = k as u8;
    symmetric::hash_g(&mut buf, &seed_input);
    let publicseed: [u8; 32] = buf[..32].try_into().unwrap();
    let noiseseed: [u8; 32] = buf[32..64].try_into().unwrap();

    let a = gen_matrix(mode, &publicseed, false);

    let mut nonce = 0u8;
    let mut skpv = PolyVec::new(k);
    let mut e = PolyVec::new(k);

    for i in 0..k {
        skpv.vec[i] = Poly::getnoise(&noiseseed, nonce, mode.eta1());
        nonce += 1;
    }
    for i in 0..k {
        e.vec[i] = Poly::getnoise(&noiseseed, nonce, mode.eta1());
        nonce += 1;
    }

    skpv.ntt();
    e.ntt();

    // pkpv = A * skpv + e
    let mut pkpv = PolyVec::new(k);
    for i in 0..k {
        PolyVec::basemul_acc_montgomery(&mut pkpv.vec[i], &a[i], &skpv);
        pkpv.vec[i].tomont();
    }
    pkpv.add(&pkpv.clone(), &e);
    pkpv.reduce();

    // Pack keys
    let pk_bytes = mode.indcpa_publickey_bytes();
    let sk_bytes = mode.indcpa_secretkey_bytes();
    let mut pk = vec![0u8; pk_bytes];
    let mut sk = vec![0u8; sk_bytes];

    skpv.tobytes(&mut sk);
    pkpv.tobytes(&mut pk[..mode.polyvec_bytes()]);
    pk[mode.polyvec_bytes()..].copy_from_slice(&publicseed);

    (pk, sk)
}

/// IND-CPA encryption.
pub fn enc(mode: KyberMode, ct: &mut [u8], msg: &[u8; 32], pk: &[u8], coins: &[u8; 32]) {
    let k = mode.k();
    let pvb = mode.polyvec_bytes();

    let pkpv = PolyVec::frombytes(&pk[..pvb], k);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&pk[pvb..pvb + 32]);

    let at = gen_matrix(mode, &seed, true);

    let mut nonce = 0u8;
    let mut sp = PolyVec::new(k);
    let mut ep = PolyVec::new(k);

    for i in 0..k {
        sp.vec[i] = Poly::getnoise(coins, nonce, mode.eta1());
        nonce += 1;
    }
    for i in 0..k {
        ep.vec[i] = Poly::getnoise(coins, nonce, mode.eta2());
        nonce += 1;
    }
    let epp = Poly::getnoise(coins, nonce, mode.eta2());

    sp.ntt();

    // b = A^T * sp
    let mut b = PolyVec::new(k);
    for i in 0..k {
        PolyVec::basemul_acc_montgomery(&mut b.vec[i], &at[i], &sp);
    }

    // v = pk^T * sp
    let mut v = Poly::new();
    PolyVec::basemul_acc_montgomery(&mut v, &pkpv, &sp);

    b.invntt_tomont();
    v.invntt_tomont();

    b.add(&b.clone(), &ep);
    let k_poly = Poly::frommsg(msg);
    let mut v2 = Poly::new();
    v2.add(&v, &epp);
    let mut v3 = Poly::new();
    v3.add(&v2, &k_poly);
    v = v3;

    b.reduce();
    v.reduce();

    // Pack ciphertext
    let pvcb = mode.polyvec_compressed_bytes();
    b.compress(&mut ct[..pvcb], mode);
    v.compress(&mut ct[pvcb..], mode);
}

/// IND-CPA decryption.
pub fn dec(mode: KyberMode, msg: &mut [u8; 32], ct: &[u8], sk: &[u8]) {
    let k = mode.k();
    let pvcb = mode.polyvec_compressed_bytes();

    let mut b = PolyVec::decompress(&ct[..pvcb], mode);
    let v = Poly::decompress(&ct[pvcb..], mode);

    let skpv = PolyVec::frombytes(sk, k);

    b.ntt();
    let mut mp = Poly::new();
    PolyVec::basemul_acc_montgomery(&mut mp, &skpv, &b);
    mp.invntt_tomont();

    let mut result = Poly::new();
    result.sub(&v, &mp);
    result.reduce();

    result.tomsg(msg);
}
