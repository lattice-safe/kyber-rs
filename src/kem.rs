//! CCA-secure KEM (Fujisaki-Okamoto transform).

use crate::indcpa;
use crate::params::{KyberMode, SSBYTES, SYMBYTES};
use crate::symmetric;
use crate::verify as ct_verify;
use alloc::vec;

/// Generate ML-KEM key pair (deterministic).
pub fn keypair_derand(
    mode: KyberMode,
    coins: &[u8; 64],
) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
    let (pk, sk_cpa) = indcpa::keypair_derand(mode, coins[..32].try_into().unwrap());

    // sk = sk_cpa || pk || H(pk) || z
    let mut sk = vec![0u8; mode.secret_key_bytes()];
    let cpa_len = mode.indcpa_secretkey_bytes();
    let pk_len = mode.public_key_bytes();

    sk[..cpa_len].copy_from_slice(&sk_cpa);
    sk[cpa_len..cpa_len + pk_len].copy_from_slice(&pk);

    let mut h_pk = [0u8; 32];
    symmetric::hash_h(&mut h_pk, &pk);
    sk[cpa_len + pk_len..cpa_len + pk_len + 32].copy_from_slice(&h_pk);

    // z = coins[32..64]
    sk[cpa_len + pk_len + 32..].copy_from_slice(&coins[32..64]);

    (pk, sk)
}

/// Encapsulate: generate shared secret and ciphertext.
pub fn encaps_derand(
    mode: KyberMode,
    pk: &[u8],
    coins: &[u8; 32],
) -> (alloc::vec::Vec<u8>, [u8; SSBYTES]) {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(coins);

    // H(pk)
    let mut h_pk = [0u8; 32];
    symmetric::hash_h(&mut h_pk, pk);
    buf[32..64].copy_from_slice(&h_pk);

    // (K, r) = G(m || H(pk))
    let mut kr = [0u8; 64];
    symmetric::hash_g(&mut kr, &buf);

    // ct = Enc(pk, m, r)
    let mut ct = vec![0u8; mode.ciphertext_bytes()];
    indcpa::enc(mode, &mut ct, coins, pk, kr[32..64].try_into().unwrap());

    let mut ss = [0u8; SSBYTES];
    ss.copy_from_slice(&kr[..32]);
    (ct, ss)
}

/// Decapsulate: recover shared secret from ciphertext.
pub fn decaps(mode: KyberMode, ct: &[u8], sk: &[u8]) -> [u8; SSBYTES] {
    let cpa_len = mode.indcpa_secretkey_bytes();
    let pk_len = mode.public_key_bytes();

    let pk = &sk[cpa_len..cpa_len + pk_len];

    // Decrypt
    let mut buf = [0u8; 64];
    let mut m = [0u8; 32];
    indcpa::dec(mode, &mut m, ct, &sk[..cpa_len]);
    buf[..32].copy_from_slice(&m);

    // H(pk)
    buf[32..64].copy_from_slice(&sk[cpa_len + pk_len..cpa_len + pk_len + 32]);

    // (K', r') = G(m' || H(pk))
    let mut kr = [0u8; 64];
    symmetric::hash_g(&mut kr, &buf);

    // Re-encrypt
    let mut cmp = vec![0u8; mode.ciphertext_bytes()];
    indcpa::enc(
        mode,
        &mut cmp,
        buf[..32].try_into().unwrap(),
        pk,
        kr[32..64].try_into().unwrap(),
    );

    let fail = ct_verify::verify(ct, &cmp);

    // Implicit rejection: SHAKE-256(z || ct)
    let z = &sk[mode.secret_key_bytes() - SYMBYTES..];
    let mut ss_reject = [0u8; 32];
    symmetric::rkprf(&mut ss_reject, z, ct);

    let mut ss = [0u8; SSBYTES];
    ss.copy_from_slice(&kr[..32]);

    // Constant-time select
    ct_verify::cmov(&mut ss, &ss_reject, fail);
    ss
}
