#![no_main]
use libfuzzer_sys::fuzz_target;
use kyber::kem::{keypair_derand, encaps_derand, decaps};
use kyber::params::{ML_KEM_512, ML_KEM_768, ML_KEM_1024};

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 { return; }

    // Use fuzz data to select mode and derive coins
    let mode = match data[0] % 3 {
        0 => ML_KEM_512,
        1 => ML_KEM_768,
        _ => ML_KEM_1024,
    };

    let mut keygen_coins = [0u8; 64];
    keygen_coins[..64.min(data.len() - 1)].copy_from_slice(&data[1..65.min(data.len())]);

    let mut enc_coins = [0u8; 32];
    let start = 65.min(data.len());
    let end = (start + 32).min(data.len());
    enc_coins[..end - start].copy_from_slice(&data[start..end]);

    let (pk, sk) = keypair_derand(mode, &keygen_coins);
    let (ct, ss_enc) = encaps_derand(mode, &pk, &enc_coins);
    let ss_dec = decaps(mode, &ct, &sk);

    // The shared secrets MUST always match for valid roundtrips
    assert_eq!(ss_enc, ss_dec, "KEM roundtrip failed!");
});
