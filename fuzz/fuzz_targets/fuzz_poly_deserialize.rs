#![no_main]
use libfuzzer_sys::fuzz_target;
use kyber::poly::Poly;
use kyber::polyvec::PolyVec;
use kyber::params::ML_KEM_768;

fuzz_target!(|data: &[u8]| {
    let mode = ML_KEM_768;

    // Fuzz poly frombytes/tobytes roundtrip
    if data.len() >= 384 {
        let p = Poly::frombytes(&data[..384]);
        let mut out = [0u8; 384];
        p.tobytes(&mut out);
        // Roundtrip: frombytes -> tobytes should not panic
    }

    // Fuzz polyvec frombytes/tobytes roundtrip
    let pvb = mode.polyvec_bytes();
    if data.len() >= pvb {
        let pv = PolyVec::frombytes(&data[..pvb], mode.k());
        let mut out = vec![0u8; pvb];
        pv.tobytes(&mut out);
    }

    // Fuzz polyvec decompress/compress roundtrip
    let pvcb = mode.polyvec_compressed_bytes();
    if data.len() >= pvcb {
        let pv = PolyVec::decompress(&data[..pvcb], mode);
        let mut out = vec![0u8; pvcb];
        pv.compress(&mut out, mode);
    }

    // Fuzz poly frommsg/tomsg roundtrip
    if data.len() >= 32 {
        let msg: &[u8; 32] = data[..32].try_into().unwrap();
        let p = Poly::frommsg(msg);
        let mut out = [0u8; 32];
        p.tomsg(&mut out);
        assert_eq!(msg, &out, "frommsg/tomsg roundtrip failed");
    }
});
