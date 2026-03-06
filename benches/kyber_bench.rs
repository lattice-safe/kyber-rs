use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kyber::kem::{decaps, encaps_derand, keypair_derand};
use kyber::params::{KyberMode, ML_KEM_1024, ML_KEM_512, ML_KEM_768};

fn bench_mode(c: &mut Criterion, mode: KyberMode, name: &str) {
    let coins = [0u8; 64];
    let (pk, sk) = keypair_derand(mode, &coins);
    let enc_coins = [1u8; 32];
    let (ct, _) = encaps_derand(mode, &pk, &enc_coins);

    c.bench_function(&format!("{} keygen", name), |b| {
        b.iter(|| keypair_derand(black_box(mode), black_box(&coins)))
    });

    c.bench_function(&format!("{} encaps", name), |b| {
        b.iter(|| encaps_derand(black_box(mode), black_box(&pk), black_box(&enc_coins)))
    });

    c.bench_function(&format!("{} decaps", name), |b| {
        b.iter(|| decaps(black_box(mode), black_box(&ct), black_box(&sk)))
    });
}

fn kyber_benchmarks(c: &mut Criterion) {
    bench_mode(c, ML_KEM_512, "ML-KEM-512");
    bench_mode(c, ML_KEM_768, "ML-KEM-768");
    bench_mode(c, ML_KEM_1024, "ML-KEM-1024");
}

criterion_group!(benches, kyber_benchmarks);
criterion_main!(benches);
