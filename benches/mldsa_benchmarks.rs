// -*- mode: rust; -*-

use criterion::{criterion_group, Criterion};

mod mldsa_benches {
    use crystals_dilithium::ml_dsa_65::Keypair;
    use rand::RngCore;

    use super::*;

    fn random_bytes(bytes: &mut [u8], n: usize) {
        rand::prelude::thread_rng()
            .try_fill_bytes(&mut bytes[..n])
            .unwrap();
    }

    fn key_generation(c: &mut Criterion) {
        let mut s = [0u8; 32];
        random_bytes(&mut s, 32);
        c.bench_function("ML-DSA keypair generation", move |b| {
            b.iter(|| Keypair::generate(None).unwrap());
        });
    }

    fn sign(c: &mut Criterion) {
        let keypair = Keypair::generate(None).unwrap();
        let mut msg = [0u8; 32];
        let mut ctx = [0u8; 32];
        random_bytes(&mut msg, 32);
        random_bytes(&mut ctx, 32);

        c.bench_function("ML-DSA signing", move |b| {
            b.iter(|| {
                keypair.sign(
                    &msg,
                    Some(&ctx),
                    crystals_dilithium::RandomMode::Deterministic,
                )
            })
        });
    }

    fn verify(c: &mut Criterion) {
        let keypair = Keypair::generate(None).unwrap();
        let mut msg = [0u8; 32];
        let mut ctx = [0u8; 32];
        random_bytes(&mut msg, 32);
        random_bytes(&mut ctx, 32);
        let sig = keypair
            .sign(
                &msg,
                Some(&ctx),
                crystals_dilithium::RandomMode::Deterministic,
            )
            .unwrap();

        c.bench_function("ML-DSA signature verification", move |b| {
            b.iter(|| keypair.verify(&msg, sig.as_slice(), Some(&ctx)))
        });
    }

    criterion_group! {
        name = mldsa_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            key_generation,
    }
}

criterion::criterion_main!(mldsa_benches::mldsa_benches);
