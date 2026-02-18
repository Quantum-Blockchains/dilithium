// -*- mode: rust; -*-

use criterion::{criterion_group, Criterion};

mod dilithium_benches {
    use crystals_dilithium::dilithium2::Keypair;

    use super::*;

    fn key_generation(c: &mut Criterion) {
        c.bench_function("Dilithium keypair generation", move |b| {
            b.iter(|| Keypair::generate(None).unwrap());
        });
    }

    fn sign(c: &mut Criterion) {
        let keypair = Keypair::generate(None).unwrap();
        let msg = b"";

        c.bench_function("Dilithium signing", move |b| b.iter(|| keypair.sign(msg)));
    }

    fn verify(c: &mut Criterion) {
        let keypair = Keypair::generate(None).unwrap();
        let msg = b"";
        let sig = keypair.sign(msg);

        c.bench_function("Dilithium signature verification", move |b| {
            b.iter(|| keypair.verify(msg, sig.as_slice()))
        });
    }

    criterion_group! {
        name = dilithium_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            key_generation,
    }
}

criterion::criterion_main!(dilithium_benches::dilithium_benches);
