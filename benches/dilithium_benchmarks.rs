// -*- mode: rust; -*-

use criterion::{Criterion, criterion_group};

mod dilithium_benches {
    use dilithium::dilithium2::Keypair;

    use super::*;

    fn key_generation(c: &mut Criterion) {
        c.bench_function("Dilithium keypair generation", move |b| {
            b.iter(|| Keypair::generate(None));
        });
    }

    fn sign(c: &mut Criterion) {
        let keypair = Keypair::generate(None);
        let msg = b"";

        c.bench_function("Dilithium signing", move |b| b.iter(|| keypair.sign(msg)));
    }

    fn verify(c: &mut Criterion) {
        let keypair = Keypair::generate(None);
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