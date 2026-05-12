use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use qevm_crypto::{EcdsaSecp256k1, MlDsaDilithium2, SignatureScheme};

fn bench_mldsa(c: &mut Criterion) {
    let msg = b"qevm-ml-dsa";
    c.bench_function("mldsa_sign_verify", |b| {
        b.iter_batched(
            || MlDsaDilithium2::keygen().expect("keygen"),
            |(pk, sk)| {
                let sig = MlDsaDilithium2::sign(msg, &sk).expect("sign");
                let ok = MlDsaDilithium2::verify(msg, &sig, &pk).expect("verify");
                assert!(ok);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_ecdsa(c: &mut Criterion) {
    let msg = b"qevm-ecdsa";
    c.bench_function("ecdsa_sign_verify", |b| {
        b.iter_batched(
            || EcdsaSecp256k1::keygen().expect("keygen"),
            |(pk, sk)| {
                let sig = EcdsaSecp256k1::sign(msg, &sk).expect("sign");
                let ok = EcdsaSecp256k1::verify(msg, &sig, &pk).expect("verify");
                assert!(ok);
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(crypto_benches, bench_mldsa, bench_ecdsa);
criterion_main!(crypto_benches);
