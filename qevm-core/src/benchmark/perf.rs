use crate::crypto::{EcdsaSecp256k1, MlDsaDilithium2, SignatureScheme};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct BenchRow {
    pub algorithm: &'static str,
    pub keygen_ms: f64,
    pub sign_ms: f64,
    pub verify_ms: f64,
}

fn avg_ms(total: Duration, iters: u32) -> f64 {
    (total.as_secs_f64() * 1000.0) / (iters as f64)
}

pub fn run_benchmarks(iters: u32) -> Vec<BenchRow> {
    let msg = b"qevm-benchmark-message";

    let mldsa = bench_scheme::<MlDsaDilithium2>(msg, iters);
    let ecdsa = bench_scheme::<EcdsaSecp256k1>(msg, iters);

    vec![mldsa, ecdsa]
}

fn bench_scheme<S: SignatureScheme>(msg: &[u8], iters: u32) -> BenchRow {
    let mut total_keygen = Duration::from_secs(0);
    let mut total_sign = Duration::from_secs(0);
    let mut total_verify = Duration::from_secs(0);

    // Pre-generate a keypair for sign/verify timing to avoid keygen mixing.
    let (pk, sk) = S::keygen().expect("keygen");
    let _sig = S::sign(msg, &sk).expect("sign");

    for _ in 0..iters {
        let t0 = Instant::now();
        let _ = S::keygen().expect("keygen");
        total_keygen += t0.elapsed();

        let t1 = Instant::now();
        let sig = S::sign(msg, &sk).expect("sign");
        total_sign += t1.elapsed();

        let t2 = Instant::now();
        let ok = S::verify(msg, &sig, &pk).expect("verify");
        total_verify += t2.elapsed();
        assert!(ok);
    }

    BenchRow {
        algorithm: S::name(),
        keygen_ms: avg_ms(total_keygen, iters),
        sign_ms: avg_ms(total_sign, iters),
        verify_ms: avg_ms(total_verify, iters),
    }
}

pub fn format_table(rows: &[BenchRow]) -> String {
    let mut out = String::new();
    out.push_str("Algorithm | KeyGen(ms) | Sign(ms) | Verify(ms)\n");
    out.push_str("---|---:|---:|---:\n");
    for r in rows {
        out.push_str(&format!(
            "{} | {:.3} | {:.3} | {:.3}\n",
            r.algorithm, r.keygen_ms, r.sign_ms, r.verify_ms
        ));
    }
    out
}
