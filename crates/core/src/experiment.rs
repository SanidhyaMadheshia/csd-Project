//! Experiment harness for the paper's evaluation (supervisor points 3, 4, 7).
//!
//! For every configuration of the ablation and every batch size N it runs
//! `warmup + repeats` independent runs of the *real* pipeline: fresh ML-DSA-44
//! accounts, off-chain FIPS 204 verification in the bundler, batch
//! authorisation, and inclusion of the wallet transaction(s) on revm with
//! committed state. Each run writes one CSV row; [`summarize`] aggregates.
//!
//! Configurations (see docs/implementation-status.md):
//! * `A0-native-model`: ML-DSA-44 verified directly in the EVM, one tx per op.
//!   **Modelled** (opcode-level cost model), not executed.
//! * `A1-attestation`: off-chain verification + ECDSA attestation by the
//!   bundler, one tx per batch. Fully trusts the bundler.
//! * `A2-groth16-per-op`: off-chain verification + one Groth16 receipt and one
//!   wallet tx per op (no batching).
//! * `A3-groth16-batch`: off-chain verification + one Groth16 receipt and one
//!   wallet tx per batch of N (the Q-EVM configuration).

use qevm_bundler::{Bundler, BundlerConfig, ProofMode};
use qevm_crypto::{MlDsa44, SignatureScheme};
use qevm_evm::{full_calldata, ReceiptStatement, EVM_SPEC_NAME};
use qevm_storage::InMemoryStorage;
use qevm_types::{Address, PqcPayload, UserOperation, WalletKind};
use qevm_utils::keccak256;
use qevm_zkvm::{LocalZkvmProver, ZkvmConfig, ZkvmProver};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Config {
    A0NativeModel,
    A1Attestation,
    A2Groth16PerOp,
    A3Groth16Batch,
}

impl Config {
    pub const ALL: [Config; 4] = [Config::A0NativeModel, Config::A1Attestation, Config::A2Groth16PerOp, Config::A3Groth16Batch];

    pub fn name(&self) -> &'static str {
        match self {
            Config::A0NativeModel => "A0-native-model",
            Config::A1Attestation => "A1-attestation",
            Config::A2Groth16PerOp => "A2-groth16-per-op",
            Config::A3Groth16Batch => "A3-groth16-batch",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s || c.name().starts_with(&format!("{s}-")))
    }

    fn mode(&self) -> Option<ProofMode> {
        match self {
            Config::A0NativeModel => None,
            Config::A1Attestation => Some(ProofMode::Batch(WalletKind::Attestation)),
            Config::A2Groth16PerOp => Some(ProofMode::PerOp),
            Config::A3Groth16Batch => Some(ProofMode::Batch(WalletKind::Groth16)),
        }
    }

    /// Trust assumption reported next to every result.
    pub fn trust(&self) -> &'static str {
        match self {
            Config::A0NativeModel => "none beyond Ethereum (signature checked on-chain)",
            Config::A1Attestation => "bundler key (bundler attests validity)",
            Config::A2Groth16PerOp | Config::A3Groth16Batch => {
                "bundler (receipt circuit does not verify ML-DSA; see circuit-spec)"
            }
        }
    }
}

/// Hooks to a process-wide peak-heap counter (provided by the binary).
#[derive(Clone, Copy)]
pub struct MemHooks {
    pub reset: fn(),
    pub peak: fn() -> usize,
}

#[derive(Clone)]
pub struct ExperimentConfig {
    pub configs: Vec<Config>,
    pub sizes: Vec<usize>,
    pub repeats: usize,
    pub warmup: usize,
    pub base_seed: u64,
    /// Nonce every fresh account starts at (1 = steady state: the account
    /// has transacted before, so its nonce slot is non-zero).
    pub start_nonce: u64,
    pub chain_id: u64,
    pub mem: Option<MemHooks>,
}

impl Default for ExperimentConfig {
    fn default() -> Self {
        Self {
            configs: Config::ALL.to_vec(),
            sizes: vec![1, 2, 4, 8, 16, 32, 64, 128, 256],
            repeats: 30,
            warmup: 3,
            base_seed: 0x5145_564d_0001,
            start_nonce: 1,
            chain_id: 1,
            mem: None,
        }
    }
}

/// One run of one configuration at one batch size.
#[derive(Debug, Clone, Serialize)]
pub struct RunRow {
    pub config: &'static str,
    pub n: usize,
    pub run: usize,
    pub seed: u64,
    /// `measured` (executed on revm) or `modelled` (A0 cost model).
    pub source: &'static str,
    pub success: bool,
    pub txs: usize,
    pub gas_total: u64,
    pub gas_per_op: f64,
    pub calldata_gas: u64,
    pub calldata_bytes: usize,
    pub proof_bytes: usize,
    /// Sum over the N ops of the off-chain FIPS 204 verification time.
    pub mldsa_verify_ms: f64,
    /// Sum of authorisation times (Groth16 prove of the binding circuit, or ECDSA sign).
    pub prove_ms: f64,
    /// Off-chain (arkworks) verification of the Groth16 proof(s); 0 for A1.
    pub verify_offchain_ms: f64,
    /// revm execution time of the wallet transaction(s).
    pub verify_evm_ms: f64,
    /// Bundler wall time: first submission → last wallet tx included.
    pub e2e_ms: f64,
    pub peak_heap_bytes: usize,
}

struct Workload {
    ops: Vec<UserOperation>,
}

fn sender_for(seed: u64, i: usize) -> Address {
    let h = keccak256(&[seed.to_be_bytes(), (i as u64).to_be_bytes()].concat());
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Address::new(a)
}

/// User side (not timed): N fresh accounts, registered, each signing one op.
fn workload(prover: &LocalZkvmProver, kind: WalletKind, n: usize, seed: u64, cfg: &ExperimentConfig) -> Workload {
    let chain = prover.chain();
    let wallet = Address::new(chain.wallet(kind).address);
    let ops = (0..n)
        .map(|i| {
            let (pk, sk) = MlDsa44::keygen().expect("keygen");
            let sender = sender_for(seed, i);
            let mut op = UserOperation::new(
                wallet,
                sender,
                cfg.start_nonce,
                cfg.chain_id,
                format!("transfer:{seed}:{i}").into_bytes(),
                PqcPayload { public_key: MlDsa44::pk_to_bytes(&pk), signature: vec![] },
            )
            .expect("op");
            chain.register_account(sender.as_bytes(), op.pk_hash(), cfg.start_nonce);
            let sig = MlDsa44::sign(op.op_hash().as_bytes(), &sk).expect("sign");
            op.pqc_payload.signature = MlDsa44::sig_to_bytes(&sig);
            op
        })
        .collect();
    Workload { ops }
}

async fn run_pipeline(
    config: Config,
    prover: &Arc<LocalZkvmProver>,
    w: Workload,
    n: usize,
    cfg: &ExperimentConfig,
) -> RunRow {
    let mode = config.mode().expect("pipeline config");
    let bundler = Bundler::new(
        BundlerConfig {
            max_mempool: n + 1,
            batch_size: n,
            mode,
            reference_receipts: false,
            submit_on_chain: true,
            ..Default::default()
        },
        Arc::new(InMemoryStorage::new(n + 1)),
        prover.clone() as Arc<dyn ZkvmProver>,
    );
    if let Some(m) = cfg.mem {
        (m.reset)();
    }
    let started = Instant::now();
    let mut mldsa_verify_ms = 0.0;
    let mut accepted = 0;
    for op in w.ops {
        let out = bundler.submit_user_operation(op).await.expect("submit");
        if out.accepted {
            accepted += 1;
        }
        mldsa_verify_ms += out.signature.map(|c| c.verify_ms).unwrap_or(0.0);
    }
    let batch = bundler.bundle_next().await.expect("bundle").expect("batch");
    let e2e_ms = started.elapsed().as_secs_f64() * 1000.0;
    let peak_heap_bytes = cfg.mem.map(|m| (m.peak)()).unwrap_or(0);

    // Off-chain verification time of the Groth16 proof(s) (not part of e2e).
    let mut verify_offchain_ms = 0.0;
    if matches!(config, Config::A2Groth16PerOp | Config::A3Groth16Batch) {
        let keys = prover.keys();
        let program = keccak256(ZkvmConfig::default().program_id.as_bytes());
        for tx in &batch.transactions {
            let st = ReceiptStatement { digest: *tx.digest.as_bytes(), program };
            let full = full_calldata(&tx.proof, &st);
            let t = Instant::now();
            let ok = keys.verify(&full, &st).unwrap_or(false);
            verify_offchain_ms += t.elapsed().as_secs_f64() * 1000.0;
            assert!(ok, "off-chain verification of the batch proof failed");
        }
    }

    let mut row = RunRow {
        config: config.name(),
        n,
        run: 0,
        seed: 0,
        source: "measured",
        success: accepted == n,
        txs: batch.transactions.len(),
        gas_total: 0,
        gas_per_op: 0.0,
        calldata_gas: 0,
        calldata_bytes: 0,
        proof_bytes: 0,
        mldsa_verify_ms,
        prove_ms: 0.0,
        verify_offchain_ms,
        verify_evm_ms: 0.0,
        e2e_ms,
        peak_heap_bytes,
    };
    for tx in &batch.transactions {
        let inc = tx.inclusion.expect("submitted");
        row.success &= inc.committed;
        row.gas_total += inc.gas.total;
        row.calldata_gas += inc.gas.calldata;
        row.calldata_bytes += tx.wallet_calldata.len();
        row.proof_bytes += tx.proof.len();
        row.prove_ms += tx.prove_time_ms;
        row.verify_evm_ms += inc.exec_ms;
    }
    row.gas_per_op = row.gas_total as f64 / n as f64;
    row
}

fn native_model_row(w: &Workload, n: usize) -> RunRow {
    let mut gas_total = 0;
    let mut calldata_gas = 0;
    let mut calldata_bytes = 0;
    for op in &w.ops {
        let g = qevm_evm::estimate_native_gas(&op.pqc_payload.public_key, &op.pqc_payload.signature, op.op_hash().as_bytes())
            .expect("well-formed key and signature");
        gas_total += g.total;
        calldata_gas += g.calldata;
        calldata_bytes += g.calldata_bytes as usize;
    }
    RunRow {
        config: Config::A0NativeModel.name(),
        n,
        run: 0,
        seed: 0,
        source: "modelled",
        success: true,
        txs: n,
        gas_total,
        gas_per_op: gas_total as f64 / n as f64,
        calldata_gas,
        calldata_bytes,
        proof_bytes: 0,
        mldsa_verify_ms: 0.0,
        prove_ms: 0.0,
        verify_offchain_ms: 0.0,
        verify_evm_ms: 0.0,
        e2e_ms: 0.0,
        peak_heap_bytes: 0,
    }
}

/// Run the whole grid. `progress` is called after every kept run.
pub async fn run_experiments(cfg: &ExperimentConfig, mut progress: impl FnMut(&RunRow)) -> Vec<RunRow> {
    let mut rows = Vec::new();
    for &config in &cfg.configs {
        // One chain per configuration; every run uses fresh accounts.
        let prover = Arc::new(LocalZkvmProver::new(ZkvmConfig { chain_id: cfg.chain_id, ..Default::default() }));
        let kind = config.mode().map(|m| m.wallet_kind()).unwrap_or(WalletKind::Groth16);
        for &n in &cfg.sizes {
            for run in 0..cfg.warmup + cfg.repeats {
                let seed = cfg.base_seed ^ ((config as u64) << 48) ^ ((n as u64) << 24) ^ run as u64;
                let w = workload(&prover, kind, n, seed, cfg);
                let mut row = match config {
                    Config::A0NativeModel => native_model_row(&w, n),
                    _ => run_pipeline(config, &prover, w, n, cfg).await,
                };
                if run < cfg.warmup {
                    continue;
                }
                row.run = run - cfg.warmup;
                row.seed = seed;
                progress(&row);
                rows.push(row);
            }
        }
    }
    rows
}

pub fn to_csv(rows: &[RunRow]) -> String {
    let mut out = String::from(
        "config,n,run,seed,source,success,txs,gas_total,gas_per_op,calldata_gas,calldata_bytes,proof_bytes,\
         mldsa_verify_ms,prove_ms,verify_offchain_ms,verify_evm_ms,e2e_ms,peak_heap_bytes\n",
    );
    for r in rows {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{:.2},{},{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{}",
            r.config,
            r.n,
            r.run,
            r.seed,
            r.source,
            r.success,
            r.txs,
            r.gas_total,
            r.gas_per_op,
            r.calldata_gas,
            r.calldata_bytes,
            r.proof_bytes,
            r.mldsa_verify_ms,
            r.prove_ms,
            r.verify_offchain_ms,
            r.verify_evm_ms,
            r.e2e_ms,
            r.peak_heap_bytes
        );
    }
    out
}

/// Descriptive statistics of one metric.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Stat {
    pub mean: f64,
    pub std: f64,
    pub median: f64,
    pub p95: f64,
    /// Half-width of the 95% confidence interval of the mean (Student t).
    pub ci95: f64,
    pub min: f64,
    pub max: f64,
}

fn t_critical_95(df: usize) -> f64 {
    // Two-sided 95% Student-t critical values; 1.96 for large df.
    const T: [f64; 30] = [
        12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131,
        2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
    ];
    if df == 0 {
        f64::NAN
    } else if df <= 30 {
        T[df - 1]
    } else {
        1.96
    }
}

pub fn stat(values: &[f64]) -> Stat {
    let n = values.len();
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let mean = v.iter().sum::<f64>() / n as f64;
    let var = if n > 1 { v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64 } else { 0.0 };
    let std = var.sqrt();
    let q = |p: f64| {
        let idx = p * (n - 1) as f64;
        let (lo, hi) = (idx.floor() as usize, idx.ceil() as usize);
        v[lo] + (v[hi] - v[lo]) * (idx - lo as f64)
    };
    Stat {
        mean,
        std,
        median: q(0.5),
        p95: q(0.95),
        ci95: if n > 1 { t_critical_95(n - 1) * std / (n as f64).sqrt() } else { 0.0 },
        min: v[0],
        max: v[n - 1],
    }
}

/// Per (config, N) aggregate.
#[derive(Debug, Clone, Serialize)]
pub struct SummaryRow {
    pub config: &'static str,
    pub n: usize,
    pub runs: usize,
    pub all_success: bool,
    pub gas_total: Stat,
    pub gas_per_op: Stat,
    pub mldsa_verify_ms: Stat,
    pub prove_ms: Stat,
    pub verify_offchain_ms: Stat,
    pub verify_evm_ms: Stat,
    pub e2e_ms: Stat,
    pub peak_heap_bytes: Stat,
    pub calldata_bytes: f64,
}

pub fn summarize(rows: &[RunRow]) -> Vec<SummaryRow> {
    let mut groups: BTreeMap<(&'static str, usize), Vec<&RunRow>> = BTreeMap::new();
    for r in rows {
        groups.entry((r.config, r.n)).or_default().push(r);
    }
    groups
        .into_iter()
        .map(|((config, n), rs)| {
            let col = |f: fn(&RunRow) -> f64| stat(&rs.iter().map(|r| f(r)).collect::<Vec<_>>());
            SummaryRow {
                config,
                n,
                runs: rs.len(),
                all_success: rs.iter().all(|r| r.success),
                gas_total: col(|r| r.gas_total as f64),
                gas_per_op: col(|r| r.gas_per_op),
                mldsa_verify_ms: col(|r| r.mldsa_verify_ms),
                prove_ms: col(|r| r.prove_ms),
                verify_offchain_ms: col(|r| r.verify_offchain_ms),
                verify_evm_ms: col(|r| r.verify_evm_ms),
                e2e_ms: col(|r| r.e2e_ms),
                peak_heap_bytes: col(|r| r.peak_heap_bytes as f64),
                calldata_bytes: rs.iter().map(|r| r.calldata_bytes as f64).sum::<f64>() / rs.len() as f64,
            }
        })
        .collect()
}

/// Flat CSV of the summary (one line per config and N), for pgfplots.
pub fn summary_csv(summary: &[SummaryRow]) -> String {
    let mut out = String::from(
        "config,n,runs,all_success,gas_total_mean,gas_per_op_mean,gas_per_op_std,gas_per_op_ci95,\
         mldsa_verify_ms_mean,mldsa_verify_ms_std,prove_ms_mean,prove_ms_std,prove_ms_ci95,\
         verify_offchain_ms_mean,verify_evm_ms_mean,verify_evm_ms_std,e2e_ms_mean,e2e_ms_std,e2e_ms_ci95,\
         e2e_ms_median,e2e_ms_p95,e2e_per_op_ms_mean,peak_heap_mib_mean,peak_heap_mib_max,calldata_bytes\n",
    );
    for s in summary {
        let _ = writeln!(
            out,
            "{},{},{},{},{:.1},{:.2},{:.2},{:.2},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.0}",
            s.config,
            s.n,
            s.runs,
            s.all_success,
            s.gas_total.mean,
            s.gas_per_op.mean,
            s.gas_per_op.std,
            s.gas_per_op.ci95,
            s.mldsa_verify_ms.mean,
            s.mldsa_verify_ms.std,
            s.prove_ms.mean,
            s.prove_ms.std,
            s.prove_ms.ci95,
            s.verify_offchain_ms.mean,
            s.verify_evm_ms.mean,
            s.verify_evm_ms.std,
            s.e2e_ms.mean,
            s.e2e_ms.std,
            s.e2e_ms.ci95,
            s.e2e_ms.median,
            s.e2e_ms.p95,
            s.e2e_ms.mean / s.n as f64,
            s.peak_heap_bytes.mean / (1024.0 * 1024.0),
            s.peak_heap_bytes.max / (1024.0 * 1024.0),
            s.calldata_bytes
        );
    }
    out
}

fn fmt_int(v: f64) -> String {
    let s = format!("{:.0}", v);
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, c) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 && *c != b'-' {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

/// Markdown report of the summary.
pub fn summary_markdown(summary: &[SummaryRow], cfg: &ExperimentConfig, env: &Environment) -> String {
    let mut md = String::new();
    let _ = writeln!(md, "# Q-EVM experiment summary\n");
    let _ = writeln!(md, "Generated by `qevm-cli experiment`. Raw data: `runs.csv`; aggregates: `summary.csv`.\n");
    let _ = writeln!(md, "## Environment\n");
    let _ = writeln!(md, "{}", env.markdown());
    let _ = writeln!(
        md,
        "## Protocol\n\n- Batch sizes N: {:?}\n- Repeats per (config, N): {} (after {} discarded warm-up runs)\n\
         - Every run uses fresh ML-DSA-44 accounts registered with nonce {} (steady state)\n\
         - Gas is the EVM's `gas_used` on revm ({}) with committed state; A0 is a cost model\n\
         - Statistics: mean ± std, median, p95, 95% CI of the mean (Student t)\n",
        cfg.sizes, cfg.repeats, cfg.warmup, cfg.start_nonce, EVM_SPEC_NAME
    );
    let _ = writeln!(md, "## Gas per operation\n");
    let _ = writeln!(md, "| config | N | gas / op (mean ± std) | 95% CI | total gas (mean) | all runs ok |");
    let _ = writeln!(md, "|---|---:|---:|---:|---:|:-:|");
    for s in summary {
        let _ = writeln!(
            md,
            "| {} | {} | {} ± {} | ± {} | {} | {} |",
            s.config,
            s.n,
            fmt_int(s.gas_per_op.mean),
            fmt_int(s.gas_per_op.std),
            fmt_int(s.gas_per_op.ci95),
            fmt_int(s.gas_total.mean),
            if s.all_success { "yes" } else { "**no**" }
        );
    }
    let _ = writeln!(md, "\n## Time and memory (measured pipeline configs)\n");
    let _ = writeln!(
        md,
        "| config | N | ML-DSA verify, all N (ms) | authorise (ms) | off-chain proof verify (ms) | EVM exec (ms) | end-to-end (ms, mean ± std) | e2e p95 (ms) | e2e / op (ms) | peak heap (MiB, max) |"
    );
    let _ = writeln!(md, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for s in summary.iter().filter(|s| s.config != Config::A0NativeModel.name()) {
        let _ = writeln!(
            md,
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} ± {:.2} | {:.2} | {:.3} | {:.1} |",
            s.config,
            s.n,
            s.mldsa_verify_ms.mean,
            s.prove_ms.mean,
            s.verify_offchain_ms.mean,
            s.verify_evm_ms.mean,
            s.e2e_ms.mean,
            s.e2e_ms.std,
            s.e2e_ms.p95,
            s.e2e_ms.mean / s.n as f64,
            s.peak_heap_bytes.max / (1024.0 * 1024.0)
        );
    }
    let _ = writeln!(
        md,
        "\n**Important:** \"authorise\" for A2/A3 is the proving time of the *binding* Groth16 circuit \
         (6 constraints). It is not the time to prove ML-DSA verification, which this prototype does not do \
         (see `offchain-cost.md` and docs/future-work-zkvm-linux.md).\n"
    );
    let _ = writeln!(md, "## Trust assumption per configuration\n");
    for c in &cfg.configs {
        let _ = writeln!(md, "- **{}**: {}", c.name(), c.trust());
    }
    md
}

/// Machine and software description recorded with every result set.
#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub cpu: String,
    pub logical_cpus: usize,
    pub mem_total: String,
    pub os: String,
    pub evm: &'static str,
    pub mldsa: &'static str,
    pub groth16: &'static str,
    pub rustc: String,
    pub git_commit: String,
    pub started_utc: String,
}

impl Environment {
    pub fn detect(rustc: String, git_commit: String, started_utc: String) -> Self {
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        let cpuinfo = read("/proc/cpuinfo");
        let cpu = cpuinfo
            .lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into());
        let mem_total = read("/proc/meminfo")
            .lines()
            .find(|l| l.starts_with("MemTotal"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into());
        let os = read("/etc/os-release")
            .lines()
            .find(|l| l.starts_with("PRETTY_NAME="))
            .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            .unwrap_or_else(|| std::env::consts::OS.to_string());
        Self {
            cpu,
            logical_cpus: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            mem_total,
            os,
            evm: EVM_SPEC_NAME,
            mldsa: "ML-DSA-44, pqcrypto-mldsa 0.1.2 (PQClean), FIPS 204 pure mode, empty context",
            groth16: "arkworks 0.4 (ark-groth16 0.4.0), BN254, binding circuit with 5 public inputs",
            rustc,
            git_commit,
            started_utc,
        }
    }

    pub fn markdown(&self) -> String {
        format!(
            "| item | value |\n|---|---|\n| CPU | {} |\n| logical CPUs visible | {} |\n| memory visible | {} |\n\
             | OS (container) | {} |\n| EVM | {} |\n| ML-DSA | {} |\n| Groth16 | {} |\n| rustc | {} |\n\
             | git commit | {} |\n| started (UTC) | {} |\n",
            self.cpu,
            self.logical_cpus,
            self.mem_total,
            self.os,
            self.evm,
            self.mldsa,
            self.groth16,
            self.rustc,
            self.git_commit,
            self.started_utc
        )
    }
}

/// Assumptions of the off-chain cost analysis (point 7). Every value here is
/// an explicit, documented assumption, not a measurement.
#[derive(Debug, Clone, Serialize)]
pub struct CostAssumptions {
    /// Per-signature zkVM proving times to evaluate (seconds); 12.4 s is the
    /// earlier draft's projection, not a measurement.
    pub prove_seconds_per_sig: Vec<f64>,
    /// Prover hardware cost in USD per hour.
    pub prover_usd_per_hour: f64,
    pub prover_label: String,
    pub gas_price_gwei: Vec<f64>,
    pub eth_usd: f64,
}

impl Default for CostAssumptions {
    fn default() -> Self {
        Self {
            prove_seconds_per_sig: vec![1.0, 5.0, 12.4, 30.0, 60.0],
            prover_usd_per_hour: 1.006,
            prover_label: "AWS g5.xlarge on-demand (1x A10G), us-east-1 list price — check before citing".into(),
            gas_price_gwei: vec![1.0, 10.0, 50.0],
            eth_usd: 3000.0,
        }
    }
}

/// Point 7: what moving verification off-chain costs, from measured on-chain
/// gas savings and a parametrised (projected) zkVM proving time.
pub fn offchain_cost_markdown(summary: &[SummaryRow], a: &CostAssumptions) -> String {
    let find = |c: Config, n: usize| summary.iter().find(|s| s.config == c.name() && s.n == n);
    let mut md = String::from("# Off-chain cost analysis (supervisor point 7)\n\n");
    let _ = writeln!(
        md,
        "## What is measured\n\n| N | off-chain ML-DSA verify per op (ms) | binding-circuit Groth16 prove per batch (ms) | \
         end-to-end per op, A3 (ms) | peak heap, A3 (MiB) |\n|---:|---:|---:|---:|---:|"
    );
    for s in summary.iter().filter(|s| s.config == Config::A3Groth16Batch.name()) {
        let _ = writeln!(
            md,
            "| {} | {:.3} | {:.2} | {:.3} | {:.1} |",
            s.n,
            s.mldsa_verify_ms.mean / s.n as f64,
            s.prove_ms.mean,
            s.e2e_ms.mean / s.n as f64,
            s.peak_heap_bytes.max / (1024.0 * 1024.0)
        );
    }
    let _ = writeln!(
        md,
        "\nThese are the only off-chain costs this prototype actually incurs. Proving ML-DSA *inside* a zkVM \
         is not implemented, so its cost is evaluated below as a parameter, not measured.\n"
    );
    let _ = writeln!(
        md,
        "## Projected cost of a sound proof\n\nAssumptions (all explicit): prover at ${:.3}/h ({}); ETH = ${:.0}; \
         proving time scales linearly with the number of signatures (no parallelism credited). The per-sig times \
         include 12.4 s, the earlier draft's projection for RISC Zero; it is **not** a measurement.\n",
        a.prover_usd_per_hour, a.prover_label, a.eth_usd
    );
    let native = find(Config::A0NativeModel, 1).map(|s| s.gas_per_op.mean);
    let sizes: Vec<usize> = summary.iter().filter(|s| s.config == Config::A3Groth16Batch.name()).map(|s| s.n).collect();
    if let Some(native) = native {
        let _ = writeln!(
            md,
            "Gas saved per op = native model ({}) − measured A3 gas/op at N. Off-chain $ per op = t_sig × price/3600.\n",
            fmt_int(native)
        );
        for &gwei in &a.gas_price_gwei {
            let _ = writeln!(md, "### Gas price {gwei} gwei\n");
            let mut header = String::from("| t_sig (s) | prover $/op |");
            let mut sep = String::from("|---:|---:|");
            for n in &sizes {
                let _ = write!(header, " net saving $/op, N={n} |");
                sep.push_str("---:|");
            }
            let _ = writeln!(md, "{header}\n{sep}");
            for &t in &a.prove_seconds_per_sig {
                let prover = t * a.prover_usd_per_hour / 3600.0;
                let mut line = format!("| {t} | {prover:.5} |");
                for &n in &sizes {
                    let ours = find(Config::A3Groth16Batch, n).map(|s| s.gas_per_op.mean).unwrap_or(f64::NAN);
                    let saved_usd = (native - ours) * gwei * 1e-9 * a.eth_usd;
                    let _ = write!(line, " {:.4} |", saved_usd - prover);
                }
                let _ = writeln!(md, "{line}");
            }
            let _ = writeln!(md);
        }
        let _ = writeln!(
            md,
            "A positive value means the off-chain proof costs less than the gas it saves. The break-even proving time \
             per signature is t* = gas_saved × gas_price × ETH / (price/3600).\n"
        );
        let _ = writeln!(md, "| gas price (gwei) | break-even t_sig at N=1 (s) | at largest N (s) |\n|---:|---:|---:|");
        for &gwei in &a.gas_price_gwei {
            let be = |n: usize| {
                let ours = find(Config::A3Groth16Batch, n).map(|s| s.gas_per_op.mean).unwrap_or(f64::NAN);
                (native - ours) * gwei * 1e-9 * a.eth_usd / (a.prover_usd_per_hour / 3600.0)
            };
            let largest = sizes.last().copied().unwrap_or(1);
            let _ = writeln!(md, "| {} | {:.0} | {:.0} |", gwei, be(1), be(largest));
        }
    }
    let _ = writeln!(
        md,
        "\n## Latency\n\nWith a sound zkVM proof, end-to-end latency per batch is at least N × t_sig on one prover \
         (plus the Groth16 wrap), so batching lowers *gas* per op but not *latency*; only parallel provers lower \
         wall-clock time. With the binding circuit used today, latency is dominated by off-chain ML-DSA \
         verification and EVM execution (table above)."
    );
    md
}
