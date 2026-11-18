use clap::{Parser, Subcommand};
use qevm_core::{BundlerConfig, Node, NodeConfig, NodeEvent};
use qevm_crypto::{
    hex_decode, hex_encode, EcdsaSecp256k1, MlDsa44, SignatureScheme,
};
use qevm_rpc::serve as serve_rpc;
use qevm_telemetry::{init_telemetry, TelemetryConfig};
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Global allocator that tracks live and peak heap bytes, so the experiment
/// harness can report peak memory per run without an external profiler.
struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn mem_reset() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

fn mem_peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

#[derive(Parser, Debug)]
#[command(name = "qevm", version, about = "Q-EVM Research Prototype")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start a local node with RPC enabled
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },

    /// Generate ML-DSA and ECDSA keypairs
    GenerateKeys,

    /// Sign a message with ML-DSA or ECDSA
    SignMessage {
        #[arg(long, default_value = "mldsa", value_parser = ["mldsa", "ecdsa"]) ]
        algo: String,
        message: String,
        #[arg(long)]
        sk_hex: String,
    },

    /// Verify a message signature
    VerifyMessage {
        #[arg(long, default_value = "mldsa", value_parser = ["mldsa", "ecdsa"]) ]
        algo: String,
        message: String,
        #[arg(long)]
        pk_hex: String,
        #[arg(long)]
        sig_hex: String,
    },

    /// Simulate bundler flow and create a batch
    Simulate {
        #[arg(long, default_value_t = 5)]
        count: usize,
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
    },

    /// Bundle the current mempool (in-process)
    Bundle {
        #[arg(long, default_value_t = 32)]
        batch_size: usize,
    },

    /// Replay a JSON file of UserOperationHex entries
    Replay {
        #[arg(long)]
        file: PathBuf,
    },

    /// Run crypto benchmarks
    Benchmark {
        #[arg(long, default_value_t = 50)]
        iters: u32,
    },

    /// Export ML-DSA-44 test vectors (pk, msg, sig) for the native baseline
    ExportMldsaVectors {
        #[arg(long, default_value_t = 100)]
        count: usize,
        #[arg(long, default_value = "results/native-baseline/vectors.json")]
        out: PathBuf,
    },

    /// Execute a compiled Solidity ML-DSA verifier on revm against exported vectors
    NativeBaseline {
        /// Hex init code (`solc --bin` output)
        #[arg(long)]
        bin: PathBuf,
        #[arg(long, default_value = "results/native-baseline/vectors.json")]
        vectors: PathBuf,
        /// JSON array of hex ABI-encoded expanded public keys, one per vector
        #[arg(long, default_value = "results/native-baseline/expanded.json")]
        expanded: PathBuf,
        #[arg(long, default_value = "results/native-baseline")]
        out: PathBuf,
        /// Description of the verifier source, recorded in the report
        #[arg(long, default_value = "unspecified")]
        source: String,
        /// Optional raw runtime (hex) of a helper contract to deploy first; its
        /// address is ABI-appended to the verifier's init code (constructor arg)
        #[arg(long)]
        helper_runtime: Option<PathBuf>,
    },

    /// Run the security / correctness case matrix and write a Markdown report
    SecurityReport {
        #[arg(long, default_value = "results/security.md")]
        out: PathBuf,
    },

    /// Run the paper's experiments (batch sweep + ablation) and write CSV/Markdown results
    Experiment {
        /// Comma-separated batch sizes
        #[arg(long, default_value = "1,2,4,8,16,32,64,128,256", value_delimiter = ',')]
        sizes: Vec<usize>,
        #[arg(long, default_value_t = 30)]
        repeats: usize,
        #[arg(long, default_value_t = 3)]
        warmup: usize,
        /// Comma-separated configs (A0,A1,A2,A3); default all
        #[arg(long, value_delimiter = ',')]
        configs: Vec<String>,
        /// Output directory
        #[arg(long, default_value = "results/latest")]
        out: PathBuf,
        /// Recorded in env.json (pass `rustc -V`)
        #[arg(long, default_value = "unknown")]
        rustc: String,
        /// Recorded in env.json (pass `git rev-parse HEAD`)
        #[arg(long, default_value = "unknown")]
        git_commit: String,
        /// Recorded in env.json (pass `date -u`)
        #[arg(long, default_value = "unknown")]
        started: String,
    },
}

#[derive(Subcommand, Debug)]
enum NodeCommand {
    Start {
        #[arg(long, default_value = "127.0.0.1:8080")]
        rpc_addr: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:9100")]
        metrics_addr: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Node { command } => match command {
            NodeCommand::Start { rpc_addr, metrics_addr } => cmd_node_start(rpc_addr, metrics_addr).await?,
        },
        Commands::GenerateKeys => cmd_generate_keys()?,
        Commands::SignMessage {
            algo,
            message,
            sk_hex,
        } => cmd_sign_message(&algo, message.as_bytes(), &sk_hex)?,
        Commands::VerifyMessage {
            algo,
            message,
            pk_hex,
            sig_hex,
        } => cmd_verify_message(&algo, message.as_bytes(), &pk_hex, &sig_hex)?,
        Commands::Simulate { count, chain_id } => cmd_simulate(count, chain_id).await?,
        Commands::Bundle { batch_size } => cmd_bundle(batch_size).await?,
        Commands::Replay { file } => cmd_replay(file).await?,
        Commands::Benchmark { iters } => cmd_benchmark(iters)?,
        Commands::ExportMldsaVectors { count, out } => {
            if let Some(dir) = out.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let v = qevm_core::native_baseline::export_vectors(count);
            std::fs::write(&out, serde_json::to_string_pretty(&v)?)?;
            println!("wrote {} vectors to {}", v.len(), out.display());
        }
        Commands::NativeBaseline { bin, vectors, expanded, out, source, helper_runtime } => {
            use qevm_core::native_baseline::*;
            let mut init = qevm_utils::hex_decode(std::fs::read_to_string(&bin)?.trim().trim_start_matches("0x"))?;
            let vectors: Vec<Vector> = serde_json::from_str(&std::fs::read_to_string(&vectors)?)?;
            let expanded: Vec<String> = serde_json::from_str(&std::fs::read_to_string(&expanded)?)?;
            let prover = qevm_zkvm::LocalZkvmProver::new(qevm_zkvm::ZkvmConfig::default());
            use qevm_zkvm::ZkvmProver;
            let chain = prover.chain();
            if let Some(h) = helper_runtime {
                let runtime = qevm_utils::hex_decode(std::fs::read_to_string(&h)?.trim().trim_start_matches("0x"))?;
                let dep = chain.deploy_runtime(&runtime).map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("helper deployed: {} bytes, {} gas", dep.code_size, dep.deploy_gas);
                let mut word = [0u8; 32];
                word[12..].copy_from_slice(&dep.address);
                init.extend_from_slice(&word);
            }
            let outcome = run_baseline(&chain, &init, &vectors, &expanded)?;
            std::fs::create_dir_all(&out)?;
            std::fs::write(out.join("baseline.csv"), baseline_csv(&outcome.rows))?;
            std::fs::write(out.join("baseline.md"), baseline_markdown(&outcome, &source))?;
            let bad = outcome.rows.iter().filter(|r| !r.valid_accepted || !r.tampered_rejected).count();
            println!("{} signatures measured, {} misbehaving; wrote {}", outcome.rows.len(), bad, out.display());
        }
        Commands::SecurityReport { out } => {
            let results = qevm_core::security::run_security_matrix().await;
            let failed = results.iter().filter(|r| !r.pass).count();
            if let Some(dir) = out.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&out, qevm_core::security::security_markdown(&results))?;
            std::fs::write(out.with_extension("json"), serde_json::to_string_pretty(&results)?)?;
            println!("{} cases, {} unexpected; wrote {}", results.len(), failed, out.display());
            if failed > 0 {
                anyhow::bail!("{failed} security cases did not behave as expected");
            }
        }
        Commands::Experiment { sizes, repeats, warmup, configs, out, rustc, git_commit, started } => {
            cmd_experiment(sizes, repeats, warmup, configs, out, rustc, git_commit, started).await?
        }
    }

    Ok(())
}

async fn cmd_node_start(rpc_addr: SocketAddr, metrics_addr: SocketAddr) -> anyhow::Result<()> {
    init_telemetry(TelemetryConfig {
        metrics_addr,
        ..TelemetryConfig::default()
    })?;

    let mut config = NodeConfig::default();
    config.bundler = BundlerConfig::default();
    let node = Arc::new(Node::new(config));

    println!("Starting Q-EVM node. RPC listening on {rpc_addr}");
    serve_rpc(rpc_addr, node).await
}

fn cmd_generate_keys() -> anyhow::Result<()> {
    let (ml_pk, ml_sk) = MlDsa44::keygen()?;
    let (ec_pk, ec_sk) = EcdsaSecp256k1::keygen()?;

    println!("ML-DSA PublicKey(hex): {}", hex_encode(&MlDsa44::pk_to_bytes(&ml_pk)));
    println!("ML-DSA SecretKey(hex): {}", hex_encode(&MlDsa44::sk_to_bytes(&ml_sk)));
    println!("ECDSA  PublicKey(hex): {}", hex_encode(&EcdsaSecp256k1::pk_to_bytes(&ec_pk)));
    println!("ECDSA  SecretKey(hex): {}", hex_encode(&EcdsaSecp256k1::sk_to_bytes(&ec_sk)));
    Ok(())
}

fn cmd_sign_message(algo: &str, msg: &[u8], sk_hex: &str) -> anyhow::Result<()> {
    let sk_bytes = hex_decode(sk_hex)?;
    let sig_hex = match algo {
        "mldsa" => {
            let sk = MlDsa44::sk_from_bytes(&sk_bytes)?;
            let sig = MlDsa44::sign(msg, &sk)?;
            hex_encode(&MlDsa44::sig_to_bytes(&sig))
        }
        "ecdsa" => {
            let sk = EcdsaSecp256k1::sk_from_bytes(&sk_bytes)?;
            let sig = EcdsaSecp256k1::sign(msg, &sk)?;
            hex_encode(&EcdsaSecp256k1::sig_to_bytes(&sig))
        }
        _ => unreachable!(),
    };

    println!("Signature(hex): {sig_hex}");
    Ok(())
}

fn cmd_verify_message(algo: &str, msg: &[u8], pk_hex: &str, sig_hex: &str) -> anyhow::Result<()> {
    let pk_bytes = hex_decode(pk_hex)?;
    let sig_bytes = hex_decode(sig_hex)?;

    let ok = match algo {
        "mldsa" => {
            let pk = MlDsa44::pk_from_bytes(&pk_bytes)?;
            let sig = MlDsa44::sig_from_bytes(&sig_bytes)?;
            MlDsa44::verify(msg, &sig, &pk)?
        }
        "ecdsa" => {
            let pk = EcdsaSecp256k1::pk_from_bytes(&pk_bytes)?;
            let sig = EcdsaSecp256k1::sig_from_bytes(&sig_bytes)?;
            EcdsaSecp256k1::verify(msg, &sig, &pk)?
        }
        _ => unreachable!(),
    };

    println!("Verified: {ok}");
    Ok(())
}

async fn cmd_simulate(count: usize, chain_id: u64) -> anyhow::Result<()> {
    init_telemetry(TelemetryConfig::default())?;
    let node = Arc::new(Node::new(NodeConfig::default()));

    let mut events = node.subscribe();
    let printer = tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            match event {
                NodeEvent::UserOperationAccepted { op_hash, onchain_gas, native_gas, prove_time_ms } => println!(
                    "accepted {op_hash}  on-chain {onchain_gas} gas (measured)  native {native_gas} gas (metered)  prove {prove_time_ms:.1} ms"
                ),
                NodeEvent::UserOperationRejected { op_hash, reason } => println!("rejected {op_hash}: {reason}"),
                NodeEvent::BatchCreated { batch_id, size, .. } => println!("Bundled batch {batch_id} with {size} operations"),
            }
        }
    });

    let demo = node.run_demo(count, chain_id).await?;
    drop(node);
    let _ = printer.await;

    let a = &demo.analysis;
    println!();
    println!("Gas analysis over {} receipts", a.samples);
    println!("  single-op wallet tx (Groth16, EVM gas_used, simulated): avg {}  min {}  max {}", a.onchain_avg, a.onchain_min, a.onchain_max);
    println!("  native ML-DSA-44 verify (opcode cost MODEL, not executed): avg {}", a.native_avg);
    println!("  reduction vs model: {:.2}%  ({} gas saved per op)", a.reduction_percent, a.gas_saved_avg);
    for batch in &demo.batches {
        println!(
            "  batch of {} ({:?}): one wallet tx, {} gas on-chain = {:.0} gas per op, included={}",
            batch.size, batch.kind, batch.onchain_gas.total, batch.gas_per_op, batch.included
        );
    }
    println!("  note: the Groth16 receipt binds the batch digest; it does not prove ML-DSA verification");
    println!(
        "  paper reference: {} -> {} gas ({:.1}%)",
        a.paper.native_gas, a.paper.groth16_gas, a.paper.reduction_percent
    );
    Ok(())
}

async fn cmd_bundle(batch_size: usize) -> anyhow::Result<()> {
    init_telemetry(TelemetryConfig::default())?;
    let mut config = NodeConfig::default();
    config.bundler.batch_size = batch_size;
    let node = Arc::new(Node::new(config));

    if let Some(batch) = node.bundle_next().await? {
        println!("Bundled batch {} with {} operations", batch.batch_id, batch.operations.len());
    } else {
        println!("No operations available in mempool");
    }
    Ok(())
}

async fn cmd_replay(file: PathBuf) -> anyhow::Result<()> {
    init_telemetry(TelemetryConfig::default())?;
    let node = Arc::new(Node::new(NodeConfig::default()));
    let raw = tokio::fs::read_to_string(file).await?;
    let ops: Vec<qevm_types::UserOperationHex> = serde_json::from_str(&raw)?;

    for op in ops {
        let outcome = node.submit_user_operation(op.to_user_op(node.wallet_address())?).await?;
        match outcome.rejection {
            None => println!("replayed op {} accepted", outcome.op_hash),
            Some(why) => println!("replayed op {} rejected: {why}", outcome.op_hash),
        }
    }
    Ok(())
}

fn cmd_benchmark(iters: u32) -> anyhow::Result<()> {
    let rows = qevm_core::run_benchmarks(iters);
    print!("{}", qevm_core::format_table(&rows));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_experiment(
    sizes: Vec<usize>,
    repeats: usize,
    warmup: usize,
    configs: Vec<String>,
    out: PathBuf,
    rustc: String,
    git_commit: String,
    started: String,
) -> anyhow::Result<()> {
    use qevm_core::experiment::*;
    let configs = if configs.is_empty() {
        Config::ALL.to_vec()
    } else {
        configs
            .iter()
            .map(|c| Config::parse(c).ok_or_else(|| anyhow::anyhow!("unknown config {c}")))
            .collect::<anyhow::Result<Vec<_>>>()?
    };
    let cfg = ExperimentConfig {
        configs,
        sizes,
        repeats,
        warmup,
        mem: Some(MemHooks { reset: mem_reset, peak: mem_peak }),
        ..Default::default()
    };
    let env = Environment::detect(rustc, git_commit, started);
    std::fs::create_dir_all(&out)?;
    let total = cfg.configs.len() * cfg.sizes.len() * cfg.repeats;
    let mut done = 0usize;
    let rows = run_experiments(&cfg, |r| {
        done += 1;
        if r.run + 1 == cfg.repeats {
            eprintln!(
                "[{done}/{total}] {} N={} gas/op={:.0} e2e={:.1}ms ok={}",
                r.config, r.n, r.gas_per_op, r.e2e_ms, r.success
            );
        }
    })
    .await;
    let summary = summarize(&rows);
    std::fs::write(out.join("runs.csv"), to_csv(&rows))?;
    std::fs::write(out.join("summary.csv"), summary_csv(&summary))?;
    std::fs::write(out.join("summary.json"), serde_json::to_string_pretty(&summary)?)?;
    std::fs::write(out.join("summary.md"), summary_markdown(&summary, &cfg, &env))?;
    std::fs::write(out.join("env.json"), serde_json::to_string_pretty(&env)?)?;
    let assumptions = CostAssumptions::default();
    std::fs::write(out.join("offchain-cost.md"), offchain_cost_markdown(&summary, &assumptions))?;
    std::fs::write(out.join("cost-assumptions.json"), serde_json::to_string_pretty(&assumptions)?)?;
    println!("wrote {} runs to {}", rows.len(), out.display());
    Ok(())
}
