use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use qevm_core::{BundlerConfig, Node, NodeConfig};
use qevm_crypto::{
    hex_decode, hex_encode, EcdsaSecp256k1, MlDsaDilithium2, SignatureScheme,
};
use qevm_rpc::serve as serve_rpc;
use qevm_telemetry::{init_telemetry, TelemetryConfig};
use qevm_types::{Address, PqcPayload, UserOperation};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Duration;

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
    let (ml_pk, ml_sk) = MlDsaDilithium2::keygen()?;
    let (ec_pk, ec_sk) = EcdsaSecp256k1::keygen()?;

    println!("ML-DSA PublicKey(hex): {}", hex_encode(&MlDsaDilithium2::pk_to_bytes(&ml_pk)));
    println!("ML-DSA SecretKey(hex): {}", hex_encode(&MlDsaDilithium2::sk_to_bytes(&ml_sk)));
    println!("ECDSA  PublicKey(hex): {}", hex_encode(&EcdsaSecp256k1::pk_to_bytes(&ec_pk)));
    println!("ECDSA  SecretKey(hex): {}", hex_encode(&EcdsaSecp256k1::sk_to_bytes(&ec_sk)));
    Ok(())
}

fn cmd_sign_message(algo: &str, msg: &[u8], sk_hex: &str) -> anyhow::Result<()> {
    let sk_bytes = hex_decode(sk_hex)?;
    let sig_hex = match algo {
        "mldsa" => {
            let sk = MlDsaDilithium2::sk_from_bytes(&sk_bytes)?;
            let sig = MlDsaDilithium2::sign(msg, &sk)?;
            hex_encode(&MlDsaDilithium2::sig_to_bytes(&sig))
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
            let pk = MlDsaDilithium2::pk_from_bytes(&pk_bytes)?;
            let sig = MlDsaDilithium2::sig_from_bytes(&sig_bytes)?;
            MlDsaDilithium2::verify(msg, &sig, &pk)?
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

    let sender = Address::from_hex("0x0000000000000000000000000000000000000001")?;
    let (pk, sk) = MlDsaDilithium2::keygen()?;

    let progress = ProgressBar::new(count as u64);
    progress.set_style(
        ProgressStyle::with_template("{spinner:.green} {pos}/{len} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );

    for i in 0..count {
        let mut op = UserOperation::new(
            sender,
            i as u64,
            chain_id,
            format!("call:{}", i).into_bytes(),
            PqcPayload {
                public_key: MlDsaDilithium2::pk_to_bytes(&pk),
                signature: vec![],
            },
        )?;
        let sig = MlDsaDilithium2::sign(op.op_hash().as_bytes(), &sk)?;
        op.pqc_payload.signature = MlDsaDilithium2::sig_to_bytes(&sig);

        let outcome = node.submit_user_operation(op).await?;
        progress.set_message(format!("submitted {} (accepted={})", i, outcome.accepted));
        progress.inc(1);
    }

    progress.finish_with_message("user operations submitted");

    tokio::time::sleep(Duration::from_millis(200)).await;
    if let Some(batch) = node.bundle_next().await? {
        println!("Bundled batch {} with {} operations", batch.batch_id, batch.operations.len());
    }

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
        let outcome = node.submit_user_operation(op.to_user_op()?).await?;
        println!("replayed op {} accepted={}", outcome.op_hash, outcome.accepted);
    }
    Ok(())
}

fn cmd_benchmark(iters: u32) -> anyhow::Result<()> {
    let rows = qevm_core::run_benchmarks(iters);
    print!("{}", qevm_core::format_table(&rows));
    Ok(())
}
