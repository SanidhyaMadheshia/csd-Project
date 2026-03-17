use clap::{Parser, Subcommand};
use qevm_core::benchmark::{format_table, run_benchmarks};
use qevm_core::bundler::{create_user_op, sign_user_op_ml_dsa, user_op_to_hex_json, Bundler};
use qevm_core::crypto::{
    hex_decode, hex_encode, EcdsaSecp256k1, MlDsaDilithium2, SignatureScheme,
};

#[derive(Parser, Debug)]
#[command(name = "qevm-core", version, about = "Q-EVM Phase 1 prototype (Rust)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate ML-DSA and ECDSA keypairs (hex encoded)
    GenerateKeys,

    /// Sign a message with ML-DSA or ECDSA
    SignMessage {
        #[arg(long, default_value = "mldsa", value_parser = ["mldsa", "ecdsa"]) ]
        algo: String,
        /// Message bytes (utf8 string)
        message: String,
        /// Secret key in hex
        #[arg(long)]
        sk_hex: String,
    },

    /// Verify a message signature with ML-DSA or ECDSA
    VerifyMessage {
        #[arg(long, default_value = "mldsa", value_parser = ["mldsa", "ecdsa"]) ]
        algo: String,
        message: String,
        /// Public key in hex
        #[arg(long)]
        pk_hex: String,
        /// Signature in hex
        #[arg(long)]
        sig_hex: String,
    },

    /// Simulate a basic ERC-4337-style bundler flow with ML-DSA signatures
    SimulateBundler {
        #[arg(long, default_value_t = 5)]
        count: u64,
    },

    /// Run simple performance benchmarks (averaged over N iterations)
    RunBenchmarks {
        #[arg(long, default_value_t = 50)]
        iters: u32,
    },
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
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
        Commands::SimulateBundler { count } => cmd_simulate_bundler(count)?,
        Commands::RunBenchmarks { iters } => cmd_run_benchmarks(iters)?,
    }

    Ok(())
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

    println!("Signature(hex): {}", sig_hex);
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

    println!("Verified: {}", ok);
    Ok(())
}

fn cmd_simulate_bundler(count: u64) -> anyhow::Result<()> {
    let sender = "0xSender".to_string();
    let (pk, sk) = MlDsaDilithium2::keygen()?;

    let mut bundler = Bundler::new();
    bundler.register_sender(sender.clone(), pk);

    for i in 0..count {
        let mut uo = create_user_op(sender.clone(), i, format!("call:{}", i).into_bytes());
        sign_user_op_ml_dsa(&mut uo, &sk)?;
        let accepted = bundler.add_user_op(uo)?;
        println!("add_user_op nonce={} accepted={}", i, accepted);
    }

    let bundle = bundler.bundle_operations();
    println!("Bundled {} operations", bundle.len());

    // Print first op as JSON example
    if let Some(first) = bundle.first() {
        println!("First bundled UserOperation (hex-json):\n{}", user_op_to_hex_json(first)?);
    }

    Ok(())
}

fn cmd_run_benchmarks(iters: u32) -> anyhow::Result<()> {
    let rows = run_benchmarks(iters);
    print!("{}", format_table(&rows));
    Ok(())
}
