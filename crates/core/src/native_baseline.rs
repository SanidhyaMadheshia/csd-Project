//! Executable native ML-DSA-44 baseline (supervisor point 5).
//!
//! The opcode cost model (`qevm_evm::native_mldsa`) is calibrated to a
//! published figure, so comparing Q-EVM against it is not a like-for-like
//! measurement. This module instead *executes* a third-party Solidity ML-DSA-44
//! verifier (ZKNox ETHDILITHIUM, NIST/FIPS 204 variant) on the **same** revm
//! chain and hard fork as the Q-EVM contracts, with the **same** FIPS 204 keys,
//! messages (op hashes) and signatures, and records the EVM's `gas_used`.
//!
//! Pipeline (scripts/native-baseline.sh):
//! 1. `qevm-cli export-mldsa-vectors` writes keys, messages and signatures;
//! 2. ZKNox's Python reference expands each public key into the contract's
//!    stored format (Â in the NTT domain, tr, NTT(t1·2^d));
//! 3. `qevm-cli native-baseline` deploys the compiled verifier, stores each key
//!    with `setKey(bytes)`, and calls `verify(bytes,bytes32,bytes)` for the
//!    valid signature and a tampered one.

use qevm_crypto::{MlDsa44, SignatureScheme};
use qevm_evm::{estimate_native_gas, keccak, LocalChain};
use qevm_utils::{hex_decode, hex_encode};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector {
    pub pk: String,
    pub msg: String,
    pub sig: String,
}

/// `count` fresh ML-DSA-44 keys, each signing one random 32-byte message.
pub fn export_vectors(count: usize) -> Vec<Vector> {
    (0..count)
        .map(|i| {
            let (pk, sk) = MlDsa44::keygen().expect("keygen");
            let msg = keccak(&[b"qevm-native-baseline".as_slice(), &(i as u64).to_be_bytes()].concat());
            let sig = MlDsa44::sign(&msg, &sk).expect("sign");
            Vector {
                pk: hex_encode(&MlDsa44::pk_to_bytes(&pk)),
                msg: hex_encode(&msg),
                sig: hex_encode(&MlDsa44::sig_to_bytes(&sig)),
            }
        })
        .collect()
}

fn selector(sig: &str) -> [u8; 4] {
    keccak(sig.as_bytes())[..4].try_into().expect("4 bytes")
}

fn word(v: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(v as u64).to_be_bytes());
    w
}

fn padded(b: &[u8]) -> Vec<u8> {
    let mut out = b.to_vec();
    out.resize(b.len().div_ceil(32) * 32, 0);
    out
}

/// ABI: `setKey(bytes)`.
fn set_key_calldata(blob: &[u8]) -> Vec<u8> {
    let mut cd = selector("setKey(bytes)").to_vec();
    cd.extend_from_slice(&word(32));
    cd.extend_from_slice(&word(blob.len()));
    cd.extend_from_slice(&padded(blob));
    cd
}

/// ABI: `verify(bytes pk, bytes32 m, bytes signature)`.
fn verify_calldata(pk: &[u8], m: &[u8; 32], sig: &[u8]) -> Vec<u8> {
    let mut cd = selector("verify(bytes,bytes32,bytes)").to_vec();
    let pk_tail = 32 + padded(pk).len();
    cd.extend_from_slice(&word(96)); // offset of pk
    cd.extend_from_slice(m);
    cd.extend_from_slice(&word(96 + pk_tail)); // offset of signature
    cd.extend_from_slice(&word(pk.len()));
    cd.extend_from_slice(&padded(pk));
    cd.extend_from_slice(&word(sig.len()));
    cd.extend_from_slice(&padded(sig));
    cd
}

/// Decode an ABI `bytes` return value.
fn decode_bytes(out: &[u8]) -> Option<Vec<u8>> {
    if out.len() < 64 {
        return None;
    }
    let len = u64::from_be_bytes(out[56..64].try_into().ok()?) as usize;
    out.get(64..64 + len).map(<[u8]>::to_vec)
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineRow {
    pub index: usize,
    pub set_key_gas: u64,
    /// `gas_used` of the `verify` transaction (21,000 + calldata + execution).
    pub verify_gas: u64,
    pub verify_calldata_bytes: usize,
    pub valid_accepted: bool,
    pub tampered_rejected: bool,
    /// The opcode cost model's estimate for the same key, message and signature.
    pub model_gas: u64,
}

pub struct BaselineOutcome {
    pub deploy_gas: u64,
    pub code_size: usize,
    pub rows: Vec<BaselineRow>,
}

/// Deploy `init_code` and measure every vector. `expanded[i]` is the ABI blob for `vectors[i].pk`.
pub fn run_baseline(
    chain: &LocalChain,
    init_code: &[u8],
    vectors: &[Vector],
    expanded: &[String],
) -> anyhow::Result<BaselineOutcome> {
    anyhow::ensure!(vectors.len() == expanded.len(), "one expanded key per vector");
    let dep = chain.deploy_init_code(init_code).map_err(|e| anyhow::anyhow!("{e}"))?;
    let ok_selector = selector("verify(bytes,bytes32,bytes)");
    let mut rows = Vec::new();
    for (i, (v, blob)) in vectors.iter().zip(expanded).enumerate() {
        let pk = hex_decode(&v.pk)?;
        let msg: [u8; 32] = hex_decode(&v.msg)?.try_into().map_err(|_| anyhow::anyhow!("msg must be 32 bytes"))?;
        let sig = hex_decode(&v.sig)?;
        let blob = hex_decode(blob.trim_start_matches("0x"))?;

        let (out, set_key_gas, ok) =
            chain.send_raw(dep.address, &set_key_calldata(&blob)).map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(ok, "setKey reverted for vector {i}");
        let pointer = decode_bytes(&out).ok_or_else(|| anyhow::anyhow!("bad setKey return"))?;

        let cd = verify_calldata(&pointer, &msg, &sig);
        let (out, verify_gas, ok) = chain.call_raw(dep.address, &cd).map_err(|e| anyhow::anyhow!("{e}"))?;
        let valid_accepted = ok && out.len() >= 4 && out[..4] == ok_selector;

        let mut bad = sig.clone();
        bad[40] ^= 1;
        let (out, _, ok) =
            chain.call_raw(dep.address, &verify_calldata(&pointer, &msg, &bad)).map_err(|e| anyhow::anyhow!("{e}"))?;
        let tampered_rejected = !(ok && out.len() >= 4 && out[..4] == ok_selector);

        let model_gas = estimate_native_gas(&pk, &sig, &msg).map(|g| g.total).unwrap_or(0);
        rows.push(BaselineRow {
            index: i,
            set_key_gas,
            verify_gas,
            verify_calldata_bytes: cd.len(),
            valid_accepted,
            tampered_rejected,
            model_gas,
        });
    }
    Ok(BaselineOutcome { deploy_gas: dep.deploy_gas, code_size: dep.code_size, rows })
}

pub fn baseline_csv(rows: &[BaselineRow]) -> String {
    let mut out =
        String::from("index,set_key_gas,verify_gas,verify_calldata_bytes,valid_accepted,tampered_rejected,model_gas\n");
    for r in rows {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{}",
            r.index, r.set_key_gas, r.verify_gas, r.verify_calldata_bytes, r.valid_accepted, r.tampered_rejected, r.model_gas
        );
    }
    out
}

pub fn baseline_markdown(o: &BaselineOutcome, source: &str) -> String {
    let verify: Vec<f64> = o.rows.iter().map(|r| r.verify_gas as f64).collect();
    let set_key: Vec<f64> = o.rows.iter().map(|r| r.set_key_gas as f64).collect();
    let model: Vec<f64> = o.rows.iter().map(|r| r.model_gas as f64).collect();
    let v = crate::experiment::stat(&verify);
    let k = crate::experiment::stat(&set_key);
    let m = crate::experiment::stat(&model);
    let accepted = o.rows.iter().filter(|r| r.valid_accepted).count();
    let rejected = o.rows.iter().filter(|r| r.tampered_rejected).count();
    let mut md = String::from("# Executable native ML-DSA-44 baseline (supervisor point 5)\n\n");
    let _ = writeln!(md, "Verifier: {source}\n");
    let _ = writeln!(
        md,
        "Executed on the same revm chain and hard fork as the Q-EVM contracts (`qevm_evm::LocalChain`, {}), \
         with the same FIPS 204 ML-DSA-44 implementation (`pqcrypto-mldsa` 0.1.2) for keys and signatures.\n",
        qevm_evm::EVM_SPEC_NAME
    );
    let _ = writeln!(md, "- Signatures: {}", o.rows.len());
    let _ = writeln!(md, "- Valid signatures accepted: {accepted}/{}", o.rows.len());
    let _ = writeln!(md, "- Tampered signatures rejected: {rejected}/{}", o.rows.len());
    let _ = writeln!(md, "- Verifier deployment: {} gas, {} bytes of code\n", o.deploy_gas, o.code_size);
    let _ = writeln!(md, "| quantity | mean | std | median | min | max |\n|---|---:|---:|---:|---:|---:|");
    for (name, s) in [
        ("`verify` transaction gas (measured)", v),
        ("`setKey` once per account (measured)", k),
        ("opcode cost model, same inputs", m),
    ] {
        let _ = writeln!(md, "| {name} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} |", s.mean, s.std, s.median, s.min, s.max);
    }
    let _ = writeln!(
        md,
        "\nModel error vs. this executed verifier: {:+.1}% (mean). The model approximates an optimised Yul verifier \
         and is *not* a substitute for this measurement. The ZKNox verifier stores an expanded public key \
         (Â, tr, NTT(t1·2^d)) on-chain once per account (`setKey`); per-signature cost is the `verify` row.\n",
        (m.mean - v.mean) / v.mean * 100.0
    );
    md
}
