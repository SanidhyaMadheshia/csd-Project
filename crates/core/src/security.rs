//! Security and correctness evaluation (supervisor point 6).
//!
//! Runs a fixed matrix of attack / malformed-input cases through the real
//! pipeline (bundler + off-chain FIPS 204 verification + wallet on revm) and
//! records expected vs. observed outcomes. The same matrix is asserted by a
//! test and written to `results/security.md` by `qevm-cli security-report`.

use qevm_bundler::{Bundler, BundlerConfig, ProofMode};
use qevm_crypto::{MlDsa44, SignatureScheme, MLDSA44_SIG_LEN};
use qevm_evm::{proof_bytes, wallet_calldata, Groth16Keys, ReceiptStatement, WalletOp, GROTH16_AUTH_LEN};
use qevm_storage::InMemoryStorage;
use qevm_types::{batch_digest_of, Address, PqcPayload, UserOperation, WalletKind};
use qevm_utils::keccak256;
use qevm_zkvm::{LocalZkvmProver, ZkvmConfig, ZkvmProver};
use serde::Serialize;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub category: &'static str,
    pub case: String,
    /// Where the case is decided: `bundler` (off-chain) or `wallet` (on-chain).
    pub layer: &'static str,
    pub expected: &'static str,
    pub observed: String,
    pub pass: bool,
}

const ACCEPT: &str = "accepted";
const REJECT: &str = "rejected";
/// Expected outcome of the soundness negative control.
pub const GAP: &str = "accepted (documented gap C1)";

struct Env {
    prover: Arc<LocalZkvmProver>,
    bundler: Bundler,
    counter: AtomicU64,
}

struct Account {
    sender: Address,
    pk: Vec<u8>,
    sk: <MlDsa44 as SignatureScheme>::SecretKey,
}

impl Env {
    fn new() -> Self {
        let prover = Arc::new(LocalZkvmProver::new(ZkvmConfig::default()));
        let bundler = Self::bundler_for(&prover);
        Self { prover, bundler, counter: AtomicU64::new(1) }
    }

    fn bundler_for(prover: &Arc<LocalZkvmProver>) -> Bundler {
        Bundler::new(
            BundlerConfig {
                mode: ProofMode::Batch(WalletKind::Groth16),
                reference_receipts: false,
                batch_size: 256,
                ..Default::default()
            },
            Arc::new(InMemoryStorage::new(1024)),
            prover.clone() as Arc<dyn ZkvmProver>,
        )
    }

    fn wallet(&self) -> Address {
        Address::new(self.prover.chain().wallet(WalletKind::Groth16).address)
    }

    fn account(&self) -> Account {
        let (pk, sk) = MlDsa44::keygen().expect("keygen");
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut a = [0u8; 20];
        a[0] = 0x5e;
        a[12..].copy_from_slice(&id.to_be_bytes());
        let pk = MlDsa44::pk_to_bytes(&pk);
        self.prover.chain().register_account(&a, keccak256(&pk), 0);
        Account { sender: Address::new(a), pk, sk }
    }

    fn unsigned(&self, acc: &Account, nonce: u64) -> UserOperation {
        UserOperation::new(
            self.wallet(),
            acc.sender,
            nonce,
            1,
            b"transfer".to_vec(),
            PqcPayload { public_key: acc.pk.clone(), signature: vec![] },
        )
        .expect("op")
    }

    fn sign(op: &mut UserOperation, sk: &<MlDsa44 as SignatureScheme>::SecretKey) {
        let sig = MlDsa44::sign(op.op_hash().as_bytes(), sk).expect("sign");
        op.pqc_payload.signature = MlDsa44::sig_to_bytes(&sig);
    }

    fn signed(&self, acc: &Account, nonce: u64) -> UserOperation {
        let mut op = self.unsigned(acc, nonce);
        Self::sign(&mut op, &acc.sk);
        op
    }

    async fn submit(&self, op: UserOperation) -> String {
        Self::submit_with(&self.bundler, op).await
    }

    async fn submit_with(bundler: &Bundler, op: UserOperation) -> String {
        let out = bundler.submit_user_operation(op).await.expect("submit");
        match out.rejection {
            None => ACCEPT.to_string(),
            Some(why) => format!("{REJECT}: {why}"),
        }
    }

    /// Bundle everything pending and report whether the wallet accepted it.
    async fn bundle(&self) -> String {
        match self.bundler.bundle_next().await.expect("bundle") {
            None => "nothing to bundle".into(),
            Some(b) => {
                let ok = b.transactions.iter().all(|t| t.inclusion.map(|i| i.committed).unwrap_or(false));
                if ok {
                    format!("{ACCEPT}: included ({} ops)", b.operations.len())
                } else {
                    format!("{REJECT}: wallet reverted")
                }
            }
        }
    }

    fn send(&self, calldata: &[u8]) -> String {
        let chain = self.prover.chain();
        let out = chain.send(chain.wallet(WalletKind::Groth16).address, calldata).expect("tx");
        if out.committed {
            format!("{ACCEPT} (gas {})", out.gas.total)
        } else {
            format!("{REJECT}: wallet reverted (gas {})", out.gas.total)
        }
    }

    fn program(&self) -> [u8; 32] {
        keccak256(ZkvmConfig::default().program_id.as_bytes())
    }

    fn prove_digest(&self, keys: &Groth16Keys, digest: [u8; 32], program: [u8; 32]) -> Vec<u8> {
        keys.prove(&ReceiptStatement { digest, program }, 3).expect("prove")
    }
}

fn outcome(expected: &'static str, observed: &str) -> bool {
    if expected == GAP {
        observed.starts_with(ACCEPT)
    } else {
        observed.starts_with(expected)
    }
}

struct Matrix(Vec<CaseResult>);

impl Matrix {
    fn push(&mut self, category: &'static str, case: impl Into<String>, layer: &'static str, expected: &'static str, observed: String) {
        let pass = outcome(expected, &observed);
        self.0.push(CaseResult { category, case: case.into(), layer, expected, observed, pass });
    }
}

/// Run the full matrix.
pub async fn run_security_matrix() -> Vec<CaseResult> {
    let env = Env::new();
    let mut m = Matrix(Vec::new());

    // ---------------------------------------------------------------- valid
    for n in [1usize, 8, 64] {
        let mut sub = Vec::new();
        for _ in 0..n {
            let acc = env.account();
            sub.push(env.submit(env.signed(&acc, 0)).await);
        }
        let all = sub.iter().all(|s| s.starts_with(ACCEPT));
        let included = env.bundle().await;
        let observed = if all { included } else { format!("{REJECT}: submission failed") };
        m.push("valid", format!("{n} valid ops, one batch"), "bundler+wallet", ACCEPT, observed);
    }

    // ------------------------------------------------- invalid signatures
    let acc = env.account();
    let base = env.signed(&acc, 0);
    let other = env.account();
    let sig_cases: Vec<(&str, Box<dyn Fn(&mut Vec<u8>)>)> = vec![
        ("bit flip in c~ (challenge hash)", Box::new(|s| s[0] ^= 1)),
        ("bit flip in z (response)", Box::new(|s| s[32 + 700] ^= 0x10)),
        ("bit flip in h (hint positions)", Box::new(|s| s[32 + 2304] ^= 0x01)),
        ("malformed hint counts (non-monotonic)", Box::new(|s| {
            let n = s.len();
            s[n - 4..].copy_from_slice(&[60, 10, 70, 80]);
        })),
        ("truncated signature (2419 bytes)", Box::new(|s| { s.pop(); })),
        ("extended signature (2421 bytes)", Box::new(|s| s.push(0))),
        ("all-zero signature", Box::new(|s| s.iter_mut().for_each(|b| *b = 0))),
    ];
    for (what, mutate) in sig_cases {
        let mut op = base.clone();
        mutate(&mut op.pqc_payload.signature);
        m.push("invalid signature", what, "bundler", REJECT, env.submit(op).await);
    }
    {
        // Signed with another account's key, but carrying this account's pk.
        let mut op = env.unsigned(&acc, 0);
        Env::sign(&mut op, &other.sk);
        m.push("invalid signature", "signed with a different key", "bundler", REJECT, env.submit(op).await);
        // Valid signature, but over a different message.
        let mut op = env.unsigned(&acc, 0);
        let sig = MlDsa44::sign(b"some other message", &acc.sk).expect("sign");
        op.pqc_payload.signature = MlDsa44::sig_to_bytes(&sig);
        m.push("invalid signature", "signature over another message", "bundler", REJECT, env.submit(op).await);
        assert_eq!(base.pqc_payload.signature.len(), MLDSA44_SIG_LEN);
    }

    // ------------------------------------- op modified after signing
    let field_cases: Vec<(&str, Box<dyn Fn(&mut UserOperation)>)> = vec![
        ("call data changed", Box::new(|o| o.call_data.push(1))),
        ("nonce changed", Box::new(|o| o.nonce += 1)),
        ("chain id changed", Box::new(|o| o.chain_id += 1)),
        ("wallet address changed", Box::new(|o| o.wallet = Address::new([0x77; 20]))),
    ];
    for (what, mutate) in field_cases {
        let mut op = base.clone();
        mutate(&mut op);
        m.push("modified op hash", what, "bundler", REJECT, env.submit(op).await);
    }
    {
        let mut op = base.clone();
        op.sender = other.sender; // other's registered key differs from op.pk
        m.push("modified op hash", "sender changed", "bundler", REJECT, env.submit(op).await);
        let mut op = base.clone();
        op.pqc_payload.public_key = other.pk.clone();
        m.push("modified op hash", "public key swapped", "bundler", REJECT, env.submit(op).await);
    }

    // ------------------------------------------------------- key binding
    {
        let (pk, sk) = MlDsa44::keygen().expect("keygen");
        let mut op = UserOperation::new(
            env.wallet(),
            Address::new([0xab; 20]),
            0,
            1,
            b"x".to_vec(),
            PqcPayload { public_key: MlDsa44::pk_to_bytes(&pk), signature: vec![] },
        )
        .expect("op");
        Env::sign(&mut op, &sk);
        m.push("key binding", "unregistered sender (valid signature)", "bundler", REJECT, env.submit(op).await);
        let stranger = MlDsa44::keygen().expect("keygen");
        let mut op = env.unsigned(&acc, 0);
        op.pqc_payload.public_key = MlDsa44::pk_to_bytes(&stranger.0);
        Env::sign(&mut op, &stranger.1);
        m.push("key binding", "registered sender, op signed by an unregistered key", "bundler", REJECT, env.submit(op).await);
    }

    // ------------------------------------------------------------ replay
    {
        let acc = env.account();
        let op = env.signed(&acc, 0);
        m.push("replay", "first submission (control)", "bundler", ACCEPT, env.submit(op.clone()).await);
        m.push("replay", "same op again, before bundling", "bundler", REJECT, env.submit(op.clone()).await);
        let included = env.bundle().await;
        m.push("replay", "bundle the original (control)", "wallet", ACCEPT, included);
        m.push("replay", "same op again, after inclusion", "bundler", REJECT, env.submit(op.clone()).await);
        let fresh = Env::bundler_for(&env.prover);
        m.push(
            "replay",
            "same op to a fresh bundler (mempool state lost)",
            "bundler (reads on-chain nonce)",
            REJECT,
            Env::submit_with(&fresh, op.clone()).await,
        );
        // On-chain: resend the exact wallet transaction / a re-randomised proof.
        let acc = env.account();
        let ops = vec![env.signed(&acc, 0)];
        let batch = env.prover.authorize_batch(&ops, WalletKind::Groth16).await.expect("authorize");
        m.push("replay", "wallet tx (control)", "wallet", ACCEPT, env.send(&batch.wallet_calldata));
        m.push("replay", "identical wallet tx resent", "wallet", REJECT, env.send(&batch.wallet_calldata));
        let keys = env.prover.keys();
        let st = ReceiptStatement { digest: *batch.digest.as_bytes(), program: env.program() };
        let full = qevm_evm::full_calldata(&batch.proof, &st);
        let rerand = keys.rerandomize(&full, 77).expect("rerandomize");
        let records: Vec<WalletOp> = ops.iter().map(UserOperation::to_wallet_op).collect();
        m.push(
            "replay",
            "re-randomised proof (different bytes, same statement)",
            "wallet",
            REJECT,
            env.send(&wallet_calldata(proof_bytes(&rerand), &records)),
        );
    }

    // ------------------------------------------------------ altered batch
    {
        let accs: Vec<Account> = (0..4).map(|_| env.account()).collect();
        let ops: Vec<UserOperation> = accs.iter().map(|a| env.signed(a, 0)).collect();
        let extra = env.account();
        let extra_op = env.signed(&extra, 0);
        let batch = env.prover.authorize_batch(&ops, WalletKind::Groth16).await.expect("authorize");
        let rec = |v: &[UserOperation]| v.iter().map(UserOperation::to_wallet_op).collect::<Vec<_>>();
        let variants: Vec<(&str, Vec<UserOperation>)> = vec![
            ("two ops reordered", vec![ops[1].clone(), ops[0].clone(), ops[2].clone(), ops[3].clone()]),
            ("one op dropped", ops[..3].to_vec()),
            ("one op added", [ops.clone(), vec![extra_op]].concat()),
            ("one op duplicated", [ops.clone(), vec![ops[0].clone()]].concat()),
        ];
        for (what, v) in variants {
            m.push("altered batch", what, "wallet", REJECT, env.send(&wallet_calldata(&batch.proof, &rec(&v))));
        }
        let mut cd = batch.wallet_calldata.clone();
        cd[GROTH16_AUTH_LEN + 31] += 1;
        m.push("altered batch", "N header changed", "wallet", REJECT, env.send(&cd));
        m.push("altered batch", "truncated calldata", "wallet", REJECT, env.send(&batch.wallet_calldata[..batch.wallet_calldata.len() - 1]));
        m.push("altered batch", "untouched batch (control)", "wallet", ACCEPT, env.send(&batch.wallet_calldata));
    }

    // ------------------------------------------------------ invalid proofs
    {
        let acc = env.account();
        let ops = vec![env.signed(&acc, 0)];
        let records: Vec<WalletOp> = ops.iter().map(UserOperation::to_wallet_op).collect();
        let digest = batch_digest_of(&ops);
        let keys = env.prover.keys();
        let good = env.prove_digest(&keys, digest, env.program());
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("all-zero proof", vec![0u8; GROTH16_AUTH_LEN]),
            ("random bytes", (0..GROTH16_AUTH_LEN).map(|i| (i * 37 % 251) as u8).collect()),
        ];
        let mut a = proof_bytes(&good).to_vec();
        a[31] ^= 1;
        cases.push(("A point not on the curve", a));
        let mut c = proof_bytes(&good).to_vec();
        c[255] ^= 1;
        cases.push(("C point tampered", c));
        let foreign = Groth16Keys::setup(999).expect("setup");
        cases.push(("proof from another trusted setup", proof_bytes(&env.prove_digest(&foreign, digest, env.program())).to_vec()));
        cases.push(("proof for another program id", proof_bytes(&env.prove_digest(&keys, digest, [0x13; 32])).to_vec()));
        let wallet = env.prover.chain().wallet(WalletKind::Groth16).address;
        let other_chain = qevm_evm::batch_digest(&[ops[0].to_wallet_op().op_hash(2, &wallet)]);
        cases.push(("proof for the same op on another chain id", proof_bytes(&env.prove_digest(&keys, other_chain, env.program())).to_vec()));
        let other_wallet = qevm_evm::batch_digest(&[ops[0].to_wallet_op().op_hash(1, &[0x42; 20])]);
        cases.push(("proof for the same op on another wallet", proof_bytes(&env.prove_digest(&keys, other_wallet, env.program())).to_vec()));
        for (what, proof) in cases {
            m.push("invalid proof", what, "wallet", REJECT, env.send(&wallet_calldata(&proof, &records)));
        }
        m.push("invalid proof", "valid proof (control)", "wallet", ACCEPT, env.send(&wallet_calldata(proof_bytes(&good), &records)));
    }

    // -------------------------------------------------- soundness control
    {
        let acc = env.account();
        // No signature at all: the attacker proves the digest directly.
        let op = env.unsigned(&acc, 0);
        let records = vec![op.to_wallet_op()];
        let keys = env.prover.keys();
        let forged = env.prove_digest(&keys, batch_digest_of(std::slice::from_ref(&op)), env.program());
        m.push(
            "soundness (negative control)",
            "unsigned op, proof made directly with the public proving key",
            "wallet",
            GAP,
            env.send(&wallet_calldata(proof_bytes(&forged), &records)),
        );
    }
    m.0
}

pub fn security_markdown(results: &[CaseResult]) -> String {
    let passed = results.iter().filter(|r| r.pass).count();
    let mut md = String::from("# Security and correctness evaluation (supervisor point 6)\n\n");
    let _ = writeln!(
        md,
        "Generated by `qevm-cli security-report`. Every case runs through the real pipeline: bundler validation, \
         off-chain FIPS 204 verification (ML-DSA-44), and the wallet contract on revm with committed state. \
         **{passed}/{} cases behave as expected.**\n",
        results.len()
    );
    let _ = writeln!(md, "| # | category | case | decided by | expected | observed | ok |\n|---:|---|---|---|---|---|:-:|");
    for (i, r) in results.iter().enumerate() {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} |",
            i + 1,
            r.category,
            r.case,
            r.layer,
            r.expected,
            r.observed.replace('|', "/"),
            if r.pass { "✓" } else { "✗" }
        );
    }
    let _ = writeln!(
        md,
        "\n**Negative control.** The last case is expected to be *accepted*. It documents finding C1: the Groth16 \
         circuit binds the batch digest but does not verify the ML-DSA signature, so anyone with the public \
         proving key can authorise a registered account's op without its signature. Today the guarantee that \
         signatures are valid rests on the bundler's off-chain check (all `bundler` rows above). The case must flip \
         to *rejected* once ML-DSA verification is proven inside a zkVM (docs/future-work-zkvm-linux.md).\n\n\
         Further on-chain cases (G2 point outside the subgroup, public input ≥ r, failed-batch rollback) are \
         covered by `crates/evm/tests/wallet.rs`."
    );
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn security_matrix_behaves_as_expected() {
        let results = run_security_matrix().await;
        let failed: Vec<_> = results.iter().filter(|r| !r.pass).collect();
        assert!(failed.is_empty(), "unexpected outcomes: {failed:#?}");
        assert!(results.len() >= 40, "matrix shrank: {}", results.len());
    }
}
