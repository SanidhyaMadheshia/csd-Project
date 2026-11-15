//! Prover side of Q-EVM.
//!
//! `LocalZkvmProver` verifies each ML-DSA-44 signature off-chain (FIPS 204,
//! native Rust), then authorises batches for the on-chain wallet: with a
//! Groth16 receipt over the batch digest (Q-EVM), or with an ECDSA
//! attestation (ablation baseline). It owns a [`LocalChain`] (revm) holding
//! the verifier and wallet contracts, used to measure gas.
//!
//! Scope: the Groth16 circuit binds the batch digest but does not verify the
//! signature itself (see `qevm_evm::groth16` and docs/circuit-spec.md).
//! Despite the crate name, no zkVM is run here; proving ML-DSA inside a zkVM
//! is future work (docs/future-work-zkvm-linux.md).

use async_trait::async_trait;
use qevm_crypto::MlDsa44;
use qevm_evm::{
    batch_digest, estimate_native_gas, proof_bytes, wallet_calldata, Attester, Groth16Keys, LocalChain,
    NativeGasBreakdown, ReceiptStatement,
};
use qevm_types::{
    BatchReceipt, OpHash, UserOperation, VerifierInfo, WalletKind, ZkvmJournal, ZkvmPublicInputs, ZkvmReceipt,
};
use qevm_utils::{keccak256, now_millis};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::time::{timeout, Duration};
use tracing::instrument;

#[derive(Debug, Error)]
pub enum ZkvmError {
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("proof generation timed out")]
    Timeout,
}

#[derive(Debug, Clone)]
pub struct ZkvmConfig {
    pub program_id: String,
    /// Seed of the (single-party, development) Groth16 setup.
    pub setup_seed: u64,
    pub proof_timeout: Duration,
    /// Chain id of the local EVM.
    pub chain_id: u64,
    /// Seed of the bundler's ECDSA attestation key (ablation baseline).
    pub attester_seed: [u8; 32],
}

impl Default for ZkvmConfig {
    fn default() -> Self {
        Self {
            program_id: "qevm.mldsa.verify".to_string(),
            setup_seed: 0x5145_564d,
            proof_timeout: Duration::from_secs(10),
            chain_id: 1,
            attester_seed: [0x42; 32],
        }
    }
}

/// Result of the off-chain signature check.
#[derive(Debug, Clone, Copy)]
pub struct SigCheck {
    pub valid: bool,
    pub verify_ms: f64,
    /// Modelled native EVM gas (zero for malformed encodings).
    pub native_gas: NativeGasBreakdown,
}

#[async_trait]
pub trait ZkvmProver: Send + Sync {
    /// Off-chain FIPS 204 verification of the op's signature over its op hash.
    async fn check_signature(&self, op: &UserOperation) -> Result<SigCheck, ZkvmError>;
    /// Per-op receipt: signature check, then a Groth16 proof for the batch of
    /// one `[op]`, with the simulated gas of a single-op wallet transaction.
    async fn prove(&self, op: &UserOperation) -> Result<ZkvmReceipt, ZkvmError>;
    /// Authorise a batch whose signatures were already checked.
    async fn authorize_batch(&self, ops: &[UserOperation], kind: WalletKind) -> Result<BatchReceipt, ZkvmError>;
    async fn verify_receipt(&self, op_hash: OpHash, receipt: &ZkvmReceipt) -> Result<bool, ZkvmError>;
    fn chain(&self) -> Arc<LocalChain>;
    fn verifier_info(&self) -> VerifierInfo;
}

#[derive(Clone)]
pub struct LocalZkvmProver {
    config: ZkvmConfig,
    keys: Arc<Groth16Keys>,
    attester: Arc<Attester>,
    chain: Arc<LocalChain>,
}

impl LocalZkvmProver {
    /// Runs the Groth16 setup and deploys the verifier and wallets on a local EVM.
    pub fn new(config: ZkvmConfig) -> Self {
        // The circuit is fixed, so setup and deployment only fail on a programming error.
        let keys = Groth16Keys::setup(config.setup_seed).expect("groth16 setup of the fixed receipt circuit");
        let attester = Attester::from_seed(config.attester_seed);
        let program = keccak256(config.program_id.as_bytes());
        let chain = LocalChain::new(keys.verifying_key(), program, attester.address(), config.chain_id)
            .expect("deploy verifier and wallets");
        Self { config, keys: Arc::new(keys), attester: Arc::new(attester), chain: Arc::new(chain) }
    }

    /// The Groth16 keys (exposed for security tests that build proofs directly).
    pub fn keys(&self) -> Arc<Groth16Keys> {
        Arc::clone(&self.keys)
    }

    fn statement(&self, digest: [u8; 32]) -> ReceiptStatement {
        ReceiptStatement { digest, program: keccak256(self.config.program_id.as_bytes()) }
    }

    /// Real Groth16 prove, off the async runtime, with a timeout.
    async fn prove_statement(&self, statement: ReceiptStatement) -> Result<(Vec<u8>, f64), ZkvmError> {
        let keys = Arc::clone(&self.keys);
        let work = tokio::task::spawn_blocking(move || {
            let mut seed_src = statement.digest.to_vec();
            seed_src.extend_from_slice(&now_millis().unwrap_or_default().to_be_bytes());
            let seed = u64::from_be_bytes(keccak256(&seed_src)[..8].try_into().expect("8 bytes"));
            let started = Instant::now();
            let calldata =
                keys.prove(&statement, seed).map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?;
            Ok((calldata, started.elapsed().as_secs_f64() * 1000.0))
        });
        match timeout(self.config.proof_timeout, work).await {
            Ok(joined) => joined.map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?,
            Err(_) => Err(ZkvmError::Timeout),
        }
    }

    fn check_signature_sync(op: &UserOperation) -> SigCheck {
        let op_hash = op.op_hash();
        let started = Instant::now();
        let valid = MlDsa44::verify_bytes(op_hash.as_bytes(), &op.pqc_payload.signature, &op.pqc_payload.public_key);
        let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
        let native_gas =
            estimate_native_gas(&op.pqc_payload.public_key, &op.pqc_payload.signature, op_hash.as_bytes())
                .unwrap_or_default();
        SigCheck { valid, verify_ms, native_gas }
    }
}

#[async_trait]
impl ZkvmProver for LocalZkvmProver {
    async fn check_signature(&self, op: &UserOperation) -> Result<SigCheck, ZkvmError> {
        Ok(Self::check_signature_sync(op))
    }

    #[instrument(skip_all)]
    async fn prove(&self, op: &UserOperation) -> Result<ZkvmReceipt, ZkvmError> {
        let op_hash = op.op_hash();
        let check = Self::check_signature_sync(op);
        let created_at = now_millis().map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?;
        let mut journal = ZkvmJournal {
            is_valid: check.valid,
            program_id: self.config.program_id.clone(),
            mldsa_verify_ms: check.verify_ms,
            prove_time_ms: 0.0,
            onchain_gas: Default::default(),
            verifier_gas: Default::default(),
            native_gas: check.native_gas,
        };
        if !check.valid {
            // The bundler only proves accepted signatures.
            return Ok(ZkvmReceipt {
                proof: Vec::new(),
                public_inputs: ZkvmPublicInputs { op_hash },
                journal,
                created_at,
                gas_saved_vs_native: 0,
            });
        }

        let digest = batch_digest(&[*op_hash.as_bytes()]);
        let (calldata, prove_time_ms) = self.prove_statement(self.statement(digest)).await?;
        let chain = &self.chain;
        journal.prove_time_ms = prove_time_ms;
        journal.verifier_gas =
            chain.measure_verify(&calldata).map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?;
        if !journal.verifier_gas.success {
            return Err(ZkvmError::ProofGenerationFailed("on-chain verifier rejected proof".into()));
        }
        let tx = wallet_calldata(proof_bytes(&calldata), &[op.to_wallet_op()]);
        journal.onchain_gas = chain
            .simulate(chain.wallet(WalletKind::Groth16).address, &tx)
            .map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?
            .gas;
        let gas_saved_vs_native = journal.native_gas.total.saturating_sub(journal.onchain_gas.total);
        Ok(ZkvmReceipt {
            proof: calldata,
            public_inputs: ZkvmPublicInputs { op_hash },
            journal,
            created_at,
            gas_saved_vs_native,
        })
    }

    #[instrument(skip_all)]
    async fn authorize_batch(&self, ops: &[UserOperation], kind: WalletKind) -> Result<BatchReceipt, ZkvmError> {
        if ops.is_empty() {
            return Err(ZkvmError::InvalidPayload("empty batch".into()));
        }
        let hashes: Vec<[u8; 32]> = ops.iter().map(|op| *op.op_hash().as_bytes()).collect();
        let digest = batch_digest(&hashes);
        let (auth, prove_time_ms) = match kind {
            WalletKind::Groth16 => {
                let (calldata, ms) = self.prove_statement(self.statement(digest)).await?;
                (proof_bytes(&calldata).to_vec(), ms)
            }
            WalletKind::Attestation => {
                let started = Instant::now();
                let sig = self.attester.sign(&digest).to_vec();
                (sig, started.elapsed().as_secs_f64() * 1000.0)
            }
        };
        let records: Vec<_> = ops.iter().map(UserOperation::to_wallet_op).collect();
        let tx = wallet_calldata(&auth, &records);
        let onchain_gas = self
            .chain
            .simulate(self.chain.wallet(kind).address, &tx)
            .map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?
            .gas;
        Ok(BatchReceipt {
            digest: OpHash::new(digest),
            kind,
            proof: auth,
            wallet_calldata: tx,
            size: ops.len(),
            onchain_gas,
            amortized_gas_per_op: (onchain_gas.total as f64 / ops.len() as f64).round() as u64,
            prove_time_ms,
            inclusion: None,
        })
    }

    async fn verify_receipt(&self, op_hash: OpHash, receipt: &ZkvmReceipt) -> Result<bool, ZkvmError> {
        if receipt.public_inputs.op_hash != op_hash || receipt.journal.program_id != self.config.program_id {
            return Ok(false);
        }
        let statement = self.statement(batch_digest(&[*op_hash.as_bytes()]));
        Ok(self.keys.verify(&receipt.proof, &statement).unwrap_or(false))
    }

    fn chain(&self) -> Arc<LocalChain> {
        Arc::clone(&self.chain)
    }

    fn verifier_info(&self) -> VerifierInfo {
        let v = self.chain.verifier();
        VerifierInfo { deploy_gas: v.deploy_gas, code_size: v.code_size }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::SignatureScheme;
    use qevm_types::{Address, PqcPayload};

    fn signed_op(prover: &LocalZkvmProver, nonce: u64) -> UserOperation {
        signed_op_for(prover, nonce, WalletKind::Groth16)
    }

    fn signed_op_for(prover: &LocalZkvmProver, nonce: u64, kind: WalletKind) -> UserOperation {
        let (pk, sk) = MlDsa44::keygen().expect("keygen");
        let wallet = Address::new(prover.chain().wallet(kind).address);
        let sender = Address::new([nonce as u8 + 1; 20]);
        let mut op = UserOperation::new(
            wallet,
            sender,
            nonce,
            1,
            b"demo".to_vec(),
            PqcPayload { public_key: MlDsa44::pk_to_bytes(&pk), signature: vec![] },
        )
        .unwrap();
        prover.chain().register_account(sender.as_bytes(), op.pk_hash(), nonce);
        let sig = MlDsa44::sign(op.op_hash().as_bytes(), &sk).expect("sign");
        op.pqc_payload.signature = MlDsa44::sig_to_bytes(&sig);
        op
    }

    #[tokio::test]
    async fn zkvm_receipt_round_trip() {
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let op = signed_op(&prover, 42);
        let receipt = prover.prove(&op).await.expect("prove");
        assert!(receipt.journal.is_valid);
        assert!(receipt.journal.verifier_gas.success);
        assert!(receipt.journal.onchain_gas.success, "single-op wallet tx must succeed");
        assert!(receipt.journal.onchain_gas.total > receipt.journal.verifier_gas.total);
        assert!(receipt.journal.native_gas.total > receipt.journal.onchain_gas.total);
        assert!(prover.verify_receipt(op.op_hash(), &receipt).await.expect("verify"));
    }

    #[tokio::test]
    async fn forged_or_mismatched_receipts_fail() {
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let op = signed_op(&prover, 1);
        let other = signed_op(&prover, 2);
        let receipt = prover.prove(&op).await.expect("prove");

        let mut replay = receipt.clone();
        replay.public_inputs.op_hash = other.op_hash();
        assert!(!prover.verify_receipt(other.op_hash(), &replay).await.unwrap());

        let mut forged = receipt.clone();
        forged.proof = keccak256(op.op_hash().as_bytes()).to_vec();
        assert!(!prover.verify_receipt(op.op_hash(), &forged).await.unwrap());

        let mut tampered = receipt;
        tampered.proof[10] ^= 0xff;
        assert!(!prover.verify_receipt(op.op_hash(), &tampered).await.unwrap());
    }

    #[tokio::test]
    async fn invalid_signature_gets_no_proof() {
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let mut op = signed_op(&prover, 3);
        op.nonce = 4; // signature no longer matches the op hash
        let receipt = prover.prove(&op).await.expect("prove");
        assert!(!receipt.journal.is_valid);
        assert!(receipt.proof.is_empty());
        assert!(!prover.verify_receipt(op.op_hash(), &receipt).await.unwrap());
    }

    #[tokio::test]
    async fn batch_authorisation_both_kinds() {
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        for kind in [WalletKind::Groth16, WalletKind::Attestation] {
            let ops: Vec<_> = (0..8).map(|i| signed_op_for(&prover, i, kind)).collect();
            let batch = prover.authorize_batch(&ops, kind).await.expect("batch");
            assert!(batch.onchain_gas.success, "{kind:?} batch must verify: {:?}", batch.onchain_gas);
            assert_eq!(batch.size, 8);
            // Ops bound to one wallet are rejected by the other (domain separation).
            let other = match kind {
                WalletKind::Groth16 => WalletKind::Attestation,
                WalletKind::Attestation => WalletKind::Groth16,
            };
            let cross = prover.authorize_batch(&ops, other).await.expect("batch");
            assert!(!cross.onchain_gas.success);
        }
    }
}
