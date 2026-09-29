//! zkVM abstraction for Q-EVM signature verification proofs.
//!
//! `LocalZkvmProver` checks the ML-DSA signature, then produces a real Groth16
//! receipt (BN254) binding the op hash, program id and validity bit. It
//! verifies that receipt on an in-process EVM to measure its on-chain gas, and
//! meters what verifying the same signature natively in the EVM would cost.

use async_trait::async_trait;
use qevm_crypto::{MlDsaDilithium2, SignatureScheme};
use qevm_evm::{estimate_native_gas, EvmGasMeter, Groth16Keys, ReceiptStatement};
use qevm_types::{
    BatchReceipt, OpHash, UserOperation, VerifierInfo, ZkvmJournal, ZkvmPublicInputs, ZkvmReceipt,
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
}

impl Default for ZkvmConfig {
    fn default() -> Self {
        Self {
            program_id: "qevm.mldsa.verify".to_string(),
            setup_seed: 0x5145_564d,
            proof_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
pub trait ZkvmProver: Send + Sync {
    async fn prove(&self, op: &UserOperation) -> Result<ZkvmReceipt, ZkvmError>;
    async fn prove_batch(&self, op_hashes: &[OpHash]) -> Result<BatchReceipt, ZkvmError>;
    async fn verify_receipt(&self, op_hash: OpHash, receipt: &ZkvmReceipt) -> Result<bool, ZkvmError>;
    fn verifier_info(&self) -> VerifierInfo;
}

#[derive(Clone)]
pub struct LocalZkvmProver {
    config: ZkvmConfig,
    keys: Arc<Groth16Keys>,
    evm: Arc<EvmGasMeter>,
}

struct Proven {
    calldata: Vec<u8>,
    prove_time_ms: f64,
    onchain: qevm_types::OnchainGas,
}

impl LocalZkvmProver {
    /// Runs the Groth16 setup and deploys the verifier contract on the local EVM.
    pub fn new(config: ZkvmConfig) -> Self {
        // The circuit is fixed, so setup and deployment only fail on a programming error.
        let keys = Groth16Keys::setup(config.setup_seed).expect("groth16 setup of the fixed receipt circuit");
        let evm = EvmGasMeter::new(keys.verifying_key()).expect("deploy groth16 verifier");
        Self { config, keys: Arc::new(keys), evm: Arc::new(evm) }
    }

    fn statement(&self, digest: [u8; 32]) -> ReceiptStatement {
        ReceiptStatement { digest, program: keccak256(self.config.program_id.as_bytes()) }
    }

    /// Real Groth16 prove (off the async runtime) + measured EVM verification gas.
    async fn prove_statement(&self, statement: ReceiptStatement) -> Result<Proven, ZkvmError> {
        let keys = Arc::clone(&self.keys);
        let evm = Arc::clone(&self.evm);
        let work = tokio::task::spawn_blocking(move || {
            let mut seed_src = statement.digest.to_vec();
            seed_src.extend_from_slice(&now_millis().unwrap_or_default().to_be_bytes());
            let seed = u64::from_be_bytes(keccak256(&seed_src)[..8].try_into().expect("8 bytes"));

            let started = Instant::now();
            let calldata = keys
                .prove(&statement, seed)
                .map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?;
            let prove_time_ms = started.elapsed().as_secs_f64() * 1000.0;

            let onchain = evm
                .measure_verify(&calldata)
                .map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?;
            if !onchain.success {
                return Err(ZkvmError::ProofGenerationFailed("on-chain verifier rejected proof".into()));
            }
            Ok(Proven { calldata, prove_time_ms, onchain })
        });
        match timeout(self.config.proof_timeout, work).await {
            Ok(joined) => joined.map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?,
            Err(_) => Err(ZkvmError::Timeout),
        }
    }
}

#[async_trait]
impl ZkvmProver for LocalZkvmProver {
    #[instrument(skip_all)]
    async fn prove(&self, op: &UserOperation) -> Result<ZkvmReceipt, ZkvmError> {
        let op_hash = op.op_hash();
        let pk_bytes = &op.pqc_payload.public_key;
        let sig_bytes = &op.pqc_payload.signature;

        let pk = MlDsaDilithium2::pk_from_bytes(pk_bytes).map_err(|e| ZkvmError::InvalidPayload(e.to_string()))?;
        let sig = MlDsaDilithium2::sig_from_bytes(sig_bytes).map_err(|e| ZkvmError::InvalidPayload(e.to_string()))?;
        let is_valid = MlDsaDilithium2::verify(op_hash.as_bytes(), &sig, &pk)
            .map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?;

        let native_gas = estimate_native_gas(pk_bytes, sig_bytes, op_hash.as_bytes())
            .map_err(|e| ZkvmError::InvalidPayload(e.to_string()))?;

        let created_at = now_millis().map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?;
        if !is_valid {
            // No proof exists for an invalid signature (the circuit requires is_valid = 1).
            return Ok(ZkvmReceipt {
                proof: Vec::new(),
                public_inputs: ZkvmPublicInputs { op_hash },
                journal: ZkvmJournal {
                    is_valid,
                    program_id: self.config.program_id.clone(),
                    prove_time_ms: 0.0,
                    onchain_gas: Default::default(),
                    native_gas,
                },
                created_at,
                gas_saved_vs_native: 0,
            });
        }

        let proven = self.prove_statement(self.statement(*op_hash.as_bytes())).await?;
        Ok(ZkvmReceipt {
            proof: proven.calldata,
            public_inputs: ZkvmPublicInputs { op_hash },
            journal: ZkvmJournal {
                is_valid,
                program_id: self.config.program_id.clone(),
                prove_time_ms: proven.prove_time_ms,
                onchain_gas: proven.onchain,
                native_gas,
            },
            created_at,
            gas_saved_vs_native: native_gas.total.saturating_sub(proven.onchain.total),
        })
    }

    #[instrument(skip_all)]
    async fn prove_batch(&self, op_hashes: &[OpHash]) -> Result<BatchReceipt, ZkvmError> {
        if op_hashes.is_empty() {
            return Err(ZkvmError::InvalidPayload("empty batch".into()));
        }
        let mut concat = Vec::with_capacity(op_hashes.len() * 32);
        for hash in op_hashes {
            concat.extend_from_slice(hash.as_bytes());
        }
        let digest = keccak256(&concat);
        let proven = self.prove_statement(self.statement(digest)).await?;
        Ok(BatchReceipt {
            digest: OpHash::new(digest),
            proof: proven.calldata,
            size: op_hashes.len(),
            onchain_gas: proven.onchain,
            amortized_gas_per_op: proven.onchain.total / op_hashes.len() as u64,
            prove_time_ms: proven.prove_time_ms,
        })
    }

    async fn verify_receipt(&self, op_hash: OpHash, receipt: &ZkvmReceipt) -> Result<bool, ZkvmError> {
        if receipt.public_inputs.op_hash != op_hash || receipt.journal.program_id != self.config.program_id {
            return Ok(false);
        }
        let statement = self.statement(*op_hash.as_bytes());
        Ok(self.keys.verify(&receipt.proof, &statement).unwrap_or(false))
    }

    fn verifier_info(&self) -> VerifierInfo {
        VerifierInfo { deploy_gas: self.evm.deploy_gas(), code_size: self.evm.code_size() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::{MlDsaDilithium2, SignatureScheme};
    use qevm_types::{Address, PqcPayload, UserOperation};

    fn signed_op(nonce: u64) -> UserOperation {
        let (pk, sk) = MlDsaDilithium2::keygen().expect("keygen");
        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let mut op = UserOperation::new(
            sender,
            nonce,
            1,
            b"demo".to_vec(),
            PqcPayload { public_key: MlDsaDilithium2::pk_to_bytes(&pk), signature: vec![] },
        )
        .unwrap();
        let sig = MlDsaDilithium2::sign(op.op_hash().as_bytes(), &sk).expect("sign");
        op.pqc_payload.signature = MlDsaDilithium2::sig_to_bytes(&sig);
        op
    }

    #[tokio::test]
    async fn zkvm_receipt_round_trip() {
        let op = signed_op(42);
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let receipt = prover.prove(&op).await.expect("prove");
        assert!(receipt.journal.is_valid);
        assert!(receipt.journal.onchain_gas.success);
        assert!(receipt.journal.native_gas.total > receipt.journal.onchain_gas.total);
        assert_eq!(
            receipt.gas_saved_vs_native,
            receipt.journal.native_gas.total - receipt.journal.onchain_gas.total
        );
        assert!(prover.verify_receipt(op.op_hash(), &receipt).await.expect("verify"));
    }

    #[tokio::test]
    async fn forged_or_mismatched_receipts_fail() {
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let op = signed_op(1);
        let other = signed_op(2);
        let receipt = prover.prove(&op).await.expect("prove");

        // Receipt replayed for another op.
        let mut replay = receipt.clone();
        replay.public_inputs.op_hash = other.op_hash();
        assert!(!prover.verify_receipt(other.op_hash(), &replay).await.unwrap());

        // Forged proof bytes (the old keccak "proof" style).
        let mut forged = receipt.clone();
        forged.proof = keccak256(op.op_hash().as_bytes()).to_vec();
        assert!(!prover.verify_receipt(op.op_hash(), &forged).await.unwrap());

        // Tampered proof point.
        let mut tampered = receipt;
        tampered.proof[10] ^= 0xff;
        assert!(!prover.verify_receipt(op.op_hash(), &tampered).await.unwrap());
    }

    #[tokio::test]
    async fn invalid_signature_gets_no_proof() {
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let mut op = signed_op(3);
        op.nonce = 4; // signature no longer matches the op hash
        let receipt = prover.prove(&op).await.expect("prove");
        assert!(!receipt.journal.is_valid);
        assert!(receipt.proof.is_empty());
        assert!(!prover.verify_receipt(op.op_hash(), &receipt).await.unwrap());
    }

    #[tokio::test]
    async fn batch_proof_amortizes_gas() {
        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let hashes: Vec<OpHash> = (0..8u8).map(|i| OpHash::new([i; 32])).collect();
        let batch = prover.prove_batch(&hashes).await.expect("batch");
        assert!(batch.onchain_gas.success);
        assert_eq!(batch.size, 8);
        assert_eq!(batch.amortized_gas_per_op, batch.onchain_gas.total / 8);
    }
}
