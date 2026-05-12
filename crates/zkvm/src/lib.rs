//! zkVM abstraction for Q-EVM signature verification proofs.

use async_trait::async_trait;
use qevm_crypto::{MlDsaDilithium2, SignatureScheme};
use qevm_types::{OpHash, UserOperation, ZkvmJournal, ZkvmPublicInputs, ZkvmReceipt};
use qevm_utils::{keccak256, now_millis};
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
    pub cycle_count_hint: u64,
    pub proof_timeout: Duration,
}

impl Default for ZkvmConfig {
    fn default() -> Self {
        Self {
            program_id: "qevm.mldsa.verify".to_string(),
            cycle_count_hint: 1_842_500,
            proof_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
pub trait ZkvmProver: Send + Sync {
    async fn prove(&self, op: &UserOperation) -> Result<ZkvmReceipt, ZkvmError>;
    async fn verify_receipt(&self, op_hash: OpHash, receipt: &ZkvmReceipt) -> Result<bool, ZkvmError>;
}

#[derive(Clone)]
pub struct LocalZkvmProver {
    config: ZkvmConfig,
}

impl LocalZkvmProver {
    pub fn new(config: ZkvmConfig) -> Self {
        Self { config }
    }

    fn compute_proof(&self, op_hash: &OpHash) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(op_hash.as_bytes());
        payload.extend_from_slice(self.config.program_id.as_bytes());
        keccak256(&payload).to_vec()
    }

}

#[async_trait]
impl ZkvmProver for LocalZkvmProver {
    #[instrument(skip_all)]
    async fn prove(&self, op: &UserOperation) -> Result<ZkvmReceipt, ZkvmError> {
        let op_hash = op.op_hash();
        let config = self.config.clone();

        let proof_future = async move {
            let valid = MlDsaDilithium2::pk_from_bytes(&op.pqc_payload.public_key)
                .map_err(|e| ZkvmError::InvalidPayload(e.to_string()))
                .and_then(|pk| {
                    MlDsaDilithium2::sig_from_bytes(&op.pqc_payload.signature)
                        .map_err(|e| ZkvmError::InvalidPayload(e.to_string()))
                        .and_then(|sig| {
                            MlDsaDilithium2::verify(op_hash.as_bytes(), &sig, &pk)
                                .map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))
                        })
                })?;

            let proof = LocalZkvmProver::new(config.clone()).compute_proof(&op_hash);
            Ok::<_, ZkvmError>((valid, proof))
        };

        let (is_valid, proof) = match timeout(self.config.proof_timeout, proof_future).await {
            Ok(result) => result?,
            Err(_) => return Err(ZkvmError::Timeout),
        };

        let journal = ZkvmJournal {
            is_valid,
            program_id: self.config.program_id.clone(),
            cycle_count: self.config.cycle_count_hint,
        };

        Ok(ZkvmReceipt {
            proof,
            public_inputs: ZkvmPublicInputs { op_hash },
            journal,
            created_at: now_millis().map_err(|e| ZkvmError::ProofGenerationFailed(e.to_string()))?,
        })
    }

    async fn verify_receipt(&self, op_hash: OpHash, receipt: &ZkvmReceipt) -> Result<bool, ZkvmError> {
        if receipt.public_inputs.op_hash != op_hash {
            return Ok(false);
        }
        if receipt.journal.program_id != self.config.program_id {
            return Ok(false);
        }
        let expected = self.compute_proof(&op_hash);
        if receipt.proof != expected {
            return Ok(false);
        }
        Ok(receipt.journal.is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::{MlDsaDilithium2, SignatureScheme};
    use qevm_types::{Address, PqcPayload, UserOperation};

    #[tokio::test]
    async fn zkvm_receipt_round_trip() {
        let (pk, sk) = MlDsaDilithium2::keygen().expect("keygen");
        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let mut op = UserOperation::new(
            sender,
            42,
            1,
            b"demo".to_vec(),
            PqcPayload {
                public_key: MlDsaDilithium2::pk_to_bytes(&pk),
                signature: vec![],
            },
        )
        .unwrap();
        let sig = MlDsaDilithium2::sign(op.op_hash().as_bytes(), &sk).expect("sign");
        op.pqc_payload.signature = MlDsaDilithium2::sig_to_bytes(&sig);

        let prover = LocalZkvmProver::new(ZkvmConfig::default());
        let receipt = prover.prove(&op).await.expect("prove");
        let ok = prover
            .verify_receipt(op.op_hash(), &receipt)
            .await
            .expect("verify");
        assert!(ok);
    }
}
