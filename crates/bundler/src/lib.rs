//! Bundler pipeline for validating and batching Q-EVM UserOperations.

use qevm_storage::Storage;
use qevm_types::{BundlerBatch, OpHash, UserOperation, ZkvmReceipt};
use qevm_utils::now_millis;
use qevm_zkvm::ZkvmProver;
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{timeout, Duration, Instant};
use tracing::{info, instrument, warn};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BundlerError {
    #[error("invalid user operation: {0}")]
    InvalidUserOperation(String),
    #[error("duplicate nonce for sender")]
    DuplicateNonce,
    #[error("zkvm error: {0}")]
    Zkvm(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("timeout while generating proof")]
    Timeout,
}

#[derive(Debug, Clone)]
pub struct BundlerConfig {
    pub max_mempool: usize,
    pub batch_size: usize,
    pub proof_timeout: Duration,
    pub proof_retries: usize,
    pub simulate_before_accept: bool,
}

impl Default for BundlerConfig {
    fn default() -> Self {
        Self {
            max_mempool: 2048,
            batch_size: 32,
            proof_timeout: Duration::from_secs(12),
            proof_retries: 2,
            simulate_before_accept: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubmissionOutcome {
    pub op_hash: OpHash,
    pub accepted: bool,
    pub receipt: Option<ZkvmReceipt>,
}

#[derive(Clone)]
pub struct Bundler {
    config: BundlerConfig,
    storage: Arc<dyn Storage>,
    zkvm: Arc<dyn ZkvmProver>,
}

impl Bundler {
    pub fn new(config: BundlerConfig, storage: Arc<dyn Storage>, zkvm: Arc<dyn ZkvmProver>) -> Self {
        Self {
            config,
            storage,
            zkvm,
        }
    }

    #[instrument(skip_all)]
    pub async fn submit_user_operation(&self, mut op: UserOperation) -> Result<SubmissionOutcome, BundlerError> {
        self.validate_basic(&op).await?;
        let op_hash = op.op_hash();

        let mut receipt = None;
        if self.config.simulate_before_accept {
            receipt = Some(self.prove_with_retry(&op).await?);
            if !receipt.as_ref().map(|r| r.journal.is_valid).unwrap_or(false) {
                return Ok(SubmissionOutcome {
                    op_hash,
                    accepted: false,
                    receipt,
                });
            }
        }

        if let Some(ref proof) = receipt {
            self.storage
                .store_receipt(op_hash, proof.clone())
                .await
                .map_err(|e| BundlerError::Storage(e.to_string()))?;
            op = op.with_receipt(proof.clone());
        }

        self.storage
            .insert_user_op(op)
            .await
            .map_err(|e| BundlerError::Storage(e.to_string()))?;

        metrics::counter!("bundler.user_ops.accepted").increment(1);
        info!("accepted user op with hash={}", op_hash);

        Ok(SubmissionOutcome {
            op_hash,
            accepted: true,
            receipt,
        })
    }

    pub async fn mempool_len(&self) -> Result<usize, BundlerError> {
        self.storage
            .mempool_len()
            .await
            .map_err(|e| BundlerError::Storage(e.to_string()))
    }

    #[instrument(skip_all)]
    pub async fn bundle_next(&self) -> Result<Option<BundlerBatch>, BundlerError> {
        let ops = self
            .storage
            .take_batch(self.config.batch_size)
            .await
            .map_err(|e| BundlerError::Storage(e.to_string()))?;

        if ops.is_empty() {
            return Ok(None);
        }

        let mut finalized_ops = Vec::with_capacity(ops.len());
        for op in ops {
            let receipt = match op.zkvm_receipt.clone() {
                Some(receipt) => receipt,
                None => self.prove_with_retry(&op).await?,
            };
            if !receipt.journal.is_valid {
                warn!("dropping invalid op hash={}", op.op_hash());
                metrics::counter!("bundler.user_ops.rejected").increment(1);
                continue;
            }
            self.storage
                .store_receipt(op.op_hash(), receipt.clone())
                .await
                .map_err(|e| BundlerError::Storage(e.to_string()))?;
            finalized_ops.push(op.with_receipt(receipt));
        }

        metrics::counter!("bundler.batches.created").increment(1);

        Ok(Some(BundlerBatch {
            batch_id: Uuid::new_v4(),
            created_at: now_millis().map_err(|e| BundlerError::Storage(e.to_string()))?,
            operations: finalized_ops,
        }))
    }

    async fn validate_basic(&self, op: &UserOperation) -> Result<(), BundlerError> {
        if op.pqc_payload.public_key.is_empty() || op.pqc_payload.signature.is_empty() {
            return Err(BundlerError::InvalidUserOperation(
                "missing PQC payload".to_string(),
            ));
        }
        if self
            .storage
            .has_sender_nonce(&op.sender, op.nonce)
            .await
            .map_err(|e| BundlerError::Storage(e.to_string()))?
        {
            return Err(BundlerError::DuplicateNonce);
        }
        Ok(())
    }

    async fn prove_with_retry(&self, op: &UserOperation) -> Result<ZkvmReceipt, BundlerError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let start = Instant::now();
            let proof_result = timeout(self.config.proof_timeout, self.zkvm.prove(op)).await;
            let elapsed = start.elapsed();
            metrics::histogram!("bundler.zkvm.proof_latency_ms").record(elapsed.as_secs_f64() * 1000.0);

            match proof_result {
                Ok(Ok(receipt)) => {
                    metrics::counter!("bundler.zkvm.proofs.generated").increment(1);
                    return Ok(receipt);
                }
                Ok(Err(err)) => {
                    warn!("zkvm error: {err}");
                    if attempts > self.config.proof_retries {
                        return Err(BundlerError::Zkvm(err.to_string()));
                    }
                }
                Err(_) => {
                    if attempts > self.config.proof_retries {
                        return Err(BundlerError::Timeout);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::{MlDsaDilithium2, SignatureScheme};
    use qevm_storage::InMemoryStorage;
    use qevm_types::{Address, PqcPayload, UserOperation};
    use qevm_zkvm::{LocalZkvmProver, ZkvmConfig};

    #[tokio::test]
    async fn bundler_accepts_valid_op() {
        let (pk, sk) = MlDsaDilithium2::keygen().expect("keygen");
        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let mut op = UserOperation::new(
            sender,
            1,
            1,
            b"demo".to_vec(),
            PqcPayload {
                public_key: MlDsaDilithium2::pk_to_bytes(&pk),
                signature: vec![],
            },
        )
        .unwrap();
        let hash = op.op_hash();
        let sig = MlDsaDilithium2::sign(hash.as_bytes(), &sk).expect("sign");
        op.pqc_payload.signature = MlDsaDilithium2::sig_to_bytes(&sig);

        let storage = Arc::new(InMemoryStorage::new(16));
        let zkvm = Arc::new(LocalZkvmProver::new(ZkvmConfig::default()));
        let bundler = Bundler::new(BundlerConfig::default(), storage, zkvm);

        let outcome = bundler.submit_user_operation(op).await.expect("submit");
        assert!(outcome.accepted);
    }
}
