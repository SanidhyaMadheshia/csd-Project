//! Node orchestration and research benchmarks for Q-EVM.

mod benchmark;

use qevm_bundler::{Bundler, BundlerError, SubmissionOutcome};
use qevm_storage::{InMemoryStorage, Storage};
use qevm_types::{BundlerBatch, OpHash, UserOperation, ZkvmReceipt};
use qevm_zkvm::{LocalZkvmProver, ZkvmConfig, ZkvmError, ZkvmProver};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};
use tracing::instrument;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("bundler error: {0}")]
    Bundler(String),
    #[error("zkvm error: {0}")]
    Zkvm(String),
    #[error("storage error: {0}")]
    Storage(String),
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub bundler: BundlerConfig,
    pub zkvm: ZkvmConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bundler: BundlerConfig::default(),
            zkvm: ZkvmConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub mempool_len: usize,
    pub last_batch_id: Option<String>,
    pub last_batch_size: usize,
}

#[derive(Debug, Clone)]
pub enum NodeEvent {
    UserOperationAccepted { op_hash: OpHash },
    UserOperationRejected { op_hash: OpHash, reason: String },
    BatchCreated { batch_id: String, size: usize },
}

pub struct Node {
    bundler: Bundler,
    storage: Arc<dyn Storage>,
    events: broadcast::Sender<NodeEvent>,
    status: RwLock<NodeStatus>,
}
pub use qevm_bundler::BundlerConfig;
pub use benchmark::*;

impl Node {
    pub fn new(config: NodeConfig) -> Self {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new(config.bundler.max_mempool));
        let zkvm: Arc<dyn ZkvmProver> = Arc::new(LocalZkvmProver::new(config.zkvm));
        let bundler = Bundler::new(config.bundler, Arc::clone(&storage), zkvm);
        let (tx, _) = broadcast::channel(256);
        Self {
            bundler,
            storage,
            events: tx,
            status: RwLock::new(NodeStatus {
                mempool_len: 0,
                last_batch_id: None,
                last_batch_size: 0,
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.events.subscribe()
    }

    #[instrument(skip_all)]
    pub async fn submit_user_operation(&self, op: UserOperation) -> Result<SubmissionOutcome, NodeError> {
        let outcome = self
            .bundler
            .submit_user_operation(op)
            .await
            .map_err(|e| NodeError::Bundler(e.to_string()))?;

        if outcome.accepted {
            let _ = self.events.send(NodeEvent::UserOperationAccepted {
                op_hash: outcome.op_hash,
            });
        } else {
            let _ = self.events.send(NodeEvent::UserOperationRejected {
                op_hash: outcome.op_hash,
                reason: "zkvm verification failed".to_string(),
            });
        }

        self.refresh_status().await?;
        Ok(outcome)
    }

    #[instrument(skip_all)]
    pub async fn bundle_next(&self) -> Result<Option<BundlerBatch>, NodeError> {
        let batch = self
            .bundler
            .bundle_next()
            .await
            .map_err(|e| NodeError::Bundler(e.to_string()))?;

        if let Some(ref batch) = batch {
            let _ = self.events.send(NodeEvent::BatchCreated {
                batch_id: batch.batch_id.to_string(),
                size: batch.operations.len(),
            });
            let mut status = self.status.write().await;
            status.last_batch_id = Some(batch.batch_id.to_string());
            status.last_batch_size = batch.operations.len();
        }

        self.refresh_status().await?;
        Ok(batch)
    }

    pub async fn status(&self) -> Result<NodeStatus, NodeError> {
        self.refresh_status().await?;
        Ok(self.status.read().await.clone())
    }

    pub async fn list_mempool(&self, limit: usize) -> Result<Vec<UserOperation>, NodeError> {
        self.storage
            .list_mempool(limit)
            .await
            .map_err(|e| NodeError::Storage(e.to_string()))
    }

    pub async fn get_receipt(&self, op_hash: &OpHash) -> Result<Option<ZkvmReceipt>, NodeError> {
        self.storage
            .get_receipt(op_hash)
            .await
            .map_err(|e| NodeError::Storage(e.to_string()))
    }

    async fn refresh_status(&self) -> Result<(), NodeError> {
        let mempool_len = self
            .bundler
            .mempool_len()
            .await
            .map_err(|e| NodeError::Bundler(e.to_string()))?;
        let mut status = self.status.write().await;
        status.mempool_len = mempool_len;
        Ok(())
    }
}

impl From<BundlerError> for NodeError {
    fn from(err: BundlerError) -> Self {
        NodeError::Bundler(err.to_string())
    }
}

impl From<ZkvmError> for NodeError {
    fn from(err: ZkvmError) -> Self {
        NodeError::Zkvm(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::{MlDsaDilithium2, SignatureScheme};
    use qevm_types::{Address, PqcPayload, UserOperation};

    #[tokio::test]
    async fn node_accepts_operation() {
        let (pk, sk) = MlDsaDilithium2::keygen().expect("keygen");
        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let mut op = UserOperation::new(
            sender,
            0,
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

        let node = Node::new(NodeConfig::default());
        let outcome = node.submit_user_operation(op).await.expect("submit");
        assert!(outcome.accepted);
    }
}
