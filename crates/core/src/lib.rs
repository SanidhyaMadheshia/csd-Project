//! Node orchestration and research benchmarks for Q-EVM.

mod benchmark;
pub mod experiment;
pub mod native_baseline;
pub mod security;

use qevm_bundler::{Bundler, BundlerError, SubmissionOutcome};
use qevm_crypto::{MlDsa44, SignatureScheme};
use qevm_storage::{InMemoryStorage, Storage};
use qevm_types::{
    Address, BatchGas, BatchReceipt, BundlerBatch, GasAnalysis, GasStats, OpHash, PqcPayload, UserOperation,
    ZkvmReceipt,
};
use qevm_zkvm::{LocalZkvmProver, ZkvmConfig, ZkvmError, ZkvmProver};
use std::sync::atomic::{AtomicU64, Ordering};
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
    UserOperationAccepted {
        op_hash: OpHash,
        /// EVM gas measured for verifying this op's Groth16 receipt.
        onchain_gas: u64,
        /// Metered gas of verifying this op's ML-DSA signature natively.
        native_gas: u64,
        prove_time_ms: f64,
    },
    UserOperationRejected { op_hash: OpHash, reason: String },
    BatchCreated { batch_id: String, size: usize, gas: Option<BatchGas> },
}

/// Result of [`Node::run_demo`].
#[derive(Debug, Clone, Serialize)]
pub struct DemoOutcome {
    pub submitted: usize,
    pub accepted: usize,
    pub batches: Vec<BatchGas>,
    pub analysis: GasAnalysis,
}

pub struct Node {
    bundler: Bundler,
    storage: Arc<dyn Storage>,
    zkvm: Arc<dyn ZkvmProver>,
    events: broadcast::Sender<NodeEvent>,
    status: RwLock<NodeStatus>,
    gas: RwLock<GasStats>,
    demo_nonce: AtomicU64,
}
pub use qevm_bundler::BundlerConfig;
pub use benchmark::*;

impl Node {
    pub fn new(config: NodeConfig) -> Self {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new(config.bundler.max_mempool));
        let zkvm: Arc<dyn ZkvmProver> = Arc::new(LocalZkvmProver::new(config.zkvm));
        let bundler = Bundler::new(config.bundler, Arc::clone(&storage), Arc::clone(&zkvm));
        let (tx, _) = broadcast::channel(256);
        Self {
            bundler,
            storage,
            zkvm,
            events: tx,
            status: RwLock::new(NodeStatus {
                mempool_len: 0,
                last_batch_id: None,
                last_batch_size: 0,
            }),
            gas: RwLock::new(GasStats::default()),
            demo_nonce: AtomicU64::new(0),
        }
    }

    /// Measured on-chain vs metered native gas over every receipt produced so far.
    pub async fn gas_analysis(&self) -> GasAnalysis {
        self.gas.read().await.analysis(Some(self.zkvm.verifier_info()))
    }

    /// Generates `count` fresh ML-DSA keys, signs and submits one op per key
    /// through the real pipeline, then bundles the mempool.
    /// Address of the wallet contract ops must target in the current mode.
    pub fn wallet_address(&self) -> Address {
        let kind = self.bundler.config().mode.wallet_kind();
        Address::new(self.zkvm.chain().wallet(kind).address)
    }

    /// Account registration: bind `keccak(public_key)` to `sender` in the
    /// wallets with starting `nonce` (the wallet's constructor in a real deployment).
    pub fn register_account(&self, sender: &Address, public_key: &[u8], nonce: u64) {
        self.zkvm.chain().register_account(sender.as_bytes(), qevm_utils::keccak256(public_key), nonce);
    }

    /// Generates `count` fresh accounts (one ML-DSA key each), registers them,
    /// signs and submits one op per account through the real pipeline, then
    /// bundles and includes the mempool on the local chain.
    pub async fn run_demo(&self, count: usize, chain_id: u64) -> Result<DemoOutcome, NodeError> {
        let wallet = self.wallet_address();
        let mut accepted = 0;
        for i in 0..count {
            let (pk, sk) = MlDsa44::keygen().map_err(|e| NodeError::Zkvm(e.to_string()))?;
            let account = self.demo_nonce.fetch_add(1, Ordering::Relaxed);
            let mut sender_bytes = [0u8; 20];
            sender_bytes[0] = 0xde;
            sender_bytes[12..].copy_from_slice(&account.to_be_bytes());
            let sender = Address::new(sender_bytes);
            let pk_bytes = MlDsa44::pk_to_bytes(&pk);
            self.register_account(&sender, &pk_bytes, 0);
            let mut op = UserOperation::new(
                wallet,
                sender,
                0,
                chain_id,
                format!("demo-call:{i}").into_bytes(),
                PqcPayload { public_key: pk_bytes, signature: vec![] },
            )
            .map_err(|e| NodeError::Bundler(e.to_string()))?;
            let sig = MlDsa44::sign(op.op_hash().as_bytes(), &sk).map_err(|e| NodeError::Zkvm(e.to_string()))?;
            op.pqc_payload.signature = MlDsa44::sig_to_bytes(&sig);
            if self.submit_user_operation(op).await?.accepted {
                accepted += 1;
            }
        }

        let mut batches = Vec::new();
        while let Some(batch) = self.bundle_next().await? {
            batches.extend(batch.transactions.iter().map(BatchReceipt::gas));
        }
        Ok(DemoOutcome { submitted: count, accepted, batches, analysis: self.gas_analysis().await })
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
            if let Some(ref receipt) = outcome.receipt {
                self.gas.write().await.record_receipt(receipt);
            }
            let _ = self.events.send(NodeEvent::UserOperationAccepted {
                op_hash: outcome.op_hash,
                onchain_gas: outcome.receipt.as_ref().map(|r| r.journal.onchain_gas.total).unwrap_or(0),
                native_gas: outcome.signature.map(|c| c.native_gas.total).unwrap_or(0),
                prove_time_ms: outcome.receipt.as_ref().map(|r| r.journal.prove_time_ms).unwrap_or(0.0),
            });
        } else {
            let reason = outcome.rejection.as_ref().map(|r| r.to_string()).unwrap_or_else(|| "rejected".into());
            let _ = self.events.send(NodeEvent::UserOperationRejected { op_hash: outcome.op_hash, reason });
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
            for tx in &batch.transactions {
                self.gas.write().await.record_batch(tx);
            }
            let _ = self.events.send(NodeEvent::BatchCreated {
                batch_id: batch.batch_id.to_string(),
                size: batch.operations.len(),
                gas: batch.transactions.last().map(BatchReceipt::gas),
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
    use qevm_crypto::{MlDsa44, SignatureScheme};
    use qevm_types::{Address, PqcPayload, UserOperation};

    #[tokio::test]
    async fn node_accepts_operation() {
        let (pk, sk) = MlDsa44::keygen().expect("keygen");
        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let node = Node::new(NodeConfig::default());
        node.register_account(&sender, &MlDsa44::pk_to_bytes(&pk), 0);
        let mut op = UserOperation::new(
            node.wallet_address(),
            sender,
            0,
            1,
            b"demo".to_vec(),
            PqcPayload {
                public_key: MlDsa44::pk_to_bytes(&pk),
                signature: vec![],
            },
        )
        .unwrap();
        let sig = MlDsa44::sign(op.op_hash().as_bytes(), &sk).expect("sign");
        op.pqc_payload.signature = MlDsa44::sig_to_bytes(&sig);

        assert!(!node.gas_analysis().await.measured);
        let outcome = node.submit_user_operation(op.clone()).await.expect("submit");
        assert!(outcome.accepted);
        // Replay: the same op again, before and after inclusion.
        assert!(!node.submit_user_operation(op.clone()).await.expect("submit").accepted);
        let batch = node.bundle_next().await.expect("bundle").expect("batch");
        assert!(batch.transactions[0].inclusion.expect("sent").committed);
        assert!(!node.submit_user_operation(op).await.expect("submit").accepted);
    }

    #[tokio::test]
    async fn demo_produces_measured_gas_analysis() {
        let node = Node::new(NodeConfig::default());
        let demo = node.run_demo(3, 1).await.expect("demo");
        assert_eq!(demo.accepted, 3);
        let a = demo.analysis;
        assert!(a.measured);
        assert_eq!(a.samples, 3);
        assert!(a.onchain_min <= a.onchain_avg && a.onchain_avg <= a.onchain_max);
        assert!(a.native_avg > a.onchain_avg);
        assert!(a.reduction_percent > 0.0 && a.reduction_percent < 100.0);
        assert_eq!(a.last_batch.expect("batch").size, 3);
        assert!(a.verifier.expect("verifier").deploy_gas > 0);
    }
}
