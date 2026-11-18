//! Storage interfaces for mempool and receipt persistence.

use async_trait::async_trait;
use qevm_types::{Address, OpHash, UserOperation, ZkvmReceipt};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("mempool full")]
    MempoolFull,
    #[error("storage error: {0}")]
    Internal(String),
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn insert_user_op(&self, op: UserOperation) -> Result<(), StorageError>;
    async fn take_batch(&self, max: usize) -> Result<Vec<UserOperation>, StorageError>;
    async fn list_mempool(&self, limit: usize) -> Result<Vec<UserOperation>, StorageError>;
    async fn mempool_len(&self) -> Result<usize, StorageError>;
    async fn store_receipt(&self, op_hash: OpHash, receipt: ZkvmReceipt) -> Result<(), StorageError>;
    async fn get_receipt(&self, op_hash: &OpHash) -> Result<Option<ZkvmReceipt>, StorageError>;
    /// Whether `(sender, nonce)` was ever accepted (pending, in flight or included).
    async fn has_sender_nonce(&self, sender: &Address, nonce: u64) -> Result<bool, StorageError>;
    /// Number of ops from `sender` still waiting in the mempool.
    async fn pending_for_sender(&self, sender: &Address) -> Result<u64, StorageError>;
}

#[derive(Debug, Default)]
struct InMemoryState {
    mempool: VecDeque<UserOperation>,
    receipts: HashMap<OpHash, ZkvmReceipt>,
    /// Every `(sender, nonce)` ever accepted. Never pruned: an op that has
    /// left the mempool (bundled or included) must not be accepted again.
    seen_nonces: HashSet<(Address, u64)>,
    pending: HashMap<Address, u64>,
}

#[derive(Clone, Default)]
pub struct InMemoryStorage {
    state: Arc<RwLock<InMemoryState>>,
    max_mempool: usize,
}

impl InMemoryStorage {
    pub fn new(max_mempool: usize) -> Self {
        Self {
            state: Arc::new(RwLock::new(InMemoryState::default())),
            max_mempool,
        }
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn insert_user_op(&self, op: UserOperation) -> Result<(), StorageError> {
        let mut state = self.state.write().await;
        if state.mempool.len() >= self.max_mempool {
            return Err(StorageError::MempoolFull);
        }
        state.seen_nonces.insert((op.sender, op.nonce));
        *state.pending.entry(op.sender).or_default() += 1;
        state.mempool.push_back(op);
        Ok(())
    }

    async fn take_batch(&self, max: usize) -> Result<Vec<UserOperation>, StorageError> {
        let mut state = self.state.write().await;
        let mut out = Vec::with_capacity(max);
        for _ in 0..max {
            if let Some(op) = state.mempool.pop_front() {
                if let Some(n) = state.pending.get_mut(&op.sender) {
                    *n = n.saturating_sub(1);
                }
                out.push(op);
            } else {
                break;
            }
        }
        Ok(out)
    }

    async fn list_mempool(&self, limit: usize) -> Result<Vec<UserOperation>, StorageError> {
        let state = self.state.read().await;
        Ok(state.mempool.iter().take(limit).cloned().collect())
    }

    async fn mempool_len(&self) -> Result<usize, StorageError> {
        let state = self.state.read().await;
        Ok(state.mempool.len())
    }

    async fn store_receipt(&self, op_hash: OpHash, receipt: ZkvmReceipt) -> Result<(), StorageError> {
        let mut state = self.state.write().await;
        state.receipts.insert(op_hash, receipt);
        Ok(())
    }

    async fn get_receipt(&self, op_hash: &OpHash) -> Result<Option<ZkvmReceipt>, StorageError> {
        let state = self.state.read().await;
        Ok(state.receipts.get(op_hash).cloned())
    }

    async fn has_sender_nonce(&self, sender: &Address, nonce: u64) -> Result<bool, StorageError> {
        let state = self.state.read().await;
        Ok(state.seen_nonces.contains(&(*sender, nonce)))
    }

    async fn pending_for_sender(&self, sender: &Address) -> Result<u64, StorageError> {
        let state = self.state.read().await;
        Ok(state.pending.get(sender).copied().unwrap_or(0))
    }
}
