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
    async fn has_sender_nonce(&self, sender: &Address, nonce: u64) -> Result<bool, StorageError>;
}

#[derive(Debug, Default)]
struct InMemoryState {
    mempool: VecDeque<UserOperation>,
    receipts: HashMap<OpHash, ZkvmReceipt>,
    sender_nonces: HashSet<(Address, u64)>,
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
        state.sender_nonces.insert((op.sender, op.nonce));
        state.mempool.push_back(op);
        Ok(())
    }

    async fn take_batch(&self, max: usize) -> Result<Vec<UserOperation>, StorageError> {
        let mut state = self.state.write().await;
        let mut out = Vec::with_capacity(max);
        for _ in 0..max {
            if let Some(op) = state.mempool.pop_front() {
                state.sender_nonces.remove(&(op.sender, op.nonce));
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
        Ok(state.sender_nonces.contains(&(*sender, nonce)))
    }
}
