//! Networking abstractions for bundler-prover coordination.

use async_trait::async_trait;
use qevm_types::{BundlerBatch, OpHash, UserOperation, ZkvmReceipt};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::instrument;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("channel closed")]
    Closed,
    #[error("network error: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub enum NetworkMessage {
    UserOperation(UserOperation),
    Batch(BundlerBatch),
    Receipt(OpHash, ZkvmReceipt),
}

#[async_trait]
pub trait Network: Send + Sync {
    async fn send(&self, message: NetworkMessage) -> Result<(), NetworkError>;
    async fn recv(&self) -> Result<NetworkMessage, NetworkError>;
}

#[derive(Clone)]
pub struct LocalNetwork {
    sender: mpsc::Sender<NetworkMessage>,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<NetworkMessage>>>,
}

impl LocalNetwork {
    pub fn pair(buffer: usize) -> (Self, Self) {
        let (a_tx, a_rx) = mpsc::channel(buffer);
        let (b_tx, b_rx) = mpsc::channel(buffer);

        let a = LocalNetwork {
            sender: a_tx,
            receiver: Arc::new(tokio::sync::Mutex::new(b_rx)),
        };
        let b = LocalNetwork {
            sender: b_tx,
            receiver: Arc::new(tokio::sync::Mutex::new(a_rx)),
        };

        (a, b)
    }
}

#[async_trait]
impl Network for LocalNetwork {
    #[instrument(skip_all)]
    async fn send(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        self.sender.send(message).await.map_err(|_| NetworkError::Closed)
    }

    #[instrument(skip_all)]
    async fn recv(&self) -> Result<NetworkMessage, NetworkError> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await.ok_or(NetworkError::Closed)
    }
}
