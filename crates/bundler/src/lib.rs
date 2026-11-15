//! Bundler pipeline for validating, batching and submitting Q-EVM UserOperations.
//!
//! Validation (off-chain, before an op enters the mempool):
//! 1. PQC payload present; `chain_id` and `wallet` match this chain's wallet;
//! 2. the sender is registered in the wallet with `keccak(pk)` (key binding);
//! 3. `(sender, nonce)` was never accepted before (replay), and the nonce is
//!    exactly `wallet.nonce[sender] + pending ops of sender` (ordering);
//! 4. the ML-DSA-44 signature over the op hash verifies (FIPS 204, native).
//!
//! Bundling authorises a batch and sends it to the wallet contract, which
//! re-checks key binding and nonces on-chain and consumes the nonces.

use qevm_storage::Storage;
use qevm_types::{BatchReceipt, BundlerBatch, OpHash, UserOperation, WalletKind, ZkvmReceipt};
use qevm_utils::now_millis;
use qevm_zkvm::{SigCheck, ZkvmProver};
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{timeout, Duration, Instant};
use tracing::{info, instrument, warn};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BundlerError {
    #[error("zkvm error: {0}")]
    Zkvm(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("chain error: {0}")]
    Chain(String),
    #[error("timeout while generating proof")]
    Timeout,
}

/// How batches are authorised on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    /// One Groth16 receipt and one wallet transaction per op (no batching).
    PerOp,
    /// One authorisation and one wallet transaction per batch.
    Batch(WalletKind),
}

impl ProofMode {
    pub fn wallet_kind(&self) -> WalletKind {
        match self {
            ProofMode::PerOp => WalletKind::Groth16,
            ProofMode::Batch(kind) => *kind,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BundlerConfig {
    pub max_mempool: usize,
    pub batch_size: usize,
    pub proof_timeout: Duration,
    pub proof_retries: usize,
    pub mode: ProofMode,
    /// In batch mode, also prove a per-op receipt at submission (for display
    /// in the dashboard). Off in experiments: it would double-count proving.
    pub reference_receipts: bool,
    /// Send each authorised batch to the wallet contract (commit on success).
    pub submit_on_chain: bool,
}

impl Default for BundlerConfig {
    fn default() -> Self {
        Self {
            max_mempool: 2048,
            batch_size: 32,
            proof_timeout: Duration::from_secs(12),
            proof_retries: 2,
            mode: ProofMode::Batch(WalletKind::Groth16),
            reference_receipts: true,
            submit_on_chain: true,
        }
    }
}

/// Why an op was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    MissingPayload,
    WrongChain { expected: u64, got: u64 },
    WrongWallet,
    UnknownAccount,
    KeyMismatch,
    /// `(sender, nonce)` was accepted before: a replay.
    DuplicateNonce,
    BadNonce { expected: u64, got: u64 },
    InvalidSignature,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::MissingPayload => write!(f, "missing PQC payload"),
            Rejection::WrongChain { expected, got } => write!(f, "wrong chain id {got} (expected {expected})"),
            Rejection::WrongWallet => write!(f, "op is bound to a different wallet contract"),
            Rejection::UnknownAccount => write!(f, "sender is not registered in the wallet"),
            Rejection::KeyMismatch => write!(f, "public key is not the one registered for the sender"),
            Rejection::DuplicateNonce => write!(f, "duplicate (sender, nonce): replay"),
            Rejection::BadNonce { expected, got } => write!(f, "nonce {got} out of order (expected {expected})"),
            Rejection::InvalidSignature => write!(f, "ML-DSA signature does not verify"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubmissionOutcome {
    pub op_hash: OpHash,
    pub accepted: bool,
    pub rejection: Option<Rejection>,
    pub signature: Option<SigCheck>,
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
        Self { config, storage, zkvm }
    }

    pub fn config(&self) -> &BundlerConfig {
        &self.config
    }

    fn rejected(op_hash: OpHash, why: Rejection, signature: Option<SigCheck>) -> SubmissionOutcome {
        metrics::counter!("bundler.user_ops.rejected").increment(1);
        SubmissionOutcome { op_hash, accepted: false, rejection: Some(why), signature, receipt: None }
    }

    #[instrument(skip_all)]
    pub async fn submit_user_operation(&self, mut op: UserOperation) -> Result<SubmissionOutcome, BundlerError> {
        let op_hash = op.op_hash();
        if let Err(why) = self.validate(&op).await? {
            return Ok(Self::rejected(op_hash, why, None));
        }

        let check = self.zkvm.check_signature(&op).await.map_err(|e| BundlerError::Zkvm(e.to_string()))?;
        if !check.valid {
            return Ok(Self::rejected(op_hash, Rejection::InvalidSignature, Some(check)));
        }

        let wants_receipt = self.config.mode == ProofMode::PerOp || self.config.reference_receipts;
        let receipt = if wants_receipt { Some(self.prove_with_retry(&op).await?) } else { None };
        if let Some(ref r) = receipt {
            self.storage
                .store_receipt(op_hash, r.clone())
                .await
                .map_err(|e| BundlerError::Storage(e.to_string()))?;
            op = op.with_receipt(r.clone());
        }

        self.storage.insert_user_op(op).await.map_err(|e| BundlerError::Storage(e.to_string()))?;
        metrics::counter!("bundler.user_ops.accepted").increment(1);
        info!("accepted user op with hash={}", op_hash);
        Ok(SubmissionOutcome { op_hash, accepted: true, rejection: None, signature: Some(check), receipt })
    }

    async fn validate(&self, op: &UserOperation) -> Result<Result<(), Rejection>, BundlerError> {
        if op.pqc_payload.public_key.is_empty() || op.pqc_payload.signature.is_empty() {
            return Ok(Err(Rejection::MissingPayload));
        }
        let chain = self.zkvm.chain();
        if op.chain_id != chain.chain_id() {
            return Ok(Err(Rejection::WrongChain { expected: chain.chain_id(), got: op.chain_id }));
        }
        let kind = self.config.mode.wallet_kind();
        if op.wallet.as_bytes() != &chain.wallet(kind).address {
            return Ok(Err(Rejection::WrongWallet));
        }
        let sender = op.sender.as_bytes();
        match chain.registered_pk_hash(kind, sender) {
            None => return Ok(Err(Rejection::UnknownAccount)),
            Some(h) if h != op.pk_hash() => return Ok(Err(Rejection::KeyMismatch)),
            Some(_) => {}
        }
        let seen = self
            .storage
            .has_sender_nonce(&op.sender, op.nonce)
            .await
            .map_err(|e| BundlerError::Storage(e.to_string()))?;
        if seen {
            return Ok(Err(Rejection::DuplicateNonce));
        }
        let pending =
            self.storage.pending_for_sender(&op.sender).await.map_err(|e| BundlerError::Storage(e.to_string()))?;
        let expected = chain.nonce(kind, sender) + pending;
        if op.nonce != expected {
            return Ok(Err(Rejection::BadNonce { expected, got: op.nonce }));
        }
        Ok(Ok(()))
    }

    pub async fn mempool_len(&self) -> Result<usize, BundlerError> {
        self.storage.mempool_len().await.map_err(|e| BundlerError::Storage(e.to_string()))
    }

    /// Take up to `batch_size` ops, authorise them and (optionally) send them
    /// to the wallet. Returns one [`BatchReceipt`] per wallet transaction.
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

        let mut transactions = Vec::new();
        match self.config.mode {
            ProofMode::PerOp => {
                for op in &ops {
                    let receipt = match op.zkvm_receipt.clone() {
                        Some(r) => r,
                        None => self.prove_with_retry(op).await?,
                    };
                    let tx = qevm_evm_calldata(&receipt.proof, std::slice::from_ref(op));
                    let gas = receipt.journal.onchain_gas;
                    transactions.push(BatchReceipt {
                        digest: OpHash::new(qevm_types::batch_digest_of(std::slice::from_ref(op))),
                        kind: WalletKind::Groth16,
                        proof: receipt.proof[..256].to_vec(),
                        wallet_calldata: tx,
                        size: 1,
                        onchain_gas: gas,
                        amortized_gas_per_op: gas.total,
                        prove_time_ms: receipt.journal.prove_time_ms,
                        inclusion: None,
                    });
                }
            }
            ProofMode::Batch(kind) => {
                let receipt = self.authorize_with_retry(&ops, kind).await?;
                transactions.push(receipt);
            }
        }

        if self.config.submit_on_chain {
            let chain = self.zkvm.chain();
            for tx in transactions.iter_mut() {
                let outcome = chain
                    .send(chain.wallet(tx.kind).address, &tx.wallet_calldata)
                    .map_err(|e| BundlerError::Chain(e.to_string()))?;
                if !outcome.committed {
                    warn!("wallet rejected batch digest={} ({} ops)", tx.digest, tx.size);
                }
                tx.inclusion = Some(outcome);
            }
        }

        metrics::counter!("bundler.batches.created").increment(1);
        Ok(Some(BundlerBatch {
            batch_id: Uuid::new_v4(),
            created_at: now_millis().map_err(|e| BundlerError::Storage(e.to_string()))?,
            operations: ops,
            transactions,
        }))
    }

    async fn prove_with_retry(&self, op: &UserOperation) -> Result<ZkvmReceipt, BundlerError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let start = Instant::now();
            let result = timeout(self.config.proof_timeout, self.zkvm.prove(op)).await;
            metrics::histogram!("bundler.zkvm.proof_latency_ms").record(start.elapsed().as_secs_f64() * 1000.0);
            match result {
                Ok(Ok(receipt)) => return Ok(receipt),
                Ok(Err(err)) => {
                    warn!("zkvm error: {err}");
                    if attempts > self.config.proof_retries {
                        return Err(BundlerError::Zkvm(err.to_string()));
                    }
                }
                Err(_) if attempts > self.config.proof_retries => return Err(BundlerError::Timeout),
                Err(_) => {}
            }
        }
    }

    async fn authorize_with_retry(&self, ops: &[UserOperation], kind: WalletKind) -> Result<BatchReceipt, BundlerError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match timeout(self.config.proof_timeout, self.zkvm.authorize_batch(ops, kind)).await {
                Ok(Ok(receipt)) => return Ok(receipt),
                Ok(Err(err)) => {
                    warn!("batch authorisation error: {err}");
                    if attempts > self.config.proof_retries {
                        return Err(BundlerError::Zkvm(err.to_string()));
                    }
                }
                Err(_) if attempts > self.config.proof_retries => return Err(BundlerError::Timeout),
                Err(_) => {}
            }
        }
    }
}

/// Wallet calldata for ops authorised by a single-op receipt (proof prefix only).
fn qevm_evm_calldata(receipt_proof: &[u8], ops: &[UserOperation]) -> Vec<u8> {
    let records: Vec<_> = ops.iter().map(UserOperation::to_wallet_op).collect();
    qevm_types::wallet_calldata(&receipt_proof[..256], &records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::{MlDsa44, SignatureScheme};
    use qevm_storage::InMemoryStorage;
    use qevm_types::{Address, PqcPayload};
    use qevm_zkvm::{LocalZkvmProver, ZkvmConfig};

    fn setup(mode: ProofMode) -> (Bundler, Arc<LocalZkvmProver>) {
        let storage = Arc::new(InMemoryStorage::new(64));
        let zkvm = Arc::new(LocalZkvmProver::new(ZkvmConfig::default()));
        let config = BundlerConfig { mode, reference_receipts: false, ..Default::default() };
        (Bundler::new(config, storage, zkvm.clone()), zkvm)
    }

    fn signed(zkvm: &LocalZkvmProver, kind: WalletKind, sender: Address, nonce: u64) -> UserOperation {
        let (pk, sk) = MlDsa44::keygen().expect("keygen");
        let wallet = Address::new(zkvm.chain().wallet(kind).address);
        let mut op = UserOperation::new(
            wallet,
            sender,
            nonce,
            1,
            b"demo".to_vec(),
            PqcPayload { public_key: MlDsa44::pk_to_bytes(&pk), signature: vec![] },
        )
        .unwrap();
        zkvm.chain().register_account(sender.as_bytes(), op.pk_hash(), nonce);
        let sig = MlDsa44::sign(op.op_hash().as_bytes(), &sk).expect("sign");
        op.pqc_payload.signature = MlDsa44::sig_to_bytes(&sig);
        op
    }

    #[tokio::test]
    async fn bundler_accepts_and_includes_valid_ops() {
        for mode in [ProofMode::PerOp, ProofMode::Batch(WalletKind::Groth16), ProofMode::Batch(WalletKind::Attestation)]
        {
            let (bundler, zkvm) = setup(mode);
            for i in 0..3u8 {
                let op = signed(&zkvm, mode.wallet_kind(), Address::new([i + 1; 20]), 0);
                assert!(bundler.submit_user_operation(op).await.expect("submit").accepted);
            }
            let batch = bundler.bundle_next().await.expect("bundle").expect("batch");
            assert_eq!(batch.operations.len(), 3);
            let expected_txs = if mode == ProofMode::PerOp { 3 } else { 1 };
            assert_eq!(batch.transactions.len(), expected_txs);
            for tx in &batch.transactions {
                assert!(tx.inclusion.expect("sent").committed, "{mode:?}: wallet must accept");
            }
        }
    }
}
