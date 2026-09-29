//! Protocol types and hashing for Q-EVM.
//!
//! These structures map directly to the UserOperation flow described in the
//! research paper and ensure deterministic hashing for zkVM public inputs.

use qevm_utils::{hex_decode, hex_encode, keccak256, now_millis, UtilsError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

pub use qevm_evm::{NativeGasBreakdown, OnchainGas};

// ---------------------------------------------------------------------------
// Paper reference values (Table II / §V-B). These are *projections* from the
// paper and are only displayed next to the measured values for comparison;
// no receipt or report takes its numbers from them.
// ---------------------------------------------------------------------------

pub const PAPER_NATIVE_GAS_REF: u64 = 2_840_000;
pub const PAPER_GROTH16_GAS_REF: u64 = 242_500;
pub const PAPER_BATCHED_GAS_PER_TX_REF: u64 = 2_900;
pub const PAPER_CYCLE_COUNT_REF: u64 = 1_842_500;

/// Ethereum mainnet block gas limit used for the ops-per-block comparison.
pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;

// ---------------------------------------------------------------------------
// Gas analysis report — served by /api/gas-analysis, built from live receipts
// ---------------------------------------------------------------------------

/// The deployed Groth16 verifier contract.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VerifierInfo {
    pub deploy_gas: u64,
    pub code_size: usize,
}

/// Gas of the most recent batch receipt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BatchGas {
    pub size: usize,
    pub onchain_gas: OnchainGas,
    pub amortized_gas_per_op: u64,
    pub prove_time_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperReference {
    pub native_gas: u64,
    pub groth16_gas: u64,
    pub reduction_percent: f64,
    pub batched_gas_per_tx: u64,
    pub cycle_count: u64,
}

impl Default for PaperReference {
    fn default() -> Self {
        Self {
            native_gas: PAPER_NATIVE_GAS_REF,
            groth16_gas: PAPER_GROTH16_GAS_REF,
            reduction_percent: reduction_percent(PAPER_NATIVE_GAS_REF, PAPER_GROTH16_GAS_REF),
            batched_gas_per_tx: PAPER_BATCHED_GAS_PER_TX_REF,
            cycle_count: PAPER_CYCLE_COUNT_REF,
        }
    }
}

pub fn reduction_percent(native: u64, onchain: u64) -> f64 {
    if native == 0 {
        return 0.0;
    }
    native.saturating_sub(onchain) as f64 / native as f64 * 100.0
}

/// Measured on-chain gas vs metered native ML-DSA gas, aggregated over every
/// receipt this node has produced. `measured` is false until the first one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasAnalysis {
    pub measured: bool,
    pub samples: u64,
    /// EVM `gas_used` of the Groth16 verifier call (last / avg / min / max).
    pub onchain_last: Option<OnchainGas>,
    pub onchain_avg: u64,
    pub onchain_min: u64,
    pub onchain_max: u64,
    /// Metered gas of verifying the same signatures natively in the EVM.
    pub native_last: Option<NativeGasBreakdown>,
    pub native_avg: u64,
    pub gas_saved_avg: u64,
    pub reduction_percent: f64,
    pub prove_time_ms_avg: f64,
    pub native_ops_per_block: u64,
    pub zkvm_ops_per_block: u64,
    pub block_gas_limit: u64,
    pub last_batch: Option<BatchGas>,
    pub verifier: Option<VerifierInfo>,
    pub paper: PaperReference,
}

/// Running totals from which [`GasAnalysis`] is built.
#[derive(Debug, Clone, Default)]
pub struct GasStats {
    samples: u64,
    onchain_sum: u64,
    onchain_min: u64,
    onchain_max: u64,
    native_sum: u64,
    prove_ms_sum: f64,
    onchain_last: Option<OnchainGas>,
    native_last: Option<NativeGasBreakdown>,
    last_batch: Option<BatchGas>,
}

impl GasStats {
    pub fn record_receipt(&mut self, receipt: &ZkvmReceipt) {
        let onchain = receipt.journal.onchain_gas.total;
        self.onchain_min = if self.samples == 0 { onchain } else { self.onchain_min.min(onchain) };
        self.onchain_max = self.onchain_max.max(onchain);
        self.samples += 1;
        self.onchain_sum += onchain;
        self.native_sum += receipt.journal.native_gas.total;
        self.prove_ms_sum += receipt.journal.prove_time_ms;
        self.onchain_last = Some(receipt.journal.onchain_gas);
        self.native_last = Some(receipt.journal.native_gas);
    }

    pub fn record_batch(&mut self, batch: &BatchReceipt) {
        self.last_batch = Some(batch.gas());
    }

    pub fn analysis(&self, verifier: Option<VerifierInfo>) -> GasAnalysis {
        let n = self.samples.max(1);
        let onchain_avg = self.onchain_sum / n;
        let native_avg = self.native_sum / n;
        GasAnalysis {
            measured: self.samples > 0,
            samples: self.samples,
            onchain_last: self.onchain_last,
            onchain_avg,
            onchain_min: self.onchain_min,
            onchain_max: self.onchain_max,
            native_last: self.native_last,
            native_avg,
            gas_saved_avg: native_avg.saturating_sub(onchain_avg),
            reduction_percent: reduction_percent(native_avg, onchain_avg),
            prove_time_ms_avg: self.prove_ms_sum / n as f64,
            native_ops_per_block: BLOCK_GAS_LIMIT.checked_div(native_avg).unwrap_or(0),
            zkvm_ops_per_block: BLOCK_GAS_LIMIT.checked_div(onchain_avg).unwrap_or(0),
            block_gas_limit: BLOCK_GAS_LIMIT,
            last_batch: self.last_batch,
            verifier,
            paper: PaperReference::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TypesError {
    #[error("invalid address length: {0}")]
    InvalidAddressLength(usize),
    #[error("invalid hash length: {0}")]
    InvalidHashLength(usize),
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("utils error: {0}")]
    Utils(String),
}

impl From<UtilsError> for TypesError {
    fn from(err: UtilsError) -> Self {
        match err {
            UtilsError::InvalidHex(e) => TypesError::InvalidHex(e),
            UtilsError::Time(e) => TypesError::Utils(e),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Address([u8; 20]);

impl Address {
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(value: &str) -> Result<Self, TypesError> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex_decode(trimmed)?;
        if bytes.len() != 20 {
            return Err(TypesError::InvalidAddressLength(bytes.len()));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex_encode(&self.0))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Address::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct OpHash([u8; 32]);

impl OpHash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(value: &str) -> Result<Self, TypesError> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex_decode(trimmed)?;
        if bytes.len() != 32 {
            return Err(TypesError::InvalidHashLength(bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex_encode(&self.0))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OpHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for OpHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for OpHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for OpHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        OpHash::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcPayload {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkvmPublicInputs {
    pub op_hash: OpHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkvmJournal {
    pub is_valid: bool,
    pub program_id: String,
    /// Wall-clock time spent generating the Groth16 proof.
    pub prove_time_ms: f64,
    /// Gas the EVM charged to verify this receipt's proof (measured on revm).
    pub onchain_gas: OnchainGas,
    /// Metered gas of verifying this op's ML-DSA signature natively in the EVM.
    pub native_gas: NativeGasBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkvmReceipt {
    /// Groth16 proof, EVM-encoded as verifier calldata: A ‖ B ‖ C ‖ public inputs.
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    pub public_inputs: ZkvmPublicInputs,
    pub journal: ZkvmJournal,
    pub created_at: u64,
    /// `native_gas.total - onchain_gas.total` for this op.
    pub gas_saved_vs_native: u64,
}

/// One Groth16 proof covering a whole batch (digest = keccak of the op hashes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReceipt {
    pub digest: OpHash,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    pub size: usize,
    pub onchain_gas: OnchainGas,
    pub amortized_gas_per_op: u64,
    pub prove_time_ms: f64,
}

impl BatchReceipt {
    pub fn gas(&self) -> BatchGas {
        BatchGas {
            size: self.size,
            onchain_gas: self.onchain_gas,
            amortized_gas_per_op: self.amortized_gas_per_op,
            prove_time_ms: self.prove_time_ms,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOperation {
    pub sender: Address,
    pub nonce: u64,
    pub chain_id: u64,
    #[serde(with = "serde_bytes")]
    pub call_data: Vec<u8>,
    pub pqc_payload: PqcPayload,
    pub zkvm_receipt: Option<ZkvmReceipt>,
    pub created_at: u64,
}

impl UserOperation {
    pub fn new(
        sender: Address,
        nonce: u64,
        chain_id: u64,
        call_data: Vec<u8>,
        pqc_payload: PqcPayload,
    ) -> Result<Self, TypesError> {
        Ok(Self {
            sender,
            nonce,
            chain_id,
            call_data,
            pqc_payload,
            zkvm_receipt: None,
            created_at: now_millis()?,
        })
    }

    pub fn op_hash(&self) -> OpHash {
        let mut payload = Vec::with_capacity(128 + self.call_data.len());
        payload.extend_from_slice(self.sender.as_bytes());
        payload.extend_from_slice(&self.chain_id.to_be_bytes());
        payload.extend_from_slice(&self.nonce.to_be_bytes());
        payload.extend_from_slice(&(self.call_data.len() as u32).to_be_bytes());
        payload.extend_from_slice(&self.call_data);
        payload.extend_from_slice(&(self.pqc_payload.public_key.len() as u32).to_be_bytes());
        payload.extend_from_slice(&self.pqc_payload.public_key);
        OpHash::new(keccak256(&payload))
    }

    pub fn with_receipt(mut self, receipt: ZkvmReceipt) -> Self {
        self.zkvm_receipt = Some(receipt);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundlerBatch {
    pub batch_id: Uuid,
    pub created_at: u64,
    pub operations: Vec<UserOperation>,
    pub batch_receipt: Option<BatchReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOperationHex {
    pub sender: String,
    pub nonce: u64,
    pub chain_id: u64,
    pub call_data: String,
    pub public_key: String,
    pub signature: String,
}

impl UserOperationHex {
    pub fn to_user_op(&self) -> Result<UserOperation, TypesError> {
        let sender = Address::from_hex(&self.sender)?;
        let call_data = hex_decode(self.call_data.strip_prefix("0x").unwrap_or(&self.call_data))?;
        let public_key = hex_decode(self.public_key.strip_prefix("0x").unwrap_or(&self.public_key))?;
        let signature = hex_decode(self.signature.strip_prefix("0x").unwrap_or(&self.signature))?;
        let payload = PqcPayload {
            public_key,
            signature,
        };
        UserOperation::new(sender, self.nonce, self.chain_id, call_data, payload)
    }

    pub fn from_user_op(op: &UserOperation) -> Self {
        Self {
            sender: op.sender.to_hex(),
            nonce: op.nonce,
            chain_id: op.chain_id,
            call_data: format!("0x{}", hex_encode(&op.call_data)),
            public_key: format!("0x{}", hex_encode(&op.pqc_payload.public_key)),
            signature: format!("0x{}", hex_encode(&op.pqc_payload.signature)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn op_hash_is_stable() {
        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let payload = PqcPayload {
            public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        };
        let op = UserOperation::new(sender, 1, 1, vec![7, 8], payload).unwrap();
        assert_eq!(op.op_hash(), op.op_hash());
    }

    proptest! {
        #[test]
        fn address_round_trip(bytes in proptest::collection::vec(any::<u8>(), 20..=20)) {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            let addr = Address::new(arr);
            let encoded = addr.to_hex();
            let decoded = Address::from_hex(&encoded).expect("decode");
            prop_assert_eq!(addr, decoded);
        }
    }
}
