//! Protocol types and hashing for Q-EVM.
//!
//! These structures map directly to the UserOperation flow described in the
//! research paper and ensure deterministic hashing for zkVM public inputs.

use qevm_utils::{hex_decode, hex_encode, keccak256, now_millis, UtilsError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

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
    pub cycle_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkvmReceipt {
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    pub public_inputs: ZkvmPublicInputs,
    pub journal: ZkvmJournal,
    pub created_at: u64,
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
