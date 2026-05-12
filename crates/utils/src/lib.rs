//! Shared hashing and utility helpers for Q-EVM.

use sha3::{Digest, Keccak256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UtilsError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("time error: {0}")]
    Time(String),
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(value: &str) -> Result<Vec<u8>, UtilsError> {
    hex::decode(value).map_err(|e| UtilsError::InvalidHex(e.to_string()))
}

pub fn now_millis() -> Result<u64, UtilsError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| UtilsError::Time(e.to_string()))?;
    Ok(duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_is_deterministic() {
        let first = keccak256(b"qevm");
        let second = keccak256(b"qevm");
        assert_eq!(first, second);
    }

    #[test]
    fn hex_round_trip() {
        let data = b"qevm-utils";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).expect("decode");
        assert_eq!(decoded, data);
    }
}
