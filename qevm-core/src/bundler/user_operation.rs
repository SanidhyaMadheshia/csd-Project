use crate::crypto::{hex_decode, hex_encode, CryptoError, CryptoResult, MlDsaDilithium2, SignatureScheme};
use pqcrypto_dilithium::dilithium2;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOperation {
    pub sender: String,
    pub nonce: u64,
    #[serde(with = "serde_bytes")]
    pub call_data: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

pub fn create_user_op(sender: impl Into<String>, nonce: u64, call_data: Vec<u8>) -> UserOperation {
    UserOperation {
        sender: sender.into(),
        nonce,
        call_data,
        signature: Vec::new(),
    }
}

fn user_op_signing_payload(uo: &UserOperation) -> Vec<u8> {
    // Minimal, deterministic payload for signing.
    // In real ERC-4337 this would be a packed hash over many fields.
    let mut out = Vec::new();
    out.extend_from_slice(uo.sender.as_bytes());
    out.extend_from_slice(&uo.nonce.to_be_bytes());
    out.extend_from_slice(&uo.call_data);
    out
}

pub fn sign_user_op_ml_dsa(uo: &mut UserOperation, sk: &dilithium2::SecretKey) -> CryptoResult<()> {
    let payload = user_op_signing_payload(uo);
    let sig = MlDsaDilithium2::sign(&payload, sk)?;
    uo.signature = MlDsaDilithium2::sig_to_bytes(&sig);
    Ok(())
}

pub fn verify_user_op(uo: &UserOperation, pk: &dilithium2::PublicKey) -> CryptoResult<bool> {
    if uo.signature.is_empty() {
        return Ok(false);
    }
    let payload = user_op_signing_payload(uo);
    let sig = MlDsaDilithium2::sig_from_bytes(&uo.signature)?;
    MlDsaDilithium2::verify(&payload, &sig, pk)
}

pub fn user_op_to_json(uo: &UserOperation) -> CryptoResult<String> {
    serde_json::to_string_pretty(uo).map_err(|e| CryptoError::Serde(e.to_string()))
}

pub fn user_op_from_json(json: &str) -> CryptoResult<UserOperation> {
    serde_json::from_str(json).map_err(|e| CryptoError::Serde(e.to_string()))
}

pub fn user_op_to_hex_json(uo: &UserOperation) -> CryptoResult<String> {
    #[derive(Serialize)]
    struct HexUserOp<'a> {
        sender: &'a str,
        nonce: u64,
        call_data: String,
        signature: String,
    }

    let hu = HexUserOp {
        sender: &uo.sender,
        nonce: uo.nonce,
        call_data: hex_encode(&uo.call_data),
        signature: hex_encode(&uo.signature),
    };

    serde_json::to_string_pretty(&hu).map_err(|e| CryptoError::Serde(e.to_string()))
}

pub fn user_op_from_hex_json(json: &str) -> CryptoResult<UserOperation> {
    #[derive(Deserialize)]
    struct HexUserOp {
        sender: String,
        nonce: u64,
        call_data: String,
        signature: String,
    }

    let hu: HexUserOp = serde_json::from_str(json).map_err(|e| CryptoError::Serde(e.to_string()))?;

    Ok(UserOperation {
        sender: hu.sender,
        nonce: hu.nonce,
        call_data: hex_decode(&hu.call_data)?,
        signature: hex_decode(&hu.signature)?,
    })
}
