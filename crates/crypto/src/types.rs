use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid key bytes")]
    InvalidKeyBytes,
    #[error("invalid signature bytes")]
    InvalidSignatureBytes,
    #[error("verification failed")]
    VerificationFailed,
    #[error("serialization error: {0}")]
    Serde(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

pub trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;

    fn name() -> &'static str;
    fn keygen() -> CryptoResult<(Self::PublicKey, Self::SecretKey)>;
    fn sign(msg: &[u8], sk: &Self::SecretKey) -> CryptoResult<Self::Signature>;
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> CryptoResult<bool>;
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(s: &str) -> CryptoResult<Vec<u8>> {
    hex::decode(s).map_err(|e| CryptoError::InvalidHex(e.to_string()))
}
