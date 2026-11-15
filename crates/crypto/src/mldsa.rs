use crate::types::{CryptoError, CryptoResult, SignatureScheme};
use pqcrypto_mldsa::mldsa44;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

/// ML-DSA-44 (FIPS 204, final standard, security category 2) via
/// `pqcrypto-mldsa` (PQClean reference/AVX2 code).
///
/// Signing and verification use the FIPS 204 "pure" mode with an **empty
/// context string**, so the signed message is M' = 0x00 ‖ 0x00 ‖ M
/// (FIPS 204, Alg. 2/3). Earlier versions of this prototype used round-3
/// CRYSTALS-Dilithium2 (`pqcrypto-dilithium`), which is *not* FIPS 204.
pub struct MlDsa44;

/// Public-key length of ML-DSA-44 in bytes (FIPS 204, Table 2).
pub const MLDSA44_PK_LEN: usize = 1312;
/// Signature length of ML-DSA-44 in bytes (FIPS 204, Table 2).
pub const MLDSA44_SIG_LEN: usize = 2420;

impl MlDsa44 {
    pub fn pk_to_bytes(pk: &mldsa44::PublicKey) -> Vec<u8> {
        pk.as_bytes().to_vec()
    }

    pub fn sk_to_bytes(sk: &mldsa44::SecretKey) -> Vec<u8> {
        sk.as_bytes().to_vec()
    }

    pub fn sig_to_bytes(sig: &mldsa44::DetachedSignature) -> Vec<u8> {
        sig.as_bytes().to_vec()
    }

    pub fn pk_from_bytes(bytes: &[u8]) -> CryptoResult<mldsa44::PublicKey> {
        mldsa44::PublicKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKeyBytes)
    }

    pub fn sk_from_bytes(bytes: &[u8]) -> CryptoResult<mldsa44::SecretKey> {
        mldsa44::SecretKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKeyBytes)
    }

    pub fn sig_from_bytes(bytes: &[u8]) -> CryptoResult<mldsa44::DetachedSignature> {
        mldsa44::DetachedSignature::from_bytes(bytes).map_err(|_| CryptoError::InvalidSignatureBytes)
    }

    /// Verify raw byte encodings; any malformed encoding is a rejection.
    pub fn verify_bytes(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        match (Self::pk_from_bytes(pk), Self::sig_from_bytes(sig)) {
            (Ok(pk), Ok(sig)) => mldsa44::verify_detached_signature(&sig, msg, &pk).is_ok(),
            _ => false,
        }
    }
}

impl SignatureScheme for MlDsa44 {
    type PublicKey = mldsa44::PublicKey;
    type SecretKey = mldsa44::SecretKey;
    type Signature = mldsa44::DetachedSignature;

    fn name() -> &'static str {
        "ML-DSA-44 (FIPS 204)"
    }

    fn keygen() -> CryptoResult<(Self::PublicKey, Self::SecretKey)> {
        Ok(mldsa44::keypair())
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> CryptoResult<Self::Signature> {
        Ok(mldsa44::detached_sign(msg, sk))
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> CryptoResult<bool> {
        Ok(mldsa44::verify_detached_signature(sig, msg, pk).is_ok())
    }
}
