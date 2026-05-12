use crate::types::{CryptoError, CryptoResult, SignatureScheme};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

/// ML-DSA (CRYSTALS-Dilithium) wrapper.
/// Flow: keypair -> detached_sign(message) -> verify_detached_signature(signature, message, public_key).
pub struct MlDsaDilithium2;

impl MlDsaDilithium2 {
    pub fn pk_to_bytes(pk: &dilithium2::PublicKey) -> Vec<u8> {
        pk.as_bytes().to_vec()
    }

    pub fn sk_to_bytes(sk: &dilithium2::SecretKey) -> Vec<u8> {
        sk.as_bytes().to_vec()
    }

    pub fn sig_to_bytes(sig: &dilithium2::DetachedSignature) -> Vec<u8> {
        sig.as_bytes().to_vec()
    }

    pub fn pk_from_bytes(bytes: &[u8]) -> CryptoResult<dilithium2::PublicKey> {
        dilithium2::PublicKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKeyBytes)
    }

    pub fn sk_from_bytes(bytes: &[u8]) -> CryptoResult<dilithium2::SecretKey> {
        dilithium2::SecretKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKeyBytes)
    }

    pub fn sig_from_bytes(bytes: &[u8]) -> CryptoResult<dilithium2::DetachedSignature> {
        dilithium2::DetachedSignature::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidSignatureBytes)
    }
}

impl SignatureScheme for MlDsaDilithium2 {
    type PublicKey = dilithium2::PublicKey;
    type SecretKey = dilithium2::SecretKey;
    type Signature = dilithium2::DetachedSignature;

    fn name() -> &'static str {
        "ML-DSA(Dilithium2)"
    }

    fn keygen() -> CryptoResult<(Self::PublicKey, Self::SecretKey)> {
        Ok(dilithium2::keypair())
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> CryptoResult<Self::Signature> {
        Ok(dilithium2::detached_sign(msg, sk))
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> CryptoResult<bool> {
        match dilithium2::verify_detached_signature(sig, msg, pk) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
