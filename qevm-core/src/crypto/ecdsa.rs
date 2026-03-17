use crate::crypto::{CryptoError, CryptoResult, SignatureScheme};
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

// ECDSA (secp256k1) wrapper using `k256`.
// Flow: random signing key -> derive verifying key -> sign(message) -> verify(signature, message, verifying_key).
pub struct EcdsaSecp256k1;

impl EcdsaSecp256k1 {
    pub fn pk_to_bytes(pk: &VerifyingKey) -> Vec<u8> {
        pk.to_encoded_point(false).as_bytes().to_vec()
    }

    pub fn sk_to_bytes(sk: &SigningKey) -> Vec<u8> {
        sk.to_bytes().to_vec()
    }

    pub fn sig_to_bytes(sig: &Signature) -> Vec<u8> {
        sig.to_bytes().to_vec()
    }

    pub fn pk_from_bytes(bytes: &[u8]) -> CryptoResult<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidKeyBytes)
    }

    pub fn sk_from_bytes(bytes: &[u8]) -> CryptoResult<SigningKey> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidKeyBytes)?;
        SigningKey::from_bytes(&arr.into()).map_err(|_| CryptoError::InvalidKeyBytes)
    }

    pub fn sig_from_bytes(bytes: &[u8]) -> CryptoResult<Signature> {
        let arr: [u8; 64] = bytes.try_into().map_err(|_| CryptoError::InvalidSignatureBytes)?;
        Signature::from_bytes(&arr.into()).map_err(|_| CryptoError::InvalidSignatureBytes)
    }
}

impl SignatureScheme for EcdsaSecp256k1 {
    type PublicKey = VerifyingKey;
    type SecretKey = SigningKey;
    type Signature = Signature;

    fn name() -> &'static str {
        "ECDSA(secp256k1)"
    }

    fn keygen() -> CryptoResult<(Self::PublicKey, Self::SecretKey)> {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().clone();
        Ok((pk, sk))
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> CryptoResult<Self::Signature> {
        Ok(sk.sign(msg))
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> CryptoResult<bool> {
        Ok(pk.verify(msg, sig).is_ok())
    }
}
