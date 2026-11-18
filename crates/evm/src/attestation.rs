//! ECDSA (secp256k1) attestations for the ablation baseline: the bundler signs
//! the batch digest and the attestation wallet checks it with `ecrecover`.
//! This is the cheapest possible authorisation and fully trusts the bundler.

use crate::wallet::{keccak, ATTESTATION_AUTH_LEN};
use k256::ecdsa::SigningKey;

pub struct Attester {
    key: SigningKey,
}

impl Attester {
    /// Deterministic key from a 32-byte seed (development only).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_slice(&seed).expect("seed is a valid secp256k1 scalar");
        Self { key }
    }

    /// Ethereum address of the attester key.
    pub fn address(&self) -> [u8; 20] {
        let point = self.key.verifying_key().to_encoded_point(false);
        let hash = keccak(&point.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        out
    }

    /// `r ‖ s ‖ v` (32 bytes each, v ∈ {27, 28}) over the raw 32-byte digest.
    pub fn sign(&self, digest: &[u8; 32]) -> [u8; ATTESTATION_AUTH_LEN] {
        let (sig, recid) = self.key.sign_prehash_recoverable(digest).expect("sign prehash");
        let mut out = [0u8; ATTESTATION_AUTH_LEN];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[95] = 27 + recid.to_byte();
        out
    }
}
