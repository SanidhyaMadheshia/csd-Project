//! Cryptographic primitives used by Q-EVM.

mod ecdsa;
mod mldsa;
mod types;

pub use ecdsa::*;
pub use mldsa::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_round_trip() {
        let (pk, sk) = MlDsaDilithium2::keygen().expect("keygen");
        let msg = b"qevm";
        let sig = MlDsaDilithium2::sign(msg, &sk).expect("sign");
        let ok = MlDsaDilithium2::verify(msg, &sig, &pk).expect("verify");
        assert!(ok);
    }

    #[test]
    fn ecdsa_round_trip() {
        let (pk, sk) = EcdsaSecp256k1::keygen().expect("keygen");
        let msg = b"qevm";
        let sig = EcdsaSecp256k1::sign(msg, &sk).expect("sign");
        let ok = EcdsaSecp256k1::verify(msg, &sig, &pk).expect("verify");
        assert!(ok);
    }
}
