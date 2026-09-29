//! Real on-chain cost measurement for Q-EVM.
//!
//! * [`groth16`]: real Groth16 receipts over BN254 (arkworks).
//! * [`verifier`]: the Groth16 verifier contract as EVM bytecode.
//! * [`executor`]: deploys and calls that verifier on revm and reports the
//!   gas the EVM charges.
//! * [`native_mldsa`]: meters what verifying ML-DSA-44 directly in the EVM
//!   would cost, from the real key and signature.

pub mod executor;
pub mod groth16;
pub mod native_mldsa;
pub mod verifier;

pub use executor::{calldata_gas, EvmError, EvmGasMeter, OnchainGas, TX_BASE_GAS};
pub use groth16::{Groth16Error, Groth16Keys, ReceiptStatement, EVM_CALLDATA_LEN, NUM_PUBLIC_INPUTS};
pub use native_mldsa::{estimate_native_gas, NativeGasBreakdown, NativeGasError};

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::{MlDsaDilithium2, SignatureScheme};

    fn statement(tag: u8) -> ReceiptStatement {
        ReceiptStatement { digest: [tag; 32], program: [0xab; 32] }
    }

    #[test]
    fn evm_verifier_accepts_valid_proof_and_rejects_tampering() {
        let keys = Groth16Keys::setup(7).expect("setup");
        let meter = EvmGasMeter::new(keys.verifying_key()).expect("deploy");
        let st = statement(0x11);
        let calldata = keys.prove(&st, 1).expect("prove");
        assert_eq!(calldata.len(), EVM_CALLDATA_LEN);
        assert!(keys.verify(&calldata, &st).expect("verify"));

        let gas = meter.measure_verify(&calldata).expect("call");
        assert!(gas.success, "valid proof must verify on-chain: {gas:?}");
        assert_eq!(gas.total, gas.intrinsic + gas.calldata + gas.execution);
        assert!((200_000..300_000).contains(&gas.total), "unexpected verify gas {}", gas.total);

        // Tampered public input (digest limb) must fail on-chain and off-chain.
        let mut bad = calldata.clone();
        bad[256 + 31] ^= 1;
        assert!(!meter.measure_verify(&bad).expect("call").success);
        assert!(!keys.verify(&bad, &st).unwrap_or(false));

        // Proof for another statement must not verify for this one.
        let other = keys.prove(&statement(0x22), 2).expect("prove");
        assert!(!keys.verify(&other, &st).expect("verify"));

        // Tampered proof point (C.x) must fail on-chain.
        let mut bad_c = calldata;
        bad_c[192 + 31] ^= 1;
        assert!(!meter.measure_verify(&bad_c).expect("call").success);
    }

    #[test]
    fn native_meter_is_deterministic_and_consistent() {
        let (pk, sk) = MlDsaDilithium2::keygen().expect("keygen");
        let msg = [0x42u8; 32];
        let sig = MlDsaDilithium2::sign(&msg, &sk).expect("sign");
        let pk = MlDsaDilithium2::pk_to_bytes(&pk);
        let sig = MlDsaDilithium2::sig_to_bytes(&sig);

        let a = estimate_native_gas(&pk, &sig, &msg).expect("meter");
        let b = estimate_native_gas(&pk, &sig, &msg).expect("meter");
        assert_eq!(a, b);
        assert!((2_600_000..3_000_000).contains(&a.total), "native ML-DSA-44 ~2.8M gas, got {}", a.total);
        assert_eq!(
            a.total,
            a.intrinsic + a.calldata + a.keccak_gas + a.ntt_gas + a.pointwise_gas
                + a.unpack_sample_gas + a.hint_gas + a.memory_gas
        );
        assert!(estimate_native_gas(&pk[1..], &sig, &msg).is_err());
    }
}
