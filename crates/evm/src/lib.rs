//! On-chain side of Q-EVM, measured on a real EVM (revm).
//!
//! * [`groth16`]: Groth16 receipts over BN254 (arkworks) and exactly what they prove.
//! * [`verifier`]: the Groth16 verifier contract as EVM bytecode.
//! * [`wallet`]: the wallet / EntryPoint contract (key binding, nonces, op-hash
//!   recomputation, batch digest) and the canonical op-hash definition.
//! * [`attestation`]: ECDSA attestations for the ablation baseline.
//! * [`executor`]: an in-process chain that deploys and calls these contracts
//!   and reports the gas the EVM charges.
//! * [`native_mldsa`]: an opcode-level *model* of verifying ML-DSA-44 directly
//!   in the EVM (not an executed contract).

mod asm;
pub mod attestation;
pub mod executor;
pub mod groth16;
pub mod native_mldsa;
pub mod verifier;
pub mod wallet;

pub use attestation::Attester;
pub use executor::{
    calldata_gas, Deployment, EvmError, LocalChain, OnchainGas, TxOutcome, WalletKind, EVM_SPEC_NAME, TX_BASE_GAS,
};
pub use groth16::{
    full_calldata, proof_bytes, Groth16Error, Groth16Keys, ReceiptStatement, EVM_CALLDATA_LEN, NUM_PUBLIC_INPUTS,
};
pub use native_mldsa::{estimate_native_gas, NativeGasBreakdown, NativeGasError};
pub use wallet::{
    batch_digest, keccak, user_op_hash, wallet_calldata, WalletOp, ATTESTATION_AUTH_LEN, GROTH16_AUTH_LEN,
    MAX_BATCH, OP_RECORD_LEN,
};

#[cfg(test)]
mod tests {
    use super::*;
    use qevm_crypto::{MlDsa44, SignatureScheme};

    fn statement(tag: u8) -> ReceiptStatement {
        ReceiptStatement { digest: [tag; 32], program: [0xab; 32] }
    }

    #[test]
    fn evm_verifier_accepts_valid_proof_and_rejects_tampering() {
        let keys = Groth16Keys::setup(7).expect("setup");
        let meter = LocalChain::new(keys.verifying_key(), [0xab; 32], [0x99; 20], 1).expect("deploy");
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
        let (pk, sk) = MlDsa44::keygen().expect("keygen");
        let msg = [0x42u8; 32];
        let sig = MlDsa44::sign(&msg, &sk).expect("sign");
        let pk = MlDsa44::pk_to_bytes(&pk);
        let sig = MlDsa44::sig_to_bytes(&sig);

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
