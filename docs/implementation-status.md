# Implementation Status: What Is Implemented, Measured, Modelled, Projected, or Future Work

Answers supervisor point 1. Every claim in the revised paper must match one row of this table.

Legend:
- **Implemented**: code exists in this repository and is tested.
- **Measured**: the number comes from running that code (revm `gas_used`, wall-clock timers, heap counter).
- **Modelled**: computed by a cost model, not by execution.
- **Projected**: taken from documentation or an earlier draft; no code here produces it.
- **Future**: planned, not implemented ([future-work-zkvm-linux.md](future-work-zkvm-linux.md)).

| Component | Status | Where | Notes |
|---|---|---|---|
| ML-DSA-44 key generation, signing, verification | Implemented, measured | `crates/crypto` | FIPS 204 final standard via `pqcrypto-mldsa` 0.1.2 (pure mode, empty context). Earlier versions used round-3 Dilithium2. |
| Off-chain signature check in the bundler | Implemented, measured | `crates/zkvm` `check_signature`, `crates/bundler` | Native Rust. This is the only place the signature is verified. |
| Op hash with domain separation | Implemented | `crates/evm/src/wallet.rs` `user_op_hash` | Covers TAG, chain id, wallet, sender, nonce, keccak(call data), keccak(pk). |
| Groth16 receipt circuit | Implemented | `crates/evm/src/groth16.rs` | **Binding circuit only** (6 constraints). It does **not** verify ML-DSA; see [circuit-spec.md](circuit-spec.md). |
| Groth16 proving time | Measured | `results/*/summary.md` | Time for the binding circuit only. Not comparable to proving ML-DSA. |
| Groth16 verifier contract | Implemented, measured | `crates/evm/src/verifier.rs` | Hand-assembled bytecode, 5 public inputs, about 241k gas per call. |
| Wallet / EntryPoint contract | Implemented, measured | `crates/evm/src/wallet.rs` | Key binding, nonce consumption, on-chain op-hash and digest recomputation, revert-all on failure. Executing the call data is out of scope (identical in every configuration). |
| Batching (one proof per batch) | Implemented, measured | `crates/bundler` `ProofMode::Batch` | Gas per op includes the per-op storage and calldata the wallet needs. |
| ECDSA attestation wallet (ablation A1) | Implemented, measured | `crates/evm/src/attestation.rs` | Trusted-bundler baseline using `ecrecover`. |
| Replay protection | Implemented, tested | wallet nonces, bundler `seen_nonces` | `results/security.md` cases 21–28. |
| Security and correctness test matrix | Implemented | `crates/core/src/security.rs`, `crates/evm/tests/wallet.rs` | 45 pipeline cases plus 13 on-chain wallet tests. |
| Native ML-DSA on the EVM, cost model | Modelled | `crates/evm/src/native_mldsa.rs` | Opcode model calibrated to an optimised Yul verifier (about 2.8M gas). **Not an execution.** |
| Native ML-DSA on the EVM, executed | **Measured**: 1,248,996 gas (optimised verifier), 8,168,152 gas (main branch); 100/100 valid accepted, 100/100 tampered rejected | `crates/core/src/native_baseline.rs`, `scripts/native-baseline.sh` | Third-party ZKNox ETHDILITHIUM verifier run on the same revm chain. |
| Experiment harness (batch sweep, repeats, ablation) | Implemented, measured | `crates/core/src/experiment.rs` | `qevm-cli experiment`. |
| Off-chain cost analysis | Measured part + projected parameter | `results/*/offchain-cost.md` | zkVM proving time is a *parameter* (12.4 s was the earlier draft's projection). |
| ML-DSA verification inside a zkVM (RISC Zero / SP1) | **Future** | FW-1 | Needs a Linux host, ideally with a GPU. Not run here. |
| "1,842,500 RISC-V cycles" for ML-DSA (earlier draft) | **Not reproducible** | — | No zkVM code exists in this repository. The revised paper does not present this number as measured. |
| "12.4 s proving time" (earlier draft) | **Projected** | — | From RISC Zero documentation, not from running anything. |
| Prague / EIP-7623 gas schedule | Future | FW-3 | All gas figures use Cancun (revm 14.0.3). |
| Testnet deployment | Future | FW-7 | — |
| Multi-party trusted setup | Future | FW-6 | The current setup is single-party, seeded and dev-only. |
| Web dashboard and RPC | Implemented | `crates/web-ui`, `crates/rpc` | Demo only. Shows modelled native gas and simulated single-op gas. |
