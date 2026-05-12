# Q-EVM Protocol Flow

This document maps the protocol flow described in the paper to the Rust implementation.

## 1) UserOperation Creation
- The wallet constructs a UserOperation with:
  - sender address
  - nonce + chain id
  - calldata
  - PQC payload (ML-DSA public key + signature)
- The wallet signs the `op_hash` (Keccak digest of the operation payload).

## 2) Bundler Validation
- The bundler performs fast structural checks:
  - payload presence
  - duplicate nonce rejection
- If simulation is enabled, it executes the zkVM prover:
  - Inputs: op hash, ML-DSA public key, ML-DSA signature
  - Output: zkVM receipt + journal
- The receipt is stored and optionally attached to the operation.

## 3) Batching
- Validated operations are placed into a batch (bounded by configuration).
- Each operation includes an associated zkVM receipt.
- The batch is ready for on-chain submission (outside this prototype).

## 4) On-Chain Validation (Wallet + Verifier)
- Smart wallet recomputes `op_hash`.
- Verifier contract checks proof validity and public input binding.
- If valid, the wallet accepts the operation and executes the call.

## Replay Protection
- The op hash is committed as a public input to the proof.
- Any mismatch between the proof and on-chain hash causes rejection.
- Nonces are enforced by the bundler to prevent mempool-level replay.
