# Q-EVM Architecture

Q-EVM is a forkless, account-abstraction-based design for post-quantum Ethereum wallets. This document describes what is **implemented**. For the implemented / future split see [implementation-status.md](implementation-status.md).

## Flow

```
User (ML-DSA-44 key, registered in the wallet as keccak(pk))
  -> Bundler (Rust)               validates the op, verifies FIPS 204 off-chain
     -> Prover                    Groth16 receipt over the batch digest (binding circuit)
        -> Wallet contract (EVM)  key binding, nonces, opHash + digest recomputation
           -> Groth16 verifier    pairing check over 5 public inputs
```

## Components

### UserOperation (`crates/types`)
- Fields: wallet, sender, nonce, chain id, call data, PQC payload (ML-DSA-44 public key + signature).
- `opHash = keccak256(TAG ‖ chain_id ‖ wallet ‖ sender ‖ nonce ‖ keccak(call_data) ‖ keccak(pk))`. The user signs this; the wallet recomputes it on-chain.

### Bundler (`crates/bundler`)
- Rejects an op if:
  - its payload is missing;
  - its chain id or wallet is wrong;
  - its sender is unregistered, or its pk is not the registered one;
  - its `(sender, nonce)` was seen before;
  - its nonce is not `wallet.nonce[sender] + pending`;
  - its ML-DSA signature is invalid.
- Modes: `PerOp` (one receipt and one transaction per op) or `Batch(kind)` (one authorisation per batch, either Groth16 or an ECDSA attestation for the ablation).
- Sends each authorised batch to the wallet on the local chain.

### Prover (`crates/zkvm`)
- Off-chain FIPS 204 verification (`check_signature`).
- Groth16 receipt over `(digest, program, 1)` using the binding circuit. It does **not** prove ML-DSA verification ([circuit-spec.md](circuit-spec.md)).
- Owns the local revm chain used for gas measurement.

### On-chain contracts (`crates/evm`, raw EVM bytecode)
- **Wallet**: for each op, check `pk[sender]` and `nonce[sender]`, then increment the nonce; recompute each opHash and the batch digest; call the verifier; revert everything on any failure.
- **Groth16 verifier**: vk_x via ecMul/ecAdd, then the 4-pair pairing check.
- **Attestation wallet**: the same per-op logic, authorised by `ecrecover` against the bundler key (ablation only).

## Security notes
- Signature validity is trusted to the bundler today.
- Key binding, nonces, domain separation and batch integrity are enforced on-chain.
- The Groth16 setup is single-party and seeded (development only).
- Evidence: `results/security.md`.

## Crate map

| Paper component | Crate |
|---|---|
| UserOperation, hashing | `qevm-types`, `qevm-evm::wallet` |
| Bundler | `qevm-bundler` |
| Prover / receipts | `qevm-zkvm`, `qevm-evm::groth16` |
| Wallet + verifier contracts | `qevm-evm::wallet`, `qevm-evm::verifier` |
| Experiments, security matrix, baseline | `qevm-core` |
| RPC / dashboard | `qevm-rpc`, `qevm-web-ui` |
