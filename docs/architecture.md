# Q-EVM Architecture

Q-EVM is a forkless, account-abstraction-based approach to post-quantum Ethereum wallets. The design moves ML-DSA verification off-chain into a zkVM coprocessor while retaining on-chain security guarantees via succinct receipts.

## High-Level Flow

```
User (Wallet/DApp)
   -> Bundler (Rust)
     -> zkVM Prover (RISC Zero / SP1)
       -> Smart Wallet (Solidity)
         -> Ethereum Network
```

## Components

### 1) UserOperation (ERC-4337 Envelope)
- Contains sender, nonce, chain id, calldata, and PQC payload.
- The `op_hash` is a deterministic Keccak digest over the operation fields.
- The hash is the **public input** to the zkVM to prevent proof replay.

### 2) Bundler Pipeline (Rust)
- Maintains a mempool and validates incoming operations.
- Executes zkVM proving for ML-DSA verification in simulation mode.
- Attaches zkVM receipts to operations and batches for on-chain submission.

### 3) zkVM Coprocessor
- Executes the ML-DSA verification algorithm inside a RISC-V VM.
- Emits a receipt containing:
  - Public inputs (op hash)
  - A proof blob
  - A journal indicating validity

### 4) Smart Wallet (Solidity)
- Computes `op_hash` on-chain.
- Verifies the zkVM receipt against `op_hash`.
- Accepts or rejects based on proof validity.

## Rust Workspace Mapping

| Paper Component | Crate | Responsibility |
| --- | --- | --- |
| Bundler | `qevm-bundler` | Validation, batching, proof orchestration |
| UserOperation | `qevm-types` | Protocol types, hashing, payload encoding |
| zkVM Prover | `qevm-zkvm` | Proof generation + verification abstraction |
| Telemetry | `qevm-telemetry` | Tracing + metrics | 
| RPC/Web | `qevm-rpc`, `qevm-web-ui` | API + visualization |

## Security Notes
- zkVM public inputs include `op_hash` to prevent replay across operations.
- PQC payloads are bound to the operation hash, ensuring signature integrity.
- The proof pipeline is deterministic in dev mode for evaluator reproducibility.
