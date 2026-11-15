# Q-EVM: Post-Quantum Account Abstraction on Ethereum (Research Prototype)

Q-EVM explores a **forkless** path to post-quantum (PQ) accounts on Ethereum. Users sign ERC-4337-style user operations with **ML-DSA-44 (FIPS 204)**. A bundler verifies the signatures off-chain and authorises each batch for an on-chain wallet contract with a **Groth16 receipt** (BN254). The wallet enforces key binding, nonces and the batch digest on-chain.

> **Scope (read first).** ML-DSA verification runs **off-chain, natively**, in the bundler. The Groth16 circuit binds the batch digest; it does **not** prove that the signature was verified. Proving ML-DSA inside a zkVM is future work. See [docs/implementation-status.md](docs/implementation-status.md) and [docs/circuit-spec.md](docs/circuit-spec.md).

## Architecture

```
User (ML-DSA-44 key)
  -> Bundler (Rust): validate (key binding, nonce, chain, wallet) + FIPS 204 verify
     -> authorise batch: Groth16 receipt over keccak(opHash_1 .. opHash_N)
        -> Wallet contract (EVM): pk[sender], nonce[sender]++, recompute opHash and digest
           -> Groth16 verifier contract (ecMul/ecAdd/pairing precompiles)
```

All contracts are emitted as EVM bytecode and executed on an in-process revm chain (Cancun rules). Reported gas is the EVM's `gas_used`.

## Workspace layout

```
crates/
  crypto     ML-DSA-44 (pqcrypto-mldsa, FIPS 204) + ECDSA wrappers
  evm        Groth16 circuit, verifier + wallet bytecode, local revm chain, native-gas model
  zkvm       prover: off-chain signature check, Groth16 / attestation batch authorisation
  bundler    validation, mempool, batching, on-chain inclusion
  core       node, experiment harness, security matrix, native baseline runner
  types      protocol types (UserOperation, receipts, gas reports)
  storage    mempool + receipt store
  rpc, web-ui, cli, telemetry, utils, network
```

## Build and test (Linux container)

The development host is Windows 11 with Smart App Control, which blocks locally built unsigned executables. Everything therefore runs in a pinned Linux container ([Dockerfile](Dockerfile), Rust 1.100.0):

```bash
scripts/dev.sh cargo test --workspace
scripts/dev.sh cargo build --release -p qevm-cli
```

On a Linux or macOS host, plain `cargo test --workspace` works too.

## Reproduce the paper's results

```bash
scripts/dev.sh /target/release/qevm-cli security-report --out results/security.md      # point 6
scripts/dev.sh /target/release/qevm-cli experiment --repeats 30 --out results/<date>    # points 3, 4, 7
scripts/native-baseline.sh                                                              # point 5
```

Details (hardware, versions, protocol): [docs/reproducibility.md](docs/reproducibility.md).

## Demo

```bash
cargo run -p qevm-cli -- simulate --count 5     # or via scripts/dev.sh
cargo run -p qevm-cli -- node start             # RPC on 127.0.0.1:8080
cargo run -p qevm-web-ui                        # dashboard on 127.0.0.1:8081
```

RPC: `GET /api/health`, `/api/status`, `/api/mempool`, `/api/gas-analysis`, `/api/events` (SSE), `/api/receipts/:hash`; `POST /api/accounts` (register sender + public key), `/api/user-operations`, `/api/demo`.

## Documents

- [docs/implementation-status.md](docs/implementation-status.md): implemented vs. measured vs. modelled vs. projected vs. future
- [docs/circuit-spec.md](docs/circuit-spec.md): the Groth16 relation, trust model, replay protection
- [docs/future-work-zkvm-linux.md](docs/future-work-zkvm-linux.md): zkVM proving plan and other deferred work
- [docs/reproducibility.md](docs/reproducibility.md): environment and experimental methodology
- [paper/revised/](paper/revised/): revised paper (LaTeX); the original PDF is unchanged

**Not audited. Research code only.**
