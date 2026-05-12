# Q-EVM — Quantum-Resistant Account Abstraction (Research Prototype)

Q-EVM explores a **forkless** path to post-quantum account abstraction on Ethereum by combining ERC-4337-style user operations with zkVM proofs for ML-DSA (Dilithium) verification.

This repository contains a production-quality Rust workspace implementing the research architecture described in `researchaPaper.pdf`.

## Architecture Snapshot

```
User -> Bundler (Rust) -> zkVM (RISC Zero / SP1) -> Smart Wallet (Solidity)
```

The bundler produces zkVM receipts that prove ML-DSA signature validity, allowing the on-chain wallet to verify succinct proofs instead of expensive lattice verification.

## Workspace Layout

```
/crates
  core        Node orchestration, benchmarks, events
  types       Protocol types and hashes
  crypto      ML-DSA + ECDSA wrappers
  bundler     Mempool + batching + validation pipeline
  zkvm        zkVM abstraction (dev-mode prover)
  network     Local network transport interfaces
  storage     Mempool + receipt persistence
  rpc         Axum-based API server
  cli         CLI demo tooling
  web-ui      Axum-backed demo dashboard
  telemetry   Tracing + metrics
  utils       Hashing + helpers
```

## Build

```bash
cargo build
cargo test
cargo bench -p qevm-crypto
```

## CLI Demo

```bash
# Start the RPC node
cargo run -p qevm-cli -- node start

# Simulate bundler flow with 5 user ops
cargo run -p qevm-cli -- simulate --count 5

# Run crypto benchmarks
cargo run -p qevm-cli -- benchmark --iters 50
```

## Web UI

```bash
cargo run -p qevm-web-ui
```

Open <http://127.0.0.1:8081> to view the live demo console.

## RPC Endpoints

- `GET /api/health`
- `GET /api/status`
- `GET /api/mempool`
- `POST /api/user-operations`
- `GET /api/receipts/:hash`
- `GET /api/events` (SSE)

## Notes

The current zkVM integration is a **dev-mode proof pipeline** that mirrors the paper’s flow and enforces deterministic public inputs. Swap in RISC Zero / SP1 receipts when wiring a production prover.
