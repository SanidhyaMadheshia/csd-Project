# Q-EVM Design Decisions

This document captures the research-driven trade-offs made in Q-EVM.

## ML-DSA over Falcon
- Falcon signatures are smaller but rely on floating-point arithmetic.
- zkVMs handle integer arithmetic efficiently, while floating-point emulation is costly.
- ML-DSA provides deterministic integer-only computation, making zkVM proofs practical.

## Forkless Deployment
- Precompile proposals (e.g., EIP-8052) require hard forks and long governance cycles.
- Q-EVM runs today using ERC-4337 account abstraction and off-chain proof generation.
- Trade-off: higher proving latency in exchange for immediate deployability.

## zkVM vs Custom Circuit
- zkVMs allow reusing Rust ML-DSA libraries and reduce engineering risk.
- Custom circuits would yield faster proofs but require specialized ZK expertise.
- As a feasibility study, Q-EVM prioritizes maintainability and development speed.

## Batching as a Scalability Lever
- Single ML-DSA proofs are slower than ECDSA precompiles.
- Batching amortizes proving time, making cost/latency competitive for high-throughput workflows.

## Dev-Mode Proof Pipeline
- The current implementation mirrors the data flow and public-input binding.
- Proofs are deterministic placeholders designed to be replaced by RISC Zero/SP1 receipts.
- This preserves protocol semantics while keeping the prototype evaluator-ready.
