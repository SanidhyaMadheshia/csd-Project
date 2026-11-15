# Q-EVM Design Decisions

## ML-DSA over Falcon
- Falcon-512 signatures are smaller (666 bytes against 2,420), but Falcon signing relies on floating-point Gaussian sampling, and verification is harder to arithmetise.
- ML-DSA uses only integer arithmetic modulo q = 8,380,417. That makes a future zkVM or circuit proof simpler, and hardware-wallet signers are simpler too.
- We use the final FIPS 204 standard (ML-DSA-44), not round-3 Dilithium.

## Forkless deployment
- Precompile proposals (EIP-8051 for ML-DSA, EIP-8052 for Falcon) need a hard fork.
- Q-EVM uses account abstraction and off-chain verification, so it can be deployed without a fork.
- Trade-off: off-chain infrastructure (bundler, prover) and, today, trust in the bundler's signature check.

## Binding receipt now, zkVM later
- The current Groth16 circuit binds the batch digest. It is cheap to prove and has the same on-chain interface (5 public inputs) as a wrapped zkVM receipt, so on-chain gas is representative.
- It does **not** make signature validity trustless. That needs ML-DSA verification inside a zkVM or a custom circuit (future work FW-1 / FW-4), which needs a Linux / GPU proving host.

## Wallet enforces state, proof enforces content
- Nonces, key binding and domain separation are checked by the wallet contract on-chain, not by the proof.
- This keeps replay protection independent of the proof system, which matters because Groth16 proofs can be re-randomised.

## Batching as a scalability lever
- One authorisation per batch amortises the verifier's fixed cost (about 241k gas).
- Per-op wallet work (two storage reads, one storage write, opHash recomputation, 128 bytes of calldata) remains. It sets the floor of gas per op that batching can reach.

## Bytecode without solc
- The verifier and wallet are emitted directly as EVM bytecode by a small assembler (`crates/evm/src/asm.rs`). This keeps the prototype self-contained, and the gas measured is exactly what this bytecode costs.
- A production deployment would use audited Solidity.
