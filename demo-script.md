# Q-EVM Evaluator Demo Script

## Opening
“Q-EVM shows how we can retrofit post-quantum security into Ethereum **without** protocol changes. The core idea is to offload ML-DSA verification into a zkVM and only verify the succinct receipt on-chain.”

## Step 1 — Start the Node
```bash
cargo run -p qevm-cli -- node start
```
Explain:
- The bundler maintains a mempool and validates PQC signatures.
- zkVM receipts are generated with deterministic public inputs.

## Step 2 — Simulate UserOperations
```bash
cargo run -p qevm-cli -- simulate --count 5
```
Explain:
- Each UserOperation is signed with ML-DSA.
- The bundler produces zkVM receipts and builds a batch.
- This mirrors the paper’s bundler validation algorithm.

## Step 3 — Launch the Web UI
```bash
cargo run -p qevm-web-ui
```
Explain while showing the dashboard:
- Node status and mempool size update in real time.
- Events show accepted/rejected operations and batch creation.
- The flow diagram matches the paper’s architecture.

## Step 4 — Benchmarks
```bash
cargo run -p qevm-cli -- benchmark --iters 50
```
Explain:
- ML-DSA is slower than ECDSA locally, but proofs make on-chain cost tractable.
- The system relies on batching to amortize zkVM latency.

## Key Takeaways
- Forkless PQC adoption using ERC-4337.
- zkVM receipts ensure verifiable ML-DSA validation without precompiles.
- Batching makes the design economically competitive for high-throughput workflows.

## Closing
“This implementation is structured for research iteration: each crate maps directly to a paper component, and the proof pipeline can be swapped for real zkVM receipts when integrating RISC Zero or SP1.”
