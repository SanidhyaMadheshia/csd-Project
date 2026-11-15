# Q-EVM Demo Steps

## 1) Setup
On this Windows machine, Smart App Control blocks locally built executables, so use the Linux container. It needs Docker Desktop to be running.
```bash
scripts/dev.sh cargo build --release -p qevm-cli
scripts/dev.sh cargo test --workspace
```
On Linux or macOS, plain `cargo build` / `cargo test` also work.

## 2) Simulate UserOperations
```bash
scripts/dev.sh /target/release/qevm-cli simulate --count 5
```
For each op, the command creates a fresh account (an ML-DSA-44 key registered in the wallet), signs the op hash, and has the bundler verify the signature off-chain. The batch then gets one Groth16 receipt and is sent to the wallet contract on revm.

Output:
- one `accepted ...` line per op;
- the simulated gas of a single-op wallet transaction (about 251k);
- the native gas from the **cost model** (about 2.8M; not an execution);
- the batch transaction's gas and gas per op.

## 3) Run the node and the dashboard
```bash
cargo run -p qevm-cli -- node start      # RPC on 127.0.0.1:8080
cargo run -p qevm-web-ui                 # dashboard on http://127.0.0.1:8081
```
Click **Run demo** (or `POST /api/demo {"count": 8}`).

## 4) Paper results
```bash
scripts/dev.sh /target/release/qevm-cli security-report --out results/security.md
scripts/dev.sh /target/release/qevm-cli experiment --repeats 30 --out results/<date>
scripts/native-baseline.sh
```

## Where the numbers come from
- **Q-EVM on-chain gas** (measured): `gas_used` of the wallet transaction. It covers the per-op key and nonce checks plus the Groth16 verifier call (`crates/evm`).
- **Native ML-DSA gas**:
  - *modelled* by `crates/evm/src/native_mldsa.rs`;
  - *executed* with the ZKNox Solidity verifier on the same revm chain (`scripts/native-baseline.sh`).
- **Proving time** (measured): the binding Groth16 circuit only. Proving ML-DSA itself in a zkVM is future work ([docs/future-work-zkvm-linux.md](docs/future-work-zkvm-linux.md)).

## Troubleshooting
- `An Application Control policy has blocked this file`: Smart App Control is blocking a locally built binary. Use `scripts/dev.sh`.
- Docker out of memory during a release build: `scripts/dev.sh` limits cargo to 2 jobs (`CARGO_BUILD_JOBS`).
- `dlltool could not create import library`: only matters for native Windows builds. Put the WinLibs `mingw64\bin` first in PATH.
