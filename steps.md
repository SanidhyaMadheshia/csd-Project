# Q-EVM Demo Steps

## 1) Setup
```bash
cargo build
cargo test
```

## 2) Start the Node (RPC)
```bash
cargo run -p qevm-cli -- node start
```

Expected output:
- `Starting Q-EVM node. RPC listening on 127.0.0.1:8080`

## 3) Simulate UserOperations
```bash
cargo run -p qevm-cli -- simulate --count 5
```

Expected output:
- Progress bar showing submissions
- `Bundled batch <id> with 5 operations`

## 4) Launch the Web UI
```bash
cargo run -p qevm-web-ui
```

Open http://127.0.0.1:8081
- Node status should show mempool + batches
- Realtime events appear when new ops are submitted

## 5) Run Benchmarks
```bash
cargo run -p qevm-cli -- benchmark --iters 50
```

Expected output:
- Table comparing ML-DSA and ECDSA keygen/sign/verify

## Troubleshooting
- If ports are in use, change `--rpc-addr` or edit `crates/web-ui/src/main.rs`.
- If no events appear in the UI, submit operations with `simulate` to trigger updates.
