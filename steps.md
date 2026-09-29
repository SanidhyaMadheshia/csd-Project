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

Each op gets a fresh ML-DSA key and signature, a real Groth16 proof, and a
verification on an in-process EVM (revm). Expected output:
- one `accepted ...` line per op with its measured on-chain gas (~240k, from
  the EVM's `gas_used`) and metered native ML-DSA gas (~2.8M), about a 91.4% reduction
- `Bundled batch <id> with 5 operations`
- a gas summary: avg/min/max on-chain gas, native gas, reduction %, batch gas
  per op, and the paper's projected figures for comparison

## 4) Launch the Web UI
```bash
cargo run -p qevm-web-ui
```

Open http://127.0.0.1:8081
- All gas figures show `—` until the node has produced a receipt
- Click **Run demo** (or `POST /api/demo {"count": 8}`) to push ops
  through the real pipeline; the numbers and bars animate in
- Receipts stream into the live feed via `/api/events`
- `GET /api/gas-analysis` returns the same aggregated measurements as JSON

## Where the gas numbers come from
- **On-chain (Q-EVM)**: `crates/evm` builds a real Groth16 proof (arkworks,
  BN254) and calls a Groth16 verifier contract (EVM bytecode with the verifying
  key embedded) through revm. The number reported is the EVM's `gas_used`.
- **Native ML-DSA**: `crates/evm/src/native_mldsa.rs` walks each real key and
  signature through FIPS 204 verification (including rejection sampling),
  counts the Keccak permutations, NTT butterflies, mulmods and calldata bytes,
  and prices them with EVM opcode costs. The per-unit costs follow an
  optimized Yul verifier calibrated to the implementation the paper cites.
- The paper's projections (`PAPER_*_REF` in `crates/types`) are only shown
  for comparison.

## 5) Run Benchmarks
```bash
cargo run -p qevm-cli -- benchmark --iters 50
```

Expected output:
- Table comparing ML-DSA and ECDSA keygen/sign/verify

## Troubleshooting
- `dlltool could not create import library ... Invalid bfd target`: an old
  32-bit `C:\MinGW\bin` comes before the 64-bit WinLibs mingw64 `bin` in PATH.
  Put the WinLibs `mingw64\bin` first in PATH.
- If ports are in use, change `--rpc-addr` or edit `crates/web-ui/src/main.rs`.
- If no events appear in the UI, submit operations with `simulate` to trigger updates.
