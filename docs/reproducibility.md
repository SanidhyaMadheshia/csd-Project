# Reproducibility: Environment, Versions and Experimental Method

Answers supervisor point 9. Every result file under `results/` records its own environment in `env.json`. This page explains how to recreate them.

## 1. Hardware used for the reported results

| Item | Value |
|---|---|
| Machine | laptop, AMD Ryzen 5 5500U (6 cores / 12 threads), 8 GB RAM (7.3 GB usable), AMD Radeon integrated graphics, no NVIDIA GPU |
| Host OS | Windows 11 Home (10.0.26300), Smart App Control enabled |
| Execution | Docker Desktop 29.8.1 with a WSL2 backend; the Linux container sees 12 logical CPUs and about 1.9 GB of RAM |
| Power | mains power; no other heavy workload while timing runs were in progress |

The earlier draft cited an Intel i7-12700K and an AWS g5.xlarge. Those machines were **not** used for any result in the revised paper.

## 2. Software

| Component | Version | Pinned by |
|---|---|---|
| Rust toolchain | 1.100.0 (`rust:1.100.0-bookworm` image) | `Dockerfile`, `rust-toolchain.toml` |
| Container OS | Debian 12 (bookworm) | `Dockerfile` |
| EVM | revm 14.0.3, hard fork **Cancun** (`SpecId::CANCUN`), chain id 1, gas price 0, tx gas limit 30,000,000 | `Cargo.lock`, `crates/evm/src/executor.rs` |
| ML-DSA | `pqcrypto-mldsa` 0.1.2 (PQClean), ML-DSA-44, FIPS 204 pure mode, empty context | `Cargo.lock` |
| Groth16 | `ark-groth16` 0.4.0, `ark-bn254` 0.4.0, circuit-specific setup from seed `0x5145564d` | `Cargo.lock`, `crates/zkvm/src/lib.rs` |
| ECDSA (ablation A1) | `k256` 0.13.4 | `Cargo.lock` |
| All other crates | exact versions | `Cargo.lock` (committed) |
| Native baseline verifier, optimised (primary baseline, 1,248,996 gas) | ZKNoxHQ/ETHDILITHIUM branch `exp/packed-verifier` @ `f85ca80c446c2d59fcd68b5efe565275599bb1f9` (experimental), `src/ZKNOX_dilithium.sol` + F1600 helper; solc 0.8.30, `--via-ir --optimize-runs 1000000 --evm-version cancun` | `scripts/native-baseline.sh` |
| Native baseline verifier, main branch (8,168,152 gas) | ZKNoxHQ/ETHDILITHIUM @ `f9f4fe1d84e68304b425e054c273c276fe44ba11`, `src/ZKNOX_dilithium.sol`; solc 0.8.30, `--optimize-runs 10000 --evm-version cancun` | `scripts/native-baseline.sh` |
| Key expansion for the baseline | ZKNox Python reference (same commit) + polyntt @ `3ac5f5dc0b204e91df4f68e347ade2bd4a82bb37`; Python 3.11 with eth_abi 6.0.0, pycryptodome 3.23.0, numpy 2.4 | `scripts/native-baseline.sh` |

**Gas schedule notes.**
- Cancun prices: EIP-2028 calldata (16 gas per non-zero byte, 4 per zero byte); EIP-1108 BN254 precompiles (ecAdd 150, ecMul 6,000, pairing 45,000 + 34,000·k); EIP-2929 cold/warm storage access.
- Pectra's EIP-7623 calldata floor is not applied (future work FW-3).
- The mainnet block gas limit is 60,000,000 as of 2026-11-15 (read from block 26,418,726; EIP-7935, raised in the Fusaka upgrade). Since Fusaka, EIP-7825 caps a single transaction at 16,777,216 gas. The prototype's dashboard constant `BLOCK_GAS_LIMIT` (30M) is a display value only and is used in no result.

## 3. How to reproduce

```bash
git clone <repository> && cd csd-Project
docker build -t qevm-dev:1 .                              # or let scripts/dev.sh build it
scripts/dev.sh cargo test --workspace                     # 31 tests, incl. 13 on-chain wallet tests and the security matrix
scripts/dev.sh cargo build --release -p qevm-cli

# Security and correctness matrix (results/security.md)
scripts/dev.sh /target/release/qevm-cli security-report --out results/security.md

# Batch sweep + ablation + off-chain cost (results/<date>/)
scripts/dev.sh /target/release/qevm-cli experiment --repeats 30 --warmup 3 \
    --out results/<date> --rustc "$(rustc -V)" --git-commit "$(git rev-parse HEAD)" --started "$(date -u +%FT%TZ)"

# Executable native ML-DSA baselines (results/native-baseline-packed/, results/native-baseline/)
scripts/native-baseline.sh
```

| Paper element | Produced by | File |
|---|---|---|
| Gas per op vs. batch size (figure) | `experiment` | `results/<date>/summary.csv` |
| Ablation table | `experiment` | `results/<date>/summary.md` |
| Time and memory table | `experiment` | `results/<date>/summary.md` |
| Off-chain cost table | `experiment` | `results/<date>/offchain-cost.md` |
| Security table | `security-report` | `results/security.md` |
| Native baseline, optimised (primary) | `native-baseline.sh` | `results/native-baseline-packed/baseline.md` |
| Native baseline, main branch | `native-baseline.sh` | `results/native-baseline/baseline.md` |

## 4. Experimental method

- **Configurations:**
  - A0: native ML-DSA on the EVM (modelled; executed separately in the native baseline);
  - A1: off-chain verification + ECDSA attestation;
  - A2: Groth16 per op;
  - A3: Groth16 per batch.
- **Batch sizes:** N ∈ {1, 2, 4, 8, 16, 32, 64, 128, 256}.
- **Repeats:** 30 kept runs per (configuration, N), after 3 discarded warm-up runs.
- **Fresh state per run:** every run creates N new ML-DSA-44 accounts, registered with nonce 1 (an account that has transacted before, so its nonce slot is non-zero). Storage slots are therefore cold in every run, and each run's gas is independent of the others.
- **Seeds:** the workload seed is logged per run (`runs.csv`, column `seed`). ML-DSA keys and Groth16 proving randomness come from the OS RNG, so the bytes differ between reproductions. Gas varies only through the calldata byte mix (zero vs. non-zero bytes).
- **What each run times:**
  - *end-to-end* = bundler wall time from the first submission to the last wallet transaction being committed;
  - *ML-DSA verify* = sum over the N signatures;
  - *authorise* = Groth16 prove (binding circuit) or ECDSA sign;
  - *off-chain proof verify* = arkworks verification of each proof (not part of end-to-end);
  - *EVM exec* = revm execution time of the wallet transaction(s).
- **Memory:** peak heap bytes during the timed pipeline, counted by a global allocator in `qevm-cli`. RSS and the stack are not included.
- **Statistics:** mean, sample standard deviation, median, p95, and a 95% CI of the mean using Student-t critical values.
- **Parallelism:** proving and verification are single-threaded per run. Timings are wall-clock on the hardware above and are meant for *relative* comparison between configurations.

## 5. Known limitations of the setup

- Gas is measured on revm, not on a live network. Block inclusion latency, the mempool and the EIP-1559 fee market are not modelled.
- The account registration write (`register_account`) is excluded from every measurement, in every configuration alike.
- The wallet does not execute `call_data`; that cost is the same in every configuration.
- Timings are on a laptop inside a container with about 1.9 GB of RAM; absolute values will differ on server hardware.
