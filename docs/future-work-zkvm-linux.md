# Future Work: Proving ML-DSA Inside a zkVM (Linux), and Other Deferred Items

The prototype measures everything that is implemented (see [implementation-status.md](implementation-status.md)). The items below were deliberately deferred because they need a Linux toolchain, a GPU or significant engineering. This document is the plan for each one, so the paper can state exactly what remains and how it will be measured.

---

## FW-1. Sound proof of ML-DSA verification (supervisor point 7, measured part)

**Why it matters.** Today the Groth16 receipt binds the batch digest but does not prove that the signature was verified (finding C1, [circuit-spec.md](circuit-spec.md) §3). Proving FIPS 204 verification inside a zkVM makes the receipt sound. It is also the only way to report a *measured* proving time in place of the projected 12.4 s.

**Why it is not done on this machine.** RISC Zero's and SP1's toolchains (`rzup`, `sp1up`) target Linux and macOS. Their Groth16 wrapping step runs in Docker on x86-64 Linux. GPU proving needs CUDA (NVIDIA) or Metal. The development laptop (AMD Ryzen 5 5500U, 7.3 GB RAM, integrated Radeon graphics) has no NVIDIA GPU, and its 7.3 GB of RAM is below what STARK proving of multi-million-cycle programs typically needs. Windows Smart App Control also blocks unsigned local binaries. The prototype therefore runs in a Linux container (see [reproducibility.md](reproducibility.md)).

### Plan

| Step | Work | Output |
|---|---|---|
| 1. Environment | Linux x86-64 host (Ubuntu 22.04/24.04 VM, cloud instance or WSL2), ≥ 32 GB RAM; Docker; optionally an NVIDIA GPU with CUDA. Install `rzup` and pin the RISC Zero version; optionally `sp1up` for SP1. | `docs/reproducibility.md` section "zkVM host" |
| 2. Guest program | `methods/guest`: read (pk, opHash, σ) for i = 1..N; run FIPS 204 `ML-DSA-44.Verify` using a pure-Rust `no_std` implementation (RustCrypto `ml-dsa`; check that it compiles for `riscv32im`); assert every signature is valid; commit d = keccak256(opHash₁ ‖ … ‖ opHash_N) to the journal. Use the zkVM's accelerated SHA-3/Keccak precompile if available, and record whether it was used. | guest crate + image ID |
| 3. Correctness | Run the guest in dev / execute-only mode on the FIPS 204 ACVP vectors and on the security matrix's invalid signatures; each must fail to produce a receipt. | test log |
| 4. Cycle count | `execute` (no proving) for N ∈ {1, 2, 4, 8, 16}: total cycles, segments, cycles per signature, share of cycles spent in SHAKE. | `results/zkvm/cycles.csv` |
| 5. Proving | STARK prove and Groth16 wrap, separately, R ≥ 5 repeats per N, on CPU and (if available) GPU: wall time, peak RSS, proof size. | `results/zkvm/prove.csv` |
| 6. Integration | Replace `program = keccak("qevm.mldsa.verify")` by the image ID; carry the Groth16 seal in the wallet calldata. Verify with RISC Zero's verifier contract (or SP1's), deployed on the same revm Cancun chain. Measure its gas against the 5-input verifier used here. | new wallet variant + gas |
| 7. Security | The negative control `soundness_gap_trivial_circuit_accepts_unverified_statement` must now be **rejected**; update it to assert rejection. Rerun the full security matrix. | `results/security.md` |
| 8. Ablation rows | Add A4 (zkVM, per op) and A5 (zkVM, batch N) to `qevm-cli experiment`: gas/op, prove time, latency, memory. | new rows in `summary.csv` |
| 9. Cost analysis | Replace the parametrised t_sig in `offchain-cost.md` with the measured values; recompute break-even. | updated report |

**Expected effort:** about 2–3 weeks for one person familiar with Rust: 1 week for steps 1–4, 1 week for steps 5–6, a few days for steps 7–9.

**Risks:**
- The FIPS 204 crate may not build for the guest target, or may be slow without a Keccak accelerator. Mitigation: try SP1, which has Keccak precompiles; or port the PQClean reference code.
- Proving memory may exceed the host. Mitigation: smaller segments, or a cloud GPU instance.
- Groth16 wrapping needs Docker on x86-64 Linux.

**What to report:** cycles per signature, STARK prove time, wrap time, total time to a receipt, peak memory, hardware, and the measured on-chain gas of the production verifier. State plainly whether these confirm or refute the 12.4 s / 1,842,500-cycle figures from the earlier draft, which no code in this repository reproduces.

---

## FW-2. Executable native ML-DSA baseline on the EVM (supervisor point 5)

**Status: done.** `scripts/native-baseline.sh` executes two ZKNox ETHDILITHIUM verifiers on the same revm chain: 1,248,996 gas (optimised branch) and 8,168,152 gas (main branch) per `verify` transaction, over 100 signatures. See `results/native-baseline*/baseline.md`. Remaining work: also run the Fireblocks verifier (reported at about 1.23M gas), and repeat under Prague rules (FW-3).

## FW-3. Prague / EIP-7623 re-run

All gas figures use the Cancun schedule in revm 14.0.3. Since Prague (Pectra), EIP-7623 sets a calldata floor price for data-heavy transactions. Re-run every experiment on a revm version with Prague rules and report both. The native baseline (≈ 3.7 KB of calldata per signature) and large batches are the configurations most likely to be affected.

## FW-4. Custom ML-DSA circuit

A hand-written arithmetic circuit (e.g. Circom/Halo2/Plonky3) for FIPS 204 verification should prove much faster than a general-purpose zkVM. The main costs are SHAKE-128/256 (ExpandA, SampleInBall) and the NTT over q = 8,380,417, which is not native to BN254. This needs specialised effort; compare against FW-1.

## FW-5. Recursive aggregation

Aggregate several batch receipts into one, so that on-chain cost per *batch* falls further and per-op cost approaches the wallet's per-op storage and calldata floor measured in the experiments.

## FW-6. Multi-party trusted setup

Replace the seeded single-party setup by an MPC ceremony, or use a transparent system such as a STARK verified on-chain or Plonk with a universal setup, and report the cost difference.

## FW-7. Testnet deployment

Deploy the wallet and verifier on Sepolia or an L2 testnet, and measure real inclusion latency and mempool propagation of 2.4 KB-signature user operations.

## FW-8. Decentralised proving

Multiple independent provers or a proving market, so the bundler is not a liveness bottleneck.
