# Changes from the Original Paper

Original: `group_52_CSD_Lab_Final.pdf` (repository root), **unchanged**.
Revised copy: `paper/revised/main.tex` (IEEEtran LaTeX, rebuilt from the original's text).

Every number in the revised paper is generated from `results/` by `scripts/make_paper_tables.py` into `tables/macros.tex`, `tables/*.tex` and `data/*.csv`. No figure is typed by hand.

## Changes by supervisor point

| # | Supervisor point | What changed in the paper |
|---|---|---|
| 1 | Implemented vs. proposed | New Table "Implementation status" (§IV). New "Scope" subsection in §I. The abstract and conclusion say plainly that ML-DSA is verified off-chain and that the receipt does not prove it. The 1,842,500-cycle count and 12.4 s proving time are no longer presented as results; they are named as unreproducible earlier-draft figures. |
| 2 | Precise Groth16 circuit, replay protection | New §V "What Is Proven": relation R_cur (public inputs, encoding, witness, 6 constraints), guarantees and non-guarantees, trust model, four-layer replay argument (including Groth16 malleability), and target relation R_ML-DSA. |
| 3 | Batch sizes, repeats, full metrics | New §VI-A/B/D: 9 batch sizes, 30 runs after 3 warm-ups, mean/std/median/p95/95% CI; total gas, gas per op, proving time, proof-verification time (off-chain and EVM execution), end-to-end latency, peak heap (Fig. 1, Tables IV and VII). |
| 4 | Ablation | New Table "Ablation": A0 native, A1 off-chain + attestation, A2 + Groth16 per op, A3 + batching, with a trust column. |
| 5 | Executable baseline | §VI-C reports the cost model and **two executed** third-party Solidity verifiers (ZKNox ETHDILITHIUM: optimised branch at 1,248,996 gas and main branch at 8,168,152 gas per `verify` transaction), run on the same revm chain and hard fork with the same 100 FIPS 204 keys and signatures. Both accept 100/100 valid and reject 100/100 tampered signatures. The 2.8M model falls between them (+124% / −66%). Reductions are reported against the cheapest executed verifier (79.9% single op, 99.19% at N=256). |
| 6 | Security tests | New §VII and Table "Security evaluation": 45 pipeline cases (valid/invalid signatures, modified op hash, replay incl. re-randomised proof, altered batch, invalid proofs, key binding), plus a documented negative control. |
| 7 | Cost moved off-chain | New §VI-E: measured off-chain costs, plus a parametrised zkVM proving-time model (12.4 s is one parameter value, labelled projected) with prover price, gas price and break-even, and the latency consequence of batching. |
| 8 | Related work | §II rewritten. New Table "Comparison with related approaches" (Solidity ML-DSA/Falcon verifiers, precompile EIPs, SP1/RISC Zero, zkLogin, Algorand, QRL, hash-based aggregation). All 43 bibliography entries were checked against primary sources on 2026-11-15. |
| 9 | Reproducibility | New Appendix (hardware, versions, commands, gas schedule); repository cited; `docs/reproducibility.md`, Dockerfile, pinned toolchain. |

## Factual corrections to the original

| Original claim | Correction | Source |
|---|---|---|
| Ref. [3] authors "Schemitt, Brandão, Peralta"; cited for "2.8M gas" | Authors are Schemitt, Fan da Silva, Lunardi, Kreutz, Brandão Mansilha, Zorzo (IEEE TrustCom 2025). The paper reports **no EVM gas figure**. It is now cited only for PQ signing/verification timings. | arXiv:2510.09271 |
| Ref. [8] CVE-2026-24850 "ML-DSA hint-index side channel" | Not a side channel: a verification bug (accepting repeated hint indices, CWE-347) in the RustCrypto `ml-dsa` crate. It no longer supports a side-channel claim, so it was removed from the revised text. Our prototype uses `pqcrypto-mldsa`, which is not affected. The case "malformed hint counts" is tested. | GHSA-5x2r-hc65-25f9 |
| "Block gas limit of 30 million" | 60,000,000 on 2026-11-15 (EIP-7935, Fusaka); per-transaction cap 2^24 (EIP-7825). | mainnet block 26,418,726 |
| "ml-dsa crate v0.1.0" | The implementation uses `pqcrypto-mldsa` 0.1.2 (FIPS 204). Earlier code used round-3 Dilithium2 (`pqcrypto-dilithium`). | `Cargo.lock` |
| Batched latency "0.4 s/tx" (§I) vs. "0.14 s/tx" (§V, conclusion) | Inconsistent projections. Both were removed. Latency is now measured for the implemented system, and the zkVM latency is discussed as N × t_sig per prover. | — |
| "2.9k gas/tx after batching" | Ignored per-op calldata and wallet state. The measured per-op floor is about 10k gas (see results). | `results/2026-11-15` |
| "zk-ECDSA 300k gas / 0.1 s", "EIP-8052 50k (est.)" | Uncited. Replaced by sourced figures (EIP-8052 proposes 3,000 gas; SP1 Groth16 about 270k). | EIP-8052; SP1 docs |
| "ECDSA 3,000 gas vs. Q-EVM 2.9k/tx (comparable)" | Compared `ecrecover` alone with a per-tx figure. Removed; A1 (attestation) is now measured with the same wallet logic. | `results/2026-11-15` |
| "measured gas reduction 91.4%" (poster) | Only the on-chain side was measured, and the 2.8M model was calibrated to the projection. Now reported against both the model and the executed baseline. | §VI-C |
| "Hardware: Intel i7-12700K, AWS g5.xlarge" | Not used for any revised result. Actual: AMD Ryzen 5 5500U laptop, Linux container. g5.xlarge appears only as a price assumption. | Appendix |
| Algorithm: wallet recomputes `keccak256(abi.encode(op))`, verifier checks it | Replaced by the implemented algorithm (on-chain op-hash recomputation, nonce, key binding, batch digest). | §IV |
| "zkVM proves Az − ct₁·2^d" (§IV-B) | Removed: no zkVM proof is implemented. The target relation is stated in §V as future work. | — |

## Title and framing
- Title extended: "… An Experimental Study of the Gas, Batching, Latency and Trust Trade-off". As the supervisor asked, the paper is no longer built around a single 91.4% figure.
- Contributions rewritten as what was built and measured, not "insights" from projections.

## Still to do (for the authors)
- Confirm the author/affiliation block and the repository URL. The repo should be public before submission.
- Check the BibTeX author lists for EIP-7600/7607 if those are cited; they are in `refs.bib` but not used.
- Journal selection (supervisor's next step).
