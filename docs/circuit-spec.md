# Groth16 Receipt Circuit and Replay Protection: Precise Specification

This document says exactly what the implemented proof system proves, what it does not prove, and how replays are prevented. It answers supervisor points 1 and 2. Source of truth: `crates/evm/src/groth16.rs` (circuit), `crates/evm/src/verifier.rs` (on-chain verifier), `crates/evm/src/wallet.rs` (wallet / EntryPoint), `crates/bundler/src/lib.rs` (off-chain validation).

## 1. Summary

| Question | Answer |
|---|---|
| Is ML-DSA verification proven inside the zk system? | **No.** The bundler verifies ML-DSA-44 (FIPS 204) natively, off-chain. |
| What does the Groth16 proof prove? | Only that the prover chose to authorise a specific 32-byte batch digest for a specific program id. The relation has no secret witness. |
| Who can create a valid proof? | Anyone who holds the proving key. In Groth16 the proving key is public. |
| What is the on-chain guarantee, then? | Key binding, nonce ordering and replay protection are enforced **on-chain** by the wallet. Signature validity is guaranteed **only off-chain**, by the bundler (trusted). |
| What would make the guarantee trustless? | Proving ML-DSA verification inside a zkVM (relation R_ML-DSA, §6). This is future work: [future-work-zkvm-linux.md](future-work-zkvm-linux.md). |

## 2. The implemented relation R_cur

Curve and field: BN254, scalar field 𝔽_r, with r = 21888242871839275222246405745257275088548364400416034343698204186575808495617.

**Public inputs** (5 field elements, in this order):

| # | Name | Encoding |
|---|---|---|
| x₁ | d_hi | the high 16 bytes of the batch digest d, as a big-endian integer (< 2¹²⁸) |
| x₂ | d_lo | the low 16 bytes of d |
| x₃ | p_hi | the high 16 bytes of p = keccak256("qevm.mldsa.verify") |
| x₄ | p_lo | the low 16 bytes of p |
| x₅ | v | validity flag; must equal 1 |

The two limbs are both below 2¹²⁸ < r, so the encoding (d, p) ↦ (x₁…x₄) is injective.

**Witness:** w = (s₁, …, s₅) ∈ 𝔽_r⁵.

**Relation:**

  R_cur = { (x, w) : sᵢ = xᵢ · xᵢ for i = 1..5, and x₅ · 1 = 1 }

**Size:** 6 R1CS constraints, 5 public inputs (plus the constant 1), 5 witness variables.

**Setup:** circuit-specific Groth16 setup (`ark-groth16` 0.4.0), single-party and deterministic from the seed `0x5145564d`. Development only: the seed fixes the toxic waste, so anyone who knows the seed can also *simulate* proofs. A production deployment would need a multi-party ceremony, and that still would not fix §3.

**Verifier contract** (`verifier.rs`, hand-assembled EVM bytecode with the verifying key embedded):
1. require `calldatasize == 416` and every public input < r;
2. vk_x = IC₀ + Σ xᵢ·ICᵢ, using precompiles 0x07 (ecMul) and 0x06 (ecAdd);
3. require e(−A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1, using precompile 0x08 (pairing; checks that points are on the curve and in the subgroup).

Calldata is A (64) ‖ B (128) ‖ C (64) ‖ 5 × 32 = 416 bytes. The off-chain verifier (arkworks) performs the same on-curve and subgroup checks.

## 3. What R_cur guarantees, and what it does not

**Guaranteed (by Groth16 knowledge soundness):** a valid proof is bound to its exact public inputs (d, p, v = 1). A proof made for one digest does not verify for any other digest or program id. The binding comes from the IC terms of the verifying key. The squaring constraints add nothing to it; they only give every input a constraint.

**Not guaranteed:**
- *Any ML-DSA signature was checked.* For every x with x₅ = 1 the witness sᵢ = xᵢ² exists and can be computed from x alone. So anyone with the public proving key can prove any digest. The negative-control test `soundness_gap_trivial_circuit_accepts_unverified_statement` (`crates/evm/tests/wallet.rs`, and case 45 of `results/security.md`) shows a wallet accepting a registered account's op that was never signed.
- *Zero knowledge has any role.* There is nothing secret to hide.
- *Uniqueness of proof bytes.* Groth16 proofs can be re-randomised: `Groth16Keys::rerandomize` produces different bytes for the same statement. Replay protection therefore cannot rely on proof bytes (see §5).

**Why the on-chain gas figure is still meaningful:** Groth16 verification cost depends on the number of public inputs (one ecMul and one ecAdd each, plus a fixed 4-pair pairing), not on circuit size. A zkVM receipt wrapped in Groth16 with the same 5-input interface would cost the same on-chain. The *proving* cost would not be comparable at all (§6).

**Trust model today:**

| Property | Enforced by | Trusted party |
|---|---|---|
| ML-DSA signature over opHash is valid | bundler, off-chain (`pqcrypto-mldsa` 0.1.2, FIPS 204) | bundler |
| pk belongs to sender | wallet on-chain (`pk[sender] == keccak(pk)`), and bundler | none |
| No replay / correct ordering | wallet on-chain (nonce), and bundler | none |
| Batch contents = what was authorised | wallet on-chain (recomputes digest) | none |
| Proof binds that digest | Groth16 verifier on-chain | setup ceremony |

## 4. Operation hash and batch statement

The user signs opHash with ML-DSA-44 (FIPS 204 pure mode, empty context string):

  opHash = keccak256( TAG ‖ chain_id ‖ wallet ‖ sender ‖ nonce ‖ keccak256(call_data) ‖ keccak256(pk) )

Each field is one 32-byte word (addresses and integers are left-padded), and TAG = keccak256("QEVM_USEROP_V1"). It is defined once, in `qevm_evm::wallet::user_op_hash`. The wallet recomputes exactly this preimage on-chain, using `CHAINID` and `ADDRESS` for the first two fields.

The batch statement is d = keccak256(opHash₁ ‖ … ‖ opHash_N), with fixed 32-byte items in batch order. A single-op receipt uses N = 1.

## 5. How replay is prevented

Four layers. Each one is tested; case numbers refer to `results/security.md`.

1. **Statement binding (cryptographic).** The proof is tied to d, and d to each opHash. Changing any field of any op, or reordering, dropping, adding or duplicating ops, changes d, so the proof no longer verifies. Cases 29–34 (altered batch) and 40–43 (proof for a different statement); off-chain, an op edited after signing fails its ML-DSA check or validation (cases 13–18).
2. **Cross-chain (domain).** `chain_id` is in opHash, and the wallet fills it from `CHAINID`. A proof made for another chain id is rejected (case 42); so is an op whose chain id was edited (case 15).
3. **Cross-contract (domain).** The wallet address is in opHash, and the wallet fills it from `ADDRESS`. Ops for another wallet, including the ablation's attestation wallet, are rejected (cases 16, 43).
4. **Same-op replay (state).** For each op the wallet requires `nonce[sender] == nonce` and then stores `nonce + 1`. If any op in the batch fails, the transaction reverts, rolling back every nonce update in the batch. Resending the same transaction, or the same ops with a re-randomised proof, is therefore rejected (cases 26–28). Layer 1 cannot stop this, because a re-randomised proof is a different, equally valid proof for the same statement.

Off-chain, the bundler applies the same rules early, so invalid ops never reach a batch:
- `(sender, nonce)` is remembered permanently (`InMemoryStorage::seen_nonces`), so an op is rejected again after it has been bundled (cases 22, 24).
- The expected nonce is `wallet.nonce[sender] + pending(sender)`, read from chain state, so even a bundler that lost its mempool rejects an included op (case 25).

**Cost of a rejected proof.** If the proof is invalid, the precompile call fails, and the wallet's verifier call uses up all the gas it was given (about 29M gas in cases 37–39, with a 30M transaction gas limit). The *submitter* pays this, not the user. As in ERC-4337, a bundler must simulate a batch before sending it. Forwarding a fixed gas budget to the verifier would cap the loss; that is a deployment detail.

## 6. Target relation (future work)

  R_ML-DSA = { (x, w) : x = (d, imageID), w = ((pkᵢ, σᵢ, opHashᵢ) for i = 1..N),
               d = keccak256(opHash₁ ‖ … ‖ opHash_N), and for every i:
               ML-DSA-44.Verify(pkᵢ, opHashᵢ, σᵢ) = 1, with keccak256(pkᵢ) committed in opHashᵢ }

This is executed as a RISC Zero or SP1 guest program; the STARK receipt is wrapped in Groth16 and keeps the same 5-input on-chain interface (d split into two limbs, imageID instead of the program id, v = 1). The wallet logic above stays the same. With R_ML-DSA, the negative control in §3 must be *rejected*, and the "bundler" rows of the trust model move to "none" (zkVM soundness plus the setup). Plan, measurements and risks: [future-work-zkvm-linux.md](future-work-zkvm-linux.md).
