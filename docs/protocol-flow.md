# Q-EVM Protocol Flow

How the protocol maps to the Rust implementation. Replay protection is specified precisely in [circuit-spec.md](circuit-spec.md) §5.

## 0. Account registration
- The wallet stores `pk[sender] = keccak256(ML-DSA-44 public key)` and a starting `nonce[sender]`.
- In this prototype, `LocalChain::register_account` writes this state directly. It stands in for the wallet's deployment / `initCode` and is not part of any measurement.

## 1. UserOperation creation
- The wallet software builds `(wallet, sender, nonce, chain_id, call_data, pk)`.
- It computes opHash ([architecture.md](architecture.md)).
- It signs opHash with ML-DSA-44 (FIPS 204 pure mode, empty context).

## 2. Bundler validation (off-chain)
1. Payload present, `chain_id` correct, `wallet` is this wallet.
2. `keccak(pk) == pk[sender]`, read from chain state.
3. `(sender, nonce)` never accepted before, and `nonce == nonce[sender] + pending(sender)`.
4. FIPS 204 verification of the signature over opHash.

A failure at any step rejects the op, and the reason is returned.

## 3. Batching and authorisation
- Up to `batch_size` ops are taken in arrival order.
- `digest = keccak256(opHash_1 ‖ … ‖ opHash_N)`.
- Groth16 mode: prove `(digest, program, 1)` with the binding circuit.
- Attestation mode (ablation only): the bundler's ECDSA signature over the digest.

## 4. On-chain validation (wallet)
- Calldata: `auth ‖ N ‖ N × (sender, nonce, keccak(call_data), keccak(pk))`.
- For each op: check the key, check and increment the nonce, recompute opHash.
- Recompute the digest, then verify the authorisation.
- Any failure reverts the whole batch, including all nonce updates.

## Replay protection (summary)
- The proof is bound to the digest, and the digest to each opHash.
- Chain id and wallet address are part of opHash.
- On-chain nonces are consumed. This also defeats re-randomised Groth16 proofs.
- The bundler remembers `(sender, nonce)` permanently and checks nonces against chain state.
