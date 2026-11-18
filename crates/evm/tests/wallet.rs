//! On-chain tests of the wallet / EntryPoint bytecode (point 6: security and
//! correctness). Every case runs on revm with committed state.

use qevm_evm::{
    batch_digest, keccak, proof_bytes, wallet_calldata, Attester, Groth16Keys, LocalChain, ReceiptStatement,
    WalletKind, WalletOp, ATTESTATION_AUTH_LEN, GROTH16_AUTH_LEN,
};

const CHAIN_ID: u64 = 1;

struct Fixture {
    keys: Groth16Keys,
    chain: LocalChain,
    program: [u8; 32],
    attester: Attester,
}

fn fixture() -> Fixture {
    let keys = Groth16Keys::setup(11).expect("setup");
    let program = keccak(b"qevm.mldsa.verify");
    let attester = Attester::from_seed([7u8; 32]);
    let chain = LocalChain::new(keys.verifying_key(), program, attester.address(), CHAIN_ID).expect("chain");
    Fixture { keys, chain, program, attester }
}

impl Fixture {
    /// `n` registered accounts, each with one pending op at its current nonce.
    fn ops(&self, n: usize, tag: u8, start_nonce: u64) -> Vec<WalletOp> {
        (0..n)
            .map(|i| {
                let mut sender = [tag; 20];
                sender[18..].copy_from_slice(&(i as u16).to_be_bytes());
                let pk_hash = keccak(&[&sender[..], b"pk"].concat());
                self.chain.register_account(&sender, pk_hash, start_nonce);
                WalletOp { sender, nonce: start_nonce, call_data_hash: keccak(&[tag, i as u8]), pk_hash }
            })
            .collect()
    }

    fn digest(&self, kind: WalletKind, ops: &[WalletOp]) -> [u8; 32] {
        let wallet = self.chain.wallet(kind).address;
        let hashes: Vec<[u8; 32]> = ops.iter().map(|o| o.op_hash(CHAIN_ID, &wallet)).collect();
        batch_digest(&hashes)
    }

    fn proof_for_digest(&self, digest: [u8; 32]) -> Vec<u8> {
        let full = self.keys.prove(&ReceiptStatement { digest, program: self.program }, 5).expect("prove");
        proof_bytes(&full).to_vec()
    }

    fn groth16_calldata(&self, ops: &[WalletOp]) -> Vec<u8> {
        let proof = self.proof_for_digest(self.digest(WalletKind::Groth16, ops));
        wallet_calldata(&proof, ops)
    }

    fn send(&self, kind: WalletKind, calldata: &[u8]) -> bool {
        self.chain.send(self.chain.wallet(kind).address, calldata).expect("tx").gas.success
    }
}

#[test]
fn valid_batches_are_accepted_and_consume_nonces() {
    let f = fixture();
    for (tag, n) in [(1u8, 1usize), (2, 8), (3, 64)] {
        let ops = f.ops(n, tag, 5);
        let cd = f.groth16_calldata(&ops);
        let out = f.chain.send(f.chain.wallet(WalletKind::Groth16).address, &cd).expect("tx");
        assert!(out.gas.success && out.committed, "batch of {n} must be accepted: {out:?}");
        for o in &ops {
            assert_eq!(f.chain.nonce(WalletKind::Groth16, &o.sender), 6);
        }
    }
}

#[test]
fn replayed_batch_is_rejected() {
    let f = fixture();
    let ops = f.ops(4, 1, 0);
    let cd = f.groth16_calldata(&ops);
    assert!(f.send(WalletKind::Groth16, &cd));
    assert!(!f.send(WalletKind::Groth16, &cd), "same calldata twice must fail (nonce consumed)");
}

#[test]
fn rerandomized_proof_cannot_replay() {
    let f = fixture();
    let ops = f.ops(2, 1, 0);
    let digest = f.digest(WalletKind::Groth16, &ops);
    let full = f.keys.prove(&ReceiptStatement { digest, program: f.program }, 5).expect("prove");
    let rerand = f.keys.rerandomize(&full, 99).expect("rerandomize");
    assert_ne!(proof_bytes(&full), proof_bytes(&rerand), "re-randomised proof has different bytes");
    // Both proofs verify for the statement on the bare verifier...
    assert!(f.chain.measure_verify(&full).expect("call").success);
    assert!(f.chain.measure_verify(&rerand).expect("call").success);
    // ...but after the first is included, the second cannot replay the ops.
    assert!(f.send(WalletKind::Groth16, &wallet_calldata(proof_bytes(&full), &ops)));
    assert!(!f.send(WalletKind::Groth16, &wallet_calldata(proof_bytes(&rerand), &ops)));
}

#[test]
fn failed_batch_rolls_back_every_nonce() {
    let f = fixture();
    let mut ops = f.ops(3, 1, 0);
    let cd_good = f.groth16_calldata(&ops);
    ops[2].nonce = 7; // wrong nonce for the last op only; proof is for the edited ops
    let cd_bad = f.groth16_calldata(&ops);
    assert!(!f.send(WalletKind::Groth16, &cd_bad));
    for o in &ops {
        assert_eq!(f.chain.nonce(WalletKind::Groth16, &o.sender), 0, "revert must roll back");
    }
    assert!(f.send(WalletKind::Groth16, &cd_good));
}

#[test]
fn modified_op_fields_break_the_proof() {
    let f = fixture();
    let ops = f.ops(2, 1, 0);
    let proof = f.proof_for_digest(f.digest(WalletKind::Groth16, &ops));
    let mutations: Vec<(&str, Box<dyn Fn(&mut WalletOp)>)> = vec![
        ("call data", Box::new(|o| o.call_data_hash[0] ^= 1)),
        ("nonce", Box::new(|o| o.nonce += 1)),
    ];
    for (what, m) in mutations {
        let mut edited = ops.clone();
        m(&mut edited[0]);
        assert!(!f.send(WalletKind::Groth16, &wallet_calldata(&proof, &edited)), "modified {what} accepted");
    }
    // Different sender (registered, correct nonce) with the original proof.
    let other = f.ops(1, 9, 0)[0];
    let mut edited = ops.clone();
    edited[0] = WalletOp { call_data_hash: ops[0].call_data_hash, ..other };
    assert!(!f.send(WalletKind::Groth16, &wallet_calldata(&proof, &edited)), "modified sender accepted");
    assert!(f.send(WalletKind::Groth16, &wallet_calldata(&proof, &ops)), "untouched batch must pass");
}

#[test]
fn proof_for_another_chain_or_wallet_is_rejected() {
    let f = fixture();
    let ops = f.ops(1, 1, 0);
    let wallet = f.chain.wallet(WalletKind::Groth16).address;
    let other_chain = batch_digest(&[ops[0].op_hash(CHAIN_ID + 1, &wallet)]);
    let other_wallet = batch_digest(&[ops[0].op_hash(CHAIN_ID, &[0x42; 20])]);
    for digest in [other_chain, other_wallet] {
        assert!(!f.send(WalletKind::Groth16, &wallet_calldata(&f.proof_for_digest(digest), &ops)));
    }
}

#[test]
fn altered_batches_are_rejected() {
    let f = fixture();
    let ops = f.ops(4, 1, 0);
    let proof = f.proof_for_digest(f.digest(WalletKind::Groth16, &ops));
    let extra = f.ops(1, 2, 0);
    let reordered = vec![ops[1], ops[0], ops[2], ops[3]];
    let dropped = ops[..3].to_vec();
    let added = [ops.clone(), extra].concat();
    let duplicated = vec![ops[0], ops[0], ops[1], ops[2], ops[3]];
    for (what, batch) in [("reordered", reordered), ("dropped", dropped), ("added", added), ("duplicated", duplicated)] {
        assert!(!f.send(WalletKind::Groth16, &wallet_calldata(&proof, &batch)), "{what} batch accepted");
    }
    // Wrong N header / truncated / trailing bytes.
    let mut cd = wallet_calldata(&proof, &ops);
    cd[GROTH16_AUTH_LEN + 31] = 5;
    assert!(!f.send(WalletKind::Groth16, &cd), "N header larger than records accepted");
    let cd = wallet_calldata(&proof, &ops);
    assert!(!f.send(WalletKind::Groth16, &cd[..cd.len() - 1]), "truncated calldata accepted");
    assert!(!f.send(WalletKind::Groth16, &[cd.clone(), vec![0]].concat()), "trailing byte accepted");
    assert!(!f.send(WalletKind::Groth16, &wallet_calldata(&proof, &[])), "empty batch accepted");
    assert!(f.send(WalletKind::Groth16, &cd));
}

#[test]
fn unregistered_or_wrong_key_is_rejected() {
    let f = fixture();
    let mut ops = f.ops(1, 1, 0);
    ops[0].pk_hash[0] ^= 1; // not the key registered for this sender
    assert!(!f.send(WalletKind::Groth16, &f.groth16_calldata(&ops)));

    // Never registered sender with pk_hash = 0 (would match an empty slot).
    let ghost = WalletOp { sender: [0xee; 20], nonce: 0, call_data_hash: [1; 32], pk_hash: [0; 32] };
    assert!(!f.send(WalletKind::Groth16, &f.groth16_calldata(&[ghost])));
}

#[test]
fn invalid_proofs_are_rejected() {
    let f = fixture();
    let ops = f.ops(1, 1, 0);
    let good = f.proof_for_digest(f.digest(WalletKind::Groth16, &ops));

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("all zero", vec![0u8; GROTH16_AUTH_LEN]),
        ("random bytes", (0..GROTH16_AUTH_LEN).map(|i| (i * 37 % 251) as u8).collect()),
    ];
    let mut flip_a = good.clone();
    flip_a[31] ^= 1; // A.x -> point not on the curve
    cases.push(("A not on curve", flip_a));
    let mut flip_b = good.clone();
    flip_b[64 + 31] ^= 1; // B.x_im
    cases.push(("B tampered", flip_b));
    let mut flip_c = good.clone();
    flip_c[192 + 63] ^= 1; // C.y
    cases.push(("C tampered", flip_c));
    let other_setup = Groth16Keys::setup(12).expect("setup");
    let digest = f.digest(WalletKind::Groth16, &ops);
    let foreign = other_setup.prove(&ReceiptStatement { digest, program: f.program }, 1).expect("prove");
    cases.push(("proof from another setup", proof_bytes(&foreign).to_vec()));
    let wrong_program = f.keys.prove(&ReceiptStatement { digest, program: [0x13; 32] }, 1).expect("prove");
    cases.push(("proof for another program id", proof_bytes(&wrong_program).to_vec()));

    for (what, proof) in cases {
        assert!(!f.send(WalletKind::Groth16, &wallet_calldata(&proof, &ops)), "{what} accepted");
    }
    assert!(f.send(WalletKind::Groth16, &wallet_calldata(&good, &ops)));
}

#[test]
fn verifier_rejects_out_of_range_inputs_and_bad_length() {
    let f = fixture();
    let st = ReceiptStatement { digest: [3; 32], program: f.program };
    let cd = f.keys.prove(&st, 1).expect("prove");
    assert!(f.chain.measure_verify(&cd).expect("call").success);
    let mut big = cd.clone();
    big[256..288].fill(0xff); // input >= r
    assert!(!f.chain.measure_verify(&big).expect("call").success);
    assert!(!f.chain.measure_verify(&cd[..415]).expect("call").success);
}

#[test]
fn attestation_wallet_accepts_only_the_bundler_key() {
    let f = fixture();
    let ops = f.ops(3, 1, 0);
    let digest = f.digest(WalletKind::Attestation, &ops);
    let good = f.attester.sign(&digest);
    assert!(f.send(WalletKind::Attestation, &wallet_calldata(&good, &ops)));
    assert!(!f.send(WalletKind::Attestation, &wallet_calldata(&good, &ops)), "replay accepted");

    let ops = f.ops(3, 2, 0);
    let digest = f.digest(WalletKind::Attestation, &ops);
    let stranger = Attester::from_seed([8u8; 32]).sign(&digest);
    assert!(!f.send(WalletKind::Attestation, &wallet_calldata(&stranger, &ops)));
    let mut bad = f.attester.sign(&digest);
    bad[40] ^= 1;
    assert!(!f.send(WalletKind::Attestation, &wallet_calldata(&bad, &ops)));
    assert_eq!(bad.len(), ATTESTATION_AUTH_LEN);
}

/// Negative control documenting the soundness gap of the current circuit
/// (docs/circuit-spec.md, finding C1): anyone holding the public proving key
/// can authorise *any* registered op, without a valid ML-DSA signature,
/// because the circuit does not verify the signature. This assertion is
/// expected to flip once ML-DSA verification is proven inside a zkVM.
#[test]
fn soundness_gap_trivial_circuit_accepts_unverified_statement() {
    let f = fixture();
    let ops = f.ops(1, 1, 0);
    // No signature exists at all here; the "attacker" just proves the digest.
    let forged = f.proof_for_digest(f.digest(WalletKind::Groth16, &ops));
    assert!(
        f.send(WalletKind::Groth16, &wallet_calldata(&forged, &ops)),
        "documented gap: the trivial receipt circuit cannot tell a signed op from an unsigned one"
    );
}

/// A G2 point that is on the twist curve but outside the prime-order subgroup
/// must be rejected by the pairing precompile (EIP-197) and off-chain.
#[test]
fn g2_point_outside_subgroup_is_rejected() {
    use ark_bn254::{Fq, Fq2, G2Affine};
    use ark_ff::{BigInteger, PrimeField};
    let f = fixture();
    let ops = f.ops(1, 1, 0);
    let good = f.proof_for_digest(f.digest(WalletKind::Groth16, &ops));

    let mut point = None;
    for i in 1u64..200 {
        if let Some(p) = G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::from(1u64)), true) {
            if p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve() {
                point = Some(p);
                break;
            }
        }
    }
    let p = point.expect("found an on-curve, non-subgroup G2 point");
    let be = |v: &Fq| v.into_bigint().to_bytes_be();
    let mut bad = good.clone();
    bad[64..96].copy_from_slice(&be(&p.x.c1));
    bad[96..128].copy_from_slice(&be(&p.x.c0));
    bad[128..160].copy_from_slice(&be(&p.y.c1));
    bad[160..192].copy_from_slice(&be(&p.y.c0));
    assert!(!f.send(WalletKind::Groth16, &wallet_calldata(&bad, &ops)));

    // Off-chain: same proof with the correct public inputs is rejected too.
    let st = ReceiptStatement { digest: f.digest(WalletKind::Groth16, &ops), program: f.program };
    let mut full = f.keys.prove(&st, 5).expect("prove");
    assert!(f.keys.verify(&full, &st).expect("verify"));
    full[..256].copy_from_slice(&bad);
    assert!(!f.keys.verify(&full, &st).unwrap_or(false));
}
