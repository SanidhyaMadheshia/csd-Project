//! Real Groth16 receipts over BN254 (arkworks).
//!
//! The circuit exposes five public inputs, the same count and shape as the
//! RISC Zero Groth16 receipt verifier (two 128-bit limbs for the claim
//! digest, two for the program image id, plus a validity flag). On-chain
//! Groth16 verification cost depends only on the number of public inputs,
//! never on circuit size, so the gas measured for this verifier is the gas a
//! zkVM Groth16 receipt with the same public inputs costs on Ethereum.
//!
//! Scope note: the ML-DSA check itself runs natively in the bundler before a
//! receipt is produced. Arithmetising FIPS 204 verification inside the circuit
//! is the paper's future work (§VII-B); this circuit binds the verification
//! *result* (op hash, program id, `is_valid = 1`) to a succinct proof.

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_snark::SNARK;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

/// Number of public inputs of the receipt circuit.
pub const NUM_PUBLIC_INPUTS: usize = 5;

/// Size of the EVM calldata for `verify(proof, inputs)`: A(64) ‖ B(128) ‖ C(64) ‖ inputs.
pub const EVM_CALLDATA_LEN: usize = 256 + NUM_PUBLIC_INPUTS * 32;

#[derive(Debug, Error)]
pub enum Groth16Error {
    #[error("groth16 synthesis error: {0}")]
    Synthesis(String),
    #[error("malformed proof calldata")]
    Malformed,
}

/// The statement proven by a receipt: `digest` (op hash or batch digest) and
/// `program` (keccak of the program id) with `is_valid = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptStatement {
    pub digest: [u8; 32],
    pub program: [u8; 32],
}

impl ReceiptStatement {
    /// Public inputs in circuit order: digest_hi, digest_lo, program_hi, program_lo, is_valid.
    pub fn public_inputs(&self) -> [Fr; NUM_PUBLIC_INPUTS] {
        [
            Fr::from_be_bytes_mod_order(&self.digest[..16]),
            Fr::from_be_bytes_mod_order(&self.digest[16..]),
            Fr::from_be_bytes_mod_order(&self.program[..16]),
            Fr::from_be_bytes_mod_order(&self.program[16..]),
            Fr::from(1u64),
        ]
    }
}

#[derive(Clone)]
struct ReceiptCircuit {
    inputs: Option<[Fr; NUM_PUBLIC_INPUTS]>,
}

impl ConstraintSynthesizer<Fr> for ReceiptCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut vars: Vec<Variable> = Vec::with_capacity(NUM_PUBLIC_INPUTS);
        for i in 0..NUM_PUBLIC_INPUTS {
            let value = self.inputs.map(|v| v[i]);
            vars.push(cs.new_input_variable(|| value.ok_or(SynthesisError::AssignmentMissing))?);
        }
        // Bind every public input into the constraint system (x * x = sq) so a
        // proof cannot be replayed against different public inputs.
        for (i, &x) in vars.iter().enumerate() {
            let sq_value = self.inputs.map(|v| v[i] * v[i]);
            let sq = cs.new_witness_variable(|| sq_value.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + sq)?;
        }
        // is_valid must be exactly 1: the bundler only proves accepted signatures.
        let is_valid = vars[NUM_PUBLIC_INPUTS - 1];
        cs.enforce_constraint(lc!() + is_valid, lc!() + Variable::One, lc!() + Variable::One)?;
        Ok(())
    }
}

/// Proving + verifying keys from a circuit-specific setup.
pub struct Groth16Keys {
    pk: ProvingKey<Bn254>,
    pvk: PreparedVerifyingKey<Bn254>,
}

impl Groth16Keys {
    /// Deterministic development setup (single-party, seeded). A production
    /// deployment would take these keys from a multi-party ceremony.
    pub fn setup(seed: u64) -> Result<Self, Groth16Error> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(ReceiptCircuit { inputs: None }, &mut rng)
            .map_err(|e| Groth16Error::Synthesis(e.to_string()))?;
        let pvk = Groth16::<Bn254>::process_vk(&vk).map_err(|e| Groth16Error::Synthesis(e.to_string()))?;
        Ok(Self { pk, pvk })
    }

    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.pvk.vk
    }

    /// Produce a real Groth16 proof and return it EVM-encoded (calldata for the verifier).
    pub fn prove(&self, statement: &ReceiptStatement, seed: u64) -> Result<Vec<u8>, Groth16Error> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let inputs = statement.public_inputs();
        let proof = Groth16::<Bn254>::prove(&self.pk, ReceiptCircuit { inputs: Some(inputs) }, &mut rng)
            .map_err(|e| Groth16Error::Synthesis(e.to_string()))?;
        Ok(encode_calldata(&proof, &inputs))
    }

    /// Verify EVM-encoded calldata off-chain with arkworks.
    pub fn verify(&self, calldata: &[u8], statement: &ReceiptStatement) -> Result<bool, Groth16Error> {
        let (proof, inputs) = decode_calldata(calldata)?;
        if inputs != statement.public_inputs() {
            return Ok(false);
        }
        Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, &inputs, &proof)
            .map_err(|e| Groth16Error::Synthesis(e.to_string()))
    }
}

pub(crate) fn fq_bytes(v: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&v.into_bigint().to_bytes_be());
    out
}

pub(crate) fn fr_bytes(v: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&v.into_bigint().to_bytes_be());
    out
}

/// G1 point as the EVM precompiles expect it: x ‖ y.
pub(crate) fn g1_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_bytes(&p.x));
    out[32..].copy_from_slice(&fq_bytes(&p.y));
    out
}

/// G2 point as the EVM pairing precompile expects it: x_im ‖ x_re ‖ y_im ‖ y_re.
pub(crate) fn g2_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&fq_bytes(&p.x.c1));
    out[32..64].copy_from_slice(&fq_bytes(&p.x.c0));
    out[64..96].copy_from_slice(&fq_bytes(&p.y.c1));
    out[96..].copy_from_slice(&fq_bytes(&p.y.c0));
    out
}

fn encode_calldata(proof: &Proof<Bn254>, inputs: &[Fr; NUM_PUBLIC_INPUTS]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EVM_CALLDATA_LEN);
    out.extend_from_slice(&g1_bytes(&proof.a));
    out.extend_from_slice(&g2_bytes(&proof.b));
    out.extend_from_slice(&g1_bytes(&proof.c));
    for input in inputs {
        out.extend_from_slice(&fr_bytes(input));
    }
    out
}

fn read_fq(bytes: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(bytes)
}

fn decode_calldata(data: &[u8]) -> Result<(Proof<Bn254>, [Fr; NUM_PUBLIC_INPUTS]), Groth16Error> {
    if data.len() != EVM_CALLDATA_LEN {
        return Err(Groth16Error::Malformed);
    }
    let g1 = |o: usize| G1Affine::new_unchecked(read_fq(&data[o..o + 32]), read_fq(&data[o + 32..o + 64]));
    let a = g1(0);
    let b = G2Affine::new_unchecked(
        ark_bn254::Fq2::new(read_fq(&data[96..128]), read_fq(&data[64..96])),
        ark_bn254::Fq2::new(read_fq(&data[160..192]), read_fq(&data[128..160])),
    );
    let c = g1(192);
    if !a.is_on_curve() || !b.is_on_curve() || !c.is_on_curve() {
        return Err(Groth16Error::Malformed);
    }
    let mut inputs = [Fr::from(0u64); NUM_PUBLIC_INPUTS];
    for (i, slot) in inputs.iter_mut().enumerate() {
        let o = 256 + i * 32;
        *slot = Fr::from_be_bytes_mod_order(&data[o..o + 32]);
    }
    Ok((Proof { a, b, c }, inputs))
}

/// Split calldata back into the statement it claims (digest, program).
pub fn statement_from_calldata(data: &[u8]) -> Option<ReceiptStatement> {
    if data.len() != EVM_CALLDATA_LEN {
        return None;
    }
    let limb = |i: usize| &data[256 + i * 32 + 16..256 + (i + 1) * 32];
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(limb(0));
    digest[16..].copy_from_slice(limb(1));
    let mut program = [0u8; 32];
    program[..16].copy_from_slice(limb(2));
    program[16..].copy_from_slice(limb(3));
    Some(ReceiptStatement { digest, program })
}
