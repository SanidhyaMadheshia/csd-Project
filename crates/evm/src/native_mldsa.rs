//! Gas meter for verifying an ML-DSA-44 signature natively in the EVM.
//!
//! Nobody can run FIPS 204 verification on mainnet today (that is the problem
//! the paper addresses), so this module *meters* it: it walks the real public
//! key and signature through ML-DSA-44 verification (FIPS 204, Alg. 8),
//! counts the work that verification actually performs, and prices each unit
//! with EVM opcode gas costs (Cancun schedule). The data-dependent parts
//! (ExpandA and SampleInBall rejection sampling, the hint weight, the calldata
//! byte mix) are executed on the actual inputs, so every signature gets its
//! own figure.
//!
//! Cost profile: an optimized Yul verifier, as in the pure-Solidity
//! implementation the paper cites for its ~2.8M gas figure ([3], Table II):
//! unrolled NTT layers, lazy reduction, `tr = H(pk)` stored in the wallet at
//! deployment. The Keccak-f round cost is calibrated to that implementation;
//! a naive memory-bound Keccak emulation costs roughly 2.7x more per round.

use crate::executor::{calldata_gas, TX_BASE_GAS};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};
use thiserror::Error;

// ML-DSA-44 parameters (FIPS 204, Table 1).
const Q: u32 = 8_380_417;
const K: usize = 4;
const L: usize = 4;
const N: usize = 256;
const TAU: usize = 39;
const OMEGA: usize = 80;
const PK_LEN: usize = 32 + K * 320;
const SIG_LEN: usize = 32 + L * 576 + OMEGA + K;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

// EVM opcode gas (Cancun).
const G_VERYLOW: u64 = 3; // ADD SUB LT GT EQ AND OR XOR NOT SHL SHR MLOAD MSTORE CALLDATALOAD PUSH DUP SWAP
const G_LOW: u64 = 5; // MUL DIV MOD
const G_MID: u64 = 8; // ADDMOD MULMOD
const G_HIGH: u64 = 10; // JUMPI
const G_JUMPDEST: u64 = 1;
const G_MEMORY: u64 = 3; // per word, plus words² / 512
const G_COLD_SLOAD: u64 = 2_100;

/// Opcode mix of one unit of work.
#[derive(Clone, Copy)]
struct OpMix {
    verylow: u64,
    low: u64,
    mid: u64,
    jumpi: u64,
    jumpdest: u64,
}

impl OpMix {
    const fn gas(&self) -> u64 {
        self.verylow * G_VERYLOW + self.low * G_LOW + self.mid * G_MID + self.jumpi * G_HIGH + self.jumpdest * G_JUMPDEST
    }
}

/// One Keccak-f[1600] round. The EVM's KECCAK256 opcode cannot be used:
/// SHAKE needs the raw permutation, so it is emulated on 64-bit lanes
/// (θ, ρ with lazily-masked SHL/SHR/OR rotations, π, χ, ι): 211 ALU/stack ops
/// plus the round-loop step. Calibrated to the optimized verifier of [3].
const KECCAK_ROUND: OpMix = OpMix { verylow: 211, low: 0, mid: 0, jumpi: 1, jumpdest: 1 };
const KECCAK_ROUNDS: u64 = 24;
/// Absorbing one block: XOR the rate lanes into the state (load, XOR, store).
const ABSORB_LANE: OpMix = OpMix { verylow: 4, low: 0, mid: 0, jumpi: 0, jumpdest: 0 };
/// `tr = H(pk)` is precomputed at wallet deployment and read back: 2 cold SLOADs.
const TR_STORAGE_GAS: u64 = 2 * G_COLD_SLOAD;

/// NTT butterfly (layers unrolled, lazy reduction): 3 MLOAD (a, b, ζ),
/// t = MULMOD(ζ, b, q), ADDMOD(a, t, q), ADDMOD(a, q − t, q) with 1 SUB,
/// 2 MSTORE, 2 index ADD, 4 DUP/SWAP.
const BUTTERFLY: OpMix = OpMix { verylow: 3 + 1 + 2 + 2 + 4, low: 0, mid: 3, jumpi: 0, jumpdest: 0 };
/// Inverse-NTT scaling by n⁻¹: MLOAD, MULMOD, MSTORE, ADD, DUP.
const INTT_SCALE: OpMix = OpMix { verylow: 4, low: 0, mid: 1, jumpi: 0, jumpdest: 0 };
/// Pointwise multiply-accumulate (unrolled): 3 MLOAD, MULMOD, ADDMOD, MSTORE, ADD, 2 DUP.
const MUL_ACC: OpMix = OpMix { verylow: 3 + 1 + 1 + 2, low: 0, mid: 2, jumpi: 0, jumpdest: 0 };
/// Unpack a 10-bit t1 coefficient and scale by 2^d: SHR, AND, SHL, MSTORE, ADD, DUP.
const UNPACK_T1: OpMix = OpMix { verylow: 6, low: 0, mid: 0, jumpi: 0, jumpdest: 0 };
/// Unpack an 18-bit z coefficient, centre it (γ1 − v) and check ‖z‖∞ < γ1 − β:
/// SHR, AND, SUB, 2 compares, OR, MSTORE, ADD, DUP, JUMPI (reject).
const UNPACK_Z: OpMix = OpMix { verylow: 9, low: 0, mid: 0, jumpi: 1, jumpdest: 0 };
/// UseHint on one coefficient of w'approx: Decompose (MOD, SUB, DIV, compares),
/// read hint bit, conditional ±1 mod 44, pack into 6 bits (SHL, OR).
const USE_HINT: OpMix = OpMix { verylow: 12, low: 3, mid: 0, jumpi: 1, jumpdest: 0 };
/// SampleInBall: per squeezed byte, compare against i and loop; per accepted
/// position, swap two coefficients and set ±1 from the sign bits.
const SAMPLE_BYTE: OpMix = OpMix { verylow: 5, low: 0, mid: 0, jumpi: 1, jumpdest: 1 };
const SAMPLE_SET: OpMix = OpMix { verylow: 10, low: 0, mid: 0, jumpi: 0, jumpdest: 0 };
/// ExpandA rejection sampling per 3-byte candidate: 3 byte extracts, mask, compare, store.
const REJ_CANDIDATE: OpMix = OpMix { verylow: 10, low: 0, mid: 0, jumpi: 1, jumpdest: 1 };

#[derive(Debug, Error)]
pub enum NativeGasError {
    #[error("public key must be {PK_LEN} bytes, got {0}")]
    PublicKeyLength(usize),
    #[error("signature must be {SIG_LEN} bytes, got {0}")]
    SignatureLength(usize),
    #[error("malformed hint encoding")]
    MalformedHint,
}

/// Metered cost of verifying one ML-DSA-44 signature inside the EVM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeGasBreakdown {
    pub intrinsic: u64,
    pub calldata: u64,
    pub calldata_bytes: u64,
    pub keccak_permutations: u64,
    pub keccak_gas: u64,
    pub ntt_butterflies: u64,
    pub ntt_gas: u64,
    pub pointwise_mults: u64,
    pub pointwise_gas: u64,
    /// Unpacking t1, z, norm checks, rejection sampling and SampleInBall bookkeeping.
    pub unpack_sample_gas: u64,
    pub hint_ones: u64,
    pub hint_gas: u64,
    pub memory_words: u64,
    pub memory_gas: u64,
    pub total: u64,
}

/// Number of Keccak-f permutations to absorb `input_len` bytes and squeeze `output_len`.
fn sponge_permutations(input_len: usize, rate: usize, output_len: usize) -> u64 {
    let absorb = input_len / rate + 1;
    let extra_squeeze = output_len.saturating_sub(1) / rate;
    (absorb + extra_squeeze) as u64
}

/// ExpandA for one matrix entry: returns (squeezed blocks, 3-byte candidates examined).
fn rej_ntt_poly(rho: &[u8], i: u8, j: u8) -> (u64, u64) {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[j, i]);
    let mut reader = xof.finalize_xof();
    let mut block = [0u8; SHAKE128_RATE];
    let (mut blocks, mut candidates, mut accepted) = (0u64, 0u64, 0usize);
    while accepted < N {
        reader.read(&mut block);
        blocks += 1;
        for t in block.chunks_exact(3) {
            if accepted == N {
                break;
            }
            candidates += 1;
            let v = t[0] as u32 | (t[1] as u32) << 8 | ((t[2] & 0x7f) as u32) << 16;
            if v < Q {
                accepted += 1;
            }
        }
    }
    (blocks, candidates)
}

/// SampleInBall(c̃): returns (squeezed blocks, bytes consumed).
fn sample_in_ball(c_tilde: &[u8]) -> (u64, u64) {
    let mut xof = Shake256::default();
    xof.update(c_tilde);
    let mut reader = xof.finalize_xof();
    let mut byte = [0u8; 1];
    let mut consumed = 8u64; // sign bits
    let mut skip = [0u8; 8];
    reader.read(&mut skip);
    for i in (N - TAU)..N {
        loop {
            reader.read(&mut byte);
            consumed += 1;
            if byte[0] as usize <= i {
                break;
            }
        }
    }
    (consumed.div_ceil(SHAKE256_RATE as u64), consumed)
}

/// Hint weight from the signature's hint encoding (FIPS 204 HintBitUnpack).
fn hint_weight(h: &[u8]) -> Result<u64, NativeGasError> {
    let mut prev = 0usize;
    for i in 0..K {
        let end = h[OMEGA + i] as usize;
        if end < prev || end > OMEGA {
            return Err(NativeGasError::MalformedHint);
        }
        prev = end;
    }
    Ok(prev as u64)
}

/// Meter the EVM gas of verifying `sig` over `msg` with `pk`.
pub fn estimate_native_gas(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<NativeGasBreakdown, NativeGasError> {
    if pk.len() != PK_LEN {
        return Err(NativeGasError::PublicKeyLength(pk.len()));
    }
    if sig.len() != SIG_LEN {
        return Err(NativeGasError::SignatureLength(sig.len()));
    }
    let rho = &pk[..32];
    let c_tilde = &sig[..32];
    let hint = &sig[32 + L * 576..];
    let hint_ones = hint_weight(hint)?;

    // --- Hashing: every SHAKE call verification performs, on the real inputs.
    let mut perms = 0u64;
    let mut absorbed_blocks = 0u64;
    let mut rej_candidates = 0u64;
    for i in 0..K as u8 {
        for j in 0..L as u8 {
            let (blocks, candidates) = rej_ntt_poly(rho, i, j);
            perms += blocks;
            absorbed_blocks += 1;
            rej_candidates += candidates;
        }
    }
    let mu = sponge_permutations(64 + msg.len(), SHAKE256_RATE, 64); // μ = H(tr ‖ M, 64)
    let w1_bytes = K * N * 6 / 8;
    let ctilde = sponge_permutations(64 + w1_bytes, SHAKE256_RATE, 32); // c̃' = H(μ ‖ w1Encode(w'1))
    let (ball_blocks, ball_bytes) = sample_in_ball(c_tilde);
    perms += mu + ctilde + ball_blocks;
    absorbed_blocks += mu + ctilde + 1;

    let keccak_gas = TR_STORAGE_GAS
        + perms * KECCAK_ROUNDS * KECCAK_ROUND.gas()
        + absorbed_blocks * (SHAKE256_RATE as u64 / 8) * ABSORB_LANE.gas();

    // --- NTT domain arithmetic: NTT(z) ×L, NTT(c) ×1, NTT(t1·2^d) ×K, NTT⁻¹ ×K.
    let transforms = (L + 1 + K + K) as u64;
    let ntt_butterflies = transforms * (N as u64 / 2) * 8;
    let ntt_gas = ntt_butterflies * BUTTERFLY.gas() + (K * N) as u64 * INTT_SCALE.gas();

    // Â∘ẑ (K·L polys) and ĉ∘t̂1 (K polys), accumulated pointwise.
    let pointwise_mults = ((K * L + K) * N) as u64;
    let pointwise_gas = pointwise_mults * MUL_ACC.gas();

    let unpack_sample_gas = (K * N) as u64 * UNPACK_T1.gas()
        + (L * N) as u64 * UNPACK_Z.gas()
        + rej_candidates * REJ_CANDIDATE.gas()
        + ball_bytes * SAMPLE_BYTE.gas()
        + TAU as u64 * SAMPLE_SET.gas();

    let hint_gas = (K * N) as u64 * USE_HINT.gas() + hint_ones * OpMix { verylow: 6, low: 0, mid: 0, jumpi: 1, jumpdest: 1 }.gas();

    // --- Memory: ẑ (L), t̂1 (K), ĉ (1), w (K), one row of Â (1) polys of 256 words,
    // plus the 25-lane Keccak state and 136-byte hash buffers.
    let memory_words = ((L + K + 1 + K + 1) * N + 25 + 2 * SHAKE256_RATE / 32 + 1) as u64;
    let memory_gas = G_MEMORY * memory_words + memory_words * memory_words / 512;

    // --- Transaction envelope: selector + pk + sig + message as calldata.
    let mut calldata = Vec::with_capacity(4 + pk.len() + sig.len() + msg.len());
    calldata.extend_from_slice(&[0xff; 4]);
    calldata.extend_from_slice(pk);
    calldata.extend_from_slice(sig);
    calldata.extend_from_slice(msg);
    let calldata_cost = calldata_gas(&calldata);

    let total = TX_BASE_GAS
        + calldata_cost
        + keccak_gas
        + ntt_gas
        + pointwise_gas
        + unpack_sample_gas
        + hint_gas
        + memory_gas;

    Ok(NativeGasBreakdown {
        intrinsic: TX_BASE_GAS,
        calldata: calldata_cost,
        calldata_bytes: calldata.len() as u64,
        keccak_permutations: perms,
        keccak_gas,
        ntt_butterflies,
        ntt_gas,
        pointwise_mults,
        pointwise_gas,
        unpack_sample_gas,
        hint_ones,
        hint_gas,
        memory_words,
        memory_gas,
        total,
    })
}
