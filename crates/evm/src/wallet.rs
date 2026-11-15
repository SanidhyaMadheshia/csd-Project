//! Q-EVM wallet / EntryPoint contract, emitted as EVM bytecode.
//!
//! This is the on-chain half of the protocol. For a batch of N user
//! operations it:
//!
//! 1. checks `calldatasize == AUTH + 32 + 128·N` (no trailing or missing bytes);
//! 2. for every op record `(sender, nonce, callDataHash, pkHash)`:
//!    * `pk[sender] != 0 && pk[sender] == pkHash` (key bound to the account),
//!    * `nonce[sender] == nonce`, then `nonce[sender] += 1` (replay protection),
//!    * recomputes `opHash = keccak256(TAG ‖ chainid ‖ address(this) ‖ sender
//!      ‖ nonce ‖ callDataHash ‖ pkHash)` (domain separation);
//! 3. computes `digest = keccak256(opHash₁ ‖ … ‖ opHash_N)` itself, so the
//!    batch statement is derived from the ops it actually executes;
//! 4. authorises the digest — either with the Groth16 verifier (Q-EVM) or,
//!    for the ablation, with an ECDSA attestation from a fixed bundler key;
//! 5. reverts on any failure, rolling back every nonce update in the batch.
//!
//! Storage layout follows Solidity's mapping layout:
//! `pk[sender]` at `keccak256(pad32(sender) ‖ 0)`,
//! `nonce[sender]` at `keccak256(pad32(sender) ‖ 1)`.
//!
//! Calldata layout: `auth(AUTH bytes) ‖ N(32) ‖ N × (sender, nonce, callDataHash, pkHash)`,
//! where `auth` is the 256-byte Groth16 proof (A ‖ B ‖ C) or `r ‖ s ‖ v` (96 bytes).
//!
//! Executing the op's `call_data` is out of scope: it costs the same in every
//! configuration compared in the paper, so it is left out of all of them.

use crate::asm::{op, Asm, FAIL};
use crate::groth16::EVM_CALLDATA_LEN;
use sha3::{Digest, Keccak256};

/// Bytes of the Groth16 proof prefix (A ‖ B ‖ C, no public inputs).
pub const GROTH16_AUTH_LEN: usize = 256;
/// Bytes of an ECDSA attestation prefix (r ‖ s ‖ v, 32 bytes each).
pub const ATTESTATION_AUTH_LEN: usize = 96;
/// Bytes per op record in wallet calldata.
pub const OP_RECORD_LEN: usize = 128;
/// Largest batch the wallet accepts (bounds the memory it touches).
pub const MAX_BATCH: usize = 4096;

/// Storage slot index of the `pk` mapping.
pub const PK_MAPPING_SLOT: u8 = 0;
/// Storage slot index of the `nonce` mapping.
pub const NONCE_MAPPING_SLOT: u8 = 1;

// Memory map of the wallet runtime.
const M_KEY: u16 = 0x00; // mapping key scratch: 0x00 key, 0x20 slot index
const M_PRE: u16 = 0x40; // opHash preimage, 7 words: 0x40..0x120
const M_PTR: u16 = 0x120; // calldata cursor
const M_END: u16 = 0x140; // calldata end
const M_OUT: u16 = 0x160; // write cursor into the opHash buffer
const M_VERIFIER_IN: u16 = 0x200; // 416-byte verifier input
const M_HASHES: u16 = 0x400; // opHash buffer

const PRECOMPILE_ECRECOVER: u16 = 0x01;

pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Domain tag prefixed to every op hash.
pub fn user_op_tag() -> [u8; 32] {
    keccak(b"QEVM_USEROP_V1")
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// The canonical op hash, exactly as the wallet recomputes it on-chain.
pub fn user_op_hash(
    chain_id: u64,
    wallet: &[u8; 20],
    sender: &[u8; 20],
    nonce: u64,
    call_data_hash: &[u8; 32],
    pk_hash: &[u8; 32],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(7 * 32);
    pre.extend_from_slice(&user_op_tag());
    pre.extend_from_slice(&word_u64(chain_id));
    pre.extend_from_slice(&word_addr(wallet));
    pre.extend_from_slice(&word_addr(sender));
    pre.extend_from_slice(&word_u64(nonce));
    pre.extend_from_slice(call_data_hash);
    pre.extend_from_slice(pk_hash);
    keccak(&pre)
}

/// Batch statement: `keccak256(opHash₁ ‖ … ‖ opHash_N)` (fixed 32-byte items).
pub fn batch_digest(op_hashes: &[[u8; 32]]) -> [u8; 32] {
    keccak(&op_hashes.concat())
}

/// Storage slot of `mapping[key]` declared at `slot`.
pub fn mapping_slot(key: &[u8; 20], slot: u8) -> [u8; 32] {
    let mut pre = [0u8; 64];
    pre[12..32].copy_from_slice(key);
    pre[63] = slot;
    keccak(&pre)
}

/// One op as the wallet receives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletOp {
    pub sender: [u8; 20],
    pub nonce: u64,
    pub call_data_hash: [u8; 32],
    pub pk_hash: [u8; 32],
}

impl WalletOp {
    pub fn op_hash(&self, chain_id: u64, wallet: &[u8; 20]) -> [u8; 32] {
        user_op_hash(chain_id, wallet, &self.sender, self.nonce, &self.call_data_hash, &self.pk_hash)
    }
}

/// How the wallet authorises a batch digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletAuth {
    /// Q-EVM: Groth16 receipt over (digest, program, is_valid = 1).
    Groth16 { verifier: [u8; 20], program: [u8; 32] },
    /// Ablation: an ECDSA (secp256k1) signature over the digest by a fixed
    /// bundler key, checked with `ecrecover`. Fully trusts the bundler.
    Attestation { bundler: [u8; 20] },
}

impl WalletAuth {
    pub fn auth_len(&self) -> usize {
        match self {
            WalletAuth::Groth16 { .. } => GROTH16_AUTH_LEN,
            WalletAuth::Attestation { .. } => ATTESTATION_AUTH_LEN,
        }
    }
}

/// Wallet calldata: `auth ‖ N ‖ records`.
pub fn wallet_calldata(auth: &[u8], ops: &[WalletOp]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth.len() + 32 + ops.len() * OP_RECORD_LEN);
    out.extend_from_slice(auth);
    out.extend_from_slice(&word_u64(ops.len() as u64));
    for o in ops {
        out.extend_from_slice(&word_addr(&o.sender));
        out.extend_from_slice(&word_u64(o.nonce));
        out.extend_from_slice(&o.call_data_hash);
        out.extend_from_slice(&o.pk_hash);
    }
    out
}

fn split_limbs(word: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&word[..16]);
    lo[16..].copy_from_slice(&word[16..]);
    (hi, lo)
}

/// Runtime bytecode of the wallet.
pub fn wallet_runtime(auth: &WalletAuth) -> Vec<u8> {
    let auth_len = auth.auth_len() as u16;
    let header = auth_len + 32;
    let mut a = Asm::new();

    // --- 1. N in [1, MAX_BATCH], calldatasize == header + 128·N
    a.cdload_at(auth_len); // [N]
    a.op(op::DUP1).op(op::ISZERO).op(op::ISZERO).require(); // N != 0
    a.push_u16(MAX_BATCH as u16 + 1).op(op::DUP2).op(op::LT).require(); // N < MAX+1
    a.push_u16(OP_RECORD_LEN as u16).op(op::MUL).push_u16(header).op(op::ADD); // [end]
    a.op(op::DUP1).mstore_top(M_END); // [end]
    a.op(op::CALLDATASIZE).op(op::EQ).require(); // []

    // Constant part of the opHash preimage.
    a.mstore_const(M_PRE, &user_op_tag());
    a.op(op::CHAINID).mstore_top(M_PRE + 0x20);
    a.op(op::ADDRESS).mstore_top(M_PRE + 0x40);
    a.push_u16(header).mstore_top(M_PTR);
    a.push_u16(M_HASHES).mstore_top(M_OUT);

    // --- 2. per-op loop
    a.label("loop");
    a.mload_at(M_PTR).mload_at(M_END).op(op::EQ).jumpi("done");

    // sender: must be a 20-byte address
    a.mload_at(M_PTR).op(op::CALLDATALOAD); // [sender]
    a.op(op::DUP1).push_u16(160).op(op::SHR).op(op::ISZERO).require(); // [sender]
    a.op(op::DUP1).mstore_top(M_KEY); // [sender]
    a.mstore_top(M_PRE + 0x60); // []

    // pk[sender] != 0 && pk[sender] == pkHash
    a.push_u16(PK_MAPPING_SLOT as u16).mstore_top(M_KEY + 0x20);
    a.push_u16(64).push_u16(M_KEY).op(op::KECCAK256).op(op::SLOAD); // [stored]
    a.op(op::DUP1).op(op::ISZERO).op(op::ISZERO).require(); // [stored]
    a.mload_at(M_PTR).push_u16(96).op(op::ADD).op(op::CALLDATALOAD); // [stored, pkh]
    a.op(op::DUP1).mstore_top(M_PRE + 0xc0); // [stored, pkh]
    a.op(op::EQ).require(); // []

    // nonce[sender] == nonce; nonce[sender] += 1
    a.push_u16(NONCE_MAPPING_SLOT as u16).mstore_top(M_KEY + 0x20);
    a.push_u16(64).push_u16(M_KEY).op(op::KECCAK256); // [nslot]
    a.op(op::DUP1).op(op::SLOAD); // [nslot, cur]
    a.op(op::DUP1).mload_at(M_PTR).push_u16(32).op(op::ADD).op(op::CALLDATALOAD); // [nslot, cur, cur, nonce]
    a.op(op::DUP1).mstore_top(M_PRE + 0x80); // [nslot, cur, cur, nonce]
    a.op(op::EQ).require(); // [nslot, cur]
    a.push_u16(1).op(op::ADD).op(op::SWAP1).op(op::SSTORE); // []

    // callDataHash
    a.mload_at(M_PTR).push_u16(64).op(op::ADD).op(op::CALLDATALOAD).mstore_top(M_PRE + 0xa0);

    // opHash -> buffer
    a.push_u16(7 * 32).push_u16(M_PRE).op(op::KECCAK256); // [h]
    a.mload_at(M_OUT).op(op::MSTORE); // []
    a.mload_at(M_OUT).push_u16(32).op(op::ADD).mstore_top(M_OUT);
    a.mload_at(M_PTR).push_u16(OP_RECORD_LEN as u16).op(op::ADD).mstore_top(M_PTR);
    a.jump("loop");

    // --- 3. digest = keccak(buffer)
    a.label("done");
    a.push_u16(M_HASHES).mload_at(M_OUT).op(op::SUB); // [len]
    a.push_u16(M_HASHES).op(op::KECCAK256); // [digest]

    // --- 4. authorise the digest
    match auth {
        WalletAuth::Groth16 { verifier, program } => {
            a.push_u16(GROTH16_AUTH_LEN as u16).push_u16(0).push_u16(M_VERIFIER_IN).op(op::CALLDATACOPY);
            let base = M_VERIFIER_IN + GROTH16_AUTH_LEN as u16;
            a.op(op::DUP1).push_u16(128).op(op::SHR).mstore_top(base); // digest_hi
            let mut mask = [0u8; 32];
            mask[16..].fill(0xff);
            a.push32(&mask).op(op::AND).mstore_top(base + 0x20); // digest_lo
            let (p_hi, p_lo) = split_limbs(program);
            a.mstore_const(base + 0x40, &p_hi);
            a.mstore_const(base + 0x60, &p_lo);
            a.mstore_const(base + 0x80, &word_u64(1));
            a.push_u16(32).push_u16(0).push_u16(EVM_CALLDATA_LEN as u16).push_u16(M_VERIFIER_IN);
            a.push20(verifier).op(op::GAS).op(op::STATICCALL).require();
            a.mload_at(0).push_u16(1).op(op::EQ).require();
        }
        WalletAuth::Attestation { bundler } => {
            a.mstore_top(M_VERIFIER_IN); // hash
            a.cdload_at(64).mstore_top(M_VERIFIER_IN + 0x20); // v
            a.cdload_at(0).mstore_top(M_VERIFIER_IN + 0x40); // r
            a.cdload_at(32).mstore_top(M_VERIFIER_IN + 0x60); // s
            a.push_u16(0).mstore_top(0);
            a.staticcall(PRECOMPILE_ECRECOVER, M_VERIFIER_IN, 128, 0, 32);
            a.mload_at(0).push20(bundler).op(op::EQ).require();
        }
    }

    // --- success: return abi.encode(true)
    a.push_u16(1).mstore_top(0).push_u16(32).push_u16(0).op(op::RETURN);

    // --- 5. any failed check reverts the whole batch
    a.label(FAIL).push_u16(0).push_u16(0).op(op::REVERT);
    a.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_hash_is_domain_separated() {
        let base = user_op_hash(1, &[1; 20], &[2; 20], 3, &[4; 32], &[5; 32]);
        assert_ne!(base, user_op_hash(2, &[1; 20], &[2; 20], 3, &[4; 32], &[5; 32]));
        assert_ne!(base, user_op_hash(1, &[9; 20], &[2; 20], 3, &[4; 32], &[5; 32]));
        assert_ne!(base, user_op_hash(1, &[1; 20], &[2; 20], 4, &[4; 32], &[5; 32]));
    }

    #[test]
    fn calldata_layout() {
        let ops = [WalletOp { sender: [7; 20], nonce: 9, call_data_hash: [1; 32], pk_hash: [2; 32] }; 3];
        let cd = wallet_calldata(&[0u8; GROTH16_AUTH_LEN], &ops);
        assert_eq!(cd.len(), GROTH16_AUTH_LEN + 32 + 3 * OP_RECORD_LEN);
        assert_eq!(cd[GROTH16_AUTH_LEN + 31], 3);
    }
}
