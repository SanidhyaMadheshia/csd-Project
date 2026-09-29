//! Groth16 verifier contract, emitted directly as EVM bytecode.
//!
//! This is the same algorithm as a snarkjs/RISC Zero `Groth16Verifier.sol`,
//! written straight-line (no solc needed) with the verifying key embedded:
//!
//! 1. require `calldatasize == 416` and every public input `< r`
//! 2. `vk_x = IC0 + Σ inputᵢ · ICᵢ`   (precompiles 0x07 ecMul, 0x06 ecAdd)
//! 3. `e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1`   (precompile 0x08)
//! 4. return a 32-byte boolean
//!
//! Calldata layout: A(64) ‖ B(128) ‖ C(64) ‖ inputs(5 × 32).

use crate::groth16::{g1_bytes, g2_bytes, EVM_CALLDATA_LEN, NUM_PUBLIC_INPUTS};
use ark_bn254::{Bn254, Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;

mod op {
    pub const STOP: u8 = 0x00;
    pub const SUB: u8 = 0x03;
    pub const MOD: u8 = 0x06;
    pub const LT: u8 = 0x10;
    pub const EQ: u8 = 0x14;
    pub const ISZERO: u8 = 0x15;
    pub const CALLDATALOAD: u8 = 0x35;
    pub const CALLDATASIZE: u8 = 0x36;
    pub const CALLDATACOPY: u8 = 0x37;
    pub const CODECOPY: u8 = 0x39;
    pub const MLOAD: u8 = 0x51;
    pub const MSTORE: u8 = 0x52;
    pub const JUMPI: u8 = 0x57;
    pub const GAS: u8 = 0x5a;
    pub const JUMPDEST: u8 = 0x5b;
    pub const PUSH1: u8 = 0x60;
    pub const PUSH2: u8 = 0x61;
    pub const PUSH32: u8 = 0x7f;
    pub const DUP1: u8 = 0x80;
    pub const SWAP1: u8 = 0x90;
    pub const RETURN: u8 = 0xf3;
    pub const STATICCALL: u8 = 0xfa;
}

const PRECOMPILE_ECADD: u16 = 0x06;
const PRECOMPILE_ECMUL: u16 = 0x07;
const PRECOMPILE_PAIRING: u16 = 0x08;

/// Minimal straight-line assembler with forward jumps to one `fail` label.
struct Asm {
    code: Vec<u8>,
    fail_refs: Vec<usize>,
}

impl Asm {
    fn new() -> Self {
        Self { code: Vec::new(), fail_refs: Vec::new() }
    }

    fn op(&mut self, opcode: u8) -> &mut Self {
        self.code.push(opcode);
        self
    }

    fn push_u16(&mut self, v: u16) -> &mut Self {
        if v <= 0xff {
            self.code.extend_from_slice(&[op::PUSH1, v as u8]);
        } else {
            self.code.push(op::PUSH2);
            self.code.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    fn push32(&mut self, word: &[u8; 32]) -> &mut Self {
        self.code.push(op::PUSH32);
        self.code.extend_from_slice(word);
        self
    }

    fn mstore_const(&mut self, offset: u16, word: &[u8; 32]) -> &mut Self {
        self.push32(word).push_u16(offset).op(op::MSTORE)
    }

    fn mstore_bytes(&mut self, offset: u16, bytes: &[u8]) -> &mut Self {
        for (i, chunk) in bytes.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word.copy_from_slice(chunk);
            self.mstore_const(offset + (i as u16) * 32, &word);
        }
        self
    }

    /// Jump to `fail` if the top of stack is zero.
    fn require(&mut self) -> &mut Self {
        self.op(op::ISZERO);
        self.code.push(op::PUSH2);
        self.fail_refs.push(self.code.len());
        self.code.extend_from_slice(&[0, 0]);
        self.op(op::JUMPI)
    }

    fn staticcall(&mut self, addr: u16, args: u16, args_len: u16, ret: u16, ret_len: u16) -> &mut Self {
        self.push_u16(ret_len)
            .push_u16(ret)
            .push_u16(args_len)
            .push_u16(args)
            .push_u16(addr)
            .op(op::GAS)
            .op(op::STATICCALL)
            .require()
    }

    fn finish(mut self) -> Vec<u8> {
        let fail = self.code.len() as u16;
        // fail: return abi.encode(false)
        self.op(op::JUMPDEST)
            .push_u16(0)
            .push_u16(0)
            .op(op::MSTORE)
            .push_u16(32)
            .push_u16(0)
            .op(op::RETURN)
            .op(op::STOP);
        for at in &self.fail_refs {
            self.code[*at..*at + 2].copy_from_slice(&fail.to_be_bytes());
        }
        self.code
    }
}

fn modulus_bytes<F: PrimeField>() -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&F::MODULUS.to_bytes_be());
    out
}

/// Runtime bytecode of the verifier for `vk`.
pub fn verifier_runtime(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    assert_eq!(vk.gamma_abc_g1.len(), NUM_PUBLIC_INPUTS + 1);
    let p = modulus_bytes::<Fq>();
    let r = modulus_bytes::<Fr>();
    let mut a = Asm::new();

    // 1. calldatasize == 416
    a.op(op::CALLDATASIZE).push_u16(EVM_CALLDATA_LEN as u16).op(op::EQ).require();

    // 1b. each public input < r
    for i in 0..NUM_PUBLIC_INPUTS {
        a.push32(&r)
            .push_u16(256 + (i as u16) * 32)
            .op(op::CALLDATALOAD)
            .op(op::LT)
            .require();
    }

    // 2. vk_x accumulator at mem[0x00..0x40] = IC0
    a.mstore_bytes(0x00, &g1_bytes(&vk.gamma_abc_g1[0]));
    for i in 0..NUM_PUBLIC_INPUTS {
        // ecMul(IC_{i+1}, input_i) : input at 0x80..0xe0, output at 0x40..0x80
        a.mstore_bytes(0x80, &g1_bytes(&vk.gamma_abc_g1[i + 1]));
        a.push_u16(256 + (i as u16) * 32).op(op::CALLDATALOAD).push_u16(0xc0).op(op::MSTORE);
        a.staticcall(PRECOMPILE_ECMUL, 0x80, 0x60, 0x40, 0x40);
        // ecAdd(acc, product) : input 0x00..0x80, output back to 0x00..0x40
        a.staticcall(PRECOMPILE_ECADD, 0x00, 0x80, 0x00, 0x40);
    }

    // 3. pairing input at 0x100..0x400 (4 pairs × 192 bytes)
    // pair 1: (-A, B)
    a.push_u16(0).op(op::CALLDATALOAD).push_u16(0x100).op(op::MSTORE);
    a.push_u16(32)
        .op(op::CALLDATALOAD)
        .push32(&p)
        .op(op::SUB) // p - A.y
        .push32(&p)
        .op(op::SWAP1)
        .op(op::MOD) // (p - A.y) mod p   (so -0 == 0)
        .push_u16(0x120)
        .op(op::MSTORE);
    a.push_u16(128).push_u16(64).push_u16(0x140).op(op::CALLDATACOPY);
    // pair 2: (alpha, beta)
    a.mstore_bytes(0x1c0, &g1_bytes(&vk.alpha_g1));
    a.mstore_bytes(0x200, &g2_bytes(&vk.beta_g2));
    // pair 3: (vk_x, gamma)
    a.push_u16(0x00).op(op::MLOAD).push_u16(0x280).op(op::MSTORE);
    a.push_u16(0x20).op(op::MLOAD).push_u16(0x2a0).op(op::MSTORE);
    a.mstore_bytes(0x2c0, &g2_bytes(&vk.gamma_g2));
    // pair 4: (C, delta)
    a.push_u16(64).push_u16(192).push_u16(0x340).op(op::CALLDATACOPY);
    a.mstore_bytes(0x380, &g2_bytes(&vk.delta_g2));

    a.staticcall(PRECOMPILE_PAIRING, 0x100, 0x300, 0x00, 0x20);

    // 4. return mem[0x00..0x20] (pairing result: 1 = valid)
    a.push_u16(32).push_u16(0).op(op::RETURN);
    a.finish()
}

/// Init code that deploys `runtime` via CREATE.
pub fn deploy_code(runtime: &[u8]) -> Vec<u8> {
    let len = runtime.len() as u16;
    // PUSH2 len, DUP1, PUSH2 offset, PUSH1 0, CODECOPY, PUSH1 0, RETURN
    let header_len: u16 = 3 + 1 + 3 + 2 + 1 + 2 + 1;
    let mut code = vec![op::PUSH2];
    code.extend_from_slice(&len.to_be_bytes());
    code.push(op::DUP1);
    code.push(op::PUSH2);
    code.extend_from_slice(&header_len.to_be_bytes());
    code.extend_from_slice(&[op::PUSH1, 0, op::CODECOPY, op::PUSH1, 0, op::RETURN]);
    debug_assert_eq!(code.len(), header_len as usize);
    code.extend_from_slice(runtime);
    code
}
