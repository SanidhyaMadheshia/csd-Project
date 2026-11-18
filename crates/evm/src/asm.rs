//! Minimal EVM assembler used to emit the verifier and wallet contracts as
//! raw bytecode (no `solc` needed). Supports named labels with forward and
//! backward jumps; every jump target is a 2-byte `PUSH2` immediate.

use std::collections::HashMap;

#[allow(dead_code)]
pub(crate) mod op {
    pub const STOP: u8 = 0x00;
    pub const ADD: u8 = 0x01;
    pub const MUL: u8 = 0x02;
    pub const SUB: u8 = 0x03;
    pub const MOD: u8 = 0x06;
    pub const LT: u8 = 0x10;
    pub const GT: u8 = 0x11;
    pub const EQ: u8 = 0x14;
    pub const ISZERO: u8 = 0x15;
    pub const AND: u8 = 0x16;
    pub const SHR: u8 = 0x1c;
    pub const KECCAK256: u8 = 0x20;
    pub const ADDRESS: u8 = 0x30;
    pub const CALLDATALOAD: u8 = 0x35;
    pub const CALLDATASIZE: u8 = 0x36;
    pub const CALLDATACOPY: u8 = 0x37;
    pub const CODECOPY: u8 = 0x39;
    pub const CHAINID: u8 = 0x46;
    pub const POP: u8 = 0x50;
    pub const MLOAD: u8 = 0x51;
    pub const MSTORE: u8 = 0x52;
    pub const SLOAD: u8 = 0x54;
    pub const SSTORE: u8 = 0x55;
    pub const JUMP: u8 = 0x56;
    pub const JUMPI: u8 = 0x57;
    pub const GAS: u8 = 0x5a;
    pub const JUMPDEST: u8 = 0x5b;
    pub const PUSH1: u8 = 0x60;
    pub const PUSH2: u8 = 0x61;
    pub const PUSH20: u8 = 0x73;
    pub const PUSH32: u8 = 0x7f;
    pub const DUP1: u8 = 0x80;
    pub const DUP2: u8 = 0x81;
    pub const SWAP1: u8 = 0x90;
    pub const RETURN: u8 = 0xf3;
    pub const STATICCALL: u8 = 0xfa;
    pub const REVERT: u8 = 0xfd;
}

/// Label every `require` jumps to on failure.
pub(crate) const FAIL: &str = "fail";

pub(crate) struct Asm {
    code: Vec<u8>,
    labels: HashMap<&'static str, u16>,
    refs: Vec<(usize, &'static str)>,
}

impl Asm {
    pub fn new() -> Self {
        Self { code: Vec::new(), labels: HashMap::new(), refs: Vec::new() }
    }

    pub fn op(&mut self, opcode: u8) -> &mut Self {
        self.code.push(opcode);
        self
    }

    pub fn push_u16(&mut self, v: u16) -> &mut Self {
        if v <= 0xff {
            self.code.extend_from_slice(&[op::PUSH1, v as u8]);
        } else {
            self.code.push(op::PUSH2);
            self.code.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn push32(&mut self, word: &[u8; 32]) -> &mut Self {
        self.code.push(op::PUSH32);
        self.code.extend_from_slice(word);
        self
    }

    pub fn push20(&mut self, addr: &[u8; 20]) -> &mut Self {
        self.code.push(op::PUSH20);
        self.code.extend_from_slice(addr);
        self
    }

    /// `mem[offset] = word`
    pub fn mstore_const(&mut self, offset: u16, word: &[u8; 32]) -> &mut Self {
        self.push32(word).push_u16(offset).op(op::MSTORE)
    }

    /// Store `bytes` (a multiple of 32 bytes) at `mem[offset..]`.
    pub fn mstore_bytes(&mut self, offset: u16, bytes: &[u8]) -> &mut Self {
        for (i, chunk) in bytes.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word.copy_from_slice(chunk);
            self.mstore_const(offset + (i as u16) * 32, &word);
        }
        self
    }

    /// Push `mem[offset]`.
    pub fn mload_at(&mut self, offset: u16) -> &mut Self {
        self.push_u16(offset).op(op::MLOAD)
    }

    /// Pop the top of stack into `mem[offset]`.
    pub fn mstore_top(&mut self, offset: u16) -> &mut Self {
        self.push_u16(offset).op(op::MSTORE)
    }

    /// Push `calldata[offset..offset+32]` for a constant offset.
    pub fn cdload_at(&mut self, offset: u16) -> &mut Self {
        self.push_u16(offset).op(op::CALLDATALOAD)
    }

    fn target(&mut self, name: &'static str) {
        self.code.push(op::PUSH2);
        self.refs.push((self.code.len(), name));
        self.code.extend_from_slice(&[0, 0]);
    }

    /// Define `name` here (emits a JUMPDEST).
    pub fn label(&mut self, name: &'static str) -> &mut Self {
        let at = u16::try_from(self.code.len()).expect("code fits in 64 KiB");
        assert!(self.labels.insert(name, at).is_none(), "duplicate label {name}");
        self.op(op::JUMPDEST)
    }

    pub fn jump(&mut self, name: &'static str) -> &mut Self {
        self.target(name);
        self.op(op::JUMP)
    }

    /// Jump to `name` if the top of stack is non-zero (consumes it).
    pub fn jumpi(&mut self, name: &'static str) -> &mut Self {
        self.target(name);
        self.op(op::JUMPI)
    }

    /// Jump to [`FAIL`] if the top of stack is zero (consumes it).
    pub fn require(&mut self) -> &mut Self {
        self.op(op::ISZERO).jumpi(FAIL)
    }

    /// `STATICCALL(gas, addr, args, args_len, ret, ret_len)` to a precompile; require success.
    pub fn staticcall(&mut self, addr: u16, args: u16, args_len: u16, ret: u16, ret_len: u16) -> &mut Self {
        self.push_u16(ret_len)
            .push_u16(ret)
            .push_u16(args_len)
            .push_u16(args)
            .push_u16(addr)
            .op(op::GAS)
            .op(op::STATICCALL)
            .require()
    }

    pub fn finish(mut self) -> Vec<u8> {
        for (at, name) in &self.refs {
            let dest = *self.labels.get(name).unwrap_or_else(|| panic!("undefined label {name}"));
            self.code[*at..*at + 2].copy_from_slice(&dest.to_be_bytes());
        }
        self.code
    }
}

/// Init code that deploys `runtime` via CREATE.
pub fn deploy_code(runtime: &[u8]) -> Vec<u8> {
    let len = u16::try_from(runtime.len()).expect("runtime fits in 64 KiB");
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
