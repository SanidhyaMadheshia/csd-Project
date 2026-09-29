//! Executes the Groth16 verifier on a real EVM (revm, Cancun rules) and
//! reports the gas the EVM actually charges.

use crate::verifier::{deploy_code, verifier_runtime};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{
    AccountInfo, Address, Bytecode, Bytes, ExecutionResult, Output, SpecId, TxKind, U256,
};
use revm::Evm;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Base cost of every Ethereum transaction (yellow paper G_transaction).
pub const TX_BASE_GAS: u64 = 21_000;

#[derive(Debug, Error)]
pub enum EvmError {
    #[error("evm execution error: {0}")]
    Execution(String),
    #[error("verifier deployment failed: {0}")]
    Deploy(String),
}

/// Gas charged by the EVM for one `verify(proof, inputs)` transaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnchainGas {
    /// Total `gas_used` reported by the EVM for the transaction.
    pub total: u64,
    /// Fixed 21,000 transaction base cost.
    pub intrinsic: u64,
    /// Calldata cost (EIP-2028: 16 gas per non-zero byte, 4 per zero byte).
    pub calldata: u64,
    /// Contract execution: precompile calls (pairing, ecMul, ecAdd) + opcodes.
    pub execution: u64,
    /// Whether the verifier returned `true`.
    pub success: bool,
}

/// EIP-2028 calldata cost.
pub fn calldata_gas(data: &[u8]) -> u64 {
    data.iter().map(|b| if *b == 0 { 4 } else { 16 }).sum()
}

/// An in-memory chain holding the deployed verifier contract.
pub struct EvmGasMeter {
    db: CacheDB<EmptyDB>,
    caller: Address,
    verifier: Address,
    deploy_gas: u64,
    code_size: usize,
}

impl EvmGasMeter {
    /// Deploys the verifier for `vk` with a real CREATE transaction.
    pub fn new(vk: &VerifyingKey<Bn254>) -> Result<Self, EvmError> {
        let caller = Address::repeat_byte(0x51);
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(
            caller,
            AccountInfo { balance: U256::from(10u128.pow(24)), ..Default::default() },
        );

        let runtime = verifier_runtime(vk);
        let init = deploy_code(&runtime);
        let result = {
            let mut evm = Evm::builder()
                .with_ref_db(&db)
                .with_spec_id(SpecId::CANCUN)
                .modify_tx_env(|tx| {
                    tx.caller = caller;
                    tx.transact_to = TxKind::Create;
                    tx.data = Bytes::from(init.clone());
                    tx.gas_limit = 30_000_000;
                    tx.gas_price = U256::ZERO;
                    tx.nonce = None;
                })
                .build();
            evm.transact().map_err(|e| EvmError::Deploy(format!("{e:?}")))?.result
        };

        let (deploy_gas, deployed) = match result {
            ExecutionResult::Success { gas_used, output: Output::Create(code, _), .. } => (gas_used, code),
            other => return Err(EvmError::Deploy(format!("{other:?}"))),
        };
        if deployed.as_ref() != runtime.as_slice() {
            return Err(EvmError::Deploy("deployed code mismatch".into()));
        }
        let verifier = caller.create(0);
        db.insert_account_info(
            verifier,
            AccountInfo {
                code: Some(Bytecode::new_raw(deployed.clone())),
                code_hash: Bytecode::new_raw(deployed).hash_slow(),
                nonce: 1,
                ..Default::default()
            },
        );

        Ok(Self { db, caller, verifier, deploy_gas, code_size: runtime.len() })
    }

    pub fn verifier_address(&self) -> Address {
        self.verifier
    }

    /// Gas used by the CREATE transaction that deployed the verifier.
    pub fn deploy_gas(&self) -> u64 {
        self.deploy_gas
    }

    pub fn code_size(&self) -> usize {
        self.code_size
    }

    /// Sends `calldata` to the verifier and returns the gas the EVM charged.
    pub fn measure_verify(&self, calldata: &[u8]) -> Result<OnchainGas, EvmError> {
        let mut evm = Evm::builder()
            .with_ref_db(&self.db)
            .with_spec_id(SpecId::CANCUN)
            .modify_tx_env(|tx| {
                tx.caller = self.caller;
                tx.transact_to = TxKind::Call(self.verifier);
                tx.data = Bytes::copy_from_slice(calldata);
                tx.gas_limit = 30_000_000;
                tx.gas_price = U256::ZERO;
                tx.nonce = None;
            })
            .build();
        let result = evm.transact().map_err(|e| EvmError::Execution(format!("{e:?}")))?.result;

        let (total, success) = match result {
            ExecutionResult::Success { gas_used, output, .. } => {
                let out = output.into_data();
                let ok = out.len() == 32 && out[31] == 1 && out[..31].iter().all(|b| *b == 0);
                (gas_used, ok)
            }
            ExecutionResult::Revert { gas_used, .. } => (gas_used, false),
            ExecutionResult::Halt { gas_used, .. } => (gas_used, false),
        };
        let calldata = calldata_gas(calldata);
        Ok(OnchainGas {
            total,
            intrinsic: TX_BASE_GAS,
            calldata,
            execution: total.saturating_sub(TX_BASE_GAS + calldata),
            success,
        })
    }
}
