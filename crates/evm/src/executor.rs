//! An in-process EVM chain (revm, Cancun rules) holding the Groth16 verifier
//! and the two wallet variants. Reports the gas the EVM actually charges.
//!
//! * [`LocalChain::simulate`] runs a transaction without committing it
//!   (like `eth_estimateGas`), so it can be repeated.
//! * [`LocalChain::send`] commits a successful transaction (like inclusion in
//!   a block), so wallet nonces persist and replays are rejected.

use crate::asm::deploy_code;
use crate::verifier::verifier_runtime;
use crate::wallet::{mapping_slot, wallet_runtime, WalletAuth, NONCE_MAPPING_SLOT, PK_MAPPING_SLOT};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{
    AccountInfo, Address, Bytes, ExecutionResult, Output, ResultAndState, SpecId, TxKind, U256,
};
use revm::{DatabaseCommit, Evm};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Instant;
use thiserror::Error;

/// Base cost of every Ethereum transaction (yellow paper G_transaction).
pub const TX_BASE_GAS: u64 = 21_000;
/// Hard fork whose gas schedule every measurement uses.
pub const EVM_SPEC: SpecId = SpecId::CANCUN;
/// Human-readable name of [`EVM_SPEC`] for reports.
pub const EVM_SPEC_NAME: &str = "Cancun (revm 14.0.3)";
/// Gas limit given to every transaction.
pub const TX_GAS_LIMIT: u64 = 30_000_000;

#[derive(Debug, Error)]
pub enum EvmError {
    #[error("evm execution error: {0}")]
    Execution(String),
    #[error("contract deployment failed: {0}")]
    Deploy(String),
}

/// Gas charged by the EVM for one transaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnchainGas {
    /// Total `gas_used` reported by the EVM for the transaction.
    pub total: u64,
    /// Fixed 21,000 transaction base cost.
    pub intrinsic: u64,
    /// Calldata cost (EIP-2028: 16 gas per non-zero byte, 4 per zero byte).
    pub calldata: u64,
    /// Contract execution: opcodes, storage and precompile calls.
    pub execution: u64,
    /// Whether the call succeeded and returned `true`.
    pub success: bool,
}

/// One executed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TxOutcome {
    pub gas: OnchainGas,
    /// Wall-clock time revm spent executing the transaction.
    pub exec_ms: f64,
    /// Whether the state changes were committed.
    pub committed: bool,
}

/// EIP-2028 calldata cost.
pub fn calldata_gas(data: &[u8]) -> u64 {
    data.iter().map(|b| if *b == 0 { 4 } else { 16 }).sum()
}

/// A deployed contract.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Deployment {
    pub address: [u8; 20],
    pub deploy_gas: u64,
    pub code_size: usize,
}

/// Which wallet a call goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletKind {
    /// Q-EVM: authorised by a Groth16 receipt.
    Groth16,
    /// Ablation: authorised by an ECDSA attestation from the bundler.
    Attestation,
}

pub struct LocalChain {
    db: Mutex<CacheDB<EmptyDB>>,
    caller: Address,
    chain_id: u64,
    verifier: Deployment,
    wallet: Deployment,
    attestation_wallet: Deployment,
}

fn addr(a: &[u8; 20]) -> Address {
    Address::from_slice(a)
}

fn run(
    db: &CacheDB<EmptyDB>,
    caller: Address,
    chain_id: u64,
    to: TxKind,
    data: &[u8],
) -> Result<(ResultAndState, f64), EvmError> {
    let mut evm = Evm::builder()
        .with_ref_db(db)
        .with_spec_id(EVM_SPEC)
        .modify_cfg_env(|cfg| cfg.chain_id = chain_id)
        .modify_tx_env(|tx| {
            tx.caller = caller;
            tx.transact_to = to;
            tx.data = Bytes::copy_from_slice(data);
            tx.gas_limit = TX_GAS_LIMIT;
            tx.gas_price = U256::ZERO;
            tx.nonce = None;
        })
        .build();
    let started = Instant::now();
    let out = evm.transact().map_err(|e| EvmError::Execution(format!("{e:?}")))?;
    Ok((out, started.elapsed().as_secs_f64() * 1000.0))
}

fn deploy(db: &mut CacheDB<EmptyDB>, caller: Address, chain_id: u64, runtime: &[u8]) -> Result<Deployment, EvmError> {
    let (ResultAndState { result, state }, _) = run(db, caller, chain_id, TxKind::Create, &deploy_code(runtime))
        .map_err(|e| EvmError::Deploy(e.to_string()))?;
    match result {
        ExecutionResult::Success { gas_used, output: Output::Create(code, Some(address)), .. } => {
            if code.as_ref() != runtime {
                return Err(EvmError::Deploy("deployed code mismatch".into()));
            }
            db.commit(state);
            Ok(Deployment { address: address.into_array(), deploy_gas: gas_used, code_size: runtime.len() })
        }
        other => Err(EvmError::Deploy(format!("{other:?}"))),
    }
}

impl LocalChain {
    /// Deploys the Groth16 verifier for `vk`, the Q-EVM wallet bound to it and
    /// `program`, and the attestation wallet bound to `bundler`.
    pub fn new(
        vk: &VerifyingKey<Bn254>,
        program: [u8; 32],
        bundler: [u8; 20],
        chain_id: u64,
    ) -> Result<Self, EvmError> {
        let caller = Address::repeat_byte(0x51);
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(caller, AccountInfo { balance: U256::from(10u128.pow(24)), ..Default::default() });

        let verifier = deploy(&mut db, caller, chain_id, &verifier_runtime(vk))?;
        let wallet = deploy(
            &mut db,
            caller,
            chain_id,
            &wallet_runtime(&WalletAuth::Groth16 { verifier: verifier.address, program }),
        )?;
        let attestation_wallet =
            deploy(&mut db, caller, chain_id, &wallet_runtime(&WalletAuth::Attestation { bundler }))?;
        Ok(Self { db: Mutex::new(db), caller, chain_id, verifier, wallet, attestation_wallet })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn verifier(&self) -> Deployment {
        self.verifier
    }

    pub fn wallet(&self, kind: WalletKind) -> Deployment {
        match kind {
            WalletKind::Groth16 => self.wallet,
            WalletKind::Attestation => self.attestation_wallet,
        }
    }

    /// Account registration (the wallet's constructor / `initCode` in a real
    /// deployment): binds `pk_hash` to `sender` and sets its starting nonce in
    /// both wallets. Written directly to state; not part of any measurement.
    pub fn register_account(&self, sender: &[u8; 20], pk_hash: [u8; 32], nonce: u64) {
        let mut db = self.db.lock().expect("chain lock");
        for w in [self.wallet.address, self.attestation_wallet.address] {
            let pk_slot = U256::from_be_bytes(mapping_slot(sender, PK_MAPPING_SLOT));
            let nonce_slot = U256::from_be_bytes(mapping_slot(sender, NONCE_MAPPING_SLOT));
            db.insert_account_storage(addr(&w), pk_slot, U256::from_be_bytes(pk_hash)).expect("in-memory db");
            db.insert_account_storage(addr(&w), nonce_slot, U256::from(nonce)).expect("in-memory db");
        }
    }

    fn storage(&self, contract: [u8; 20], slot: [u8; 32]) -> U256 {
        let db = self.db.lock().expect("chain lock");
        db.accounts
            .get(&addr(&contract))
            .and_then(|acc| acc.storage.get(&U256::from_be_bytes(slot)).copied())
            .unwrap_or(U256::ZERO)
    }

    /// `pk[sender]` in the given wallet, if registered.
    pub fn registered_pk_hash(&self, kind: WalletKind, sender: &[u8; 20]) -> Option<[u8; 32]> {
        let v = self.storage(self.wallet(kind).address, mapping_slot(sender, PK_MAPPING_SLOT));
        (v != U256::ZERO).then(|| v.to_be_bytes())
    }

    /// `nonce[sender]` in the given wallet.
    pub fn nonce(&self, kind: WalletKind, sender: &[u8; 20]) -> u64 {
        let v = self.storage(self.wallet(kind).address, mapping_slot(sender, NONCE_MAPPING_SLOT));
        v.try_into().unwrap_or(u64::MAX)
    }

    fn execute(&self, to: [u8; 20], data: &[u8], commit: bool) -> Result<TxOutcome, EvmError> {
        let mut db = self.db.lock().expect("chain lock");
        let (ResultAndState { result, state }, exec_ms) =
            run(&db, self.caller, self.chain_id, TxKind::Call(addr(&to)), data)?;
        let (total, success) = match result {
            ExecutionResult::Success { gas_used, output, .. } => {
                let out = output.into_data();
                let ok = out.len() == 32 && out[31] == 1 && out[..31].iter().all(|b| *b == 0);
                (gas_used, ok)
            }
            ExecutionResult::Revert { gas_used, .. } => (gas_used, false),
            ExecutionResult::Halt { gas_used, .. } => (gas_used, false),
        };
        let committed = commit && success;
        if committed {
            db.commit(state);
        }
        let calldata = calldata_gas(data);
        Ok(TxOutcome {
            gas: OnchainGas {
                total,
                intrinsic: TX_BASE_GAS,
                calldata,
                execution: total.saturating_sub(TX_BASE_GAS + calldata),
                success,
            },
            exec_ms,
            committed,
        })
    }

    /// Run a transaction to `to` without changing state.
    pub fn simulate(&self, to: [u8; 20], data: &[u8]) -> Result<TxOutcome, EvmError> {
        self.execute(to, data, false)
    }

    /// Run a transaction to `to`, committing its state if it succeeds.
    pub fn send(&self, to: [u8; 20], data: &[u8]) -> Result<TxOutcome, EvmError> {
        self.execute(to, data, true)
    }

    /// Call the Groth16 verifier directly (416-byte calldata), without state changes.
    pub fn measure_verify(&self, calldata: &[u8]) -> Result<OnchainGas, EvmError> {
        Ok(self.simulate(self.verifier.address, calldata)?.gas)
    }

    /// Deploy arbitrary runtime code (used for the native ML-DSA baseline).
    pub fn deploy_runtime(&self, runtime: &[u8]) -> Result<Deployment, EvmError> {
        let mut db = self.db.lock().expect("chain lock");
        deploy(&mut db, self.caller, self.chain_id, runtime)
    }

    /// Deploy from init code (e.g. `solc --bin` output); returns the address and gas.
    pub fn deploy_init_code(&self, init: &[u8]) -> Result<Deployment, EvmError> {
        let mut db = self.db.lock().expect("chain lock");
        let (ResultAndState { result, state }, _) = run(&db, self.caller, self.chain_id, TxKind::Create, init)?;
        match result {
            ExecutionResult::Success { gas_used, output: Output::Create(code, Some(address)), .. } => {
                db.commit(state);
                Ok(Deployment { address: address.into_array(), deploy_gas: gas_used, code_size: code.len() })
            }
            other => Err(EvmError::Deploy(format!("{other:?}"))),
        }
    }

    /// Raw transaction returning output bytes, gas and success, committing on success.
    pub fn send_raw(&self, to: [u8; 20], data: &[u8]) -> Result<(Vec<u8>, u64, bool), EvmError> {
        let mut db = self.db.lock().expect("chain lock");
        let (ResultAndState { result, state }, _) = run(&db, self.caller, self.chain_id, TxKind::Call(addr(&to)), data)?;
        Ok(match result {
            ExecutionResult::Success { gas_used, output, .. } => {
                db.commit(state);
                (output.into_data().to_vec(), gas_used, true)
            }
            ExecutionResult::Revert { gas_used, output } => (output.to_vec(), gas_used, false),
            ExecutionResult::Halt { gas_used, .. } => (Vec::new(), gas_used, false),
        })
    }

    /// Raw call returning the output bytes and gas (no commit); for baselines.
    pub fn call_raw(&self, to: [u8; 20], data: &[u8]) -> Result<(Vec<u8>, u64, bool), EvmError> {
        let db = self.db.lock().expect("chain lock");
        let (ResultAndState { result, .. }, _) = run(&db, self.caller, self.chain_id, TxKind::Call(addr(&to)), data)?;
        Ok(match result {
            ExecutionResult::Success { gas_used, output, .. } => (output.into_data().to_vec(), gas_used, true),
            ExecutionResult::Revert { gas_used, output } => (output.to_vec(), gas_used, false),
            ExecutionResult::Halt { gas_used, .. } => (Vec::new(), gas_used, false),
        })
    }
}
