use crate::bundler::UserOperation;
use crate::crypto::CryptoResult;
use crate::bundler::verify_user_op;
use pqcrypto_dilithium::dilithium2;
use std::collections::HashMap;

#[derive(Default)]
pub struct Bundler {
    mempool: Vec<UserOperation>,
    // Sender -> public key
    pubkeys: HashMap<String, dilithium2::PublicKey>,
}

impl Bundler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_sender(&mut self, sender: impl Into<String>, pk: dilithium2::PublicKey) {
        self.pubkeys.insert(sender.into(), pk);
    }

    pub fn validate_user_op(&self, uo: &UserOperation) -> CryptoResult<bool> {
        let pk = match self.pubkeys.get(&uo.sender) {
            Some(pk) => pk,
            None => return Ok(false),
        };
        verify_user_op(uo, pk)
    }

    pub fn add_user_op(&mut self, uo: UserOperation) -> CryptoResult<bool> {
        if self.validate_user_op(&uo)? {
            log::info!("accepted user_op sender={} nonce={}", uo.sender, uo.nonce);
            self.mempool.push(uo);
            Ok(true)
        } else {
            log::info!("rejected user_op sender={} nonce={}", uo.sender, uo.nonce);
            Ok(false)
        }
    }

    pub fn bundle_operations(&mut self) -> Vec<UserOperation> {
        let bundled = self.mempool.clone();
        self.mempool.clear();
        bundled
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }
}
