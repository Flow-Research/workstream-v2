//! Transaction types and validation for FlowStream
//! 
//! Implements the 19 transaction types from the design:
//! actor.*, project.*, policy.*, task.*, bundle.*, submission.*,
//! check.*, route.*, review.*, revision.*, accept.*, award.*, etc.

use flowstream_core::{types::*, Result, Error};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxValidator;

impl TxValidator {
    pub fn new() -> Self {
        TxValidator
    }
    
    pub fn validate(&self, tx: &Transaction) -> Result<()> {
        // Basic validation
        if tx.actions.is_empty() {
            return Err(Error::Transaction("Empty transaction".to_string()));
        }
        if tx.fee.max_fee == 0 {
            return Err(Error::Transaction("Zero fee".to_string()));
        }
        Ok(())
    }
}

impl Default for TxValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction builder for convenience
#[derive(Default)]
pub struct TxBuilder {
    chain_id: u64,
    account: Option<AccountId>,
    nonce: Option<Nonce>,
    actions: Vec<Action>,
    fee: Option<FeeSpec>,
    auth: Vec<u8>,
}

impl TxBuilder {
    pub fn new() -> Self {
        Self {
            chain_id: 1,
            ..Default::default()
        }
    }
    
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }
    
    pub fn account(mut self, account: AccountId) -> Self {
        self.account = Some(account);
        self
    }
    
    pub fn nonce(mut self, key_id: u16, seq: u64) -> Self {
        self.nonce = Some(Nonce { key_id, seq });
        self
    }
    
    pub fn add_action(mut self, action_type: ActionType, payload: Vec<u8>) -> Self {
        self.actions.push(Action { action_type, payload });
        self
    }
    
    pub fn fee(mut self, fee: FeeSpec) -> Self {
        self.fee = Some(fee);
        self
    }
    
    pub fn auth(mut self, auth: Vec<u8>) -> Self {
        self.auth = auth;
        self
    }
    
    pub fn build(self) -> Result<Transaction> {
        Ok(Transaction {
            chain_id: self.chain_id,
            account: self.account.ok_or_else(|| Error::Transaction("Account required".to_string()))?,
            nonce: self.nonce.ok_or_else(|| Error::Transaction("Nonce required".to_string()))?,
            actions: self.actions,
            fee: self.fee.ok_or_else(|| Error::Transaction("Fee required".to_string()))?,
            auth: self.auth,
            signature: None,
        })
    }
}
