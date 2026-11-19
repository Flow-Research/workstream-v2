//! Account abstraction validator module system (issue #87).
//!
//! Single account primitive with modular validators:
//! - **Human**: passkey + device keys + recovery (`HumanValidator`).
//! - **Agent**: delegated with scope/expiry or self-sovereign (`AgentValidator`).
//! - **Service**: programmatic (`ServiceValidator`).
//!
//! Validators are pluggable modules registered in a [`ValidatorSet`] and
//! dispatched by the validator assigned to an [`Account`].

use crate::hash::H256;
use crate::types::AccountId;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Lifecycle status of an account.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountStatus {
    /// Registered but not yet permitted to validate/act.
    Pending,
    /// Currently permitted to validate and act.
    Active,
    /// Temporarily frozen; must be reactivated before acting.
    Frozen,
}

impl AccountStatus {
    /// Whether the status satisfies a required status.
    pub fn satisfies(&self, required: &AccountStatus) -> bool {
        self == required
    }
}

/// Kind of account: human (person), agent (delegated authority), service (program).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountKind {
    Human,
    Agent,
    Service,
}

/// Authority scope attached to a delegation or service grant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    pub resource: H256,
    pub expires_at: u64,
}

/// Key reference controlling an account (passkey / device / program key hash).
pub type KeyRef = H256;

/// Reference to the validator module instance assigned to an account.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRef {
    pub validator_id: H256,
}

/// Account abstraction: single principal with modular validators.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub kind: AccountKind,
    pub status: AccountStatus,
    pub validator: ValidatorRef,
    pub controllers: Vec<KeyRef>,
    pub delegate_of: Option<AccountId>,
    pub scope: Option<Scope>,
}

/// Context in which an account is validated (required status + clock).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorContext {
    pub required_status: AccountStatus,
    pub now: u64,
}

/// Modular account validator: decides whether an account may act.
pub trait AccountValidator: Send + Sync {
    /// Validate the account for the given context.
    fn validate(&self, account: &Account, ctx: &ValidatorContext) -> Result<()>;
}

/// Validator module for human accounts: passkey + device keys + recovery.
#[derive(Clone, Copy, Debug, Default)]
pub struct HumanValidator;

impl HumanValidator {
    pub fn new() -> Self {
        Self
    }
}

impl AccountValidator for HumanValidator {
    fn validate(&self, account: &Account, ctx: &ValidatorContext) -> Result<()> {
        if account.kind != AccountKind::Human {
            return Err(Error::Validation(
                "human validator requires an account of kind Human".to_string(),
            ));
        }
        if !account.status.satisfies(&ctx.required_status) {
            return Err(Error::Validation(format!(
                "human account status {:?} does not satisfy required {:?}",
                account.status, ctx.required_status
            )));
        }
        if account.controllers.is_empty() {
            return Err(Error::Validation(
                "human account requires at least one controller key".to_string(),
            ));
        }
        Ok(())
    }
}

/// Validator module for agent accounts: delegated with scope/expiry or self-sovereign.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentValidator;

impl AgentValidator {
    pub fn new() -> Self {
        Self
    }
}

impl AccountValidator for AgentValidator {
    fn validate(&self, account: &Account, ctx: &ValidatorContext) -> Result<()> {
        if account.kind != AccountKind::Agent {
            return Err(Error::Validation(
                "agent validator requires an account of kind Agent".to_string(),
            ));
        }
        if !account.status.satisfies(&ctx.required_status) {
            return Err(Error::Validation(format!(
                "agent account status {:?} does not satisfy required {:?}",
                account.status, ctx.required_status
            )));
        }
        match (&account.delegate_of, &account.scope) {
            // Self-sovereign agent: no delegation scope required.
            (None, None) => Ok(()),
            // Delegated agent: a scope must be present and unexpired.
            (Some(_), Some(scope)) => {
                if scope.expires_at <= ctx.now {
                    return Err(Error::Validation(
                        "agent delegation scope expired".to_string(),
                    ));
                }
                Ok(())
            }
            // Delegated agents without a scope (or self-sovereign agents with
            // one) are rejected to keep the delegation model total.
            _ => Err(Error::Validation(
                "delegated agent requires a delegation scope".to_string(),
            )),
        }
    }
}

/// Validator module for service accounts: programmatic.
#[derive(Clone, Copy, Debug, Default)]
pub struct ServiceValidator;

impl ServiceValidator {
    pub fn new() -> Self {
        Self
    }
}

impl AccountValidator for ServiceValidator {
    fn validate(&self, account: &Account, ctx: &ValidatorContext) -> Result<()> {
        if account.kind != AccountKind::Service {
            return Err(Error::Validation(
                "service validator requires an account of kind Service".to_string(),
            ));
        }
        if !account.status.satisfies(&ctx.required_status) {
            return Err(Error::Validation(format!(
                "service account status {:?} does not satisfy required {:?}",
                account.status, ctx.required_status
            )));
        }
        if let Some(scope) = &account.scope {
            if scope.expires_at <= ctx.now {
                return Err(Error::Validation(
                    "service account scope expired".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Validator module registry: registers named validator modules and dispatches
/// validation to the module assigned to an account.
#[derive(Default)]
pub struct ValidatorSet {
    modules: std::collections::HashMap<H256, std::sync::Arc<dyn AccountValidator>>,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or re-register) a validator module under a deterministic id.
    pub fn register(
        &mut self,
        validator_id: H256,
        validator: std::sync::Arc<dyn AccountValidator>,
    ) {
        self.modules.insert(validator_id, validator);
    }

    /// Validate an account through its assigned validator module.
    pub fn validate(&self, account: &Account, ctx: &ValidatorContext) -> Result<()> {
        let module = self
            .modules
            .get(&account.validator.validator_id)
            .ok_or_else(|| {
                Error::Validation(format!(
                    "no validator module registered for id {:?}",
                    account.validator.validator_id
                ))
            })?;
        module.validate(account, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(required: AccountStatus, now: u64) -> ValidatorContext {
        ValidatorContext {
            required_status: required,
            now,
        }
    }

    fn human_account(status: AccountStatus, controllers: Vec<H256>) -> Account {
        Account {
            id: H256::from_bytes([1u8; 32]),
            kind: AccountKind::Human,
            status,
            validator: ValidatorRef {
                validator_id: H256::from_bytes([9u8; 32]),
            },
            controllers,
            delegate_of: None,
            scope: None,
        }
    }

    #[test]
    fn human_validator_accepts_active_account_with_controllers() {
        let validator = HumanValidator::new();
        let account = human_account(AccountStatus::Active, vec![H256::from_bytes([2u8; 32])]);
        assert!(validator
            .validate(&account, &ctx(AccountStatus::Active, 0))
            .is_ok());
    }

    #[test]
    fn human_validator_rejects_wrong_kind_or_missing_controllers() {
        let validator = HumanValidator::new();
        let agent = Account {
            kind: AccountKind::Agent,
            ..human_account(AccountStatus::Active, Vec::new())
        };
        assert!(validator
            .validate(&agent, &ctx(AccountStatus::Active, 0))
            .is_err());

        let human = human_account(AccountStatus::Pending, vec![H256::from_bytes([2u8; 32])]);
        assert!(validator
            .validate(&human, &ctx(AccountStatus::Active, 0))
            .is_err());
    }

    #[test]
    fn agent_validator_accepts_self_sovereign_and_delegated() {
        let validator = AgentValidator::new();

        let self_sovereign = Account {
            kind: AccountKind::Agent,
            status: AccountStatus::Active,
            delegate_of: None,
            scope: None,
            ..human_account(AccountStatus::Active, Vec::new())
        };
        assert!(validator
            .validate(&self_sovereign, &ctx(AccountStatus::Active, 0))
            .is_ok());

        let delegated = Account {
            kind: AccountKind::Agent,
            status: AccountStatus::Active,
            delegate_of: Some(self_sovereign.id),
            scope: Some(Scope {
                resource: H256::ZERO,
                expires_at: 100,
            }),
            ..human_account(AccountStatus::Active, Vec::new())
        };
        assert!(validator
            .validate(&delegated, &ctx(AccountStatus::Active, 0))
            .is_ok());
        assert!(validator
            .validate(&delegated, &ctx(AccountStatus::Active, 200))
            .is_err());
    }

    #[test]
    fn service_validator_accepts_active_service_with_unexpired_scope() {
        let validator = ServiceValidator::new();
        let service = Account {
            kind: AccountKind::Service,
            status: AccountStatus::Active,
            scope: Some(Scope {
                resource: H256::ZERO,
                expires_at: 50,
            }),
            ..human_account(AccountStatus::Active, Vec::new())
        };
        assert!(validator
            .validate(&service, &ctx(AccountStatus::Active, 10))
            .is_ok());
        assert!(validator
            .validate(&service, &ctx(AccountStatus::Active, 60))
            .is_err());
    }

    #[test]
    fn validator_set_dispatches_by_assigned_module() {
        let mut set = ValidatorSet::new();
        set.register(
            H256::from_bytes([9u8; 32]),
            std::sync::Arc::new(HumanValidator),
        );
        set.register(
            H256::from_bytes([8u8; 32]),
            std::sync::Arc::new(ServiceValidator),
        );

        let mut human = human_account(AccountStatus::Active, vec![H256::ZERO]);
        human.validator = ValidatorRef {
            validator_id: H256::from_bytes([9u8; 32]),
        };
        assert!(set.validate(&human, &ctx(AccountStatus::Active, 0)).is_ok());

        let service = Account {
            kind: AccountKind::Service,
            status: AccountStatus::Active,
            validator: ValidatorRef {
                validator_id: H256::from_bytes([8u8; 32]),
            },
            ..human_account(AccountStatus::Active, Vec::new())
        };
        assert!(set
            .validate(&service, &ctx(AccountStatus::Active, 0))
            .is_ok());

        let unassigned = Account {
            validator: ValidatorRef {
                validator_id: H256::from_bytes([7u8; 32]),
            },
            ..human_account(AccountStatus::Active, Vec::new())
        };
        assert!(set
            .validate(&unassigned, &ctx(AccountStatus::Active, 0))
            .is_err());
    }
}
