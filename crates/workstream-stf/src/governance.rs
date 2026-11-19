//! Governance is opt-in at genesis. A configured chain requires on-chain
//! approval before activating a successor to a governance-enabled fork.
use crate::encode_payload;
use crate::handlers::{GovSetParametersPayload, GovSetSequencerPayload, GovUpgradePayload};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use workstream_core::{
    fork::features, Action, ActionType, Error, Event, ForkSchedule, Hash, Result, Transaction, H256,
};
use workstream_state::State;

const CONFIG: &[u8] = b"WS:v1:gov:config";
const SEQUENCER: &[u8] = b"WS:v1:gov:sequencer";
const PROPOSAL: &[u8] = b"WS:v1:gov:upgrade:";
const PARAM: &[u8] = b"WS:v1:gov:param:";

#[derive(Serialize, Deserialize)]
struct Config {
    authority: H256,
    delay: u64,
}

#[derive(Serialize, Deserialize)]
struct Proposal {
    ready: u64,
    approved: bool,
    fork_hash: H256,
}

fn read<T: DeserializeOwned>(state: &State, key: &[u8]) -> Result<Option<T>> {
    state
        .get(key)?
        .map(|bytes| postcard::from_bytes(&bytes).map_err(|e| Error::State(e.to_string())))
        .transpose()
}

/// Trusted genesis setup, not a transaction. `authority` is SHA-256 of the
/// governor's verifying key; all replicas must start from this state root.
pub fn initialize(state: &mut State, authority: H256, delay_blocks: u64) -> Result<()> {
    if state.last_header.is_some()
        || state.get(CONFIG)?.is_some()
        || authority == H256::ZERO
        || delay_blocks == 0
    {
        return Err(Error::Config(
            "invalid governance genesis configuration".into(),
        ));
    }
    state.set(
        CONFIG,
        &encode_payload(&Config {
            authority,
            delay: delay_blocks,
        })?,
    )
}

pub fn sequencer(state: &State) -> Result<Option<H256>> {
    read(state, SEQUENCER)
}
pub fn parameter(state: &State, name: &str) -> Result<Option<String>> {
    read(state, &[PARAM, name.as_bytes()].concat())
}

/// Validate the boundary against the *parent* state, including for empty blocks.
pub fn check_activation(state: &State, schedule: &ForkSchedule, height: u64) -> Result<()> {
    let fork = schedule
        .active_fork_at(height)
        .ok_or_else(|| Error::Fork("no active fork".into()))?;
    if height != 0
        && height == fork.activation_height
        && schedule
            .active_fork_at(height - 1)
            .is_some_and(|prev| prev.has_feature(features::GOVERNANCE))
    {
        let proposal: Option<Proposal> =
            read(state, &[PROPOSAL, &fork.fork_id.to_be_bytes()].concat())?;
        let hash = Hash::sha256(&encode_payload(fork)?);
        if !proposal.is_some_and(|p| p.approved && p.fork_hash == hash) {
            return Err(Error::Fork(
                "scheduled upgrade lacks governance approval".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn apply(
    state: &mut State,
    tx: &Transaction,
    action: &Action,
    schedule: &ForkSchedule,
    height: u64,
) -> Result<Event> {
    let config: Config = read(state, CONFIG)?
        .ok_or_else(|| Error::Unauthorized("governance not initialized".into()))?;
    let key = tx.public_key.as_deref().ok_or(Error::InvalidSignature)?;
    if tx.chain_id != schedule.chain_id
        || tx.account != config.authority
        || Hash::sha256(key) != config.authority
    {
        return Err(Error::Unauthorized(
            "governance signing authority required".into(),
        ));
    }
    fn decode<T: DeserializeOwned>(action: &Action) -> Result<T> {
        let (v, rest) = postcard::take_from_bytes(&action.payload)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        if !rest.is_empty() {
            return Err(Error::Validation("trailing governance payload".into()));
        }
        Ok(v)
    }
    let (kind, data) = match action.action_type {
        ActionType::GovUpgrade | ActionType::GovExecuteUpgrade => {
            let GovUpgradePayload { target_fork_id } = decode(action)?;
            let fork = schedule
                .forks
                .iter()
                .find(|f| f.activation_height > height)
                .filter(|f| f.fork_id == target_fork_id)
                .ok_or_else(|| Error::Fork("expected next scheduled fork".into()))?;
            let key = [PROPOSAL, &target_fork_id.to_be_bytes()].concat();
            let existing: Option<Proposal> = read(state, &key)?;
            let fork_hash = Hash::sha256(&encode_payload(fork)?);
            let (kind, proposal) = if action.action_type == ActionType::GovUpgrade {
                let ready = height
                    .checked_add(config.delay)
                    .filter(|h| *h < fork.activation_height)
                    .ok_or_else(|| {
                        Error::InvalidTransition("insufficient time before activation".into())
                    })?;
                if existing.is_some() {
                    return Err(Error::InvalidTransition("upgrade already proposed".into()));
                }
                (
                    "gov.upgrade_proposed",
                    Proposal {
                        ready,
                        approved: false,
                        fork_hash,
                    },
                )
            } else {
                let mut p = existing.ok_or_else(|| Error::NotFound("upgrade proposal".into()))?;
                if p.approved || p.fork_hash != fork_hash || height < p.ready {
                    return Err(Error::InvalidTransition("upgrade is not executable".into()));
                }
                p.approved = true;
                ("gov.upgrade_approved", p)
            };
            state.set(&key, &encode_payload(&proposal)?)?;
            (kind, encode_payload(&(target_fork_id, proposal.ready))?)
        }
        ActionType::GovSetSequencer => {
            let GovSetSequencerPayload { sequencer } = decode(action)?;
            if sequencer == H256::ZERO {
                return Err(Error::Validation("zero sequencer".into()));
            }
            state.set(SEQUENCER, &encode_payload(&sequencer)?)?;
            ("gov.sequencer_set", encode_payload(&sequencer)?)
        }
        ActionType::GovSetParameters => {
            let GovSetParametersPayload {
                param_key,
                param_value,
            } = decode(action)?;
            if param_key.is_empty()
                || param_key.len() > 64
                || !param_key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || param_value.len() > 1024
            {
                return Err(Error::Validation("invalid governance parameter".into()));
            }
            state.set(
                &[PARAM, param_key.as_bytes()].concat(),
                &encode_payload(&param_value)?,
            )?;
            (
                "gov.parameters_set",
                encode_payload(&(param_key, param_value))?,
            )
        }
        _ => return Err(Error::InvalidTransition("not a governance action".into())),
    };
    Ok(Event {
        event_type: kind.into(),
        data,
        block_number: height,
        tx_index: 0,
    })
}
