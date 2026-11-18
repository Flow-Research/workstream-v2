//! Whole-note transfers and withdrawal authorizations. State stores a value
//! commitment and a spend-key hash, never the amount or the opening.

use serde::{Deserialize, Serialize};
use workstream_core::{
    privacy::{note_nullifier, ShieldedNote},
    Action, ActionType, Error, Event, Hash, Result, Transaction, H256,
};
use workstream_state::State;

#[derive(Serialize, Deserialize)]
struct IssuedNote {
    commitment: H256,
    owner: H256,
}

#[derive(Serialize, Deserialize)]
pub struct NoteSpend {
    pub input: H256,
    /// Transfer: recipient spend-key hash. Withdrawal: destination identifier.
    pub recipient: H256,
}

fn issued_key(id: H256) -> Vec<u8> {
    [b"WS:v1:k:issued-note:", id.as_bytes().as_slice()].concat()
}

/// Called by trusted genesis/funding code after backing has been established.
/// This is intentionally not a user-callable mint action.
pub fn issue(state: &mut State, note: &ShieldedNote, owner: H256) -> Result<H256> {
    if note.amount == 0 {
        return Err(Error::Validation("empty note".into()));
    }
    let commitment = note.commitment();
    insert(state, commitment, &IssuedNote { commitment, owner })?;
    Ok(commitment)
}

fn insert(state: &mut State, id: H256, note: &IssuedNote) -> Result<()> {
    let key = issued_key(id);
    if state.get(&key)?.is_some() {
        return Err(Error::InvalidTransition("note already issued".into()));
    }
    state.set(&key, &super::encode_payload(note)?)
}

// Runs on execute_tx's isolated draft: output creation, nullifier, and nonce
// all become canonical together, or all are discarded.
pub(super) fn apply(state: &mut State, tx: &Transaction, action: &Action) -> Result<Event> {
    let req: NoteSpend =
        postcard::from_bytes(&action.payload).map_err(|e| Error::Serialization(e.to_string()))?;
    let bytes = state
        .get(&issued_key(req.input))?
        .ok_or_else(|| Error::NotFound("unissued note".into()))?;
    let note: IssuedNote = postcard::from_bytes(&bytes).map_err(|e| Error::State(e.to_string()))?;
    let key = tx.public_key.as_deref().ok_or(Error::InvalidSignature)?;
    if Hash::sha256(key) != note.owner {
        return Err(Error::Unauthorized("wrong note spend key".into()));
    }
    let serial = note_nullifier(req.input);
    let spent_key = [b"WS:v1:k:spent-note:", serial.as_bytes().as_slice()].concat();
    if state.get(&spent_key)?.is_some() {
        return Err(Error::InvalidTransition("note already spent".into()));
    }
    let (kind, destination) = match action.action_type {
        ActionType::NoteTransfer => {
            let output = Hash::sha256_concat(&[
                b"WS:v1:transferred-note:",
                serial.as_bytes(),
                req.recipient.as_bytes(),
            ]);
            insert(
                state,
                output,
                &IssuedNote {
                    commitment: note.commitment,
                    owner: req.recipient,
                },
            )?;
            ("note.transferred", output)
        }
        ActionType::NoteWithdraw => ("note.withdrawal-authorized", req.recipient),
        _ => return Err(Error::InvalidTransition("unexpected note action".into())),
    };
    state.set(&spent_key, &[1])?;
    Ok(Event {
        event_type: kind.into(),
        data: super::encode_payload(&(serial, note.commitment, destination))?,
        block_number: 0,
        tx_index: 0,
    })
}
