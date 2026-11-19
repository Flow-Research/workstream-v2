//! Offline inspection of a transaction JSON document on stdin.
use std::io::{self, Read};
use workstream_core::{Hash, Transaction};
use workstream_crypto::signature::tx_message_hash;
use workstream_tx::{tx_hash, TxValidator};

fn inspect() -> Result<serde_json::Value, &'static str> {
    const LIMIT: usize = 256 * 1024;
    let mut bytes = Vec::new();
    io::stdin()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "input unavailable")?;
    if bytes.len() > LIMIT {
        return Err("transaction too large");
    }
    let tx: Transaction = serde_json::from_slice(&bytes).map_err(|_| "invalid transaction JSON")?;
    let signed_hash = if tx.signature.is_some() || tx.public_key.is_some() {
        TxValidator::new()
            .validate(&tx)
            .map_err(|_| "invalid signed transaction")?;
        Some(tx_hash(&tx).map_err(|_| "invalid transaction")?.to_string())
    } else {
        None
    };
    Ok(serde_json::json!({
        "network": tx.chain_id, "account": tx.account.to_string(), "nonce": tx.nonce,
        "max_fee": tx.fee.max_fee.to_string(), "payer": tx.fee.payer, "asset_id": tx.fee.asset_id,
        "actions": tx.actions.iter().map(|a| serde_json::json!({"type": a.action_type,
            "payload_bytes": a.payload.len(), "payload_hash": Hash::sha256(&a.payload).to_string()})).collect::<Vec<_>>(),
        "approval_digest": tx_message_hash(&tx).map_err(|_| "invalid transaction")?.to_string(),
        "signed_tx_hash": signed_hash
    }))
}

fn main() -> std::process::ExitCode {
    match inspect() {
        Ok(summary) => {
            println!("{summary}");
            std::process::ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}
