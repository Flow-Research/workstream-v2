//! Deterministic, public dev-chain fixture for the multi-process smoke test.
use workstream_core::{types::*, Hash};
use workstream_stf::{encode_payload, ActorRegisterPayload, ActorRole};
use workstream_tx::TxBuilder;

fn main() -> workstream_core::Result<()> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let mut tx = TxBuilder::new()
        .chain_id(1)
        .account(Hash::sha256(key.verifying_key().as_bytes()))
        .nonce(
            0,
            if std::env::args().nth(1).as_deref() == Some("future-nonce") {
                99
            } else {
                0
            },
        )
        .add_action(
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Sponsor,
            })?,
        )
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1000,
        })
        .build()?;
    workstream_crypto::signature::sign_tx_ed25519(&mut tx, &key)?;
    println!("{}", serde_json::json!(tx));
    Ok(())
}
