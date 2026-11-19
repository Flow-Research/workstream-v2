use workstream_core::traits::sequencer::{BuildBlockRequest, SequencerApi};
use workstream_core::{Action, ActionType, FeePayer, FeeSpec};
use workstream_sequencer::SequencerApiImpl;
use workstream_stf::{
    encode_payload, mvp_genesis_schedule, ActorRegisterPayload, ActorRole, StateTransitionFunction,
};
use workstream_wallet::{RecoveryKey, Wallet};

#[test]
fn backup_recovers_the_account_only_with_the_matching_identity() {
    let wallet = Wallet::generate(1).unwrap();
    let recovery = RecoveryKey::generate();
    let mut backup = wallet.backup(&recovery.to_public()).unwrap();
    assert_eq!(
        Wallet::restore(1, &backup, &recovery).unwrap().account(),
        wallet.account()
    );
    assert!(Wallet::restore(1, &backup, &RecoveryKey::generate()).is_err());
    *backup.last_mut().unwrap() ^= 1;
    assert!(Wallet::restore(1, &backup, &recovery).is_err());
}

#[tokio::test]
async fn restored_wallet_submits_a_transaction_that_executes_in_a_block() {
    let original = Wallet::generate(1).unwrap();
    let recovery = RecoveryKey::generate();
    let backup = original.backup(&recovery.to_public()).unwrap();
    let wallet = Wallet::restore(1, &backup, &recovery).unwrap();
    let api = SequencerApiImpl::new(
        StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap(),
    );
    let action = Action {
        action_type: ActionType::ActorRegister,
        payload: encode_payload(&ActorRegisterPayload {
            role: ActorRole::Worker,
        })
        .unwrap(),
    };
    let tx = wallet
        .sign(
            0,
            FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            },
            [action],
        )
        .unwrap();
    let mut tampered = tx.clone();
    tampered.fee.max_fee += 1;
    assert!(wallet.submit(&api, &tampered).await.is_err());
    assert_eq!(api.get_mempool_status().await.unwrap().pending_count, 0);
    assert_eq!(
        wallet.submit(&api, &tx).await.unwrap(),
        workstream_sequencer::tx_hash(&tx).unwrap()
    );
    let block = api
        .preview_block(BuildBlockRequest {
            version: 1,
            api_version: 1,
            max_txs: None,
        })
        .await
        .unwrap();
    assert_eq!(block.tx_count, 1);
    assert_eq!(api.get_mempool_status().await.unwrap().pending_count, 1);
}

#[test]
fn reviewed_signature_binds_restored_account_network_and_payload() {
    use workstream_crypto::signature::tx_message_hash;
    let wallet = Wallet::generate(7).unwrap();
    let recovery = RecoveryKey::generate();
    let backup = wallet.backup(&recovery.to_public()).unwrap();
    let restored = Wallet::restore(7, &backup, &recovery).unwrap();
    let draft = workstream_tx::TxBuilder::new()
        .chain_id(7)
        .account(wallet.account())
        .nonce(0, 12)
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 100,
        })
        .add_action(ActionType::ActorRegister, vec![1])
        .build()
        .unwrap();
    let approved = tx_message_hash(&draft).unwrap();
    let signed = restored.sign_reviewed(draft.clone(), approved).unwrap();
    assert_eq!(tx_message_hash(&signed).unwrap(), approved);
    assert!(restored.sign_reviewed(signed, approved).is_err());
    let mut edited = draft.clone();
    edited.actions[0].payload.push(2);
    assert!(restored.sign_reviewed(edited, approved).is_err());
    assert!(Wallet::restore(8, &backup, &recovery)
        .unwrap()
        .sign_reviewed(draft.clone(), approved)
        .is_err());
    assert!(Wallet::generate(7)
        .unwrap()
        .sign_reviewed(draft, approved)
        .is_err());
}
