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
