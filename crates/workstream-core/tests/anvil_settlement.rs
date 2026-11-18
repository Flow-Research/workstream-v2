//! Run with scripts/test-anvil-settlement.sh (isolated, prefunded local chain).
use ed25519_dalek::{Signer, SigningKey};
use workstream_core::{
    bridge::{
        AnvilSettlement, DepositAuthority, DepositReceipt, DurableBridgePool, Payout,
        SettlementRail,
    },
    privacy::{Asset, AssetKind, ShieldedNote},
    Error, Result, H256,
};

#[test]
#[ignore = "requires the disposable vault deployed by scripts/test-anvil-settlement.sh"]
fn accepted_payment_survives_relay_restart() {
    let env = |k| std::env::var(k).unwrap();
    let address =
        |k| <[u8; 20]>::try_from(hex::decode(env(k).trim_start_matches("0x")).unwrap()).unwrap();
    let rail = || {
        AnvilSettlement::new(
            env("WS_ENDPOINT").parse().unwrap(),
            address("WS_VAULT"),
            address("WS_OPERATOR"),
        )
        .unwrap()
    };
    let mut recipient = [0; 32];
    recipient[12..].copy_from_slice(&address("WS_RECIPIENT"));
    let recipient = H256::from_bytes(recipient);
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let authority = DepositAuthority {
        domain: H256::from_bytes([1; 32]),
        public_key: key.verifying_key().to_bytes(),
    };
    let note = ShieldedNote::new(H256::from_bytes([2; 32]), 12345, H256::from_bytes([3; 32]));
    let deposit = DepositReceipt {
        domain: authority.domain,
        asset: Asset {
            id: note.asset,
            kind: AssetKind::NativeGas,
        },
        amount: note.amount,
        recipient,
        task: None,
        note_commitment: note.commitment(),
        source_event: H256::from_bytes([4; 32]),
    };
    let sig = key
        .sign(deposit.signing_digest().unwrap().as_bytes())
        .to_bytes();
    let payout = Payout {
        domain: deposit.domain,
        asset: deposit.asset.id,
        amount: deposit.amount,
        recipient,
        escrow_id: note.commitment(),
    };
    struct LostAck(AnvilSettlement);
    impl SettlementRail for LostAck {
        fn pay_once(&mut self, p: &Payout) -> Result<H256> {
            self.0.pay_once(p)?;
            Err(Error::Timeout("discarded vault acknowledgement".into()))
        }
    }
    {
        let mut store = DurableBridgePool::create(dir.path(), authority).unwrap();
        let id = store.accept_deposit(&deposit, &sig, note).unwrap();
        store.release(id, recipient).unwrap();
        let error = store.settle(id, &mut LostAck(rail())).unwrap_err();
        assert!(
            matches!(&error, Error::Timeout(msg) if msg == "discarded vault acknowledgement"),
            "{error}"
        );
    }
    let mut store = DurableBridgePool::open(dir.path(), authority).unwrap();
    assert_eq!(store.pending_settlements().unwrap(), vec![payout.escrow_id]);
    let mut rail = rail();
    let receipt = store.settle(payout.escrow_id, &mut rail).unwrap();
    assert_ne!(receipt, H256::ZERO);
    assert!(store.pending_settlements().unwrap().is_empty());
    assert!(rail
        .pay_once(&Payout {
            amount: 1,
            ..payout
        })
        .is_err());
}
