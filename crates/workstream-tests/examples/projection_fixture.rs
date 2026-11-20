//! Deterministic signed transaction sequence for the projection drill.
//!
//! The sequence exercises actor/grant work-item, review and receipt projections
//! through the connected runtime without any producer-local shortcuts.
use workstream_core::hash::H256;
use workstream_core::types::*;
use workstream_crypto::signature;
use workstream_stf::{
    derive_guide, derive_project, derive_submission, derive_task, encode_payload,
    ActorGrantPayload, ActorRegisterPayload, ActorRole, BundleAdmitPayload, Capability,
    GuideActivatePayload, GuideIngestPayload, ProjectCreatePayload, ReviewDecidePayload,
    ReviewDecision, ReviewLeasePayload, SubmissionCreatePayload, SubmissionIdPayload,
    TaskCreatePayload, TaskIdPayload, TaskReleasePayload, TaskScreenPayload,
};
use workstream_tx::TxBuilder;

#[path = "../../../tests/support/accounts.rs"]
mod accounts;

fn account(tag: u8) -> AccountId {
    accounts::account(tag)
}

fn tx(acct: AccountId, seq: u64, action: ActionType, payload: Vec<u8>) -> Transaction {
    let mut tx = TxBuilder::new()
        .chain_id(1)
        .account(acct)
        .nonce(0, seq)
        .add_action(action, payload)
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1_000,
        })
        .build()
        .unwrap();
    signature::sign_tx_ed25519(&mut tx, &accounts::signer(acct)).unwrap();
    tx
}

fn main() -> workstream_core::Result<()> {
    let sponsor = account(0x11);
    let worker = account(0x22);
    let reviewer = account(0x33);
    if std::env::args().nth(1).as_deref() == Some("unauthorized-claim") {
        let project = derive_project(&sponsor, "Projection Drill Project");
        let task = derive_task(&project, "Projection drill task");
        let tx = tx(
            reviewer,
            3,
            ActionType::TaskClaim,
            encode_payload(&TaskIdPayload { task })?,
        );
        println!("{}", serde_json::json!(tx));
        return Ok(());
    }

    let project = derive_project(&sponsor, "Projection Drill Project");
    let guide_hash = H256::from_bytes([0xBB; 32]);
    let guide = derive_guide(&project, 1, &guide_hash);
    let task = derive_task(&project, "Projection drill task");
    let content = H256::from_bytes([0xCC; 32]);
    let submission = derive_submission(&task, &content);

    let txs = vec![
        tx(
            sponsor,
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Sponsor,
            })?,
        ),
        tx(
            worker,
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Worker,
            })?,
        ),
        tx(
            reviewer,
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Worker,
            })?,
        ),
        tx(
            sponsor,
            1,
            ActionType::ActorGrant,
            encode_payload(&ActorGrantPayload {
                grantee: worker,
                capability: Capability::ClaimWork,
            })?,
        ),
        tx(
            sponsor,
            2,
            ActionType::ActorGrant,
            encode_payload(&ActorGrantPayload {
                grantee: worker,
                capability: Capability::SubmitWork,
            })?,
        ),
        tx(
            sponsor,
            3,
            ActionType::ProjectCreate,
            encode_payload(&ProjectCreatePayload {
                title: "Projection Drill Project".into(),
            })?,
        ),
        tx(
            sponsor,
            4,
            ActionType::GuideIngest,
            encode_payload(&GuideIngestPayload {
                project,
                version: 1,
                content_hash: guide_hash,
            })?,
        ),
        tx(
            sponsor,
            5,
            ActionType::GuideActivate,
            encode_payload(&GuideActivatePayload { project, guide })?,
        ),
        tx(
            sponsor,
            6,
            ActionType::TaskCreate,
            encode_payload(&TaskCreatePayload {
                project,
                title: "Projection drill task".into(),
                award: 1_000,
            })?,
        ),
        tx(
            sponsor,
            7,
            ActionType::TaskScreen,
            encode_payload(&TaskScreenPayload { task })?,
        ),
        tx(
            sponsor,
            8,
            ActionType::TaskRelease,
            encode_payload(&TaskReleasePayload {
                task,
                reason: "screened, scope frozen".into(),
            })?,
        ),
        tx(
            worker,
            1,
            ActionType::TaskClaim,
            encode_payload(&TaskIdPayload { task })?,
        ),
        tx(
            worker,
            2,
            ActionType::TaskStart,
            encode_payload(&TaskIdPayload { task })?,
        ),
        tx(
            worker,
            3,
            ActionType::BundleAdmit,
            encode_payload(&BundleAdmitPayload {
                task,
                content_hash: content,
            })?,
        ),
        tx(
            worker,
            4,
            ActionType::SubmissionCreate,
            encode_payload(&SubmissionCreatePayload {
                task,
                content_hash: content,
            })?,
        ),
        tx(
            reviewer,
            1,
            ActionType::ReviewLease,
            encode_payload(&ReviewLeasePayload { submission })?,
        ),
        tx(
            reviewer,
            2,
            ActionType::ReviewDecide,
            encode_payload(&ReviewDecidePayload {
                submission,
                decision: ReviewDecision::Accept,
            })?,
        ),
        tx(
            sponsor,
            9,
            ActionType::AcceptFinal,
            encode_payload(&SubmissionIdPayload { submission })?,
        ),
    ];
    println!("{}", serde_json::json!(txs));
    Ok(())
}
