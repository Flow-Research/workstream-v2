//! End-to-end MVP happy path test (issue #33).
//!
//! Wires together the full M0.5 stack:
//! - Sequencer builds blocks from submitted transactions
//! - Node syncs blocks and verifies state
//! - Full task lifecycle: register → grant → project → guide → screen →
//!   release → claim → start → admit → submit → review → accept
//!
//! This test verifies the core consensus property: sequencer and node
//! arrive at identical state after processing the same transactions.

use workstream_core::hash::H256;
use workstream_core::types::*;
use workstream_node::{MemoryBlockSource, Node};
use workstream_sequencer::Sequencer;
use workstream_stf::{
    derive_bundle, derive_guide, derive_project, derive_submission, derive_task, encode_payload,
    get_active_guide, get_actor, get_bundle, get_project, get_submission, get_task,
    mvp_genesis_schedule, ActorGrantPayload, ActorRegisterPayload, ActorRole, BundleAdmitPayload,
    BundleStatus, Capability, GuideActivatePayload, GuideIngestPayload, ProjectCreatePayload,
    ReviewDecidePayload, ReviewDecision, ReviewLeasePayload, StateTransitionFunction,
    SubmissionCreatePayload, SubmissionIdPayload, SubmissionStatus, TaskCreatePayload,
    TaskIdPayload, TaskReleasePayload, TaskScreenPayload, TaskStatus,
};
use workstream_tx::TxBuilder;

// Test accounts
fn sponsor() -> AccountId {
    H256::from_bytes([0x11; 32])
}

fn worker() -> AccountId {
    H256::from_bytes([0x22; 32])
}

/// A second worker acting as an independent reviewer. The review policy
/// forbids the submission's author and the task's sponsor from reviewing.
fn reviewer() -> AccountId {
    H256::from_bytes([0x33; 32])
}

fn content_hash() -> H256 {
    H256::from_bytes([0xCC; 32])
}

// Transaction builders
fn tx(acct: AccountId, seq: u64, action_type: ActionType, payload: Vec<u8>) -> Transaction {
    TxBuilder::new()
        .chain_id(1)
        .account(acct)
        .nonce(0, seq)
        .add_action(action_type, payload)
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1_000,
        })
        .build()
        .unwrap()
}

fn register_sponsor() -> Transaction {
    tx(
        sponsor(),
        0,
        ActionType::ActorRegister,
        encode_payload(&ActorRegisterPayload {
            role: ActorRole::Sponsor,
        })
        .unwrap(),
    )
}

fn register_worker() -> Transaction {
    tx(
        worker(),
        0,
        ActionType::ActorRegister,
        encode_payload(&ActorRegisterPayload {
            role: ActorRole::Worker,
        })
        .unwrap(),
    )
}

fn register_reviewer() -> Transaction {
    tx(
        reviewer(),
        0,
        ActionType::ActorRegister,
        encode_payload(&ActorRegisterPayload {
            role: ActorRole::Worker,
        })
        .unwrap(),
    )
}

fn grant_claim() -> Transaction {
    tx(
        sponsor(),
        1,
        ActionType::ActorGrant,
        encode_payload(&ActorGrantPayload {
            grantee: worker(),
            capability: Capability::ClaimWork,
        })
        .unwrap(),
    )
}

fn grant_submit() -> Transaction {
    tx(
        sponsor(),
        2,
        ActionType::ActorGrant,
        encode_payload(&ActorGrantPayload {
            grantee: worker(),
            capability: Capability::SubmitWork,
        })
        .unwrap(),
    )
}

fn create_project() -> Transaction {
    tx(
        sponsor(),
        3,
        ActionType::ProjectCreate,
        encode_payload(&ProjectCreatePayload {
            title: "MVP Test Project".to_string(),
        })
        .unwrap(),
    )
}

fn project_id() -> ProjectId {
    derive_project(&sponsor(), "MVP Test Project")
}

/// Constant guide version content for the e2e run: v1 ingested and
/// activated so the task can be screened.
fn guide_content() -> H256 {
    H256::from_bytes([0xBB; 32])
}

fn ingest_guide(transaction_seq: u64) -> Transaction {
    tx(
        sponsor(),
        transaction_seq,
        ActionType::GuideIngest,
        encode_payload(&GuideIngestPayload {
            project: project_id(),
            version: 1,
            content_hash: guide_content(),
        })
        .unwrap(),
    )
}

fn activate_guide(transaction_seq: u64) -> Transaction {
    tx(
        sponsor(),
        transaction_seq,
        ActionType::GuideActivate,
        encode_payload(&GuideActivatePayload {
            project: project_id(),
            guide: derive_guide(&project_id(), 1, &guide_content()),
        })
        .unwrap(),
    )
}

fn create_task() -> Transaction {
    tx(
        sponsor(),
        6,
        ActionType::TaskCreate,
        encode_payload(&TaskCreatePayload {
            project: project_id(),
            title: "Implement feature X".to_string(),
            award: 1000,
        })
        .unwrap(),
    )
}

fn task_id() -> TaskId {
    derive_task(&project_id(), "Implement feature X")
}

fn screen_task(transaction_seq: u64) -> Transaction {
    tx(
        sponsor(),
        transaction_seq,
        ActionType::TaskScreen,
        encode_payload(&TaskScreenPayload { task: task_id() }).unwrap(),
    )
}

fn release_task(transaction_seq: u64) -> Transaction {
    tx(
        sponsor(),
        transaction_seq,
        ActionType::TaskRelease,
        encode_payload(&TaskReleasePayload {
            task: task_id(),
            reason: "screened, scope frozen".to_string(),
        })
        .unwrap(),
    )
}

fn claim_task() -> Transaction {
    tx(
        worker(),
        1,
        ActionType::TaskClaim,
        encode_payload(&TaskIdPayload { task: task_id() }).unwrap(),
    )
}

fn start_task() -> Transaction {
    tx(
        worker(),
        2,
        ActionType::TaskStart,
        encode_payload(&TaskIdPayload { task: task_id() }).unwrap(),
    )
}

fn admit_bundle() -> Transaction {
    tx(
        worker(),
        3,
        ActionType::BundleAdmit,
        encode_payload(&BundleAdmitPayload {
            task: task_id(),
            content_hash: content_hash(),
        })
        .unwrap(),
    )
}

fn bundle_id() -> H256 {
    derive_bundle(&task_id(), &worker(), &content_hash())
}

fn submit_work() -> Transaction {
    tx(
        worker(),
        4,
        ActionType::SubmissionCreate,
        encode_payload(&SubmissionCreatePayload {
            task: task_id(),
            content_hash: content_hash(),
        })
        .unwrap(),
    )
}

fn submission_id() -> SubmissionId {
    derive_submission(&task_id(), &content_hash())
}

fn review_lease() -> Transaction {
    tx(
        reviewer(),
        1,
        ActionType::ReviewLease,
        encode_payload(&ReviewLeasePayload {
            submission: submission_id(),
        })
        .unwrap(),
    )
}

fn review_decide() -> Transaction {
    tx(
        reviewer(),
        2,
        ActionType::ReviewDecide,
        encode_payload(&ReviewDecidePayload {
            submission: submission_id(),
            decision: ReviewDecision::Accept,
        })
        .unwrap(),
    )
}

fn accept_final() -> Transaction {
    tx(
        sponsor(),
        9,
        ActionType::AcceptFinal,
        encode_payload(&SubmissionIdPayload {
            submission: submission_id(),
        })
        .unwrap(),
    )
}

fn mvp_stf() -> StateTransitionFunction {
    StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap()
}

/// Full MVP happy path: sequencer produces blocks, node verifies and syncs.
#[test]
fn e2e_mvp_happy_path() {
    // === Phase 1: Setup ===
    let mut sequencer = Sequencer::new(mvp_stf());

    // === Phase 2: Submit transactions to sequencer ===

    // Block 1: Actor registration (sponsor + worker)
    sequencer.submit_tx(register_sponsor()).unwrap();
    sequencer.submit_tx(register_worker()).unwrap();

    // Block 2: Reviewer registration + first capability grant
    sequencer.submit_tx(register_reviewer()).unwrap();
    sequencer.submit_tx(grant_claim()).unwrap();

    // Block 3: Second capability grant + project creation
    sequencer.submit_tx(grant_submit()).unwrap();
    sequencer.submit_tx(create_project()).unwrap();

    // Block 4: Guide ingestion + activation
    sequencer.submit_tx(ingest_guide(4)).unwrap();
    sequencer.submit_tx(activate_guide(5)).unwrap();

    // Block 5: Task creation + screening
    sequencer.submit_tx(create_task()).unwrap();
    sequencer.submit_tx(screen_task(7)).unwrap();

    // Block 6: Task release + worker claim
    sequencer.submit_tx(release_task(8)).unwrap();
    sequencer.submit_tx(claim_task()).unwrap();

    // Block 7: Worker starts + admits the work bundle
    sequencer.submit_tx(start_task()).unwrap();
    sequencer.submit_tx(admit_bundle()).unwrap();

    // Block 8: Submission + review lease
    sequencer.submit_tx(submit_work()).unwrap();
    sequencer.submit_tx(review_lease()).unwrap();

    // Block 9: Review decision + sponsor acceptance
    sequencer.submit_tx(review_decide()).unwrap();
    sequencer.submit_tx(accept_final()).unwrap();

    // === Phase 3: Build blocks ===
    let mut blocks = Vec::new();
    for _ in 0..9 {
        blocks.push(sequencer.build_block(Some(2)).unwrap());
    }

    // Verify sequencer built 9 blocks with expected tx counts
    assert_eq!(blocks.len(), 9);
    assert_eq!(blocks[0].transactions.len(), 2); // sponsor + worker register
    assert_eq!(blocks[1].transactions.len(), 2); // reviewer register + claim grant
    assert_eq!(blocks[2].transactions.len(), 2); // submit grant + project
    assert_eq!(blocks[3].transactions.len(), 2); // guide ingest + activate
    assert_eq!(blocks[4].transactions.len(), 2); // task create + screen
    assert_eq!(blocks[5].transactions.len(), 2); // release + claim
    assert_eq!(blocks[6].transactions.len(), 2); // start + bundle admit
    assert_eq!(blocks[7].transactions.len(), 2); // submit + review lease
    assert_eq!(blocks[8].transactions.len(), 2); // review decide + accept

    // === Phase 4: Node syncs blocks ===
    let mut source = MemoryBlockSource::new();
    for block in blocks {
        source.push(block);
    }

    let mut node = Node::new(mvp_stf(), mvp_genesis_schedule().unwrap(), source);
    let results = node.sync().unwrap();

    // Verify all blocks applied
    assert_eq!(results.len(), 9);
    assert_eq!(node.tip(), 9);

    // === Phase 5: Verify state convergence ===
    assert_eq!(node.state_root(), sequencer.state().root());

    // === Phase 6: Verify final state ===
    let state = node.state();

    // Actors exist with correct roles
    let sponsor_record = get_actor(state, &sponsor()).unwrap().unwrap();
    assert_eq!(sponsor_record.role, ActorRole::Sponsor);

    let worker_record = get_actor(state, &worker()).unwrap().unwrap();
    assert_eq!(worker_record.role, ActorRole::Worker);
    // Sponsor-scoped grants: both capabilities issued by the sponsor.
    assert!(worker_record
        .grants
        .iter()
        .any(|g| g.capability == Capability::ClaimWork && g.grantor == sponsor()));
    assert!(worker_record
        .grants
        .iter()
        .any(|g| g.capability == Capability::SubmitWork && g.grantor == sponsor()));

    // Project exists
    let project_record = get_project(state, &project_id()).unwrap().unwrap();
    assert_eq!(project_record.title, "MVP Test Project");
    assert_eq!(project_record.owner, sponsor());

    // Guide lineage: v1 ingested and active before screening.
    let expected_guide = derive_guide(&project_id(), 1, &guide_content());
    assert_eq!(
        get_active_guide(state, &project_id()).unwrap(),
        Some(expected_guide)
    );

    // Task is completed, assignee verified, screened under the active guide
    let task_record = get_task(state, &task_id()).unwrap().unwrap();
    assert_eq!(task_record.status, TaskStatus::Completed);
    assert_eq!(task_record.assignee, Some(worker()));
    assert_eq!(task_record.award, 1000);
    assert_eq!(task_record.screened_under, Some(expected_guide));

    // Reviewer is an independent registered actor (not author, not sponsor)
    let reviewer_record = get_actor(state, &reviewer()).unwrap().unwrap();
    assert_eq!(reviewer_record.role, ActorRole::Worker);

    // The admitted bundle was consumed by the submission
    let bundle_record = get_bundle(state, &bundle_id()).unwrap().unwrap();
    assert_eq!(bundle_record.status, BundleStatus::Consumed);
    assert_eq!(bundle_record.author, worker());

    // Submission is accepted after a positive review
    let submission_record = get_submission(state, &submission_id()).unwrap().unwrap();
    assert_eq!(submission_record.status, SubmissionStatus::Accepted);
    assert_eq!(submission_record.author, worker());
    assert_eq!(submission_record.content_hash, content_hash());
    assert_eq!(submission_record.accept_reviews, 1);

    // MMR has the review record and the acceptance record
    assert_eq!(state.mmr.size(), 2);

    // === Phase 7: Verify events ===
    let all_events: Vec<&Event> = results.iter().flat_map(|r| &r.events).collect();
    let event_types: Vec<&str> = all_events.iter().map(|e| e.event_type.as_str()).collect();

    assert_eq!(
        event_types,
        vec![
            "actor.registered", // sponsor
            "actor.registered", // worker
            "actor.registered", // reviewer
            "actor.granted",    // claim
            "actor.granted",    // submit
            "project.created",
            "guide.ingested",
            "guide.activated",
            "task.created",
            "task.screened",
            "task.released",
            "task.claimed",
            "task.started",
            "bundle.admitted",
            "submission.created",
            "review.leased",
            "review.decided",
            "accept.finalized",
        ]
    );

    // Events have correct block numbers
    for (idx, expected_block) in [1u64, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9]
        .into_iter()
        .enumerate()
    {
        assert_eq!(all_events[idx].block_number, expected_block, "event {idx}");
    }

    println!("✓ E2E MVP happy path completed successfully!");
    println!("  - Sequencer built 9 blocks with 18 transactions");
    println!("  - Node verified and synced all blocks");
    println!("  - State roots converged: {}", node.state_root().hash());
    println!(
        "  - Full lifecycle: Draft → Screened → Released → Claimed → Started → \
         Submitted → Reviewed → Completed"
    );
}

/// Verify deterministic replay: two independent runs produce identical state.
#[test]
fn e2e_deterministic_replay() {
    fn run_full_flow() -> (StateRoot, Vec<H256>) {
        let mut sequencer = Sequencer::new(mvp_stf());

        // Full transaction set
        for tx in [
            register_sponsor(),
            register_worker(),
            register_reviewer(),
            grant_claim(),
            grant_submit(),
            create_project(),
            ingest_guide(4),
            activate_guide(5),
            create_task(),
            screen_task(7),
            release_task(8),
            claim_task(),
            start_task(),
            admit_bundle(),
            submit_work(),
            review_lease(),
            review_decide(),
            accept_final(),
        ] {
            sequencer.submit_tx(tx).unwrap();
        }

        // Build blocks
        let mut blocks = Vec::new();
        let mut header_hashes = Vec::new();
        while sequencer.pending() > 0 || blocks.is_empty() {
            let block = sequencer.build_block(Some(2)).unwrap();
            header_hashes.push(workstream_sequencer::header_hash(&block.header));
            blocks.push(block);
            if blocks.len() >= 9 {
                break;
            }
        }

        // Node sync
        let mut source = MemoryBlockSource::new();
        for block in blocks {
            source.push(block);
        }

        let mut node = Node::new(mvp_stf(), mvp_genesis_schedule().unwrap(), source);
        node.sync().unwrap();

        (node.state_root(), header_hashes)
    }

    let (root1, hashes1) = run_full_flow();
    let (root2, hashes2) = run_full_flow();

    // Identical state roots
    assert_eq!(root1, root2);

    // Identical header chain
    assert_eq!(hashes1, hashes2);

    println!("✓ Deterministic replay verified!");
    println!(
        "  - Two independent runs produced identical state: {}",
        root1.hash()
    );
}

/// Verify sequencer-node state convergence with varying block sizes.
#[test]
fn e2e_varying_block_sizes() {
    let mut sequencer = Sequencer::new(mvp_stf());

    // Submit all transactions
    for tx in [
        register_sponsor(),
        register_worker(),
        register_reviewer(),
        grant_claim(),
        grant_submit(),
        create_project(),
        ingest_guide(4),
        activate_guide(5),
        create_task(),
        screen_task(7),
        release_task(8),
        claim_task(),
        start_task(),
        admit_bundle(),
        submit_work(),
        review_lease(),
        review_decide(),
        accept_final(),
    ] {
        sequencer.submit_tx(tx).unwrap();
    }

    // Build with varying batch sizes summing to all 18 transactions
    let mut blocks = Vec::new();
    for batch_size in [1, 3, 4, 2, 5, 3] {
        if sequencer.pending() > 0 {
            blocks.push(sequencer.build_block(Some(batch_size)).unwrap());
        }
    }

    // Node syncs
    let mut source = MemoryBlockSource::new();
    for block in &blocks {
        source.push(block.clone());
    }

    let mut node = Node::new(mvp_stf(), mvp_genesis_schedule().unwrap(), source);
    node.sync().unwrap();

    // State converges regardless of block batching
    assert_eq!(node.state_root(), sequencer.state().root());

    // Verify block tx counts
    let tx_counts: Vec<usize> = blocks.iter().map(|b| b.transactions.len()).collect();
    assert_eq!(tx_counts, vec![1, 3, 4, 2, 5, 3]);
    assert_eq!(tx_counts.iter().sum::<usize>(), 18);

    println!("✓ Varying block sizes: {:?} → state converged", tx_counts);
}
