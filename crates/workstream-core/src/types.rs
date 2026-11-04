use crate::hash::H256;
use serde::{Deserialize, Serialize};

// Identifiers
pub type BlockNumber = u64;
pub type TxIndex = u32;
pub type AccountId = H256;
pub type ProjectId = H256;
pub type TaskId = H256;
pub type SubmissionId = H256;
pub type GuideId = H256;
pub type BundleId = H256;
pub type LeaseId = H256;
pub type RecordId = H256;
pub type PolicyId = H256;

// State roots
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateRoot {
    pub version: u8,
    pub smt_root: H256, // Mutable lifecycle objects
    pub mmr_root: H256, // Immutable records
}

impl StateRoot {
    pub fn new(smt_root: H256, mmr_root: H256) -> Self {
        StateRoot {
            version: 1,
            smt_root,
            mmr_root,
        }
    }

    pub fn hash(&self) -> H256 {
        crate::hash::Hash::sha256_concat(&[
            &[self.version],
            self.smt_root.as_bytes(),
            self.mmr_root.as_bytes(),
        ])
    }
}

// Block header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub number: BlockNumber,
    pub parent_hash: H256,
    pub timestamp: u64, // Consensus-derived, not wall clock
    pub tx_root: H256,
    pub state_root: StateRoot,
    pub da_ref: H256,
    /// Active fork id at this block (MUST match the resolved fork)
    pub fork_id: u64,
    /// zkVM guest image hash used to produce the proof (MUST be approved for fork_id)
    pub guest_hash: H256,
    /// Proof system version (MUST be >= fork's min_proof_system)
    pub proof_system_version: u32,
    pub proof: Option<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub proof_data: Vec<u8>,
    pub proof_type: ProofType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofType {
    ZkVm,      // General zkVM proof
    Recursive, // Recursive composition
}

// Block
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

// Transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: u64,
    pub account: AccountId,
    pub nonce: Nonce,
    pub actions: Vec<Action>,
    pub fee: FeeSpec,
    pub auth: Vec<u8>, // Opaque to base layer
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nonce {
    pub key_id: u16,
    pub seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeSpec {
    pub payer: FeePayer,
    pub asset_id: u32,
    pub max_fee: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FeePayer {
    Self_,
    Paymaster { paymaster: AccountId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    pub action_type: ActionType,
    pub payload: Vec<u8>, // Canonical encoded payload
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionType {
    // Actor & identity
    ActorRegister,
    ActorLink,
    ActorGrant,
    ActorRevoke,
    ActorSuspend,
    ActorReactivate,
    ActorDeactivate,

    // Project & guide
    ProjectCreate,
    GuideIngest,

    // Policy
    PolicyCompile,
    PolicyApprove,
    GuideActivate,

    // Task lifecycle
    TaskCreate,
    TaskScreen,
    TaskRelease,
    TaskClaim,
    TaskStart,

    // Bundle & submission
    BundlePrepare,
    BundleAdmit,
    SubmissionCreate,

    // Checks & routing
    CheckRun,
    RouteSubmission,

    // Review
    ReviewLease,
    ReviewDecide,

    // Revision
    RevisionPrepare,

    // Acceptance & records
    AcceptFinal,

    // Compensation
    AwardFulfill,

    // Reputation
    ReputationProject,

    // Governance
    GovUpgrade,
    GovSetSequencer,
    GovSetParameters,
}

// Events
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub event_type: String,
    pub data: Vec<u8>,
    pub block_number: BlockNumber,
    pub tx_index: TxIndex,
}

// Trait definitions
pub trait State: Clone {
    type Error;
    fn get(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, Self::Error>;
    fn set(&mut self, key: &[u8], value: &[u8]) -> std::result::Result<(), Self::Error>;
    fn root(&self) -> StateRoot;
}
