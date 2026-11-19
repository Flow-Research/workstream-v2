//! WorkStream prover: zkVM guest program and proof generation runtime (issue #80).
//!
//! The prover executes the deterministic state-transition guest program over
//! block transitions and asks a pluggable [`ZkvmBackend`] for the zero-knowledge
//! proof. The default backend runs the guest logic in memory (local development
//! and tests); a real RISC Zero backend plugs in behind the same trait and is
//! selected explicitly with [`Prover::with_risc0`].

use std::sync::Arc;

pub mod fold;
pub mod risc0;
pub mod runtime;
mod verifier;
pub use verifier::ReceiptVerifier;

use async_trait::async_trait;
use workstream_core::hash::{Hash, H256};
use workstream_core::traits::prover::{
    GuestInfo, ProofBundleResponse, ProveBlockRequest, ProveBlockTransition, ProverApi,
    ProverStatus, ZkProof, ZkvmBackend,
};
use workstream_core::traits::verifier::{
    BlockProofVerifier, VerifierApi, VerifyBlockRequest, VerifyBlockResponse, VerifyProofRequest,
    VerifyProofResponse,
};
use workstream_core::types::{Proof, ProofType};
use workstream_core::{Error, Result};
use workstream_state::{State, StateSnapshot};
use workstream_stf::StateTransitionFunction;

/// Guest program identifier: the deterministic STF state-transition program
/// (`stateroot_post = STF(stateroot_pre, txs)`) compiled to the zkVM guest.
pub const DEFAULT_GUEST_ID: &str = "workstream-stf-guest-v1";

/// Backend selector. Unset (or `in-memory`) keeps the portable development
/// backend; `risc0` opts into the external RISC Zero prover and requires
/// `WORKSTREAM_GUEST_IMAGE` and `WORKSTREAM_GUEST_ID`.
pub const PROVER_BACKEND_ENV: &str = "WORKSTREAM_PROVER_BACKEND";

const ZK_PROOF_TAG: &[u8] = b"WS:v1:in-memory-zk-proof:";

/// Encode a full zkVM proof envelope for attachment to a block header.
///
/// The header's `Proof` is intentionally a small typed wrapper so header
/// hashing can exclude the proof without changing the header layout. The
/// canonical `ZkProof` (including guest hash and commitment) is stored in
/// `proof_data` using postcard, which keeps the header self-verifying.
pub fn encode_header_proof(proof: &ZkProof) -> Result<Proof> {
    proof.validate()?;
    Ok(Proof {
        proof_data: postcard::to_allocvec(proof)
            .map_err(|e| Error::Serialization(format!("zk proof envelope encode: {e}")))?,
        proof_type: ProofType::ZkVm,
    })
}

/// Decode and validate the zkVM proof envelope attached to a block header.
pub fn decode_header_proof(proof: &Proof) -> Result<ZkProof> {
    if proof.proof_type != ProofType::ZkVm {
        return Err(Error::Validation(format!(
            "unsupported header proof type: {:?}",
            proof.proof_type
        )));
    }
    let decoded: ZkProof = postcard::from_bytes(&proof.proof_data)
        .map_err(|e| Error::Serialization(format!("zk proof envelope decode: {e}")))?;
    decoded.validate()?;
    Ok(decoded)
}

fn decode_witness(bytes: &[u8]) -> Result<State> {
    if bytes.is_empty() {
        return Err(Error::InvalidProof("missing backend witness".into()));
    }
    let snapshot: StateSnapshot = postcard::from_bytes(bytes)
        .map_err(|e| Error::Serialization(format!("backend witness decode: {e}")))?;
    State::from_snapshot(snapshot)
}

pub fn encode_witness(state: &State) -> Result<Vec<u8>> {
    postcard::to_allocvec(&state.snapshot())
        .map_err(|e| Error::Serialization(format!("backend witness encode: {e}")))
}

/// Prover runtime that generates block-transition proofs through a backend.
pub struct Prover {
    backend: Arc<dyn ZkvmBackend>,
}

impl Prover {
    /// Create a prover with the development in-memory backend.
    pub fn new() -> Self {
        Self::with_backend(Arc::new(InMemoryZkBackend::new(
            StateTransitionFunction::new(),
        )))
    }

    /// Create a prover bound to a specific STF/fork schedule.
    pub fn with_stf(stf: StateTransitionFunction) -> Self {
        Self::with_backend(Arc::new(InMemoryZkBackend::new(stf)))
    }

    /// Create a prover with a custom backend.
    pub fn with_backend(backend: Arc<dyn ZkvmBackend>) -> Self {
        Self { backend }
    }

    /// Create a prover backed by a real RISC Zero guest/prover.
    pub fn with_risc0(stf: StateTransitionFunction) -> Self {
        Self::with_backend(Arc::new(RiscZeroBackend::new(stf)))
    }

    /// Select the backend from [`PROVER_BACKEND_ENV`]. Unknown values fail
    /// closed instead of silently falling back to the development backend.
    pub fn from_env(stf: StateTransitionFunction) -> Result<Self> {
        let backend = std::env::var(PROVER_BACKEND_ENV).unwrap_or_default();
        match backend.trim().to_ascii_lowercase().as_str() {
            "" | "in-memory" | "in_memory" | "memory" => Ok(Self::with_stf(stf)),
            "risc0" | "risc-zero" | "risc-zkvm" => Ok(Self::with_risc0(stf)),
            other => Err(Error::Config(format!(
                "unsupported {PROVER_BACKEND_ENV}: {other}"
            ))),
        }
    }

    pub fn backend(&self) -> Arc<dyn ZkvmBackend> {
        self.backend.clone()
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProverApi for Prover {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn prove_block(&self, req: ProveBlockRequest) -> Result<ProofBundleResponse> {
        req.validate()?;
        let transition = req.into_transition();
        let proof = self.backend.prove_block_transition(&transition).await?;
        proof.validate()?;
        workstream_ops::PROOFS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let public_inputs = proof.public_inputs;
        let stateroot_post = H256::from_bytes(
            public_inputs
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidProof("invalid post-state root".into()))?,
        );
        Ok(ProofBundleResponse {
            version: 1,
            api_version: 1,
            proof_bytes: proof.proof_bytes,
            public_inputs,
            guest_id: proof.guest_id,
            guest_hash: proof.guest_hash,
            stateroot_pre: transition.stateroot_pre,
            stateroot_post,
            commitment: proof.commitment,
        })
    }

    async fn get_supported_guests(&self) -> Result<Vec<GuestInfo>> {
        Ok(vec![GuestInfo {
            version: 1,
            api_version: 1,
            guest_id: DEFAULT_GUEST_ID.to_string(),
            name: "workstream-stf-guest-v1".to_string(),
        }])
    }

    async fn get_prover_status(&self) -> Result<ProverStatus> {
        Ok(ProverStatus {
            version: 1,
            api_version: 1,
            available: true,
            queue_length: 0,
        })
    }
}

/// Deterministic development backend: it executes the transition from the
/// private witness state, resolves the fork at the candidate height, and
/// commits the result into a reproducible proof hash.
#[derive(Clone)]
pub struct InMemoryZkBackend {
    stf: StateTransitionFunction,
    /// Optional fixed witness used by [`InMemoryZkBackend::at`] for callers
    /// that do not populate `ProveBlockTransition::backend_witness`.
    fixed_witness: Option<(State, u64)>,
}

impl InMemoryZkBackend {
    pub fn new(stf: StateTransitionFunction) -> Self {
        Self {
            stf,
            fixed_witness: None,
        }
    }

    pub fn with_stf(stf: StateTransitionFunction) -> Self {
        Self::new(stf)
    }

    /// Bind the backend to a specific pre-state and height.
    pub fn at(state: State, height: u64, stf: StateTransitionFunction) -> Self {
        Self {
            stf,
            fixed_witness: Some((state, height)),
        }
    }

    fn witness_state(&self, transition: &ProveBlockTransition) -> Result<(State, u64)> {
        if !transition.backend_witness.is_empty() {
            return Ok((
                decode_witness(&transition.backend_witness)?,
                transition.height,
            ));
        }
        self.fixed_witness
            .clone()
            .ok_or_else(|| Error::InvalidProof("missing backend witness".into()))
    }

    /// Deterministically compute the proof envelope for a guest-program
    /// transition.
    pub fn compute_proof(&self, transition: &ProveBlockTransition) -> Result<ZkProof> {
        transition.validate()?;
        let (state, height) = self.witness_state(transition)?;
        let pre = state.root().hash();
        if pre != transition.stateroot_pre {
            return Err(Error::InvalidProof("witness pre-state mismatch".into()));
        }

        let fork = self
            .stf
            .active_fork_at(height)
            .ok_or_else(|| Error::Fork(format!("no active fork at height {height}")))?;
        if fork.guest_hash != transition.guest_hash {
            return Err(Error::InvalidProof(
                "witness guest hash is not approved for the fork".into(),
            ));
        }

        let mut draft = state;
        for tx in &transition.transactions {
            // The sequencer includes only transactions that executed
            // successfully; a failing one here means the witness/header pair
            // is inconsistent and must fail closed.
            self.stf.execute_tx_with_fork(&mut draft, tx, fork)?;
        }
        let post = draft.root().hash();
        if post != transition.stateroot_post {
            return Err(Error::InvalidProof("witness post-state mismatch".into()));
        }

        let mut material = transition.commitment_hash()?.as_bytes().to_vec();
        material.extend_from_slice(pre.as_bytes());
        material.extend_from_slice(post.as_bytes());
        material.extend_from_slice(transition.guest_hash.as_bytes());
        let proof_hash = Hash::sha256_concat(&[ZK_PROOF_TAG, &material]);

        Ok(ZkProof {
            version: 1,
            proof_bytes: proof_hash.as_bytes().to_vec(),
            public_inputs: post.as_bytes().to_vec(),
            guest_id: DEFAULT_GUEST_ID.to_string(),
            guest_hash: fork.guest_hash,
            stateroot_pre: pre,
            commitment: transition.commitment_hash()?,
        })
    }
}

#[async_trait]
impl ZkvmBackend for InMemoryZkBackend {
    async fn prove_block_transition(&self, transition: &ProveBlockTransition) -> Result<ZkProof> {
        self.compute_proof(transition)
    }

    fn verify_block_transition(
        &self,
        transition: &ProveBlockTransition,
        proof: &ZkProof,
    ) -> Result<bool> {
        transition.validate()?;
        proof.validate()?;
        let expected = self.compute_proof(transition)?;
        Ok(proof.version == expected.version
            && proof.proof_bytes == expected.proof_bytes
            && proof.public_inputs == expected.public_inputs
            && proof.guest_id == expected.guest_id
            && proof.guest_hash == expected.guest_hash
            && proof.stateroot_pre == expected.stateroot_pre
            && proof.commitment == expected.commitment)
    }
}

/// Host backend for real RISC Zero receipts. The guest image, its measured ID
/// and the fork schedule are all supplied by the caller; nothing is inferred
/// from the proof itself.
#[derive(Clone)]
pub struct RiscZeroBackend {
    stf: StateTransitionFunction,
}

impl RiscZeroBackend {
    pub fn new(stf: StateTransitionFunction) -> Self {
        Self { stf }
    }

    pub fn with_stf(stf: StateTransitionFunction) -> Self {
        Self::new(stf)
    }

    /// Compatibility constructor binding a pre-state and height; the
    /// transition's private witness remains authoritative when present.
    pub fn at(state: State, height: u64, stf: StateTransitionFunction) -> Self {
        let _ = (state, height);
        Self::new(stf)
    }

    pub fn fork_schedule(&self) -> &workstream_core::ForkSchedule {
        self.stf.fork_schedule()
    }
}

impl Default for RiscZeroBackend {
    fn default() -> Self {
        Self::new(StateTransitionFunction::new())
    }
}

#[async_trait]
impl ZkvmBackend for RiscZeroBackend {
    async fn prove_block_transition(&self, transition: &ProveBlockTransition) -> Result<ZkProof> {
        transition.validate()?;
        let state = decode_witness(&transition.backend_witness)?;
        let pre = state.root().hash();
        if pre != transition.stateroot_pre {
            return Err(Error::InvalidProof("witness pre-state mismatch".into()));
        }
        let fork = self.stf.active_fork_at(transition.height).ok_or_else(|| {
            Error::Fork(format!("no active fork at height {}", transition.height))
        })?;
        if fork.guest_hash != transition.guest_hash {
            return Err(Error::InvalidProof(
                "witness guest hash is not approved for the fork".into(),
            ));
        }

        workstream_stf::governance::check_activation(
            &state,
            self.stf.fork_schedule(),
            transition.height,
        )?;
        let mut draft = state.clone();
        for tx in &transition.transactions {
            self.stf.execute_tx_with_fork(&mut draft, tx, fork)?;
        }
        let post = draft.root().hash();
        if post != transition.stateroot_post {
            return Err(Error::InvalidProof("witness post-state mismatch".into()));
        }

        let (image, approved) = risc0::configured_image()?;
        if approved != fork.guest_hash {
            return Err(Error::InvalidProof(
                "configured guest image is not approved for the fork".into(),
            ));
        }
        let witness = workstream_stf::receipt::Witness {
            before: state.snapshot(),
            height: transition.height,
            block_hash: H256::from_bytes(transition.block_hash),
            pre,
            post,
            transactions: transition.transactions.clone(),
            schedule: self.stf.fork_schedule().clone(),
        };
        let proof_bytes =
            tokio::task::spawn_blocking(move || risc0::prove(&image, approved, &witness))
                .await
                .map_err(|e| Error::Other(e.to_string()))??;

        Ok(ZkProof {
            version: 1,
            proof_bytes,
            public_inputs: post.as_bytes().to_vec(),
            guest_id: approved.to_hex(),
            guest_hash: approved,
            stateroot_pre: pre,
            commitment: H256::from_bytes(transition.block_hash),
        })
    }

    fn verify_block_transition(
        &self,
        transition: &ProveBlockTransition,
        proof: &ZkProof,
    ) -> Result<bool> {
        transition.validate()?;
        proof.validate()?;
        if proof.stateroot_pre != transition.stateroot_pre
            || proof.guest_hash != transition.guest_hash
            || proof.commitment.as_bytes() != &transition.block_hash
            || proof.public_inputs.as_slice() != transition.stateroot_post.as_bytes()
        {
            return Ok(false);
        }
        let claim = workstream_stf::receipt::Claim::new(
            transition.height,
            H256::from_bytes(transition.block_hash),
            transition.stateroot_pre,
            transition.stateroot_post,
            &transition.transactions,
        )?;
        Ok(risc0::verify(&proof.proof_bytes, transition.guest_hash, &claim).is_ok())
    }
}

/// In-memory [`VerifierApi`] client plus the synchronous node verifier seam.
#[derive(Clone)]
pub struct InMemoryVerifier {
    backend: Arc<dyn ZkvmBackend>,
}

impl InMemoryVerifier {
    pub fn new(stf: StateTransitionFunction) -> Self {
        Self::with_backend(Arc::new(InMemoryZkBackend::new(stf)))
    }

    pub fn with_stf(stf: StateTransitionFunction) -> Self {
        Self::new(stf)
    }

    pub fn with_backend(backend: Arc<dyn ZkvmBackend>) -> Self {
        Self { backend }
    }
}

impl BlockProofVerifier for InMemoryVerifier {
    fn verify_block_transition(
        &self,
        transition: &ProveBlockTransition,
        proof: &ZkProof,
    ) -> Result<bool> {
        self.backend.verify_block_transition(transition, proof)
    }
}

impl Default for InMemoryVerifier {
    fn default() -> Self {
        Self::new(StateTransitionFunction::new())
    }
}

#[async_trait]
impl VerifierApi for InMemoryVerifier {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn verify_block(&self, req: VerifyBlockRequest) -> Result<VerifyBlockResponse> {
        req.validate()?;
        let transition = req.clone().into_transition();
        transition.validate()?;
        let proof = decode_header_proof(&Proof {
            proof_data: req.proof_bundle,
            proof_type: ProofType::ZkVm,
        })?;
        let valid = proof.commitment == H256::from_bytes(transition.block_hash)
            && proof.guest_hash == transition.guest_hash
            && proof.stateroot_pre == transition.stateroot_pre
            && proof.public_inputs == transition.stateroot_post.as_bytes().to_vec()
            && self.backend.verify_block_transition(&transition, &proof)?;
        Ok(VerifyBlockResponse {
            version: 1,
            api_version: 1,
            valid,
            error: (!valid).then(|| "zk proof verification failed".to_string()),
        })
    }

    async fn verify_proof(&self, req: VerifyProofRequest) -> Result<VerifyProofResponse> {
        req.validate()?;
        let transition = req.clone().into_transition();
        transition.validate()?;
        let proof = ZkProof {
            version: 1,
            proof_bytes: req.proof_bytes,
            public_inputs: req.public_inputs,
            guest_id: DEFAULT_GUEST_ID.to_string(),
            guest_hash: req.guest_hash,
            stateroot_pre: req.stateroot_pre,
            commitment: H256::from_bytes(req.block_hash),
        };
        let valid = self.backend.verify_block_transition(&transition, &proof)?;
        Ok(VerifyProofResponse {
            version: 1,
            api_version: 1,
            valid,
            error: (!valid).then(|| "zk proof verification failed".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_core::proof::ProofCommitment;
    use workstream_core::types::{BlockHeader, StateRoot};

    fn test_stf() -> StateTransitionFunction {
        StateTransitionFunction::new()
    }

    fn transition(state: &State, height: u64) -> ProveBlockTransition {
        let pre = state.root().hash();
        let header = BlockHeader {
            number: height,
            parent_hash: H256::from_bytes([1; 32]),
            timestamp: height * 12,
            tx_root: H256::from_bytes([2; 32]),
            state_root: state.root(),
            da_ref: H256::ZERO,
            fork_id: 1,
            guest_hash: H256::ZERO,
            proof_system_version: 1,
            proof: None,
        };
        let commitment = ProofCommitment::new(&header, pre, &[]).unwrap();
        let block_hash = *commitment.hash().unwrap().as_bytes();
        ProveBlockTransition {
            version: 1,
            height,
            block_hash,
            stateroot_pre: pre,
            stateroot_post: state.root().hash(),
            guest_hash: H256::ZERO,
            commitment,
            transactions: vec![],
            backend_witness: encode_witness(state).unwrap(),
        }
    }

    fn request(state: &State, height: u64) -> ProveBlockRequest {
        let t = transition(state, height);
        ProveBlockRequest {
            version: 1,
            api_version: 1,
            height: t.height,
            block_hash: t.block_hash,
            stateroot_pre: t.stateroot_pre,
            stateroot_post: t.stateroot_post,
            guest_hash: t.guest_hash,
            commitment: t.commitment,
            transactions: t.transactions,
            backend_witness: t.backend_witness,
        }
    }

    #[tokio::test]
    async fn in_memory_backend_proves_transition() {
        let backend = InMemoryZkBackend::new(test_stf());
        let state = State::new();
        let proof = backend
            .prove_block_transition(&transition(&state, 1))
            .await
            .unwrap();
        proof.validate().unwrap();
        assert_eq!(proof.guest_id, DEFAULT_GUEST_ID);
        assert_eq!(proof.public_inputs.len(), 32);
        assert_eq!(proof.proof_bytes.len(), 32);
        assert!(backend
            .verify_block_transition(&transition(&state, 1), &proof)
            .unwrap());
    }

    #[tokio::test]
    async fn in_memory_backend_rejects_wrong_height() {
        let backend = InMemoryZkBackend::new(test_stf());
        let state = State::new();
        let mut t = transition(&state, 1);
        t.height = 2;
        assert!(matches!(
            backend.prove_block_transition(&t).await,
            Err(Error::Validation(_)) | Err(Error::InvalidProof(_))
        ));
    }

    #[tokio::test]
    async fn prover_propagates_bundle_fields() {
        let prover = Prover::with_stf(test_stf());
        let state = State::new();
        let bundle = prover.prove_block(request(&state, 1)).await.unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.api_version, 1);
        assert_eq!(bundle.guest_hash, H256::ZERO);
        assert_eq!(bundle.stateroot_post, state.root().hash());
        assert_ne!(bundle.commitment, H256::ZERO);
    }

    #[tokio::test]
    async fn envelope_round_trip_and_tamper_detection() {
        let backend = InMemoryZkBackend::new(test_stf());
        let state = State::new();
        let proof = backend.compute_proof(&transition(&state, 1)).unwrap();
        let envelope = encode_header_proof(&proof).unwrap();
        let decoded = decode_header_proof(&envelope).unwrap();
        assert_eq!(decoded, proof);

        let mut tampered = envelope;
        tampered.proof_data[0] ^= 0xff;
        assert!(decode_header_proof(&tampered).is_err());
    }

    #[tokio::test]
    async fn verifier_rejects_tampered_envelope() {
        let backend = Arc::new(InMemoryZkBackend::new(test_stf())) as Arc<dyn ZkvmBackend>;
        let verifier = InMemoryVerifier::with_backend(backend.clone());
        let state = State::new();
        let t = transition(&state, 1);
        let mut proof = backend.prove_block_transition(&t).await.unwrap();
        proof.proof_bytes[0] ^= 0xff;
        let envelope = encode_header_proof(&proof).unwrap();

        let response = verifier
            .verify_block(VerifyBlockRequest {
                version: 1,
                api_version: 1,
                height: t.height,
                block_hash: t.block_hash,
                proof_bundle: envelope.proof_data,
                stateroot_pre: t.stateroot_pre,
                stateroot_post: t.stateroot_post,
                guest_hash: t.guest_hash,
                commitment: t.commitment,
                transactions: t.transactions,
                backend_witness: t.backend_witness,
            })
            .await
            .unwrap();
        assert!(!response.valid);
    }

    #[tokio::test]
    async fn risc0_backend_rejects_wrong_prestate_before_config() {
        let backend = RiscZeroBackend::default();
        let mut t = transition(&State::new(), 1);
        t.stateroot_pre = H256::from_bytes([9; 32]);
        assert!(matches!(
            backend.prove_block_transition(&t).await,
            Err(Error::Validation(_)) | Err(Error::InvalidProof(_))
        ));
    }

    #[test]
    fn header_proof_rejects_wrong_type() {
        let proof = Proof {
            proof_data: vec![0; 8],
            proof_type: ProofType::Recursive,
        };
        assert!(decode_header_proof(&proof).is_err());
        let _ = StateRoot::new(H256::ZERO, H256::ZERO);
    }
}
