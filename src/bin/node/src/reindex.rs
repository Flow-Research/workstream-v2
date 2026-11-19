//! Wipe and rebuild PostgreSQL projections from verifier-accepted blocks.
//!
//! The immutable `verified_blocks` log is replayed through the same full
//! verification path used by the connected node. Derived tables and the
//! cursor are reset in one transaction first, so a crash during rebuild leaves
//! a safe incomplete cursor rather than a partially updated projection.
use workstream_core::Result;
use workstream_node::projection::{Projection, ProjectionInput};
use workstream_node::{MemoryBlockSource, Node};

#[tokio::main]
async fn main() -> Result<()> {
    let (stf, prover) = workstream_prover::runtime::load()?;
    let chain = stf.fork_schedule().chain_id;
    let schedule = stf.fork_schedule().clone();
    let projection = Projection::open(chain).await?.ok_or_else(|| {
        workstream_core::Error::Config("projection database is not configured".into())
    })?;
    let blocks = projection.reset().await?;
    let mut node = Node::with_backend(stf, schedule, MemoryBlockSource::new(), prover.backend())
        .require_proof();

    for block in blocks {
        let verified = block.clone();
        let ids = verified
            .transactions
            .iter()
            .map(workstream_sequencer::tx_hash)
            .collect::<Result<Vec<_>>>()?;
        let applied = node.apply_block(block)?;
        projection
            .apply(ProjectionInput {
                height: applied.height,
                state_root: &applied.state_root,
                da_ref: verified.header.da_ref,
                block: &verified,
                events: &applied.events,
                tx_hashes: &ids,
            })
            .await?;
    }

    let status = projection.status().await?;
    println!(
        "{}",
        serde_json::json!({
            "chain": status.chain,
            "verified_height": status.verified_height,
            "indexed_height": status.indexed_height,
            "lag": status.lag,
            "indexed_state_root": status.indexed_state_root,
            "indexed_da_ref": status.indexed_da_ref,
        })
    );
    Ok(())
}
