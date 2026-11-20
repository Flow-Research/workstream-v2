//! Restore a fresh verifier from a verified block archive and a checkpoint hint.
//!
//! The checkpoint is never trusted to skip verification. Every archived block
//! is replayed from genesis with attached proof verification; only then are the
//! resulting tip and state root compared with the operator-supplied checkpoint.
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::Deserialize;
use workstream_core::types::{Block, BlockNumber, StateRoot};
use workstream_core::{Error, Result, H256};
use workstream_node::{BlockSource, Node};

#[derive(Parser, Debug)]
#[command(name = "workstream-restore")]
#[command(about = "Verify and restore a node from an immutable block archive")]
struct Args {
    /// Directory containing manifest.json and <height>.json block files.
    #[arg(long)]
    archive: PathBuf,
    /// Externally supplied checkpoint: height, state_root and optional da_ref.
    #[arg(long)]
    checkpoint: PathBuf,
    /// Optional directory in which to persist the restored verifier state.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct ArchiveManifest {
    version: u32,
    blocks: Vec<ArchiveEntry>,
}

#[derive(Debug, Deserialize)]
struct ArchiveEntry {
    height: BlockNumber,
    da_ref: H256,
}

#[derive(Debug, Deserialize)]
struct TrustedCheckpoint {
    height: BlockNumber,
    state_root: StateRoot,
    da_ref: Option<H256>,
}

#[derive(Default)]
struct ArchiveSource {
    blocks: Vec<Block>,
    next: usize,
}

impl BlockSource for ArchiveSource {
    fn next_block(&mut self, next_height: BlockNumber) -> Option<Block> {
        let block = self.blocks.get(self.next)?;
        if block.header.number != next_height {
            return None;
        }
        self.next += 1;
        Some(block.clone())
    }

    fn block_at(&self, height: BlockNumber) -> Option<Block> {
        self.blocks
            .iter()
            .find(|block| block.header.number == height)
            .cloned()
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::Io(format!("reading {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Serialization(format!("decoding {}: {e}", path.display())))
}

fn load_archive(dir: &Path) -> Result<ArchiveSource> {
    let manifest: ArchiveManifest = read_json(&dir.join("manifest.json"))?;
    if manifest.version != 1 || manifest.blocks.is_empty() {
        return Err(Error::VersionMismatch(
            "unsupported archive manifest".into(),
        ));
    }
    let mut blocks = Vec::with_capacity(manifest.blocks.len());
    for (index, entry) in manifest.blocks.iter().enumerate() {
        let expected = index as BlockNumber + 1;
        if entry.height != expected || entry.da_ref == H256::ZERO {
            return Err(Error::Validation(format!(
                "archive entry {expected} has an invalid height or DA reference"
            )));
        }
        let block: Block = read_json(&dir.join(format!("{:08}.json", entry.height)))?;
        if block.header.number != entry.height || block.header.da_ref != entry.da_ref {
            return Err(Error::Validation(format!(
                "archive block {} does not match its manifest reference",
                entry.height
            )));
        }
        blocks.push(block);
    }
    Ok(ArchiveSource { blocks, next: 0 })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let archive = load_archive(&args.archive)?;
    let checkpoint: TrustedCheckpoint = read_json(&args.checkpoint)?;
    let (stf, prover) = workstream_prover::runtime::load()?;
    let schedule = stf.fork_schedule().clone();
    let mut node = Node::with_backend(stf, schedule, archive, prover.backend()).require_proof();
    let applied = node.sync()?;
    if applied.len() != checkpoint.height as usize {
        return Err(Error::State(format!(
            "archive synced {} blocks but checkpoint expects {}",
            applied.len(),
            checkpoint.height
        )));
    }
    if node.tip() != checkpoint.height || node.state_root() != checkpoint.state_root {
        return Err(Error::Determinism(format!(
            "restored tip {}, root {} disagrees with trusted checkpoint height {}, root {}",
            node.tip(),
            node.state_root().hash(),
            checkpoint.height,
            checkpoint.state_root.hash()
        )));
    }
    let restored_ref = node
        .last_header()
        .map(|header| header.da_ref)
        .ok_or_else(|| Error::State("restored chain has no tip header".into()))?;
    if checkpoint
        .da_ref
        .is_some_and(|expected| expected != restored_ref)
    {
        return Err(Error::Determinism(
            "restored DA reference disagrees with trusted checkpoint".into(),
        ));
    }
    if let Some(out) = args.out.as_deref() {
        node.save_state(out)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "height": node.tip(),
            "state_root": node.state_root(),
            "da_ref": restored_ref,
            "verified_blocks": applied.len(),
        })
    );
    Ok(())
}
