//! One SQLite database per chain; COMMIT is the durable acknowledgement boundary.
use super::*;
use rusqlite::{params, Connection, OptionalExtension};
use workstream_core::{Error, H256};
use workstream_state::State;

pub(super) struct Journal(Connection);

/// Durable publication intent for one canonical block height.
#[derive(Debug)]
pub(super) struct Publication {
    pub(super) da_ref: H256,
    pub(super) block: Block,
}

fn db(e: rusqlite::Error) -> Error {
    Error::Io(format!("admission journal: {e}"))
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(v).map_err(|e| Error::Serialization(e.to_string()))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    postcard::from_bytes(bytes).map_err(|e| Error::Serialization(e.to_string()))
}

impl Journal {
    pub(super) fn open(dir: &Path, chain: u64) -> Result<Self> {
        let c = Connection::open(dir.join(format!("chain-{chain}.sqlite"))).map_err(db)?;
        c.execute_batch("PRAGMA synchronous=EXTRA;
            CREATE TABLE IF NOT EXISTS admissions(id BLOB UNIQUE NOT NULL, signed BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN ('Pending','Published','Rejected')), height INTEGER);
            CREATE INDEX IF NOT EXISTS queue ON admissions(status);
            CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, block BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS block_refs(height INTEGER PRIMARY KEY, da_ref BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), snapshot BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoint_meta(id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL, state_root BLOB NOT NULL, da_ref BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS publications(height INTEGER PRIMARY KEY, da_ref BLOB NOT NULL, block BLOB NOT NULL, accepted INTEGER NOT NULL DEFAULT 0 CHECK(accepted IN (0,1)));").map_err(db)?;
        // Backfill references for journals created before object DA existed.
        let published: Vec<(u64, Vec<u8>)> = c
            .prepare("SELECT height,block FROM blocks")
            .map_err(db)?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(db)?
            .collect::<std::result::Result<_, _>>()
            .map_err(db)?;
        for (height, bytes) in published {
            let block: Block = decode(&bytes)?;
            c.execute(
                "INSERT OR IGNORE INTO block_refs(height,da_ref) VALUES(?,?)",
                params![height, block.header.da_ref.as_bytes().as_slice()],
            )
            .map_err(db)?;
        }
        Ok(Self(c))
    }
    pub(super) fn restore(&self, seq: &mut Sequencer) -> Result<()> {
        let snapshot: Option<Vec<u8>> = self
            .0
            .query_row("SELECT snapshot FROM checkpoint WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)?;
        if let Some(bytes) = snapshot {
            let state = State::from_snapshot(decode(&bytes)?)?;
            seq.last_header = state.last_header.clone();
            seq.state = state;
        }
        // The snapshot is a local hint, not an authority. Its metadata must
        // agree with the header and the recomputed state root before any
        // pending admission is replayed.
        let meta: Option<(u64, Vec<u8>, Vec<u8>)> = self
            .0
            .query_row(
                "SELECT height,state_root,da_ref FROM checkpoint_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        if let Some((height, state_root, da_ref)) = meta {
            let actual_root = encode(&seq.state().root())?;
            let actual_da_ref = seq
                .last_header
                .as_ref()
                .map(|h| h.da_ref)
                .unwrap_or(H256::ZERO);
            if height != seq.tip()
                || state_root != actual_root
                || da_ref != actual_da_ref.as_bytes().as_slice()
            {
                return Err(Error::Determinism(
                    "checkpoint snapshot disagrees with its committed metadata".into(),
                ));
            }
        }
        let mut stmt = self
            .0
            .prepare("SELECT id,signed FROM admissions WHERE status='Pending' ORDER BY rowid")
            .map_err(db)?;
        let mut rows = stmt.query([]).map_err(db)?;
        while let Some(row) = rows.next().map_err(db)? {
            let id: Vec<u8> = row.get(0).map_err(db)?;
            let bytes: Vec<u8> = row.get(1).map_err(db)?;
            if seq.submit_tx(decode(&bytes)?)?.as_bytes().as_slice() != id {
                return Err(Error::State("journal transaction identity mismatch".into()));
            }
        }
        Ok(())
    }
    pub(super) fn receipt(&self, id: H256) -> Result<Receipt> {
        let found = self
            .0
            .query_row(
                "SELECT status,height FROM admissions WHERE id=?",
                [id.as_bytes().as_slice()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<u64>>(1)?)),
            )
            .optional()
            .map_err(db)?;
        let (status, height) = found.unwrap_or(("Unknown".into(), None));
        Ok(Receipt {
            tx_hash: id,
            status,
            height,
        })
    }
    pub(super) fn admit(&self, seq: &mut Sequencer, tx: Transaction) -> Result<Receipt> {
        if tx.chain_id != seq.stf.fork_schedule().chain_id {
            return Err(Error::Transaction("wrong admission chain".into()));
        }
        let id = crate::tx_hash(&tx)?;
        let receipt = self.receipt(id)?;
        if receipt.status != "Unknown" {
            return Ok(receipt);
        }
        let bytes = encode(&tx)?;
        // Validate and reserve before persisting, without installing speculative state.
        seq.mempool.check_admission(&tx)?;
        self.0
            .execute(
                "INSERT INTO admissions(id,signed,status) VALUES(?,?,'Pending')",
                params![id.as_bytes().as_slice(), bytes],
            )
            .map_err(db)?;
        seq.mempool.enqueue_checked(id, tx);
        Ok(Receipt {
            tx_hash: id,
            status: "Pending".into(),
            height: None,
        })
    }
    /// Return a previously recorded publication intent for `height`.
    pub(super) fn publication(&self, height: u64) -> Result<Option<Publication>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .0
            .query_row(
                "SELECT da_ref,block FROM publications WHERE height=?",
                [height],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(da_ref, bytes)| {
            let array: [u8; 32] = da_ref
                .try_into()
                .map_err(|_| Error::State("publication reference length mismatch".into()))?;
            Ok(Publication {
                da_ref: H256::from_bytes(array),
                block: decode(&bytes)?,
            })
        })
        .transpose()
    }

    /// Record the stable publication key before the external DA write.
    ///
    /// Replaying a pending admission after a crash must reproduce the exact
    /// same key and bytes. Any divergence is a determinism failure, never a
    /// second publication under a different logical object.
    pub(super) fn record_publication(&self, block: &Block) -> Result<()> {
        if block.header.da_ref == H256::ZERO {
            return Err(Error::State("publication key is not committed".into()));
        }
        let bytes = encode(block)?;
        if let Some(existing) = self.publication(block.header.number)? {
            if existing.da_ref != block.header.da_ref || encode(&existing.block)? != bytes {
                return Err(Error::Determinism(format!(
                    "publication replay diverged at height {}",
                    block.header.number
                )));
            }
            return Ok(());
        }
        self.0
            .execute(
                "INSERT INTO publications(height,da_ref,block) VALUES(?,?,?)",
                params![
                    block.header.number,
                    block.header.da_ref.as_bytes().as_slice(),
                    bytes
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    pub(super) fn finish(&mut self, id: H256, block: &Block, seq: &Sequencer) -> Result<()> {
        let status = match block.transactions.as_slice() {
            [] => "Rejected",
            [tx] if crate::tx_hash(tx)? == id => "Published",
            _ => return Err(Error::State("admission batch identity mismatch".into())),
        };
        let t = self.0.transaction().map_err(db)?;
        let block_bytes = encode(block)?;
        let published: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row(
                "SELECT da_ref,block FROM publications WHERE height=?",
                [block.header.number],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        match published {
            Some((da_ref, bytes)) => {
                if da_ref != block.header.da_ref.as_bytes().as_slice() || bytes != block_bytes {
                    return Err(Error::Determinism(format!(
                        "local commit disagrees with publication at height {}",
                        block.header.number
                    )));
                }
            }
            None => {
                t.execute(
                    "INSERT INTO publications(height,da_ref,block,accepted) VALUES(?,?,?,1)",
                    params![
                        block.header.number,
                        block.header.da_ref.as_bytes().as_slice(),
                        block_bytes
                    ],
                )
                .map_err(db)?;
            }
        }
        t.execute(
            "INSERT INTO blocks VALUES(?,?)",
            params![block.header.number, block_bytes],
        )
        .map_err(db)?;
        t.execute(
            "INSERT OR REPLACE INTO block_refs(height,da_ref) VALUES(?,?)",
            params![
                block.header.number,
                block.header.da_ref.as_bytes().as_slice()
            ],
        )
        .map_err(db)?;
        t.execute(
            "INSERT OR REPLACE INTO checkpoint VALUES(1,?)",
            [encode(&seq.state.snapshot())?],
        )
        .map_err(db)?;
        t.execute(
            "INSERT OR REPLACE INTO checkpoint_meta(id,height,state_root,da_ref) VALUES(1,?,?,?)",
            params![
                block.header.number,
                encode(&seq.state().root())?,
                block.header.da_ref.as_bytes().as_slice()
            ],
        )
        .map_err(db)?;
        t.execute(
            "UPDATE publications SET accepted=1 WHERE height=?",
            [block.header.number],
        )
        .map_err(db)?;
        if t.execute(
            "UPDATE admissions SET status=?,height=? WHERE id=? AND status='Pending'",
            params![status, block.header.number, id.as_bytes().as_slice()],
        )
        .map_err(db)?
            != 1
        {
            return Err(Error::State("missing pending receipt".into()));
        }
        t.commit().map_err(db)
    }
    pub(super) fn block(&self, height: u64) -> Result<Option<Block>> {
        let bytes: Option<Vec<u8>> = self
            .0
            .query_row("SELECT block FROM blocks WHERE height=?", [height], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)?;
        bytes.map(|b| decode(&b)).transpose()
    }
    pub(super) fn da_ref(&self, height: u64) -> Result<Option<H256>> {
        let bytes: Option<Vec<u8>> = self
            .0
            .query_row(
                "SELECT da_ref FROM block_refs WHERE height=?",
                [height],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        bytes
            .map(|bytes| {
                let array: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| Error::State("journal DA reference length mismatch".into()))?;
                Ok(H256::from_bytes(array))
            })
            .transpose()
    }
    pub(super) fn queue(&self) -> Result<(u64, u64)> {
        self.0.query_row("SELECT count(*),coalesce(sum(length(signed)),0) FROM admissions WHERE status='Pending'",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(db)
    }
}
