//! One SQLite database per chain; COMMIT is the durable acknowledgement boundary.
use super::*;
use rusqlite::{params, Connection, OptionalExtension};
use workstream_core::{Error, H256};
use workstream_state::State;

pub(super) struct Journal(Connection);
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
            CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), snapshot BLOB NOT NULL);").map_err(db)?;
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
    pub(super) fn finish(&mut self, id: H256, block: &Block, seq: &Sequencer) -> Result<()> {
        let status = match block.transactions.as_slice() {
            [] => "Rejected",
            [tx] if crate::tx_hash(tx)? == id => "Published",
            _ => return Err(Error::State("admission batch identity mismatch".into())),
        };
        let t = self.0.transaction().map_err(db)?;
        t.execute(
            "INSERT INTO blocks VALUES(?,?)",
            params![block.header.number, encode(block)?],
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
