//! Single-writer local relay store. Keep the directory private: the snapshot
//! contains note openings. Use one directory per chain and bridge instance.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use tempfile::NamedTempFile;

use super::*;

const FILE: &str = "escrows.v1";
const MAGIC: &[u8] = b"WS:bridge:v1\0";

/// Each successful mutation is durable before its result is returned.
/// The lock file is never renamed; process death releases the OS lock.
pub struct DurableBridgePool {
    directory: PathBuf,
    _lock: File,
}

impl DurableBridgePool {
    /// Initialize an empty store in an existing, private directory.
    /// Refuses to replace an existing snapshot.
    pub fn create(directory: &Path) -> Result<Self> {
        let store = Self::lock(directory)?;
        let file = directory.join(FILE);
        if file.try_exists().map_err(io_error)? {
            return Err(Error::State("bridge store already exists".into()));
        }
        store.save(&BridgePool::new())?;
        Ok(store)
    }

    /// Resume an existing store. Missing or corrupt data is never treated as
    /// an empty pool (which would discard its replay protection).
    pub fn open(directory: &Path) -> Result<Self> {
        let store = Self::lock(directory)?;
        store.load()?;
        Ok(store)
    }

    fn lock(directory: &Path) -> Result<Self> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("bridge.lock"))
            .map_err(io_error)?;
        FileExt::try_lock_exclusive(&lock).map_err(io_error)?;
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
        })
    }

    fn load(&self) -> Result<BridgePool> {
        let bytes = std::fs::read(self.directory.join(FILE)).map_err(io_error)?;
        let (checksum, payload) = bytes
            .strip_prefix(MAGIC)
            .and_then(|b| b.split_at_checked(32))
            .ok_or_else(|| Error::State("invalid bridge snapshot header".into()))?;
        if Hash::sha256(payload).as_bytes() != checksum {
            return Err(Error::State("bridge snapshot checksum mismatch".into()));
        }
        let (rows, rest) = postcard::take_from_bytes::<Vec<BridgeEscrow>>(payload)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        if !rest.is_empty() {
            return Err(Error::State("trailing bridge snapshot data".into()));
        }
        let mut pool = BridgePool::new();
        for escrow in rows {
            let expected = escrow.task.map_or_else(
                || escrow.note.commitment(),
                |task| BridgePool::payout_escrow_id(task, escrow.recipient, escrow.amount),
            );
            if expected != escrow.escrow_id || escrow.amount == 0 {
                return Err(Error::State("invalid stored escrow".into()));
            }
            pool.insert_escrow(escrow)?;
        }
        Ok(pool)
    }

    fn save(&self, pool: &BridgePool) -> Result<()> {
        let mut rows: Vec<_> = pool.escrows.values().collect();
        rows.sort_unstable_by_key(|e| e.escrow_id);
        let payload =
            postcard::to_allocvec(&rows).map_err(|e| Error::Serialization(e.to_string()))?;
        let mut tmp = NamedTempFile::new_in(&self.directory).map_err(io_error)?;
        tmp.write_all(MAGIC)
            .and_then(|()| tmp.write_all(Hash::sha256(&payload).as_bytes()))
            .and_then(|()| tmp.write_all(&payload))
            .map_err(io_error)?;
        tmp.as_file().sync_all().map_err(io_error)?;
        tmp.persist(self.directory.join(FILE))
            .map_err(|e| io_error(e.error))?;
        File::open(&self.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(io_error)
    }

    fn update<T>(&mut self, mutate: impl FnOnce(&mut BridgePool) -> Result<T>) -> Result<T> {
        let mut pool = self.load()?;
        let result = mutate(&mut pool)?;
        self.save(&pool)?;
        Ok(result)
    }

    pub fn deposit(
        &mut self,
        asset: Asset,
        amount: u128,
        recipient: AccountId,
        note: ShieldedNote,
    ) -> Result<H256> {
        self.update(|pool| pool.deposit(asset, amount, recipient, note))
    }

    pub fn deposit_task(
        &mut self,
        task: TaskId,
        worker: AccountId,
        award: u128,
        asset: Asset,
        note: ShieldedNote,
    ) -> Result<H256> {
        self.update(|pool| pool.deposit_task(task, worker, award, asset, note.amount, note))
    }

    pub fn release(&mut self, id: H256, recipient: AccountId) -> Result<BridgeEscrow> {
        self.update(|pool| pool.release(id, recipient))
    }

    /// Consume the funded escrow exactly once locally. External settlement
    /// must use its own idempotent delivery protocol.
    pub fn apply_finalized_award(&mut self, event: &Event) -> Result<BridgeEscrow> {
        self.update(|pool| pool.apply_finalized_award(event))
    }

    pub fn get(&self, id: &H256) -> Result<Option<BridgeEscrow>> {
        Ok(self.load()?.escrows.remove(id))
    }
}

fn io_error(error: io::Error) -> Error {
    Error::Io(format!("bridge store: {error}"))
}
