//! Single-writer local relay store. Keep the directory private: the snapshot
//! contains note openings. Use one directory per chain and bridge instance.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use tempfile::NamedTempFile;

use super::*;

const FILE: &str = "escrows.v1";
// Keep the original path so create() cannot reset a pre-authentication store.
const MAGIC: &[u8] = b"WS:bridge:v2\0";

#[derive(Serialize, Deserialize)]
struct Snapshot {
    authority: DepositAuthority,
    receipts: BTreeSet<H256>,
    rows: Vec<BridgeEscrow>,
}

/// Each successful mutation is durable before its result is returned.
/// The lock file is never renamed; process death releases the OS lock.
pub struct DurableBridgePool {
    directory: PathBuf,
    authority: DepositAuthority,
    _lock: File,
}

impl DurableBridgePool {
    /// Initialize an empty store in an existing, private directory.
    /// Refuses to replace an existing snapshot.
    pub fn create(directory: &Path, authority: DepositAuthority) -> Result<Self> {
        let store = Self::lock(directory, authority)?;
        let file = directory.join(FILE);
        if file.try_exists().map_err(io_error)? {
            return Err(Error::State("bridge store already exists".into()));
        }
        store.save(&BridgePool::new())?;
        Ok(store)
    }

    /// Resume an existing store. Missing or corrupt data is never treated as
    /// an empty pool (which would discard its replay protection).
    pub fn open(directory: &Path, authority: DepositAuthority) -> Result<Self> {
        let store = Self::lock(directory, authority)?;
        store.load()?;
        Ok(store)
    }

    fn lock(directory: &Path, authority: DepositAuthority) -> Result<Self> {
        authority.key()?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("bridge.lock"))
            .map_err(io_error)?;
        FileExt::try_lock_exclusive(&lock).map_err(io_error)?;
        Ok(Self {
            authority,
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
        let (snapshot, rest) = postcard::take_from_bytes::<Snapshot>(payload)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        if !rest.is_empty() {
            return Err(Error::State("trailing bridge snapshot data".into()));
        }
        if snapshot.authority != self.authority || snapshot.receipts.len() != snapshot.rows.len() {
            return Err(Error::State(
                "bridge authority or receipt index mismatch".into(),
            ));
        }
        let mut pool = BridgePool {
            consumed_receipts: snapshot.receipts,
            ..BridgePool::new()
        };
        for escrow in snapshot.rows {
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
        let mut rows: Vec<_> = pool.escrows.values().cloned().collect();
        rows.sort_unstable_by_key(|e| e.escrow_id);
        let payload = postcard::to_allocvec(&Snapshot {
            authority: self.authority,
            receipts: pool.consumed_receipts.clone(),
            rows,
        })
        .map_err(|e| Error::Serialization(e.to_string()))?;
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

    /// Verify before funding. The replay marker and escrow are committed by
    /// the same snapshot replacement, regardless of escrow type.
    pub fn accept_deposit(
        &mut self,
        receipt: &DepositReceipt,
        signature: &[u8; 64],
        note: ShieldedNote,
    ) -> Result<H256> {
        receipt.verify(&self.authority, signature, &note)?;
        self.update(|pool| {
            if !pool.consumed_receipts.insert(receipt.source_event) {
                return Err(Error::InvalidTransition(
                    "deposit receipt already consumed".into(),
                ));
            }
            match receipt.task {
                Some(task) => pool.deposit_task(
                    task,
                    receipt.recipient,
                    receipt.amount,
                    receipt.asset.clone(),
                    receipt.amount,
                    note,
                ),
                None => pool.deposit(
                    receipt.asset.clone(),
                    receipt.amount,
                    receipt.recipient,
                    note,
                ),
            }
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::AssetKind;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn only_an_authenticated_unused_receipt_can_change_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let key = SigningKey::from_bytes(&[3; 32]);
        let other = SigningKey::from_bytes(&[4; 32]);
        let authority = DepositAuthority {
            public_key: key.verifying_key().to_bytes(),
            domain: H256::from_bytes([5; 32]),
        };
        let note = ShieldedNote::new(H256::ZERO, 123, H256::from_bytes([6; 32]));
        let receipt = DepositReceipt {
            domain: authority.domain,
            source_event: H256::from_bytes([7; 32]),
            asset: Asset {
                kind: AssetKind::BridgedStablecoin,
                id: note.asset,
            },
            amount: note.amount,
            recipient: H256::from_bytes([8; 32]),
            task: None,
            note_commitment: note.commitment(),
        };
        let sign = |r: &DepositReceipt, k: &SigningKey| {
            k.sign(r.signing_digest().unwrap().as_bytes()).to_bytes()
        };
        let sig = sign(&receipt, &key);
        let altered = DepositReceipt {
            task: Some(H256::ZERO),
            ..receipt.clone()
        };
        let snapshot = || std::fs::read(path.join(FILE)).unwrap();
        let reject_invalid = |store: &mut DurableBridgePool| {
            let before = snapshot();
            assert!(matches!(
                store.accept_deposit(&receipt, &sign(&receipt, &other), note.clone()),
                Err(Error::InvalidSignature)
            ));
            assert!(matches!(
                store.accept_deposit(&altered, &sig, note.clone()),
                Err(Error::InvalidSignature)
            ));
            let foreign = DepositReceipt {
                domain: H256::ZERO,
                ..receipt.clone()
            };
            assert!(matches!(
                store.accept_deposit(&foreign, &sign(&foreign, &key), note.clone()),
                Err(Error::Unauthorized(_))
            ));
            assert_eq!(snapshot(), before);
        };
        let mut store = DurableBridgePool::create(path, authority).unwrap();
        reject_invalid(&mut store);
        let id = store.accept_deposit(&receipt, &sig, note.clone()).unwrap();
        let funded = snapshot();
        assert_eq!(store.load().unwrap().len(), 1);
        assert!(matches!(
            store.accept_deposit(&receipt, &sig, note.clone()),
            Err(Error::InvalidTransition(_))
        ));
        assert_eq!(snapshot(), funded);
        drop(store);
        assert!(DurableBridgePool::open(
            path,
            DepositAuthority {
                public_key: other.verifying_key().to_bytes(),
                ..authority
            }
        )
        .is_err());
        let mut store = DurableBridgePool::open(path, authority).unwrap();
        reject_invalid(&mut store);
        assert!(matches!(
            store.accept_deposit(&receipt, &sig, note.clone()),
            Err(Error::InvalidTransition(_))
        ));
        // Even another authentic receipt for a distinct note cannot reuse the
        // same source event, independent of the note/escrow uniqueness checks.
        let second = ShieldedNote {
            blinding: H256::ZERO,
            ..note
        };
        let duplicate = DepositReceipt {
            note_commitment: second.commitment(),
            ..altered
        };
        assert!(matches!(
            store.accept_deposit(&duplicate, &sign(&duplicate, &key), second),
            Err(Error::InvalidTransition(_))
        ));
        assert_eq!(snapshot(), funded);
        assert_eq!(store.get(&id).unwrap().unwrap().amount, 123);
    }
}
