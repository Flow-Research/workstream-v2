//! Durable delivery outbox for verified chain events (issue #137).
//!
//! Verified events are durably recorded here before any notification provider
//! is contacted. Delivery identities are derived from immutable event content
//! (event type, recipient and subject), so a retry after a provider failure
//! reuses the same delivery instead of creating a second one.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rusqlite::{params, Connection, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use workstream_core::{Error, Result};

pub type DeliveryResult = std::result::Result<(), String>;

pub const EVENT_REVIEW_DECIDED: &str = "review.decided";
pub const EVENT_ACCEPT_FINALIZED: &str = "accept.finalized";

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_DELIVERED: &str = "delivered";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_OPTED_OUT: &str = "opted_out";

/// Initial retry delay after a failed delivery; doubles per attempt, capped.
const DELIVERY_BACKOFF_SECS: i64 = 30;
const MAX_BACKOFF_SECS: i64 = 3600;
/// Webhook signature timestamp tolerance (five minutes).
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// Public, provider-safe notification content for a verified event.
///
/// Notifications deliberately carry decision metadata and a canonical status
/// link only. Witnesses, signing material, raw payloads and private evidence
/// bytes never enter an outbound notification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notification {
    pub event_type: String,
    pub chain: String,
    pub block_number: u64,
    pub tx_index: u32,
    pub subject: String,
    pub decision: Option<String>,
    pub canonical_link: String,
}

impl Notification {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_type: impl Into<String>,
        chain: impl Into<String>,
        block_number: u64,
        tx_index: u32,
        subject: impl Into<String>,
        decision: Option<String>,
        canonical_link: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            chain: chain.into(),
            block_number,
            tx_index,
            subject: subject.into(),
            decision,
            canonical_link: canonical_link.into(),
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::Serialization(e.to_string()))
    }
}

/// One durable delivery target. Retries keep the same delivery identity.
#[derive(Clone, Debug)]
pub struct Delivery {
    pub delivery_id: String,
    pub event_type: String,
    pub subject: String,
    pub recipient: String,
    pub notification_json: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub last_error: Option<String>,
}

/// Sends one verified notification. Returning `Err` schedules a durable
/// retry that preserves the same delivery identity.
#[async_trait]
pub trait DeliverySink: Send + Sync {
    async fn deliver(&self, delivery: &Delivery) -> DeliveryResult;
}

/// HTTP sink for signed webhook providers. Each delivery is signed over
/// `delivery_id.timestamp.body`; providers must validate that signature before
/// accepting the event.
pub struct WebhookSink {
    url: String,
    secret: String,
    client: reqwest::Client,
}

impl WebhookSink {
    pub fn new(url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            secret: secret.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl DeliverySink for WebhookSink {
    async fn deliver(&self, delivery: &Delivery) -> DeliveryResult {
        let body = delivery.notification_json.clone();
        let timestamp = now_secs();
        let signature = sign_delivery(&self.secret, &delivery.delivery_id, timestamp, &body);
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("X-Workstream-Delivery", &delivery.delivery_id)
            .header("X-Workstream-Signature", &signature)
            .body(delivery.notification_json.clone())
            .send()
            .await
            .map_err(|e| format!("webhook delivery failed: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("webhook provider returned status {status}"));
        }
        Ok(())
    }
}

/// Canonical status link for a finalized accept: the durable receipt of the
/// accepting transaction. Verification status lives behind the same chain, so
/// the link never embeds witnesses or private evidence.
pub fn canonical_receipt_link(tx_hash: &str) -> String {
    format!("/explorer?kind=receipt&key={tx_hash}")
}

/// Canonical status link for an independent review decision.
pub fn canonical_review_link(submission: &str) -> String {
    format!("/review?submission={submission}")
}

/// Opt-in subscriber set for verified-event notifications. Delivery targets
/// are operator-configured; an empty set disables notification delivery.
pub fn configured_subscribers() -> Vec<String> {
    std::env::var("WORKSTREAM_NOTIFICATION_SUBSCRIBERS")
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
        .unwrap_or_default()
}

/// Stable delivery identity for one event/recipient pair. Immutable event
/// content plus recipient selection keep the id stable across retries.
pub fn delivery_id(event_type: &str, recipient: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"WS:v1:notif:dl:v1");
    hasher.update(event_type.as_bytes());
    hasher.update([0]);
    hasher.update(recipient.as_bytes());
    hasher.update([0]);
    hasher.update(subject.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    format!("0x{}", hex::encode(bytes))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sign a delivery for a webhook provider over `delivery_id.timestamp.body`.
pub fn sign_delivery(secret: &str, delivery_id: &str, timestamp: i64, body: &str) -> String {
    format!(
        "sha256={}",
        hex::encode(hmac_sha256(
            secret.as_bytes(),
            format!("{delivery_id}.{timestamp}.{body}").as_bytes()
        ))
    )
}

/// Validate a signed delivery. The signature covers the delivery id, a
/// timestamp and the exact notification body; freshness is bounded.
pub fn verify_delivery_signature(
    secret: &str,
    delivery_id: &str,
    timestamp: i64,
    signature: &str,
    body: &str,
    now_secs: i64,
) -> bool {
    let Some(expected) = signature.strip_prefix("sha256=") else {
        return false;
    };
    let actual = hex::encode(hmac_sha256(
        secret.as_bytes(),
        format!("{delivery_id}.{timestamp}.{body}").as_bytes(),
    ));
    if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
        return false;
    }
    (now_secs - timestamp).abs() <= SIGNATURE_TOLERANCE_SECS
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed: [u8; 32] = Sha256::digest(key).into();
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out: [u8; 32] = outer.finalize().into();
    out
}

/// SQLite-backed durable outbox. One row per stable delivery identity.
#[derive(Debug)]
pub struct Outbox {
    db: Mutex<Connection>,
}

impl Outbox {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path)
            .map_err(|e| Error::Io(format!("notifications outbox open: {e}")))?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS deliveries (
                delivery_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                recipient TEXT NOT NULL,
                notification TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending','delivered','failed','opted_out')),
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,
                last_error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS deliveries_pending ON deliveries(status, next_attempt_at);
            CREATE TABLE IF NOT EXISTS opt_outs (
                event_type TEXT NOT NULL,
                recipient TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (event_type, recipient)
            );",
        )
        .map_err(|e| Error::Io(format!("notifications outbox schema: {e}")))?;
        Ok(Self { db: Mutex::new(db) })
    }

    fn lock(&self) -> std::result::Result<std::sync::MutexGuard<'_, Connection>, Error> {
        self.db
            .lock()
            .map_err(|_| Error::Io("notifications outbox lock".to_string()))
    }

    fn row_to_delivery(row: &Row<'_>) -> Result<Delivery> {
        Ok(Delivery {
            delivery_id: row
                .get(0)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            event_type: row
                .get(1)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            subject: row
                .get(2)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            recipient: row
                .get(3)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            notification_json: row
                .get(4)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            status: row
                .get(5)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            attempts: row
                .get(6)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            next_attempt_at: row
                .get(7)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
            last_error: row
                .get(8)
                .map_err(|e| Error::Io(format!("notifications delivery read: {e}")))?,
        })
    }

    /// Read one delivery through the caller-held connection guard.
    fn delivery_on(db: &Connection, delivery_id: &str) -> Result<Option<Delivery>> {
        let delivery = db
            .query_row(
                "SELECT delivery_id,event_type,subject,recipient,notification,status,attempts,next_attempt_at,last_error FROM deliveries WHERE delivery_id=?1",
                params![delivery_id],
                |row: &Row<'_>| -> rusqlite::Result<Delivery> {
                    Ok(Delivery {
                        delivery_id: row.get(0)?,
                        event_type: row.get(1)?,
                        subject: row.get(2)?,
                        recipient: row.get(3)?,
                        notification_json: row.get(4)?,
                        status: row.get(5)?,
                        attempts: row.get(6)?,
                        next_attempt_at: row.get(7)?,
                        last_error: row.get(8)?,
                    })
                },
            )
            .map_err(|e| Error::Io(format!("notifications delivery lookup: {e}")))?;
        Ok(Some(delivery))
    }

    /// Enqueue a notification for a recipient. Re-enqueueing an event that
    /// already reached a terminal state never creates a second delivery.
    pub fn enqueue(&self, notification: &Notification, recipient: &str) -> Result<Delivery> {
        let delivery_id = delivery_id(&notification.event_type, recipient, &notification.subject);
        let now = now_secs();
        let db = self.lock()?;
        db.execute(
            "INSERT INTO deliveries(delivery_id,event_type,subject,recipient,notification,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,0,?7,unixepoch(),unixepoch()) ON CONFLICT(delivery_id) DO NOTHING",
            params![
                &delivery_id,
                &notification.event_type,
                &notification.subject,
                recipient,
                &notification.to_json()?,
                STATUS_PENDING,
                now
            ],
        )
        .map_err(|e| Error::Io(format!("notifications enqueue: {e}")))?;
        let delivery = Self::delivery_on(&db, &delivery_id)?;
        Ok(delivery.expect("delivery row must exist"))
    }

    /// Claim due pending deliveries and apply opt-outs. The caller dispatches
    /// each claimed delivery and then records the outcome.
    pub fn claim_due(&self, now: i64) -> Result<Vec<Delivery>> {
        let db = self.lock()?;
        let mut statement = db
            .prepare(
                "SELECT delivery_id,event_type,subject,recipient,notification,status,attempts,next_attempt_at,last_error FROM deliveries WHERE status = ?1 AND next_attempt_at <= ?2 ORDER BY created_at",
            )
            .map_err(|e| Error::Io(format!("notifications claim prepare: {e}")))?;
        let mut rows = statement
            .query(params![STATUS_PENDING, now])
            .map_err(|e| Error::Io(format!("notifications claim query: {e}")))?;
        let mut opt_out_statement = db
            .prepare("SELECT 1 FROM opt_outs WHERE event_type=?1 AND recipient=?2")
            .map_err(|e| Error::Io(format!("notifications claim prepare opt-out: {e}")))?;
        let mut due = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| Error::Io(format!("notifications claim fetch: {e}")))?
        {
            let delivery = Self::row_to_delivery(row)?;
            let opt_out = opt_out_statement
                .query(params![&delivery.event_type, &delivery.recipient])
                .map_err(|e| Error::Io(format!("notifications claim opt-out: {e}")))?
                .next()
                .map_err(|e| Error::Io(format!("notifications claim opt-out: {e}")))?
                .is_some();
            if opt_out {
                let _ = db.execute(
                    "UPDATE deliveries SET status=?2,updated_at=unixepoch() WHERE delivery_id=?1",
                    params![&delivery.delivery_id, STATUS_OPTED_OUT],
                )
                .map_err(|e| Error::Io(format!("notifications opt-out: {e}")))?;
                continue;
            }
            due.push(delivery);
        }
        Ok(due)
    }

    /// Record a successful delivery as terminal.
    pub fn mark_delivered(&self, delivery_id: &str) -> Result<()> {
        let db = self.lock()?;
        db.execute(
            "UPDATE deliveries SET status=?2,attempts=attempts+1,updated_at=unixepoch() WHERE delivery_id=?1 AND status='pending'",
            params![delivery_id, STATUS_DELIVERED],
        )
        .map_err(|e| Error::Io(format!("notifications mark delivered: {e}")))?;
        Ok(())
    }

    /// Record a provider failure and schedule the retry with the same
    /// delivery identity.
    pub fn mark_failed(&self, delivery_id: &str, error: &str, now: i64) -> Result<()> {
        let db = self.lock()?;
        let delivery = Self::delivery_on(&db, delivery_id)?
            .ok_or_else(|| Error::Io("notifications delivery missing".to_string()))?;
        let attempts = delivery.attempts + 1;
        let backoff =
            (DELIVERY_BACKOFF_SECS * (1i64 << (attempts - 1).clamp(0, 6))).min(MAX_BACKOFF_SECS);
        db.execute(
            "UPDATE deliveries SET status='pending',attempts=?2,next_attempt_at=?3,last_error=?4,updated_at=unixepoch() WHERE delivery_id=?1 AND status='pending'",
            params![delivery_id, attempts, now + backoff, error],
        )
        .map_err(|e| Error::Io(format!("notifications mark failed: {e}")))?;
        Ok(())
    }

    pub fn delivery(&self, delivery_id: &str) -> Result<Option<Delivery>> {
        let db = self.lock()?;
        Self::delivery_on(&db, delivery_id)
    }

    /// Per-(event, recipient) operator opt-out. Opted-out deliveries are
    /// never sent and are recorded as opted out.
    pub fn is_opted_out(&self, event_type: &str, recipient: &str) -> Result<bool> {
        let db = self.lock()?;
        let mut statement = db
            .prepare("SELECT 1 FROM opt_outs WHERE event_type=?1 AND recipient=?2")
            .map_err(|e| Error::Io(format!("notifications opt-out lookup: {e}")))?;
        let mut rows = statement
            .query(params![event_type, recipient])
            .map_err(|e| Error::Io(format!("notifications opt-out lookup: {e}")))?;
        let opt_out = rows
            .next()
            .map_err(|e| Error::Io(format!("notifications opt-out lookup: {e}")))?
            .is_some();
        Ok(opt_out)
    }

    pub fn opt_out(&self, event_type: &str, recipient: &str) -> Result<()> {
        let db = self.lock()?;
        db.execute(
            "INSERT INTO opt_outs(event_type,recipient,created_at) VALUES(?1,?2,unixepoch()) ON CONFLICT(event_type,recipient) DO NOTHING",
            params![event_type, recipient],
        )
        .map_err(|e| Error::Io(format!("notifications opt-out write: {e}")))?;
        Ok(())
    }
}

impl Default for Outbox {
    fn default() -> Self {
        Self {
            db: Mutex::new(Connection::open(":memory:").expect("in-memory notifications outbox")),
        }
    }
}

/// Consumer loop: claim due deliveries, deliver, and record the outcome.
pub async fn run(db_path: &Path, sink: Arc<dyn DeliverySink>) -> Result<()> {
    let outbox = Outbox::open(db_path)?;
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        let now = now_secs();
        let deliveries = outbox.claim_due(now)?;
        for delivery in deliveries {
            let delivered = sink.deliver(&delivery).await.is_ok();
            if delivered {
                outbox.mark_delivered(&delivery.delivery_id)?;
            } else {
                outbox.mark_failed(&delivery.delivery_id, "provider failure", now)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notification(event_type: &str, subject: &str) -> Notification {
        Notification::new(
            event_type,
            "1",
            7,
            0,
            subject,
            Some("accept".to_string()),
            canonical_receipt_link("0xabc"),
        )
    }

    struct MockSink {
        fail_first: bool,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl DeliverySink for MockSink {
        async fn deliver(&self, _delivery: &Delivery) -> DeliveryResult {
            if self.fail_first
                && self
                    .calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    == 0
            {
                return Err("provider unavailable".to_string());
            }
            Ok(())
        }
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn delivers_claimed_delivery_and_never_redelivers_delivered() {
        let dir = temp_dir();
        let outbox = Outbox::open(&dir.path().join("notifications.sqlite")).unwrap();
        outbox.opt_out("review.decided", "nobody").unwrap();
        let notification = notification(EVENT_ACCEPT_FINALIZED, "0xabc");
        let delivered_delivery = outbox.enqueue(&notification, "reviewer-1").unwrap();
        assert_eq!(delivered_delivery.status, STATUS_PENDING);
        assert!(!outbox
            .is_opted_out(EVENT_ACCEPT_FINALIZED, "reviewer-1")
            .unwrap());

        let sink = Arc::new(MockSink {
            fail_first: false,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let now = now_secs();
        let due = outbox.claim_due(now).unwrap();
        assert_eq!(due.len(), 1);
        sink.deliver(&due[0]).await.unwrap();
        outbox.mark_delivered(&due[0].delivery_id).unwrap();

        let again = outbox.claim_due(now + 1).unwrap();
        assert!(again.is_empty());
        assert_eq!(
            outbox
                .delivery(&delivered_delivery.delivery_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_DELIVERED
        );
    }

    #[tokio::test]
    async fn retry_after_provider_failure_preserves_delivery_id() {
        let dir = temp_dir();
        let outbox = Outbox::open(&dir.path().join("notifications.sqlite")).unwrap();
        let notification = notification(EVENT_ACCEPT_FINALIZED, "0xabc");
        let first = outbox.enqueue(&notification, "reviewer-1").unwrap();

        let failing = Arc::new(MockSink {
            fail_first: true,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let now = now_secs();
        let due = outbox.claim_due(now).unwrap();
        assert_eq!(due.len(), 1);
        assert!(failing.deliver(&due[0]).await.is_err());
        outbox
            .mark_failed(&due[0].delivery_id, "provider failure", now)
            .unwrap();

        let failed = outbox.delivery(&first.delivery_id).unwrap().unwrap();
        assert_eq!(failed.status, STATUS_PENDING);
        assert_eq!(failed.attempts, 1);
        assert!(failed.next_attempt_at > now);
        assert_eq!(failed.last_error.as_deref(), Some("provider failure"));

        // The retry reuses the same delivery id and is scheduled later.
        let retry_due = outbox.claim_due(failed.next_attempt_at).unwrap();
        assert_eq!(retry_due.len(), 1);
        assert_eq!(retry_due[0].delivery_id, first.delivery_id);
        let succeeding = Arc::new(MockSink {
            fail_first: false,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        succeeding.deliver(&retry_due[0]).await.unwrap();
        outbox.mark_delivered(&retry_due[0].delivery_id).unwrap();
        assert_eq!(
            outbox.delivery(&first.delivery_id).unwrap().unwrap().status,
            STATUS_DELIVERED
        );
    }

    #[test]
    fn webhook_signature_validation_is_tight() {
        let now = 1_700_000_000;
        let signature = sign_delivery(
            "secret",
            "0xabc",
            now,
            "{\"event_type\":\"accept.finalized\"}",
        );
        assert!(verify_delivery_signature(
            "secret",
            "0xabc",
            now,
            &signature,
            "{\"event_type\":\"accept.finalized\"}",
            now
        ));
        assert!(!verify_delivery_signature(
            "secret",
            "0xabc",
            now,
            &signature,
            "{\"event_type\":\"accept.finalized\"}",
            now + 301
        ));
        assert!(!verify_delivery_signature(
            "secret",
            "0xabc",
            now,
            &signature,
            "{\"event_type\":\"tampered\"}",
            now
        ));
        assert!(!verify_delivery_signature(
            "other",
            "0xabc",
            now,
            &signature,
            "{\"event_type\":\"accept.finalized\"}",
            now
        ));
        assert!(!verify_delivery_signature(
            "secret",
            "0xabc",
            now,
            "sha1=abc",
            "{\"event_type\":\"accept.finalized\"}",
            now
        ));
    }

    #[test]
    fn opt_out_marks_delivery_without_delivery() {
        let dir = temp_dir();
        let outbox = Outbox::open(&dir.path().join("notifications.sqlite")).unwrap();
        outbox.opt_out(EVENT_REVIEW_DECIDED, "reviewer-1").unwrap();
        assert!(outbox
            .is_opted_out(EVENT_REVIEW_DECIDED, "reviewer-1")
            .unwrap());
        assert!(!outbox
            .is_opted_out(EVENT_REVIEW_DECIDED, "reviewer-2")
            .unwrap());

        let notification = notification(EVENT_REVIEW_DECIDED, "0xabc");
        let delivery = outbox.enqueue(&notification, "reviewer-1").unwrap();
        let due = outbox.claim_due(now_secs()).unwrap();
        assert!(due.is_empty());
        assert_eq!(
            outbox
                .delivery(&delivery.delivery_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_OPTED_OUT
        );
    }

    #[test]
    fn notification_is_public_and_links_canonical_status() {
        let notification = Notification::new(
            EVENT_ACCEPT_FINALIZED,
            "1",
            9,
            2,
            "0xsub",
            Some("accept".to_string()),
            canonical_receipt_link("0xdeadbeef"),
        );
        let json = notification.to_json().unwrap();
        assert!(json.contains("\"canonical_link\":\"/explorer?kind=receipt&key=0xdeadbeef\""));
        assert!(!json.contains("witness"));
        assert!(!json.contains("evidence"));
        assert!(!json.contains("payload"));
        assert!(json.contains("accept.finalized"));
    }

    #[test]
    fn delivery_identity_is_stable_per_event_and_recipient() {
        assert_eq!(
            delivery_id("accept.finalized", "reviewer-1", "0xabc"),
            delivery_id("accept.finalized", "reviewer-1", "0xabc")
        );
        assert_ne!(
            delivery_id("accept.finalized", "reviewer-1", "0xabc"),
            delivery_id("accept.finalized", "reviewer-2", "0xabc")
        );
        assert_ne!(
            delivery_id("accept.finalized", "reviewer-1", "0xabc"),
            delivery_id("review.decided", "reviewer-1", "0xabc")
        );
    }
}
