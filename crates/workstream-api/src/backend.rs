//! Backend abstraction for the browser-safe HTTP surface (issue #130).
//!
//! The real implementation is supplied by the connected node and reuses its
//! writer/receipt/projection state. A fake implementation in the contract
//! tests exercises expiry, idempotency and stale-projection behaviour without
//! privileged services. The trait deliberately exposes only read models and
//! submission of *already signed* bytes; there is no signing, witness, DA or
//! P2P capability on this boundary.
use crate::contract::{ApiErrorBody, ChainData, PageData, ReceiptData, SubmitData, SubmitRequest};
use async_trait::async_trait;

/// Capabilities the HTTPS API is allowed to call. Implementations must fail
/// closed and must never echo transaction payloads, witnesses, blinding
/// factors or signing material in error messages.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    /// Logical network identifier reported in every response envelope.
    fn network(&self) -> String;

    /// Current `(read_height, indexed_height)` used to stamp envelopes. Cheap:
    /// backed by the verifier's watch channel and the projection cursor.
    async fn heights(&self) -> (u64, u64);

    /// Validate and forward signed transaction bytes. Must reuse
    /// `SubmitTxRequest::validate` and `workstream_tx::TxValidator` rather
    /// than duplicating protocol rules.
    async fn submit(&self, request: SubmitRequest) -> Result<SubmitData, ApiErrorBody>;

    /// Look up a receipt by 0x-prefixed hash. A miss is `NOT_FOUND`, never an
    /// inference about rejection.
    async fn receipt(&self, tx_hash: &str) -> Result<ReceiptData, ApiErrorBody>;

    /// Verified tip and projection cursor in one consistent snapshot.
    async fn chain(&self) -> Result<ChainData, ApiErrorBody>;

    /// Whitelisted projection page (`events`, `work_items`, `grants`,
    /// `reviews`, `receipts`). Unknown kinds are rejected by the backend.
    async fn page(&self, kind: &str, cursor: &str, limit: u64) -> Result<PageData, ApiErrorBody>;
}
