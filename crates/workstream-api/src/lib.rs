//! Browser-safe HTTPS API for WorkStream (issue #130).
//!
//! This crate exposes a versioned, envelope-based facade over a node's read
//! models and transaction submission. Signing keys stay in the client: the
//! only write accepted is already-signed canonical transaction bytes, which
//! are revalidated with the shared protocol validator before forwarding.
//!
//! The API is deliberately incapable of signing, proving, publishing to DA or
//! gossiping on P2P. Projection rows are read hints, never authorities.

pub mod backend;
pub mod contract;
pub mod openapi;
pub mod server;
pub mod vectors;

pub use backend::Backend;
pub use contract::{
    ApiErrorBody, ChainData, Envelope, ErrorCode, PageData, ReceiptData, RequestMeta, SessionData,
    SubmitData, SubmitRequest, API_VERSION,
};
pub use server::{load_tls_config, router, serve_tls, ApiConfig, ApiState, TlsListener};
