//! Versioned, browser-safe wire contract (issue #130).
//!
//! Every response is wrapped in an envelope carrying the API version, the
//! caller's request id, the logical network (chain id) and the read height the
//! answer was produced against. Stable error codes are strings, not numeric
//! JSON-RPC internals, so a generated TypeScript client can switch on them.
//!
//! Signing keys never cross this boundary. Submission accepts an already
//! signed transaction's canonical bytes; the server only validates and
//! forwards them after reusing the protocol validator.
use serde::{Deserialize, Serialize};

/// Current contract version. Bump when a field is added, removed or changes
/// meaning; clients echo it and reject a version they do not understand.
pub const API_VERSION: u32 = 1;

/// Stable error codes. The string form is part of the public contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Malformed request body or parameters.
    InvalidRequest,
    /// Unsupported contract version.
    UnsupportedVersion,
    /// A transaction or projection request failed protocol validation.
    InvalidTransaction,
    /// A duplicate request id was reused with a different body.
    DuplicateRequest,
    /// The referenced receipt does not exist at the reported read height.
    NotFound,
    /// Projection read model is not configured or is behind its cursor.
    StaleProjection,
    /// The trusted network/chain does not match the request.
    NetworkMismatch,
    /// Required session/authorization was absent or expired.
    Unauthorized,
    /// Internal or downstream dependency failure; safe to retry later.
    Internal,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::InvalidTransaction => "INVALID_TRANSACTION",
            Self::DuplicateRequest => "DUPLICATE_REQUEST",
            Self::NotFound => "NOT_FOUND",
            Self::StaleProjection => "STALE_PROJECTION",
            Self::NetworkMismatch => "NETWORK_MISMATCH",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Internal => "INTERNAL",
        }
    }
}

/// Error body with a stable code and a message that never includes secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Envelope attached to every response, success or failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Contract version; equals [`API_VERSION`].
    pub api_version: u32,
    /// Echoed request id from `X-Request-Id`, or a server-generated id.
    pub request_id: String,
    /// Logical network identifier (chain id as a decimal string).
    pub network: String,
    /// Verified height this answer was produced against.
    pub read_height: u64,
    /// Cursor height of the projection read model (0 when no projection).
    pub indexed_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorBody>,
    /// Present on success; absent when `error` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> Envelope<T> {
    pub fn ok(
        request_id: impl Into<String>,
        network: impl Into<String>,
        read_height: u64,
        indexed_height: u64,
        data: T,
    ) -> Self {
        Self {
            api_version: API_VERSION,
            request_id: request_id.into(),
            network: network.into(),
            read_height,
            indexed_height,
            error: None,
            data: Some(data),
        }
    }

    pub fn err(
        request_id: impl Into<String>,
        network: impl Into<String>,
        read_height: u64,
        indexed_height: u64,
        error: ApiErrorBody,
    ) -> Self {
        Self {
            api_version: API_VERSION,
            request_id: request_id.into(),
            network: network.into(),
            read_height,
            indexed_height,
            error: Some(error),
            data: None,
        }
    }
}

/// Request metadata extracted by the server and passed to handlers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestMeta {
    pub request_id: String,
    pub network: String,
    /// Opaque session token (empty on public routes).
    pub session: String,
    /// Consistent snapshot stamped into the response envelope.
    pub read_height: u64,
    pub indexed_height: u64,
    /// Monotonic request sequence for idempotency bookkeeping.
    pub sequence: u64,
}

/// Submission request: a signed transaction's canonical JSON bytes plus the
/// dto/api version gates. No private key field exists in this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRequest {
    pub version: u32,
    pub api_version: u32,
    /// JSON encoding of a signed `workstream_core::types::Transaction`.
    pub tx_bytes: Vec<u8>,
}

/// Opaque, short-lived browser session. It is a capability to call the
/// read/forward facade only; keys never leave the client and a session grants
/// no action authority on chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionData {
    pub token: String,
    pub api_version: u32,
    pub expires_in_secs: u64,
}

/// Stable acknowledgement. `tx_hash` and `height` are 0x-prefixed/optional
/// domain values; no payload, witness or signing material is returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitData {
    pub tx_hash: String,
    pub status: String,
    pub height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptData {
    pub tx_hash: String,
    pub status: String,
    pub height: Option<u64>,
}

/// Chain status read from the verifier and projection cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainData {
    pub height: u64,
    pub state_root: String,
    pub da_ref: Option<String>,
    pub indexed_height: u64,
    pub lag: u64,
    /// True when the projection cursor is behind the verified tip.
    pub stale: bool,
}

/// One page of a projection read model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageData {
    pub kind: String,
    pub items: Vec<serde_json::Value>,
    pub next_cursor: Option<String>,
    /// True when the page was served while the projection was behind.
    pub stale: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_have_stable_string_forms() {
        assert_eq!(ErrorCode::StaleProjection.as_str(), "STALE_PROJECTION");
        assert_eq!(ErrorCode::DuplicateRequest.as_str(), "DUPLICATE_REQUEST");
        let json = serde_json::to_string(&ApiErrorBody::new(
            ErrorCode::Unauthorized,
            "session expired",
        ))
        .unwrap();
        assert_eq!(
            json,
            r#"{"code":"UNAUTHORIZED","message":"session expired"}"#
        );
    }

    #[test]
    fn success_envelope_omits_error_and_failure_omits_data() {
        let ok = Envelope::ok(
            "r1",
            "1",
            2,
            1,
            SubmitData {
                tx_hash: "0x00".into(),
                status: "Pending".into(),
                height: None,
            },
        );
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"api_version\":1"));
        assert!(json.contains("\"request_id\":\"r1\""));
        assert!(json.contains("\"network\":\"1\""));
        assert!(json.contains("\"read_height\":2"));
        assert!(!json.contains("\"error\""));

        let err = Envelope::<SubmitData>::err(
            "r2",
            "1",
            2,
            1,
            ApiErrorBody::new(ErrorCode::NotFound, "no receipt"),
        );
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("\"data\""));
        assert!(json.contains("\"error\""));
    }
}
