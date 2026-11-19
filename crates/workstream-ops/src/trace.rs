//! OpenTelemetry-compatible trace correlation for a transaction's journey.
//!
//! A transaction is identified by its signed hash, which is immutable from
//! admission through verification. Every dependency derives the same W3C trace
//! id from that hash, so a single `trace_id` joins the sequencer, prover, node
//! and indexer logs without any service having to trust a caller-supplied
//! identifier. A caller cannot forge another transaction's correlation because
//! the id is a one-way function of the hash the writer actually admitted.
//!
//! Only domain hashes are inputs here. No signing key, witness, blinding factor
//! or payload byte is ever passed to this module or emitted as a field.
use opentelemetry::trace::{SpanId, TraceId};
use sha2::{Digest, Sha256};

/// The service name attached to every span created by this process.
///
/// It comes from the existing identity directory selection, never from an
/// untrusted network field.
pub fn service_name() -> &'static str {
    match std::env::var("WORKSTREAM_ROLE").as_deref() {
        Ok("sequencer") => "workstream-sequencer",
        Ok("prover") => "workstream-prover",
        Ok("node") => "workstream-node",
        _ => "workstream",
    }
}

fn digest(seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // Domain separation keeps trace ids distinct from chain hashes while
    // remaining stable across every process for the same input hash.
    hasher.update(b"workstream/trace/v1/");
    hasher.update(seed);
    hasher.finalize().into()
}

/// Derive a W3C trace id from an immutable domain hash (transaction, block or
/// commitment). Identical inputs in any service produce identical ids.
pub fn trace_id(seed: &[u8]) -> TraceId {
    let bytes = digest(seed);
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[..16]);
    TraceId::from_bytes(id)
}

/// Derive a span id that is local to one stage of the pipeline. The stage name
/// prevents the admission, proving and verification spans from colliding even
/// though they share a trace id.
pub fn span_id(seed: &[u8], stage: &str) -> SpanId {
    let mut hasher = Sha256::new();
    hasher.update(b"workstream/span/v1/");
    hasher.update(seed);
    hasher.update(b"/");
    hasher.update(stage.as_bytes());
    let bytes = hasher.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[..8]);
    SpanId::from_bytes(id)
}

/// A correlation context safe to attach to a `tracing` span. It contains only
/// the derived ids and a safe service label; it has no `Debug` view of any
/// payload.
#[derive(Clone, Copy)]
pub struct Correlation {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub service: &'static str,
}

impl Correlation {
    /// Correlate one stage of a flow keyed by an immutable hash.
    pub fn new(seed: &[u8], stage: &'static str) -> Self {
        Self {
            trace_id: trace_id(seed),
            span_id: span_id(seed, stage),
            service: service_name(),
        }
    }

    /// W3C `traceparent` value, accepted by OpenTelemetry collectors and
    /// propagation libraries (`00-<trace>-<span>-01`).
    pub fn traceparent(&self) -> String {
        format!("00-{}-{:x}-01", self.trace_id, self.span_id)
    }

    /// Attach this context as fields on a `tracing` span. Events inside the
    /// span inherit `trace_id`, `span_id` and `service`, so JSON logs from all
    /// processes can be joined on `trace_id` alone.
    pub fn span(&self) -> tracing::Span {
        tracing::info_span!(
            "workstream.transaction",
            trace_id = %self.trace_id,
            span_id = %self.span_id,
            service = self.service,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_ids_are_stable_across_services_and_stages() {
        let hash = [7u8; 32];
        assert_eq!(trace_id(&hash), trace_id(&hash));
        assert_eq!(span_id(&hash, "admit"), span_id(&hash, "admit"));
        assert_ne!(span_id(&hash, "admit"), span_id(&hash, "verify"));
    }

    #[test]
    fn distinct_transactions_have_distinct_traces() {
        assert_ne!(trace_id(&[1u8; 32]), trace_id(&[2u8; 32]));
    }

    #[test]
    fn traceparent_is_w3c_formatted() {
        let context = Correlation::new(&[9u8; 32], "admit");
        let value = context.traceparent();
        let parts: Vec<_> = value.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "00");
        assert_eq!(parts[1].len(), 32);
        assert_eq!(parts[2].len(), 16);
        assert_eq!(parts[3], "01");
        assert!(parts[1].bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
