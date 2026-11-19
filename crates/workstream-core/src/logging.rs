//! Unified logging utilities using tracing

pub use crate::error::ErrorCode;

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Build the default environment filter used by all initializers.
fn filter(default: &str) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default))
}

/// The service role is a safe, operator-controlled correlation field. It is
/// read once from the runtime directory selection and never from the network.
pub fn service_role() -> &'static str {
    match std::env::var("WORKSTREAM_ROLE").as_deref() {
        Ok("sequencer") => "sequencer",
        Ok("prover") => "prover",
        Ok("node") => "node",
        _ => "unknown",
    }
}

/// Initialize tracing subscriber with default configuration.
///
/// When `WORKSTREAM_LOG_FORMAT=json`, events are emitted as JSON so trace ids,
/// transaction/block hashes and proof-job keys can be joined across services
/// by an OpenTelemetry collector or the local drill. Structured fields are
/// attached by callers at safe boundaries; this layer only changes encoding,
/// never the set of recorded fields, so no secret is introduced here.
pub fn init_tracing() {
    let env_filter = filter("info");
    let registry = tracing_subscriber::registry();
    if std::env::var("WORKSTREAM_LOG_FORMAT").as_deref() == Ok("json") {
        let _ = registry
            .with(fmt::layer().json())
            .with(env_filter)
            .try_init();
    } else {
        let _ = registry.with(fmt::layer()).with(env_filter).try_init();
    }
}

/// Initialize tracing subscriber with custom filter
pub fn init_tracing_with_filter(filter: &str) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .try_init();
}

/// Initialize tracing subscriber for testing
pub fn init_tracing_test() {
    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer())
        .with(EnvFilter::new("debug"))
        .try_init();
}

#[macro_export]
macro_rules! log_error {
    ($err:expr) => {
        tracing::error!(error = %$err, category = ?$err.category(), "error occurred");
    };
    ($err:expr, $($arg:tt)*) => {
        tracing::error!(error = %$err, category = ?$err.category(), $($arg)*);
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        tracing::warn!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        tracing::trace!($($arg)*);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, Result};

    #[test]
    fn test_init_tracing_test() {
        // Should not panic even if called multiple times
        init_tracing_test();
        init_tracing_test();
    }

    #[test]
    fn test_init_tracing_with_filter() {
        // Should not panic even if a subscriber is already set
        init_tracing_test();
        init_tracing_with_filter("info");
        init_tracing_with_filter("debug");
    }

    #[test]
    fn test_init_tracing_default() {
        // Should not panic even if a subscriber is already set
        init_tracing_test();
        init_tracing();
        init_tracing();
    }

    #[test]
    fn test_log_macros_compile_and_run() {
        init_tracing_test();

        crate::log_info!("test info message");
        crate::log_warn!("test warn message");
        crate::log_debug!("test debug message");
        crate::log_trace!("test trace message");

        let err = Error::Validation("bad input".to_string());
        crate::log_error!(err);

        let err2 = Error::Timeout("slow".to_string());
        crate::log_error!(err2, "operation timed out with retries left: {}", 3);

        let _: Result<()> = Ok(());
    }

    #[test]
    fn test_log_error_with_format_args() {
        init_tracing_test();

        let err = Error::NotFound("missing".to_string());
        crate::log_error!(err, "resource id: {}", "abc123");
    }

    #[test]
    fn test_error_code_reexport() {
        // ErrorCode should be accessible from the logging module for backwards compatibility
        let code: ErrorCode = crate::Error::Timeout("x".to_string()).code();
        assert_eq!(code, ErrorCode::E7001);
    }
}
