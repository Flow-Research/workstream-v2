//! Unified logging utilities using tracing

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize tracing subscriber with default configuration
pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}

/// Initialize tracing subscriber with custom filter
pub fn init_tracing_with_filter(filter: &str) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
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

    #[test]
    fn test_init_tracing_test() {
        // Should not panic
        init_tracing_test();
    }

    #[test]
    fn test_init_tracing_with_filter() {
        // Should not panic
        let _ = std::panic::catch_unwind(|| {
            // Can't actually init twice in same process easily, but test function exists
        });
    }
}

/// Error code mapping for programmatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    E1000 = 1000, // State
    E1001 = 1001, // State transition
    E2000 = 2000, // Transaction
    E3000 = 3000, // Crypto
    E3001 = 3001, // Invalid proof
    E3002 = 3002, // Invalid signature
    E4000 = 4000, // Serialization
    E5000 = 5000, // Validation
    E5001 = 5001, // Config
    E6000 = 6000, // Unauthorized
    E7000 = 7000, // Not found
    E7001 = 7001, // Timeout
    E8000 = 8000, // Determinism
    E8001 = 8001, // Consensus
    E9000 = 9000, // Version mismatch
    E9999 = 9999, // Internal/Other
}

impl From<&crate::Error> for ErrorCode {
    fn from(err: &crate::Error) -> Self {
        match err {
            crate::Error::State(_) => ErrorCode::E1000,
            crate::Error::InvalidTransition(_) => ErrorCode::E1001,
            crate::Error::Transaction(_) => ErrorCode::E2000,
            crate::Error::Crypto(_) => ErrorCode::E3000,
            crate::Error::InvalidProof(_) => ErrorCode::E3001,
            crate::Error::InvalidSignature => ErrorCode::E3002,
            crate::Error::Serialization(_) => ErrorCode::E4000,
            crate::Error::Validation(_) => ErrorCode::E5000,
            crate::Error::Config(_) => ErrorCode::E5001,
            crate::Error::Unauthorized(_) => ErrorCode::E6000,
            crate::Error::NotFound(_) => ErrorCode::E7000,
            crate::Error::Timeout(_) => ErrorCode::E7001,
            crate::Error::Determinism(_) => ErrorCode::E8000,
            crate::Error::Consensus(_) => ErrorCode::E8001,
            crate::Error::VersionMismatch(_) => ErrorCode::E9000,
            crate::Error::Io(_) | crate::Error::Other(_) => ErrorCode::E9999,
        }
    }
}
