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
