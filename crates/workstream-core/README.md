# workstream-core

Core types, traits, errors, and utilities for WorkStream.

## Features

### Error Handling
Unified error types with categories, retryability, and fatality checks:

```rust
use workstream_core::{Error, Result};

fn example() -> Result<()> {
    Err(Error::Validation("invalid input".to_string()))
}
```

Error categories and helpers:
- `ErrorCategory` - Classify errors by type
- `error.category()` - Get error category
- `error.is_retryable()` - Check if error can be retried
- `error.is_fatal()` - Check if error is fatal

### Logging
Tracing-based logging with utilities:

```rust
use workstream_core::logging;

fn main() {
    logging::init_tracing();
    tracing::info!("Application started");
}
```

Available functions:
- `init_tracing()` - Initialize with default settings (respects RUST_LOG)
- `init_tracing_with_filter(filter)` - Initialize with custom filter
- `init_tracing_test()` - Initialize for tests

Macros:
- `log_error!`, `log_warn!`, `log_info!`, `log_debug!`, `log_trace!`

### Component Traits
Versioned interfaces for cross-component communication:
- `SequencerApi`
- `ProverApi`
- `VerifierApi`
- `DaClient`

See `docs/design/interfaces-and-boundaries.md` for details.
