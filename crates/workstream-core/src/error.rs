use thiserror::Error;

/// Error categories for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    State,
    Transaction,
    Crypto,
    Serialization,
    Validation,
    Authorization,
    Network,
    Consensus,
    Configuration,
    Internal,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("State error: {0}")]
    State(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),

    #[error("Determinism violation: {0}")]
    Determinism(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Version mismatch: {0}")]
    VersionMismatch(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Other: {0}")]
    Other(String),
}

impl Error {
    pub fn category(&self) -> ErrorCategory {
        match self {
            Error::State(_) | Error::InvalidTransition(_) => ErrorCategory::State,
            Error::Transaction(_) => ErrorCategory::Transaction,
            Error::Crypto(_) | Error::InvalidProof(_) | Error::InvalidSignature => {
                ErrorCategory::Crypto
            }
            Error::Serialization(_) => ErrorCategory::Serialization,
            Error::Validation(_) => ErrorCategory::Validation,
            Error::Config(_) => ErrorCategory::Configuration,
            Error::Unauthorized(_) => ErrorCategory::Authorization,
            Error::NotFound(_) | Error::Timeout(_) => ErrorCategory::Network,
            Error::Determinism(_) | Error::Consensus(_) => ErrorCategory::Consensus,
            Error::VersionMismatch(_) => ErrorCategory::Internal,
            Error::Io(_) | Error::Other(_) => ErrorCategory::Internal,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Timeout(_) | Error::Io(_))
    }

    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::Determinism(_) | Error::Consensus(_) | Error::InvalidSignature
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        assert_eq!(Error::State("x".to_string()).category(), ErrorCategory::State);
        assert_eq!(Error::Transaction("x".to_string()).category(), ErrorCategory::Transaction);
        assert_eq!(Error::Crypto("x".to_string()).category(), ErrorCategory::Crypto);
        assert_eq!(Error::InvalidProof("x".to_string()).category(), ErrorCategory::Crypto);
        assert_eq!(Error::InvalidSignature.category(), ErrorCategory::Crypto);
        assert_eq!(Error::Validation("x".to_string()).category(), ErrorCategory::Validation);
        assert_eq!(Error::Config("x".to_string()).category(), ErrorCategory::Configuration);
        assert_eq!(Error::Unauthorized("x".to_string()).category(), ErrorCategory::Authorization);
        assert_eq!(Error::NotFound("x".to_string()).category(), ErrorCategory::Network);
        assert_eq!(Error::Timeout("x".to_string()).category(), ErrorCategory::Network);
        assert_eq!(Error::Determinism("x".to_string()).category(), ErrorCategory::Consensus);
        assert_eq!(Error::Consensus("x".to_string()).category(), ErrorCategory::Consensus);
    }

    #[test]
    fn test_error_retryable() {
        assert!(Error::Timeout("x".to_string()).is_retryable());
        assert!(Error::Io("x".to_string()).is_retryable());
        assert!(!Error::Validation("x".to_string()).is_retryable());
        assert!(!Error::InvalidSignature.is_retryable());
    }

    #[test]
    fn test_error_fatal() {
        assert!(Error::Determinism("x".to_string()).is_fatal());
        assert!(Error::Consensus("x".to_string()).is_fatal());
        assert!(Error::InvalidSignature.is_fatal());
        assert!(!Error::Timeout("x".to_string()).is_fatal());
        assert!(!Error::Validation("x".to_string()).is_fatal());
    }

    #[test]
    fn test_error_display() {
        let err = Error::Validation("invalid input".to_string());
        assert_eq!(err.to_string(), "Validation error: invalid input");
        
        let err = Error::Config("missing key".to_string());
        assert_eq!(err.to_string(), "Configuration error: missing key");
        
        let err = Error::InvalidSignature;
        assert_eq!(err.to_string(), "Invalid signature");
    }

    #[test]
    fn test_result_type() {
        fn returns_error() -> Result<()> {
            Err(Error::Other("test".to_string()))
        }
        assert!(returns_error().is_err());
    }
}
