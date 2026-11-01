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
        assert_eq!(
            Error::State("x".to_string()).category(),
            ErrorCategory::State
        );
        assert_eq!(
            Error::Transaction("x".to_string()).category(),
            ErrorCategory::Transaction
        );
        assert_eq!(
            Error::Crypto("x".to_string()).category(),
            ErrorCategory::Crypto
        );
        assert_eq!(
            Error::InvalidProof("x".to_string()).category(),
            ErrorCategory::Crypto
        );
        assert_eq!(Error::InvalidSignature.category(), ErrorCategory::Crypto);
        assert_eq!(
            Error::Validation("x".to_string()).category(),
            ErrorCategory::Validation
        );
        assert_eq!(
            Error::Config("x".to_string()).category(),
            ErrorCategory::Configuration
        );
        assert_eq!(
            Error::Unauthorized("x".to_string()).category(),
            ErrorCategory::Authorization
        );
        assert_eq!(
            Error::NotFound("x".to_string()).category(),
            ErrorCategory::Network
        );
        assert_eq!(
            Error::Timeout("x".to_string()).category(),
            ErrorCategory::Network
        );
        assert_eq!(
            Error::Determinism("x".to_string()).category(),
            ErrorCategory::Consensus
        );
        assert_eq!(
            Error::Consensus("x".to_string()).category(),
            ErrorCategory::Consensus
        );
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

    #[test]
    fn test_error_codes() {
        assert_eq!(Error::State("x".to_string()).code(), ErrorCode::E1000);
        assert_eq!(
            Error::InvalidTransition("x".to_string()).code(),
            ErrorCode::E1001
        );
        assert_eq!(Error::Transaction("x".to_string()).code(), ErrorCode::E2000);
        assert_eq!(Error::Crypto("x".to_string()).code(), ErrorCode::E3000);
        assert_eq!(
            Error::InvalidProof("x".to_string()).code(),
            ErrorCode::E3001
        );
        assert_eq!(Error::InvalidSignature.code(), ErrorCode::E3002);
        assert_eq!(
            Error::Serialization("x".to_string()).code(),
            ErrorCode::E4000
        );
        assert_eq!(Error::Validation("x".to_string()).code(), ErrorCode::E5000);
        assert_eq!(Error::Config("x".to_string()).code(), ErrorCode::E5001);
        assert_eq!(
            Error::Unauthorized("x".to_string()).code(),
            ErrorCode::E6000
        );
        assert_eq!(Error::NotFound("x".to_string()).code(), ErrorCode::E7000);
        assert_eq!(Error::Timeout("x".to_string()).code(), ErrorCode::E7001);
        assert_eq!(Error::Determinism("x".to_string()).code(), ErrorCode::E8000);
        assert_eq!(Error::Consensus("x".to_string()).code(), ErrorCode::E8001);
        assert_eq!(
            Error::VersionMismatch("x".to_string()).code(),
            ErrorCode::E9000
        );
        assert_eq!(Error::Io("x".to_string()).code(), ErrorCode::E9999);
        assert_eq!(Error::Other("x".to_string()).code(), ErrorCode::E9999);
    }

    #[test]
    fn test_error_code_as_u32() {
        assert_eq!(ErrorCode::E1000.as_u32(), 1000);
        assert_eq!(ErrorCode::E9999.as_u32(), 9999);
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert_eq!(err.category(), ErrorCategory::Internal);
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: Error = json_err.into();
        assert!(matches!(err, Error::Serialization(_)));
        assert_eq!(err.category(), ErrorCategory::Serialization);
    }

    #[test]
    fn test_error_code_from_ref() {
        let err = Error::Timeout("slow".to_string());
        let code = ErrorCode::from(&err);
        assert_eq!(code, ErrorCode::E7001);
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}

impl Error {
    /// Get the stable numeric error code for programmatic handling
    pub fn code(&self) -> ErrorCode {
        ErrorCode::from(self)
    }
}

/// Stable numeric error codes for programmatic handling across boundaries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// State error
    E1000 = 1000,
    /// State transition error
    E1001 = 1001,
    /// Transaction error
    E2000 = 2000,
    /// Crypto error
    E3000 = 3000,
    /// Invalid proof
    E3001 = 3001,
    /// Invalid signature
    E3002 = 3002,
    /// Serialization error
    E4000 = 4000,
    /// Validation error
    E5000 = 5000,
    /// Configuration error
    E5001 = 5001,
    /// Unauthorized
    E6000 = 6000,
    /// Not found
    E7000 = 7000,
    /// Timeout
    E7001 = 7001,
    /// Determinism violation
    E8000 = 8000,
    /// Consensus error
    E8001 = 8001,
    /// Version mismatch
    E9000 = 9000,
    /// Internal or other error
    E9999 = 9999,
}

impl ErrorCode {
    /// Numeric value of the error code
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }
}

impl From<&Error> for ErrorCode {
    fn from(err: &Error) -> Self {
        match err {
            Error::State(_) => ErrorCode::E1000,
            Error::InvalidTransition(_) => ErrorCode::E1001,
            Error::Transaction(_) => ErrorCode::E2000,
            Error::Crypto(_) => ErrorCode::E3000,
            Error::InvalidProof(_) => ErrorCode::E3001,
            Error::InvalidSignature => ErrorCode::E3002,
            Error::Serialization(_) => ErrorCode::E4000,
            Error::Validation(_) => ErrorCode::E5000,
            Error::Config(_) => ErrorCode::E5001,
            Error::Unauthorized(_) => ErrorCode::E6000,
            Error::NotFound(_) => ErrorCode::E7000,
            Error::Timeout(_) => ErrorCode::E7001,
            Error::Determinism(_) => ErrorCode::E8000,
            Error::Consensus(_) => ErrorCode::E8001,
            Error::VersionMismatch(_) => ErrorCode::E9000,
            Error::Io(_) | Error::Other(_) => ErrorCode::E9999,
        }
    }
}
