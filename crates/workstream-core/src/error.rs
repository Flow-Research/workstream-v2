use thiserror::Error;

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
    
    #[error("Other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
