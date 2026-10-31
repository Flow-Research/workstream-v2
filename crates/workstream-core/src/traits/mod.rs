//! Component interfaces and boundaries
//! 
//! This module defines versioned trait interfaces for cross-component communication
//! following the design in docs/design/interfaces-and-boundaries.md

pub mod sequencer;
pub mod prover;
pub mod verifier;
pub mod da;

pub use sequencer::SequencerApi;
pub use prover::ProverApi;
pub use verifier::VerifierApi;
pub use da::DaClient;

/// Status message for version negotiation during component handshake
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StatusMessage {
    pub api_version: u32,
    pub min_api_version: u32,
    pub component: ComponentType,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ComponentType {
    Sequencer,
    Prover,
    Node,
    DaClient,
}

impl StatusMessage {
    pub fn new(component: ComponentType, api_version: u32, min_api_version: u32) -> Self {
        Self {
            api_version,
            min_api_version,
            component,
            capabilities: Vec::new(),
        }
    }

    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn is_compatible(&self, other: &StatusMessage) -> bool {
        // Check if versions are compatible
        !(self.api_version < other.min_api_version || other.api_version < self.min_api_version)
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.api_version == 0 || self.min_api_version == 0 {
            return Err(crate::Error::Validation("api versions must be >= 1".to_string()));
        }
        if self.min_api_version > self.api_version {
            return Err(crate::Error::Validation(
                "min_api_version cannot be greater than api_version".to_string(),
            ));
        }
        Ok(())
    }
}

/// Trait for DTO validation
pub trait Validate {
    fn validate(&self) -> crate::Result<()>;
}
