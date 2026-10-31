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
