//! Unified configuration system
//!
//! Per-component TOML configuration with defaults, validation, and environment
//! variable overrides. All binaries load configuration through this module so
//! that behavior is consistent and config errors are surfaced uniformly via
//! [`crate::Error`].
//!
//! ## Loading order (later wins)
//! 1. Built-in defaults via [`Default`]
//! 2. TOML file (optional, via `--config`)
//! 3. Environment overrides (e.g. `WORKSTREAM_SEQUENCER_PORT`)
//! 4. CLI flags (applied by the binary after loading)

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Environment variable prefix for overrides
pub const ENV_PREFIX: &str = "WORKSTREAM";

/// Default log level when none is specified
pub const DEFAULT_LOG_LEVEL: &str = "info";

// ---------------------------------------------------------------------------
// Component configs
// ---------------------------------------------------------------------------

/// Sequencer configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SequencerConfig {
    /// RPC port for transaction submission
    #[serde(default = "default_sequencer_port")]
    pub port: u16,
    /// Maximum number of transactions held in the mempool
    #[serde(default = "default_mempool_size")]
    pub mempool_size: usize,
    /// Block production interval in milliseconds
    #[serde(default = "default_block_interval_ms")]
    pub block_interval_ms: u64,
    /// Log level for the sequencer
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_sequencer_port() -> u16 {
    8545
}
fn default_mempool_size() -> usize {
    10_000
}
fn default_block_interval_ms() -> u64 {
    2_000
}
fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            port: default_sequencer_port(),
            mempool_size: default_mempool_size(),
            block_interval_ms: default_block_interval_ms(),
            log_level: default_log_level(),
        }
    }
}

impl SequencerConfig {
    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(Error::Config("sequencer port cannot be 0".to_string()));
        }
        if self.mempool_size == 0 {
            return Err(Error::Config(
                "sequencer mempool_size must be greater than 0".to_string(),
            ));
        }
        if self.block_interval_ms == 0 {
            return Err(Error::Config(
                "sequencer block_interval_ms must be greater than 0".to_string(),
            ));
        }
        if self.log_level.is_empty() {
            return Err(Error::Config(
                "sequencer log_level cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Apply environment variable overrides (e.g. `WORKSTREAM_SEQUENCER_PORT=1234`)
    pub fn apply_env_overrides(&mut self) -> Result<()> {
        if let Some(v) = read_env_u16("WORKSTREAM_SEQUENCER_PORT")? {
            self.port = v;
        }
        if let Some(v) = read_env_usize("WORKSTREAM_SEQUENCER_MEMPOOL_SIZE")? {
            self.mempool_size = v;
        }
        if let Some(v) = read_env_u64("WORKSTREAM_SEQUENCER_BLOCK_INTERVAL_MS")? {
            self.block_interval_ms = v;
        }
        if let Ok(v) = std::env::var("WORKSTREAM_SEQUENCER_LOG_LEVEL") {
            self.log_level = v;
        }
        Ok(())
    }
}

/// Prover configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProverConfig {
    /// zkVM backend name (e.g. "risc0", "sp1")
    pub zkvm: String,
    /// Optional path to a file listing block numbers to prove
    #[serde(default)]
    pub blocks: Option<String>,
    /// Guest program identifier
    #[serde(default)]
    pub guest_id: Option<String>,
    /// Log level for the prover
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            zkvm: "risc0".to_string(),
            blocks: None,
            guest_id: None,
            log_level: default_log_level(),
        }
    }
}

impl ProverConfig {
    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        if self.zkvm.is_empty() {
            return Err(Error::Config("prover zkvm cannot be empty".to_string()));
        }
        if self.log_level.is_empty() {
            return Err(Error::Config(
                "prover log_level cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Apply environment variable overrides (e.g. `WORKSTREAM_PROVER_ZKVM=sp1`)
    pub fn apply_env_overrides(&mut self) -> Result<()> {
        if let Ok(v) = std::env::var("WORKSTREAM_PROVER_ZKVM") {
            self.zkvm = v;
        }
        if let Ok(v) = std::env::var("WORKSTREAM_PROVER_BLOCKS") {
            self.blocks = Some(v);
        }
        if let Ok(v) = std::env::var("WORKSTREAM_PROVER_GUEST_ID") {
            self.guest_id = Some(v);
        }
        if let Ok(v) = std::env::var("WORKSTREAM_PROVER_LOG_LEVEL") {
            self.log_level = v;
        }
        Ok(())
    }
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeConfig {
    /// P2P listening port
    #[serde(default = "default_node_p2p_port")]
    pub p2p_port: u16,
    /// Whether to sync from genesis on startup
    #[serde(default)]
    pub sync: bool,
    /// Optional RPC port for client queries
    #[serde(default)]
    pub rpc_port: Option<u16>,
    /// Directory for chain data
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Log level for the node
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_node_p2p_port() -> u16 {
    30303
}
fn default_data_dir() -> String {
    ".workstream".to_string()
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            p2p_port: default_node_p2p_port(),
            sync: false,
            rpc_port: None,
            data_dir: default_data_dir(),
            log_level: default_log_level(),
        }
    }
}

impl NodeConfig {
    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        if self.p2p_port == 0 {
            return Err(Error::Config("node p2p_port cannot be 0".to_string()));
        }
        if self.data_dir.is_empty() {
            return Err(Error::Config("node data_dir cannot be empty".to_string()));
        }
        if self.log_level.is_empty() {
            return Err(Error::Config("node log_level cannot be empty".to_string()));
        }
        Ok(())
    }

    /// Apply environment variable overrides (e.g. `WORKSTREAM_NODE_P2P_PORT=30304`)
    pub fn apply_env_overrides(&mut self) -> Result<()> {
        if let Some(v) = read_env_u16("WORKSTREAM_NODE_P2P_PORT")? {
            self.p2p_port = v;
        }
        if let Some(v) = read_env_bool("WORKSTREAM_NODE_SYNC")? {
            self.sync = v;
        }
        if let Some(v) = read_env_u16("WORKSTREAM_NODE_RPC_PORT")? {
            self.rpc_port = Some(v);
        }
        if let Ok(v) = std::env::var("WORKSTREAM_NODE_DATA_DIR") {
            self.data_dir = v;
        }
        if let Ok(v) = std::env::var("WORKSTREAM_NODE_LOG_LEVEL") {
            self.log_level = v;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Loading helpers
// ---------------------------------------------------------------------------

/// Load a config from a TOML file. Fails if the file is missing or malformed.
pub fn load_from_file<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let contents = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!(
            "failed to read config file {}: {e}",
            path.display()
        ))
    })?;
    load_from_str(&contents)
}

/// Parse a config from a TOML string.
pub fn load_from_str<T>(contents: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    toml::from_str(contents).map_err(|e| Error::Config(format!("failed to parse config: {e}")))
}

/// Full load sequence shared by all binaries: defaults → file (optional) → env.
///
/// Returns `(config, file_was_used)`.
pub fn load_config<T>(config_path: Option<&Path>) -> Result<T>
where
    T: Default + for<'de> Deserialize<'de> + ValidateConfig,
{
    let mut config = match config_path {
        Some(path) => load_from_file(path)?,
        None => T::default(),
    };
    config.apply_env_overrides()?;
    config.validate()?;
    Ok(config)
}

/// Trait implemented by all component configs so the shared loader can
/// validate and apply environment overrides generically.
pub trait ValidateConfig {
    fn validate(&self) -> Result<()>;
    fn apply_env_overrides(&mut self) -> Result<()>;
}

impl ValidateConfig for SequencerConfig {
    fn validate(&self) -> Result<()> {
        SequencerConfig::validate(self)
    }
    fn apply_env_overrides(&mut self) -> Result<()> {
        SequencerConfig::apply_env_overrides(self)
    }
}

impl ValidateConfig for ProverConfig {
    fn validate(&self) -> Result<()> {
        ProverConfig::validate(self)
    }
    fn apply_env_overrides(&mut self) -> Result<()> {
        ProverConfig::apply_env_overrides(self)
    }
}

impl ValidateConfig for NodeConfig {
    fn validate(&self) -> Result<()> {
        NodeConfig::validate(self)
    }
    fn apply_env_overrides(&mut self) -> Result<()> {
        NodeConfig::apply_env_overrides(self)
    }
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

fn read_env_u16(key: &str) -> Result<Option<u16>> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<u16>()
            .map(Some)
            .map_err(|e| Error::Config(format!("invalid value for {key}: {e}"))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(Error::Config(format!("failed to read {key}: {e}"))),
    }
}

fn read_env_usize(key: &str) -> Result<Option<usize>> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<usize>()
            .map(Some)
            .map_err(|e| Error::Config(format!("invalid value for {key}: {e}"))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(Error::Config(format!("failed to read {key}: {e}"))),
    }
}

fn read_env_u64(key: &str) -> Result<Option<u64>> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<u64>()
            .map(Some)
            .map_err(|e| Error::Config(format!("invalid value for {key}: {e}"))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(Error::Config(format!("failed to read {key}: {e}"))),
    }
}

fn read_env_bool(key: &str) -> Result<Option<bool>> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<bool>()
            .map(Some)
            .map_err(|e| Error::Config(format!("invalid value for {key}: {e}"))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(Error::Config(format!("failed to read {key}: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize env-var tests: `std::env::set_var` is process-global and
    /// parallel tests would race on the same keys.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set an env var for the duration of a test, restoring the previous
    /// value (or removing it) afterwards.
    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn test_sequencer_defaults() {
        let cfg = SequencerConfig::default();
        assert_eq!(cfg.port, 8545);
        assert_eq!(cfg.mempool_size, 10_000);
        assert_eq!(cfg.block_interval_ms, 2_000);
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_node_defaults() {
        let cfg = NodeConfig::default();
        assert_eq!(cfg.p2p_port, 30303);
        assert!(!cfg.sync);
        assert_eq!(cfg.data_dir, ".workstream");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_prover_defaults() {
        let cfg = ProverConfig::default();
        assert_eq!(cfg.zkvm, "risc0");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_load_sequencer_from_str() {
        let toml_str = r#"
port = 9000
mempool_size = 500
block_interval_ms = 1000
log_level = "debug"
"#;
        let cfg: SequencerConfig = load_from_str(toml_str).unwrap();
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.mempool_size, 500);
        assert_eq!(cfg.block_interval_ms, 1000);
        assert_eq!(cfg.log_level, "debug");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_load_node_from_str_partial_uses_defaults() {
        let toml_str = r#"
p2p_port = 40000
"#;
        let cfg: NodeConfig = load_from_str(toml_str).unwrap();
        assert_eq!(cfg.p2p_port, 40000);
        assert_eq!(cfg.data_dir, ".workstream"); // default applied
        assert_eq!(cfg.log_level, "info"); // default applied
    }

    #[test]
    fn test_load_prover_from_str() {
        let toml_str = r#"
zkvm = "sp1"
blocks = "blocks.txt"
guest_id = "workstream-guest"
"#;
        let cfg: ProverConfig = load_from_str(toml_str).unwrap();
        assert_eq!(cfg.zkvm, "sp1");
        assert_eq!(cfg.blocks.as_deref(), Some("blocks.txt"));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validation_failures() {
        let cfg = SequencerConfig {
            port: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());

        let cfg = SequencerConfig {
            mempool_size: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());

        let cfg = NodeConfig {
            data_dir: String::new(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());

        let cfg = ProverConfig {
            zkvm: String::new(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_malformed_toml() {
        let result: Result<SequencerConfig> = load_from_str("not valid toml {{{");
        assert!(result.is_err());
        match result {
            Err(Error::Config(msg)) => assert!(msg.contains("failed to parse")),
            _ => panic!("expected config error"),
        }
    }

    #[test]
    fn test_missing_file() {
        let result: Result<SequencerConfig> =
            load_from_file(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_env_override_sequencer_port() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("WORKSTREAM_SEQUENCER_PORT", "9999");
        let mut cfg = SequencerConfig::default();
        cfg.apply_env_overrides().unwrap();
        assert_eq!(cfg.port, 9999);
    }

    #[test]
    fn test_env_override_node_p2p_port() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("WORKSTREAM_NODE_P2P_PORT", "40404");
        let mut cfg = NodeConfig::default();
        cfg.apply_env_overrides().unwrap();
        assert_eq!(cfg.p2p_port, 40404);
    }

    #[test]
    fn test_env_override_prover_zkvm() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("WORKSTREAM_PROVER_ZKVM", "sp1");
        let mut cfg = ProverConfig::default();
        cfg.apply_env_overrides().unwrap();
        assert_eq!(cfg.zkvm, "sp1");
    }

    #[test]
    fn test_invalid_env_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("WORKSTREAM_SEQUENCER_PORT", "not-a-number");
        let mut cfg = SequencerConfig::default();
        let result = cfg.apply_env_overrides();
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_without_file() {
        let _lock = ENV_LOCK.lock().unwrap();
        let cfg: SequencerConfig = load_config(None).unwrap();
        assert_eq!(cfg, SequencerConfig::default());
    }

    #[test]
    fn test_roundtrip_serialization() {
        let cfg = NodeConfig {
            p2p_port: 50000,
            sync: true,
            rpc_port: Some(8546),
            data_dir: "/tmp/ws".to_string(),
            log_level: "debug".to_string(),
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        let parsed: NodeConfig = load_from_str(&toml_str).unwrap();
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn test_env_prefix_constant() {
        assert_eq!(ENV_PREFIX, "WORKSTREAM");
    }
}
