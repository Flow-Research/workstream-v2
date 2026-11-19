//! Common startup policy for all three service binaries.
use crate::{risc0, Prover, PROVER_BACKEND_ENV};
use workstream_core::{fork::ForkSchedule, Error, Result};
use workstream_stf::{mvp_genesis_schedule, StateTransitionFunction};

fn setting(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(Error::Config(format!("invalid UTF-8 in {name}"))),
    }
}

fn policy(profile: &str, backend: Option<&str>) -> Result<bool> {
    let strict = match profile {
        "dev" => false,
        "testnet" | "production" => true,
        _ => return Err(Error::Config("unknown WORKSTREAM_PROFILE".into())),
    };
    match backend.unwrap_or(if strict { "risc0" } else { "in-memory" }) {
        "risc0" => Ok(true),
        "in-memory" if !strict => Ok(false),
        _ => Err(Error::Config(
            "unsupported proof backend for profile".into(),
        )),
    }
}

/// Load the trusted operator schedule, verify image identity before readiness,
/// and construct one backend for all clients in this process.
pub fn load() -> Result<(StateTransitionFunction, Prover)> {
    load_checked(None, None)
}

/// Optional prover settings assert the shared deployment selection; they must
/// never silently select a different network or backend for just one role.
pub fn load_checked(
    requested_backend: Option<&str>,
    requested_guest: Option<&str>,
) -> Result<(StateTransitionFunction, Prover)> {
    let profile = setting("WORKSTREAM_PROFILE")?.unwrap_or_else(|| "dev".into());
    let backend = setting(PROVER_BACKEND_ENV)?;
    let real = policy(&profile, backend.as_deref())?;
    if requested_backend
        .is_some_and(|b| b != "auto" && b != if real { "risc0" } else { "in-memory" })
    {
        return Err(Error::Config(
            "prover zkvm conflicts with the shared backend selection".into(),
        ));
    }
    let schedule: ForkSchedule = match setting("WORKSTREAM_FORK_SCHEDULE")? {
        Some(path) => serde_json::from_slice(
            &std::fs::read(path)
                .map_err(|e| Error::Config(format!("reading fork schedule: {e}")))?,
        )
        .map_err(|e| Error::Config(format!("invalid fork schedule: {e}")))?,
        None if profile == "dev" => mvp_genesis_schedule()?,
        None => return Err(Error::Config("missing WORKSTREAM_FORK_SCHEDULE".into())),
    };
    schedule.validate()?;
    if let Some(id) = requested_guest {
        if workstream_core::H256::from_hex(id.trim_start_matches("0x"))?
            != schedule.genesis_fork().guest_hash
        {
            return Err(Error::Config(
                "prover guest_id conflicts with fork schedule".into(),
            ));
        }
    }
    let chain = setting("WORKSTREAM_CHAIN_ID")?;
    if profile != "dev" || chain.is_some() {
        let expected = chain
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|id| *id != 0);
        if expected != Some(schedule.chain_id) {
            return Err(Error::Config(
                "WORKSTREAM_CHAIN_ID missing, invalid or different from schedule".into(),
            ));
        }
    }
    if real {
        let (image, approved) = risc0::configured_image()?;
        if risc0::image_id(&image)? != approved
            || schedule.forks.iter().any(|f| f.guest_hash != approved)
        {
            return Err(Error::Config(
                "guest image, configured identity and scheduled guest must match".into(),
            ));
        }
    }
    if profile != "dev"
        && schedule
            .forks
            .iter()
            .any(|f| !f.has_feature("risc0-receipts"))
    {
        return Err(Error::Config(
            "every non-dev fork must require risc0-receipts".into(),
        ));
    }
    tracing::info!(profile, chain_id=schedule.chain_id, real_receipts=real, guest=%schedule.genesis_fork().guest_hash, "validated proof configuration");
    let stf = StateTransitionFunction::with_schedule(schedule)?;
    let prover = if real {
        Prover::with_risc0(stf.clone())
    } else {
        Prover::with_stf(stf.clone())
    };
    Ok((stf, prover))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deployed_profiles_never_fall_back_to_memory() {
        for profile in ["production", "testnet"] {
            assert!(policy(profile, None).unwrap());
            assert!(policy(profile, Some("in-memory")).is_err());
            assert!(policy(profile, Some("")).is_err());
        }
        assert!(!policy("dev", None).unwrap());
        assert!(policy("prodution", None).is_err());
    }
}
