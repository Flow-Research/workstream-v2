//! RISC Zero host backend. Guest images are operator-supplied artifacts;
//! approval is by measured image ID, never by a name or hash in the receipt.
use bincode::Options;
use risc0_zkvm::{sha::Digest, Receipt};
use std::{fs, path::Path, process::Command};
use workstream_core::{Error, Result, H256};
use workstream_stf::receipt::{Claim, Witness};

pub fn configured_image() -> Result<(Vec<u8>, H256)> {
    let path = std::env::var_os("WORKSTREAM_GUEST_IMAGE")
        .ok_or_else(|| Error::Config("missing WORKSTREAM_GUEST_IMAGE".into()))?;
    Ok((fs::read(path).map_err(io)?, configured_id()?))
}

pub fn configured_id() -> Result<H256> {
    let id = std::env::var("WORKSTREAM_GUEST_ID")
        .map_err(|_| Error::Config("missing WORKSTREAM_GUEST_ID".into()))?;
    H256::from_hex(id.trim_start_matches("0x"))
}

pub fn package(user_elf: &[u8]) -> Vec<u8> {
    risc0_binfmt::ProgramBinary::new(user_elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode()
}

pub fn image_id(image: &[u8]) -> Result<H256> {
    let digest = risc0_binfmt::compute_image_id(image).map_err(|e| Error::Crypto(e.to_string()))?;
    H256::from_hex(&digest.to_string())
}

/// Run the external local prover. No dev-mode receipt can pass the final check.
pub fn prove(image: &[u8], approved: H256, input: &Witness) -> Result<Vec<u8>> {
    if image_id(image)? != approved {
        return Err(Error::InvalidProof("unapproved guest image".into()));
    }
    let claim = Claim::new(
        input.height,
        input.block_hash,
        input.pre,
        input.post,
        &input.transactions,
    )?;
    let temp = tempfile::tempdir().map_err(io)?;
    let path = |name: &str| temp.path().join(name);
    fs::write(path("guest.bin"), image).map_err(io)?;
    let payload = postcard::to_allocvec(input).map_err(|e| Error::Serialization(e.to_string()))?;
    if payload.len() > 16 * 1024 * 1024 {
        return Err(Error::Validation("oversized witness".into()));
    }
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend(payload);
    fs::write(path("input"), frame).map_err(io)?;
    let status = Command::new("r0vm")
        .env_remove("RISC0_DEV_MODE")
        .arg("--elf")
        .arg(path("guest.bin"))
        .arg("--initial-input")
        .arg(path("input"))
        .arg("--receipt")
        .arg(path("receipt"))
        .status()
        .map_err(io)?;
    if !status.success() {
        return Err(Error::InvalidProof(format!(
            "guest execution or proving failed ({status})"
        )));
    }
    let bytes = fs::read(path("receipt")).map_err(io)?;
    verify(&bytes, approved, &claim)?;
    Ok(bytes)
}

pub fn verify(bytes: &[u8], approved: H256, expected: &Claim) -> Result<()> {
    if verified_claim(bytes, approved)? != *expected {
        return Err(Error::InvalidProof("transition journal mismatch".into()));
    }
    Ok(())
}

pub fn verified_claim(bytes: &[u8], approved: H256) -> Result<Claim> {
    const LIMIT: u64 = 64 << 20;
    if bytes.len() as u64 > LIMIT {
        return Err(Error::InvalidProof("oversized receipt".into()));
    }
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(LIMIT)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| Error::InvalidProof(e.to_string()))?;
    let digest = Digest::try_from(approved.as_bytes().as_slice())
        .map_err(|_| Error::InvalidProof("invalid image ID".into()))?;
    receipt
        .verify(digest)
        .map_err(|e| Error::InvalidProof(e.to_string()))?;
    let (claim, rest) = postcard::take_from_bytes::<Claim>(&receipt.journal.bytes)
        .map_err(|e| Error::InvalidProof(e.to_string()))?;
    if claim.version != 1 || !rest.is_empty() {
        return Err(Error::InvalidProof("invalid transition journal".into()));
    }
    Ok(claim)
}

fn io(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

/// Build-time packaging only; never use a receipt-supplied ELF as a trust root.
pub fn package_file(input: &Path, output: &Path) -> Result<H256> {
    let image = package(&fs::read(input).map_err(io)?);
    let id = image_id(&image)?;
    fs::write(output, image).map_err(io)?;
    Ok(id)
}
