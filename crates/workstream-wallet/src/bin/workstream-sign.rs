//! Offline signing from an age backup. The recovery identity is supplied on
//! redirected stdin so it never needs to appear in argv or the environment.
use clap::Parser;
use std::{
    fs::File,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};
use workstream_core::H256;
use workstream_wallet::{RecoveryKey, Wallet};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Sign a reviewed draft locally; redirect one age X25519 identity line to stdin")]
struct Args {
    /// Encrypted wallet backup.
    #[arg(long)]
    backup: PathBuf,
    /// Unsigned transaction JSON.
    #[arg(long)]
    draft: PathBuf,
    /// Expected chain ID, independently selected by the operator.
    #[arg(long)]
    network: u64,
    /// Exact approval_digest shown by workstream-inspect.
    #[arg(long)]
    approve: String,
}

fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "input unavailable")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input unavailable")?;
    if bytes.len() > limit {
        return Err("input too large");
    }
    Ok(bytes)
}

fn sign(args: Args) -> Result<(), &'static str> {
    let hex = args
        .approve
        .strip_prefix("0x")
        .filter(|s| s.len() == 64)
        .ok_or("invalid approval digest")?;
    let approved = H256::from_hex(hex).map_err(|_| "invalid approval digest")?;
    let draft = serde_json::from_slice(&read_file(&args.draft, 256 * 1024)?)
        .map_err(|_| "invalid draft JSON")?;
    let backup = read_file(&args.backup, 4096)?;
    if io::stdin().is_terminal() {
        return Err("redirect a recovery identity to stdin");
    }
    // Fixed allocation; no unzeroized copies from a growing string.
    let mut buf = Zeroizing::new([0u8; 257]);
    let mut input = io::stdin().lock().take(buf.len() as u64);
    let mut length = 0;
    while length < buf.len() {
        let n = input
            .read(&mut buf[length..])
            .map_err(|_| "identity unavailable")?;
        if n == 0 {
            break;
        }
        length += n;
    }
    if length == buf.len() {
        return Err("identity too large");
    }
    let identity: RecoveryKey = std::str::from_utf8(&buf[..length])
        .ok()
        .and_then(|s| s.trim_end().parse().ok())
        .ok_or("invalid identity")?;
    let wallet =
        Wallet::restore(args.network, &backup, &identity).map_err(|_| "cannot restore backup")?;
    let signed = wallet
        .sign_reviewed(draft, approved)
        .map_err(|_| "draft does not match signing approval or wallet")?;
    serde_json::to_writer(io::stdout().lock(), &signed)
        .map_err(|_| "cannot write signed transaction")
}

fn main() -> ExitCode {
    match sign(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
