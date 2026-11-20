//! Single-host transport. The operator supplies a trusted private directory;
//! services never unlink a socket they did not create or bind a public port.
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
use workstream_core::{Error, Result};
pub mod tls;

pub fn directory() -> Result<Option<PathBuf>> {
    let Some(path) = std::env::var_os("WORKSTREAM_RUNTIME_DIR").map(PathBuf::from) else {
        return Ok(None);
    };
    let meta = std::fs::symlink_metadata(&path).map_err(io_err)?;
    if !path.is_absolute() || !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::Config(
            "runtime directory must be absolute, private (0700), and not a symlink".into(),
        ));
    }
    Ok(Some(path))
}

pub fn io_err(e: io::Error) -> Error {
    Error::Io(e.to_string())
}

pub fn listen(path: &Path) -> Result<UnixListener> {
    UnixListener::bind(path).map_err(io_err)
}

pub async fn read<T: DeserializeOwned>(
    s: &mut (impl tokio::io::AsyncRead + Unpin),
    limit: usize,
) -> Result<T> {
    timeout(Duration::from_secs(10), async {
        let len = s.read_u32().await.map_err(io_err)? as usize;
        if len > limit {
            return Err(Error::Validation("IPC frame too large".into()));
        }
        let mut bytes = vec![0; len];
        s.read_exact(&mut bytes).await.map_err(io_err)?;
        serde_json::from_slice(&bytes).map_err(|_| Error::Validation("invalid IPC message".into()))
    })
    .await
    .map_err(|_| Error::Timeout("IPC read".into()))?
}

pub const BLOCK_LIMIT: usize = 16 << 20;
pub const ADMISSION_LIMIT: usize = 256 << 10;
pub async fn write<T: Serialize>(
    s: &mut (impl tokio::io::AsyncWrite + Unpin),
    msg: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(|e| Error::Serialization(e.to_string()))?;
    if bytes.len() > BLOCK_LIMIT {
        return Err(Error::Validation("IPC reply too large".into()));
    }
    timeout(Duration::from_secs(10), async {
        s.write_u32(bytes.len() as u32).await?;
        s.write_all(&bytes).await?;
        s.flush().await
    })
    .await
    .map_err(|_| Error::Timeout("IPC write".into()))?
    .map_err(io_err)
}

pub async fn call<Q: Serialize, R: DeserializeOwned>(
    client: &tls::Client,
    path: &Path,
    req: &Q,
) -> Result<R> {
    let socket = timeout(Duration::from_secs(3), UnixStream::connect(path))
        .await
        .map_err(|_| Error::Timeout("service connect".into()))?
        .map_err(io_err)?;
    let mut s = client.connect(socket).await?;
    write(&mut s, req).await?;
    // Proving can take longer than receiving a bounded message. Wait for its
    // first byte under a separate overall work deadline.
    let mut first = [0u8; 1];
    timeout(Duration::from_secs(300), s.read_exact(&mut first))
        .await
        .map_err(|_| Error::Timeout("service reply".into()))?
        .map_err(io_err)?;
    let reply: std::result::Result<R, String> =
        read(&mut first.as_slice().chain(s), BLOCK_LIMIT).await?;
    reply.map_err(Error::Validation)
}
