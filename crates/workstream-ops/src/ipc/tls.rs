//! Per-process credentials. Servers require both a valid chain and the
//! configured caller's exact leaf certificate before reading a request.
use super::{io_err, Error, Result};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::UnixStream, time::timeout};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    },
    TlsAcceptor, TlsConnector,
};

struct Identity {
    dir: PathBuf,
    roots: RootCertStore,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    fn load() -> Result<Self> {
        let dir = PathBuf::from(std::env::var_os("WORKSTREAM_IDENTITY_DIR").ok_or_else(|| {
            Error::Config("connected runtime requires WORKSTREAM_IDENTITY_DIR".into())
        })?);
        let path = dir.join("key.der");
        let meta = fs::symlink_metadata(&path).map_err(io_err)?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Config(
                "service key must be a private regular file".into(),
            ));
        }
        let key = PrivateKeyDer::try_from(fs::read(path).map_err(io_err)?)
            .map_err(|_| Error::Config("invalid service key".into()))?;
        let leaf = CertificateDer::from(fs::read(dir.join("cert.der")).map_err(io_err)?);
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                fs::read(dir.join("ca.der")).map_err(io_err)?,
            ))
            .map_err(config_err)?;
        Ok(Self {
            dir,
            roots,
            leaf,
            key,
        })
    }
}
fn config_err(e: impl std::fmt::Display) -> Error {
    Error::Config(format!("service TLS: {e}"))
}

#[derive(Clone)]
pub struct Client {
    connector: TlsConnector,
    name: ServerName<'static>,
}
impl Client {
    pub fn load(name: &'static str) -> Result<Self> {
        let id = Identity::load()?;
        let cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(id.roots)
            .with_client_auth_cert(vec![id.leaf], id.key)
            .map_err(config_err)?;
        Ok(Self {
            connector: Arc::new(cfg).into(),
            name: ServerName::try_from(name).map_err(config_err)?,
        })
    }
    pub(super) async fn connect(
        &self,
        s: UnixStream,
    ) -> Result<tokio_rustls::client::TlsStream<UnixStream>> {
        timeout(
            Duration::from_secs(3),
            self.connector.connect(self.name.clone(), s),
        )
        .await
        .map_err(|_| Error::Timeout("service TLS".into()))?
        .map_err(io_err)
    }
}
pub struct Server {
    acceptor: TlsAcceptor,
    caller: CertificateDer<'static>,
}
impl Server {
    pub fn load() -> Result<Self> {
        let id = Identity::load()?;
        let caller =
            CertificateDer::from(fs::read(id.dir.join("allowed-client.der")).map_err(io_err)?);
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(id.roots))
            .build()
            .map_err(config_err)?;
        let cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![id.leaf], id.key)
            .map_err(config_err)?;
        Ok(Self {
            acceptor: Arc::new(cfg).into(),
            caller,
        })
    }
    pub async fn accept(
        &self,
        s: UnixStream,
    ) -> Result<tokio_rustls::server::TlsStream<UnixStream>> {
        let tls = timeout(Duration::from_secs(3), self.acceptor.accept(s))
            .await
            .map_err(|_| Error::Timeout("service TLS".into()))?
            .map_err(io_err)?;
        if tls.get_ref().1.peer_certificates().and_then(|c| c.first()) != Some(&self.caller) {
            return Err(Error::Unauthorized("unexpected service identity".into()));
        }
        Ok(tls)
    }
}
