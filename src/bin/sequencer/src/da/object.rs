//! S3-compatible data availability adapter (MinIO locally, S3-compatible hosted
//! endpoints).
//!
//! Every object is an envelope carrying the SHA-256 of its exact payload.
//! Reads verify that digest, and writes use `If-None-Match: *` so an already
//! committed logical reference cannot be silently rebound to different bytes.
//! Requests are signed with AWS Signature Version 4.
use super::*;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    rustls::{pki_types::CertificateDer, pki_types::ServerName, ClientConfig},
    TlsConnector,
};

const MAX_OBJECT: usize = 32 << 20;
const MAX_RESPONSE: usize = MAX_OBJECT + (64 << 10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Envelope {
    version: u32,
    sha256: [u8; 32],
    payload: Vec<u8>,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

/// A bidirectional stream, used so plain TCP and TLS share one I/O path.
trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}

/// Configuration for an S3-compatible DA provider. Constructed from the
/// operator environment; credentials can be supplied through files so they
/// never appear in process listings.
#[derive(Clone)]
pub struct ObjectDaClient {
    host: String,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    bucket: String,
    prefix: String,
    region: String,
    access: String,
    secret: Arc<Vec<u8>>,
}

fn read_secret(env_name: &str, file_name: &str) -> Result<String> {
    let value = if let Some(path) = std::env::var_os(file_name) {
        std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("reading {file_name}: {e}")))?
            .trim_end()
            .to_string()
    } else {
        std::env::var(env_name)
            .map_err(|_| Error::Config(format!("missing {env_name} or {file_name}")))?
    };
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(Error::Config(format!("invalid {env_name}")));
    }
    Ok(value)
}

fn ca_roots() -> Result<Arc<ClientConfig>> {
    let path = std::env::var("WORKSTREAM_DA_CA_FILE")
        .map_err(|_| Error::Config("https DA endpoints require WORKSTREAM_DA_CA_FILE".into()))?;
    let pem = std::fs::read_to_string(&path)
        .map_err(|e| Error::Config(format!("reading DA CA bundle: {e}")))?;
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap_or("");
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|e| Error::Config(format!("invalid DA CA certificate: {e}")))?;
        roots
            .add(CertificateDer::from(der))
            .map_err(|e| Error::Config(format!("invalid DA CA certificate: {e}")))?;
    }
    if roots.is_empty() {
        return Err(Error::Config(
            "DA CA bundle contains no certificates".into(),
        ));
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

fn valid_bucket(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !bucket.starts_with('.')
        && !bucket.ends_with('.')
        && !bucket.starts_with('-')
        && !bucket.ends_with('-')
        && !bucket.contains("..")
}

fn clean_prefix(value: &str) -> Result<String> {
    let trimmed = value.trim_matches('/');
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Config("invalid WORKSTREAM_DA_PREFIX".into()));
    }
    Ok(trimmed.to_string())
}

impl ObjectDaClient {
    /// Configure from the operator environment. No producer-local state is
    /// kept: each process that needs DA constructs its own client.
    pub fn from_env() -> Result<Self> {
        let endpoint = std::env::var("WORKSTREAM_DA_ENDPOINT")
            .map_err(|_| Error::Config("missing WORKSTREAM_DA_ENDPOINT".into()))?;
        let (scheme, host) = endpoint
            .strip_prefix("http://")
            .map(|h| (false, h))
            .or_else(|| endpoint.strip_prefix("https://").map(|h| (true, h)))
            .ok_or_else(|| Error::Config("DA endpoint must be http:// or https://".into()))?;
        let host = host.trim_end_matches('/').to_string();
        if host.is_empty() || host.contains('/') || host.contains('?') || host.contains('#') {
            return Err(Error::Config("invalid DA endpoint host".into()));
        }
        let bucket = std::env::var("WORKSTREAM_DA_BUCKET")
            .map_err(|_| Error::Config("missing WORKSTREAM_DA_BUCKET".into()))?;
        if !valid_bucket(&bucket) {
            return Err(Error::Config("invalid DA bucket name".into()));
        }
        let prefix = clean_prefix(
            &std::env::var("WORKSTREAM_DA_PREFIX").unwrap_or_else(|_| "workstream".into()),
        )?;
        let region = std::env::var("WORKSTREAM_DA_REGION").unwrap_or_else(|_| "us-east-1".into());
        if region.is_empty() || region.contains('/') {
            return Err(Error::Config("invalid WORKSTREAM_DA_REGION".into()));
        }
        let tls = if scheme {
            let config = ca_roots()?;
            let name = host
                .rsplit_once('@')
                .map(|(_, n)| n)
                .unwrap_or(&host)
                .split(':')
                .next()
                .unwrap_or(&host)
                .to_string();
            let name = ServerName::try_from(name)
                .map_err(|_| Error::Config("invalid DA TLS server name".into()))?;
            Some((TlsConnector::from(config), name))
        } else {
            None
        };
        Ok(Self {
            host,
            tls,
            bucket,
            prefix,
            region,
            access: read_secret("WORKSTREAM_DA_ACCESS_KEY", "WORKSTREAM_DA_ACCESS_KEY_FILE")?,
            secret: Arc::new(
                read_secret("WORKSTREAM_DA_SECRET_KEY", "WORKSTREAM_DA_SECRET_KEY_FILE")?
                    .into_bytes(),
            ),
        })
    }

    #[cfg(test)]
    fn test_client(host: String, bucket: &str, secret: &[u8]) -> Self {
        Self {
            host,
            tls: None,
            bucket: bucket.to_string(),
            prefix: "workstream".into(),
            region: "us-east-1".into(),
            access: "test-key".into(),
            secret: Arc::new(secret.to_vec()),
        }
    }

    fn object_path(&self, key: &str) -> String {
        if key.is_empty() {
            format!("/{}/", self.bucket)
        } else {
            format!("/{}/{}/{key}", self.bucket, self.prefix)
        }
    }

    fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| Error::Crypto("invalid SigV4 key length".into()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn signing_key(&self, date: &str) -> Result<Vec<u8>> {
        let mut prefixed = b"AWS4".to_vec();
        prefixed.extend_from_slice(&self.secret);
        let key = Self::hmac(&prefixed, date.as_bytes())?;
        let key = Self::hmac(&key, self.region.as_bytes())?;
        let key = Self::hmac(&key, b"s3")?;
        Self::hmac(&key, b"aws4_request")
    }

    fn authorization(
        &self,
        method: &str,
        path: &str,
        amz: &str,
        payload_hash: &str,
    ) -> Result<String> {
        let date = &amz[..8];
        let canonical = format!(
            "{method}\n{path}\n\nhost:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{amz}\n\n{SIGNED_HEADERS}\n{payload}",
            host = self.host,
            payload = payload_hash
        );
        let mut canonical_hash = Sha256::new();
        canonical_hash.update(canonical.as_bytes());
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
            hex::encode(canonical_hash.finalize())
        );
        let key = self.signing_key(date)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|_| Error::Crypto("invalid SigV4 signing key".into()))?;
        mac.update(to_sign.as_bytes());
        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={}",
            self.access,
            hex::encode(mac.finalize().into_bytes())
        ))
    }

    async fn request(
        &self,
        method: &str,
        key: &str,
        body: &[u8],
        conditional: bool,
    ) -> Result<HttpResponse> {
        let (amz, _) = amz_time()?;
        let payload_hash = hex::encode(Sha256::digest(body));
        let path = self.object_path(key);
        let authorization = self.authorization(method, &path, &amz, &payload_hash)?;
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nX-Amz-Date: {amz}\r\nX-Amz-Content-Sha256: {payload}\r\nAuthorization: {authorization}\r\n",
            host = self.host,
            payload = payload_hash
        );
        if conditional {
            request.push_str("If-None-Match: *\r\n");
        }
        request.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ));
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body);

        let stream = timeout(IO_TIMEOUT, TcpStream::connect(&self.host))
            .await
            .map_err(|_| Error::Timeout("DA connect timed out".into()))?
            .map_err(|e| Error::Io(format!("DA connect: {e}")))?;
        let mut socket: Box<dyn Socket> = match &self.tls {
            Some((connector, name)) => {
                let tls = timeout(IO_TIMEOUT, connector.connect(name.clone(), stream))
                    .await
                    .map_err(|_| Error::Timeout("DA TLS handshake timed out".into()))?
                    .map_err(|e| Error::Io(format!("DA TLS handshake: {e}")))?;
                Box::new(tls)
            }
            None => Box::new(stream),
        };
        timeout(IO_TIMEOUT, socket.write_all(&bytes))
            .await
            .map_err(|_| Error::Timeout("DA write timed out".into()))?
            .map_err(|e| Error::Io(format!("DA write: {e}")))?;
        let mut raw = Vec::new();
        timeout(
            IO_TIMEOUT,
            (&mut socket)
                .take(MAX_RESPONSE as u64)
                .read_to_end(&mut raw),
        )
        .await
        .map_err(|_| Error::Timeout("DA read timed out".into()))?
        .map_err(|e| Error::Io(format!("DA read: {e}")))?;
        parse_http(raw)
    }

    async fn put(&self, kind: &str, logical: &str, payload: &[u8]) -> Result<()> {
        let digest = sha256(payload);
        let envelope = postcard::to_allocvec(&Envelope {
            version: 1,
            sha256: digest,
            payload: payload.to_vec(),
        })
        .map_err(|e| Error::Serialization(format!("DA envelope: {e}")))?;
        let key = format!("{kind}/{logical}");
        let response = self.request("PUT", &key, &envelope, true).await?;
        match response.status {
            200 | 204 => Ok(()),
            412 => {
                // A concurrent producer may have written exactly the same
                // bytes. Only accept that as success after confirming identity.
                let existing = self.request("GET", &key, &[], false).await?;
                if existing.status != 200 {
                    return Err(Error::Io(format!(
                        "DA conflict verification failed: {}",
                        existing.status
                    )));
                }
                let existing = decode_envelope(&existing.body)?;
                if existing.payload != payload {
                    return Err(Error::Validation(
                        "conflicting DA object for committed reference".into(),
                    ));
                }
                Ok(())
            }
            status => Err(Error::Io(format!("DA PUT failed: {status}"))),
        }
    }

    async fn get(&self, kind: &str, logical: &str) -> Result<Vec<u8>> {
        let key = format!("{kind}/{logical}");
        let response = self.request("GET", &key, &[], false).await?;
        match response.status {
            200 => Ok(decode_envelope(&response.body)?.payload),
            404 => Err(Error::NotFound(format!("DA object {key} not found"))),
            status => Err(Error::Io(format!("DA GET failed: {status}"))),
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn decode_envelope(bytes: &[u8]) -> Result<Envelope> {
    let envelope: Envelope = postcard::from_bytes(bytes)
        .map_err(|e| Error::Serialization(format!("DA envelope: {e}")))?;
    if envelope.version != 1 {
        return Err(Error::VersionMismatch(
            "unsupported DA envelope version".into(),
        ));
    }
    if envelope.payload.len() > MAX_OBJECT || sha256(&envelope.payload) != envelope.sha256 {
        return Err(Error::Validation(
            "DA object failed content identity check".into(),
        ));
    }
    Ok(envelope)
}

fn parse_http(raw: Vec<u8>) -> Result<HttpResponse> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Io("DA response has no header terminator".into()))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::Io("DA response has no status".into()))?;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| Error::Io("invalid DA content length".into()))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Error::Io("chunked DA responses are not supported".into()));
        }
    }
    let mut body = raw[split + 4..].to_vec();
    if let Some(length) = length {
        if length > MAX_RESPONSE || body.len() < length {
            return Err(Error::Io("truncated DA response".into()));
        }
        body.truncate(length);
    } else {
        return Err(Error::Io("DA response missing content length".into()));
    }
    Ok(HttpResponse { status, body })
}

/// Convert a Unix timestamp into the AWS `YYYYMMDDTHHMMSSZ` and `YYYYMMDD`
/// forms without pulling in a date-time dependency.
fn amz_time() -> Result<(String, String)> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Other("clock before Unix epoch".into()))?
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let date = format!("{year:04}{month:02}{day:02}");
    Ok((
        format!(
            "{date}T{:02}{:02}{:02}Z",
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60
        ),
        date,
    ))
}

fn logical_id(da_id: &str) -> Result<String> {
    let hex = da_id
        .strip_prefix("da:")
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Validation("invalid DA reference".into()))?;
    Ok(hex.to_ascii_lowercase())
}

#[async_trait]
impl DaClient for ObjectDaClient {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn post_block(&self, req: PostBlockRequest) -> Result<PostBlockResponse> {
        req.validate()?;
        if req.block_bytes.len() > MAX_OBJECT {
            return Err(Error::Validation("block exceeds DA object limit".into()));
        }
        let logical = req
            .commitment
            .map(|c| hex::encode(c.as_bytes()))
            .unwrap_or_else(|| hex::encode(sha256(&req.block_bytes)));
        self.put("blocks", &logical, &req.block_bytes).await?;
        Ok(PostBlockResponse {
            version: 1,
            api_version: 1,
            da_id: format!("da:{logical}"),
            available: true,
        })
    }

    async fn get_block(&self, req: GetBlockRequest) -> Result<GetBlockResponse> {
        req.validate()?;
        let logical = logical_id(&req.da_id)?;
        let bytes = self.get("blocks", &logical).await?;
        Ok(GetBlockResponse {
            version: 1,
            api_version: 1,
            block_bytes: Some(bytes),
        })
    }

    async fn get_availability(&self) -> Result<AvailabilityInfo> {
        let started = std::time::Instant::now();
        let response = self.request("HEAD", "", &[], false).await?;
        if response.status != 200 && response.status != 204 {
            return Err(Error::Io(format!(
                "DA bucket unavailable: {}",
                response.status
            )));
        }
        Ok(AvailabilityInfo {
            version: 1,
            api_version: 1,
            available: true,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    async fn post_tx(&self, req: PostTxRequest) -> Result<PostTxResponse> {
        req.validate()?;
        let logical = hex::encode(sha256(&req.tx_bytes));
        self.put("txs", &logical, &req.tx_bytes).await?;
        Ok(PostTxResponse {
            version: 1,
            api_version: 1,
            da_id: format!("da:{logical}"),
            available: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use workstream_core::Hash;

    #[derive(Default)]
    struct Provider {
        objects: HashMap<String, Vec<u8>>,
    }

    struct Mock {
        addr: std::net::SocketAddr,
        objects: Arc<std::sync::Mutex<Provider>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn authorization(
        method: &str,
        path: &str,
        host: &str,
        amz: &str,
        payload_hash: &str,
        access: &str,
        secret: &[u8],
    ) -> String {
        let date = &amz[..8];
        let canonical = format!(
            "{method}\n{path}\n\nhost:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{amz}\n\n{SIGNED_HEADERS}\n{payload}",
            payload = payload_hash
        );
        let scope = format!("{date}/us-east-1/s3/aws4_request");
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical))
        );
        let mut prefixed = b"AWS4".to_vec();
        prefixed.extend_from_slice(secret);
        let mut key = hmac(&prefixed, date.as_bytes());
        key = hmac(&key, b"us-east-1");
        key = hmac(&key, b"s3");
        key = hmac(&key, b"aws4_request");
        format!(
            "AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={}",
            hex::encode(hmac(&key, to_sign.as_bytes()))
        )
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("test HMAC key");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn reply(status: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// In-repo S3-compatible peer. It verifies SigV4 and payload hashes and
    /// enforces conditional PUT, so tests exercise the real wire contract.
    async fn mock(secret: &'static [u8], access: &'static str) -> Mock {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let addr = listener.local_addr().unwrap();
        let objects = Arc::new(std::sync::Mutex::new(Provider::default()));
        let state = objects.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    // Read exactly one request. `read_to_end` would wait for a
                    // client half-close that HTTP/1.1 does not send.
                    let mut head_bytes = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        match socket.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head_bytes.push(byte[0]),
                        }
                        if head_bytes.ends_with(b"\r\n\r\n") {
                            break;
                        }
                        if head_bytes.len() > 16 << 10 {
                            return;
                        }
                    }
                    let Some(split) = head_bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&head_bytes[..split]).to_string();
                    let header = |name: &str| {
                        head.lines().find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            if key.eq_ignore_ascii_case(name) {
                                Some(value.trim().to_string())
                            } else {
                                None
                            }
                        })
                    };
                    let body_len = header("content-length")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);
                    if body_len > MAX_OBJECT {
                        return;
                    }
                    let mut body = vec![0u8; body_len];
                    if socket.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let request = head.lines().next().unwrap_or("");
                    let mut parts = request.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let host = header("host").unwrap_or_default();
                    let amz = header("x-amz-date").unwrap_or_default();
                    let payload_hash = header("x-amz-content-sha256").unwrap_or_default();
                    let valid = amz.len() == 16
                        && hex::encode(Sha256::digest(&body)) == payload_hash
                        && header("authorization").as_deref()
                            == Some(&authorization(
                                &method,
                                &path,
                                &host,
                                &amz,
                                &payload_hash,
                                access,
                                secret,
                            ));
                    if !valid {
                        let _ = socket
                            .write_all(&reply("403 Forbidden", b"bad signature"))
                            .await;
                        let _ = socket.shutdown().await;
                        return;
                    }
                    let response = if method == "PUT" {
                        let mut table = state.lock().unwrap();
                        if header("if-none-match").as_deref() == Some("*")
                            && table.objects.contains_key(&path)
                        {
                            reply("412 Precondition Failed", b"")
                        } else {
                            table.objects.insert(path, body);
                            reply("204 No Content", b"")
                        }
                    } else if method == "GET" {
                        let value = state.lock().unwrap().objects.get(&path).cloned();
                        match value {
                            Some(bytes) => reply("200 OK", &bytes),
                            None => reply("404 Not Found", b""),
                        }
                    } else if method == "HEAD" {
                        reply("200 OK", b"")
                    } else {
                        reply("405 Method Not Allowed", b"")
                    };
                    let _ = socket.write_all(&response).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Mock {
            addr,
            objects,
            server,
        }
    }

    fn test_client(mock: &Mock) -> ObjectDaClient {
        ObjectDaClient::test_client(mock.addr.to_string(), "workstream", b"test-secret")
    }

    fn post(bytes: &[u8], commitment: H256) -> PostBlockRequest {
        PostBlockRequest {
            version: 1,
            api_version: 1,
            block_bytes: bytes.to_vec(),
            commitment: Some(commitment),
        }
    }

    #[tokio::test]
    async fn content_identity_and_idempotent_write() {
        let mock = mock(b"test-secret", "test-key").await;
        let client = test_client(&mock);
        let commitment = Hash::sha256(b"committed reference");
        let posted = client
            .post_block(post(b"exact bytes", commitment))
            .await
            .unwrap();
        assert_eq!(posted.da_id, format!("da:{}", commitment.to_hex()));
        // A second, independent process may write the same bytes to the same
        // reference; conditional PUT plus envelope equality makes it idempotent.
        let other = test_client(&mock);
        other
            .post_block(post(b"exact bytes", commitment))
            .await
            .unwrap();
        let fetched = other
            .get_block(GetBlockRequest {
                version: 1,
                api_version: 1,
                da_id: posted.da_id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(fetched.block_bytes.as_deref(), Some(&b"exact bytes"[..]));
        assert!(client.get_availability().await.unwrap().available);
    }

    #[tokio::test]
    async fn conflicting_overwrite_is_rejected() {
        let mock = mock(b"test-secret", "test-key").await;
        let client = test_client(&mock);
        let commitment = Hash::sha256(b"committed reference");
        client.post_block(post(b"first", commitment)).await.unwrap();
        let err = client
            .post_block(post(b"replacement", commitment))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
        let stored = mock.objects.lock().unwrap().objects.len();
        assert_eq!(stored, 1);
    }

    #[tokio::test]
    async fn read_rejects_tampered_envelope() {
        let mock = mock(b"test-secret", "test-key").await;
        let client = test_client(&mock);
        let commitment = Hash::sha256(b"committed reference");
        let posted = client
            .post_block(post(b"original", commitment))
            .await
            .unwrap();
        let path = format!("/workstream/workstream/blocks/{}", commitment.to_hex());
        {
            let mut table = mock.objects.lock().unwrap();
            let envelope = table.objects.get_mut(&path).unwrap();
            let last = envelope.len() - 1;
            envelope[last] ^= 1;
        }
        let err = client
            .get_block(GetBlockRequest {
                version: 1,
                api_version: 1,
                da_id: posted.da_id,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn signature_mismatch_is_rejected() {
        let mock = mock(b"test-secret", "test-key").await;
        let wrong =
            ObjectDaClient::test_client(mock.addr.to_string(), "workstream", b"wrong-secret");
        let err = wrong
            .post_block(post(b"payload", Hash::sha256(b"ref")))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
        assert!(mock.objects.lock().unwrap().objects.is_empty());
    }

    #[tokio::test]
    async fn unavailability_fails_bounded() {
        let mock = mock(b"test-secret", "test-key").await;
        let addr = mock.addr.to_string();
        drop(mock);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = ObjectDaClient::test_client(addr, "workstream", b"test-secret");
        let started = std::time::Instant::now();
        let err = client
            .get_block(GetBlockRequest {
                version: 1,
                api_version: 1,
                da_id: format!("da:{}", "ab".repeat(32)),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn malformed_reference_is_rejected() {
        let mock = mock(b"test-secret", "test-key").await;
        let err = test_client(&mock)
            .get_block(GetBlockRequest {
                version: 1,
                api_version: 1,
                da_id: "da:not-a-hash".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }
}
