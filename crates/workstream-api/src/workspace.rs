//! Workspace resource-server login using an OIDC provider's JWT access token.
//! Only a configured public key is trusted; no discovery or token-directed I/O.
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct WorkspaceLogin {
    key: DecodingKey,
    validation: Validation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    issuer: String,
    audience: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    scope: String,
    exp: u64,
    iat: u64,
    aud: String,
}

impl WorkspaceLogin {
    pub fn from_config(bytes: &[u8]) -> Result<Self, &'static str> {
        let cfg: Config =
            serde_json::from_slice(bytes).map_err(|_| "invalid workspace configuration")?;
        if !cfg.issuer.starts_with("https://") || cfg.audience.is_empty() {
            return Err("invalid workspace issuer or audience");
        }
        let key = DecodingKey::from_rsa_components(&cfg.n, &cfg.e)
            .map_err(|_| "invalid workspace public key")?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[cfg.issuer]);
        validation.set_audience(&[cfg.audience]);
        validation.validate_nbf = true;
        validation.leeway = 0;
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        Ok(Self { key, validation })
    }

    /// Return only a workspace subject. No role, grant or account is imported.
    pub(crate) fn subject(&self, token: &str) -> Option<String> {
        if token.len() > 8192 {
            return None;
        }
        let jwt = decode::<Claims>(token, &self.key, &self.validation).ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let c = jwt.claims;
        (jwt.header.typ.as_deref() == Some("at+jwt")
            && !c.aud.is_empty()
            && c.exp > now
            && c.iat <= now
            && !c.sub.is_empty()
            && c.sub.len() <= 255
            && c.scope
                .split_ascii_whitespace()
                .any(|s| s == "workspace:login"))
        .then_some(c.sub)
    }
}
