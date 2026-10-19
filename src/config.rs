use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value};
use url::Url;

/// Claims dev-idp sets itself; personas and extra claims may not override them.
pub const RESERVED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "nonce",
    "auth_time",
    "azp",
    "client_id",
    "scope",
    "scp",
    "at_hash",
    "c_hash",
    "sid",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub key_seed: Option<String>,
    pub signing_key: Option<String>,
    #[serde(default = "one_hour", with = "humantime_serde")]
    pub access_token_ttl: Duration,
    #[serde(default = "one_hour", with = "humantime_serde")]
    pub id_token_ttl: Duration,
    #[serde(default = "seven_days", with = "humantime_serde")]
    pub refresh_token_ttl: Duration,
    #[serde(default)]
    pub lenient: bool,
    #[serde(default)]
    pub clients: Vec<Client>,
    #[serde(default)]
    pub personas: Vec<Persona>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub id: String,
    pub name: Option<String>,
    /// No secret means a public client, which must use PKCE.
    pub secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// Limits which personas the picker shows for this client.
    pub personas: Option<Vec<String>>,
    /// Replaces the default access token audience `[client_id, issuer]`.
    pub audience: Option<Vec<String>>,
    /// Also emit the scope as an array in the `scp` claim.
    #[serde(default)]
    pub scp: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persona {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub picture: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub claims: Map<String, Value>,
}

fn default_issuer() -> String {
    "http://localhost:5556".into()
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:5556".parse().unwrap()
}

fn one_hour() -> Duration {
    Duration::from_secs(3600)
}

fn seven_days() -> Duration {
    Duration::from_secs(7 * 24 * 3600)
}

impl Config {
    /// Reads the file, applies `DEV_IDP_*` overrides and validates the result.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut config = Config::parse(&text)?;
        config.apply_env(|name| std::env::var(name).ok())?;
        config.validate()?;
        Ok(config)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        yaml_serde::from_str(text).map_err(|e| format!("invalid config: {e}"))
    }

    /// Only restart-only fields can be overridden, so hot-reloaded YAML edits
    /// are never silently shadowed by the environment.
    pub fn apply_env(&mut self, var: impl Fn(&str) -> Option<String>) -> Result<(), String> {
        if let Some(v) = var("DEV_IDP_ISSUER") {
            self.issuer = v;
        }
        if let Some(v) = var("DEV_IDP_LISTEN") {
            self.listen = v
                .parse()
                .map_err(|e| format!("DEV_IDP_LISTEN: invalid address {v:?}: {e}"))?;
        }
        if let Some(v) = var("DEV_IDP_KEY_SEED") {
            self.key_seed = Some(v);
        }
        if let Some(v) = var("DEV_IDP_SIGNING_KEY") {
            self.signing_key = Some(v);
        }
        Ok(())
    }

    pub fn validate(&mut self) -> Result<(), String> {
        let issuer = self.issuer.trim_end_matches('/').to_string();
        let url =
            Url::parse(&issuer).map_err(|e| format!("issuer: invalid URL {issuer:?}: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") || url.query().is_some() {
            return Err(format!(
                "issuer: must be an http(s) URL without query: {issuer:?}"
            ));
        }
        self.issuer = issuer;

        if self.key_seed.is_none() && self.signing_key.is_none() {
            return Err("set key_seed or signing_key".into());
        }
        if self.personas.is_empty() {
            return Err("define at least one persona".into());
        }

        let mut ids = HashSet::new();
        for p in &self.personas {
            if p.id.is_empty() || !ids.insert(p.id.as_str()) {
                return Err(format!("persona id {:?} is empty or duplicated", p.id));
            }
            if let Some(reserved) = p
                .claims
                .keys()
                .find(|k| RESERVED_CLAIMS.contains(&k.as_str()))
            {
                return Err(format!(
                    "persona {:?}: claim {reserved:?} is set by dev-idp",
                    p.id
                ));
            }
        }

        let mut client_ids = HashSet::new();
        for c in &self.clients {
            if c.id.is_empty() || !client_ids.insert(c.id.as_str()) {
                return Err(format!("client id {:?} is empty or duplicated", c.id));
            }
            for uri in c.redirect_uris.iter().chain(&c.post_logout_redirect_uris) {
                Url::parse(uri)
                    .map_err(|e| format!("client {:?}: invalid URI {uri:?}: {e}", c.id))?;
            }
            for p in c.personas.iter().flatten() {
                if !ids.contains(p.as_str()) {
                    return Err(format!("client {:?}: unknown persona {p:?}", c.id));
                }
            }
        }
        Ok(())
    }

    pub fn client(&self, id: &str) -> Option<&Client> {
        self.clients.iter().find(|c| c.id == id)
    }

    pub fn persona(&self, id: &str) -> Option<&Persona> {
        self.personas.iter().find(|p| p.id == id)
    }

    /// Keeps the restart-only fields of `self` and reports which ones changed in `new`.
    pub fn restart_only_changes(&self, new: &mut Config) -> Vec<&'static str> {
        let mut changed = Vec::new();
        if self.issuer != new.issuer {
            changed.push("issuer");
            new.issuer = self.issuer.clone();
        }
        if self.listen != new.listen {
            changed.push("listen");
            new.listen = self.listen;
        }
        if self.key_seed != new.key_seed {
            changed.push("key_seed");
            new.key_seed = self.key_seed.clone();
        }
        if self.signing_key != new.signing_key {
            changed.push("signing_key");
            new.signing_key = self.signing_key.clone();
        }
        changed
    }
}

impl Client {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }

    pub fn allows_persona(&self, id: &str) -> bool {
        self.personas
            .as_ref()
            .is_none_or(|ps| ps.iter().any(|p| p == id))
    }

    /// The client lenient mode uses for a client_id that isn't configured.
    pub fn lenient(id: &str) -> Client {
        Client {
            id: id.to_string(),
            name: None,
            secret: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            personas: None,
            audience: None,
            scp: false,
        }
    }
}

/// Whether a redirect URI points at this machine (used by lenient mode).
pub fn is_localhost_uri(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "key_seed: test\npersonas:\n  - id: alice\n    name: Alice Admin\n";

    #[test]
    fn defaults() {
        let mut c = Config::parse(MINIMAL).unwrap();
        c.validate().unwrap();
        assert_eq!(c.issuer, "http://localhost:5556");
        assert_eq!(c.access_token_ttl, Duration::from_secs(3600));
        assert_eq!(c.refresh_token_ttl, Duration::from_secs(7 * 24 * 3600));
        assert!(!c.lenient);
    }

    #[test]
    fn env_overrides_restart_only_fields() {
        let mut c = Config::parse(MINIMAL).unwrap();
        c.apply_env(|name| match name {
            "DEV_IDP_ISSUER" => Some("http://dev-idp:5556/".into()),
            "DEV_IDP_LISTEN" => Some("0.0.0.0:8080".into()),
            _ => None,
        })
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.issuer, "http://dev-idp:5556");
        assert_eq!(c.listen.port(), 8080);
        assert_eq!(c.key_seed.as_deref(), Some("test"));
    }

    #[test]
    fn rejects_bad_configs() {
        let cases = [
            ("personas: [{id: a, name: A}]", "key_seed or signing_key"),
            (
                "key_seed: x\npersonas: [{id: a, name: A}, {id: a, name: B}]",
                "duplicated",
            ),
            (
                "key_seed: x\npersonas: [{id: a, name: A, claims: {sub: x}}]",
                "set by dev-idp",
            ),
            (
                "key_seed: x\npersonas: [{id: a, name: A}]\nclients: [{id: c, personas: [b]}]",
                "unknown persona",
            ),
            (
                "key_seed: x\npersonas: [{id: a, name: A}]\nclients: [{id: c, redirect_uris: [nope]}]",
                "invalid URI",
            ),
        ];
        for (yaml, expected) in cases {
            let err = Config::parse(yaml)
                .and_then(|mut c| c.validate())
                .unwrap_err();
            assert!(err.contains(expected), "{yaml:?}: {err}");
        }
        assert!(
            Config::parse("key_seed: x\ntypo: 1")
                .unwrap_err()
                .contains("typo")
        );
    }

    #[test]
    fn localhost_uris() {
        assert!(is_localhost_uri("http://localhost:3000/cb"));
        assert!(is_localhost_uri("http://app.localhost/cb"));
        assert!(is_localhost_uri("http://127.0.0.1:8080/cb"));
        assert!(is_localhost_uri("http://[::1]/cb"));
        assert!(!is_localhost_uri("https://example.com/cb"));
        assert!(!is_localhost_uri("javascript:alert(1)"));
    }
}
