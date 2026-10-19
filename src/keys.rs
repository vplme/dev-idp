use axum_extra::extract::cookie::Key;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};

use crate::config::Config;

pub struct SigningKey {
    /// RFC 7638 JWK thumbprint, so a different key always gets a different kid.
    pub kid: String,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    /// Public JWK as served from /jwks.
    pub jwk: Value,
    /// Signs the session cookie; derived from the key so sessions survive restarts.
    pub cookie_key: Key,
}

impl SigningKey {
    pub fn from_config(config: &Config) -> Result<SigningKey, String> {
        let key = match (&config.signing_key, &config.key_seed) {
            (Some(pem), _) => parse_pem(pem)?,
            (None, Some(seed)) => from_seed(seed)?,
            (None, None) => return Err("set key_seed or signing_key".into()),
        };
        SigningKey::new(&key)
    }

    fn new(key: &RsaPrivateKey) -> Result<SigningKey, String> {
        let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
        // Thumbprint input: required members only, in lexicographic order, no whitespace.
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));

        let der = key
            .to_pkcs1_der()
            .map_err(|e| format!("cannot encode key: {e}"))?;
        let decoding = DecodingKey::from_rsa_components(&n, &e)
            .map_err(|e| format!("cannot build decoding key: {e}"))?;
        let jwk = json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e });
        let cookie_key = Key::from(&Sha512::digest(der.as_bytes()));

        Ok(SigningKey {
            kid,
            encoding: EncodingKey::from_rsa_der(der.as_bytes()),
            decoding,
            jwk,
            cookie_key,
        })
    }
}

/// Deterministic for a given seed, as long as the rsa crate's key generation doesn't change.
fn from_seed(seed: &str) -> Result<RsaPrivateKey, String> {
    let mut rng = ChaCha20Rng::from_seed(Sha256::digest(seed.as_bytes()).into());
    RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("cannot generate key: {e}"))
}

fn parse_pem(pem: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|_| "signing_key: expected an RSA private key in PKCS#8 or PKCS#1 PEM".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_key() {
        let a = SigningKey::new(&from_seed("dev-idp").unwrap()).unwrap();
        let b = SigningKey::new(&from_seed("dev-idp").unwrap()).unwrap();
        let c = SigningKey::new(&from_seed("other").unwrap()).unwrap();
        assert_eq!(a.kid, b.kid);
        assert_ne!(a.kid, c.kid);
    }

    #[test]
    fn pem_round_trip() {
        let key = from_seed("pem").unwrap();
        let pem = key.to_pkcs1_pem(Default::default()).unwrap();
        let parsed = parse_pem(&pem).unwrap();
        assert_eq!(
            SigningKey::new(&parsed).unwrap().kid,
            SigningKey::new(&key).unwrap().kid
        );
        assert!(parse_pem("garbage").is_err());
    }
}
