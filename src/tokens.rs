use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, Header, Validation};
use serde_json::{Map, Value, json};

use crate::config::{Client, Config, RESERVED_CLAIMS, User};
use crate::keys::SigningKey;
use crate::state::Grant;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn has_scope(scope: &str, wanted: &str) -> bool {
    scope.split_whitespace().any(|s| s == wanted)
}

/// Standard claims allowed by the granted scopes (`profile`, `email`).
pub fn standard_claims(user: &User, scope: &str) -> Map<String, Value> {
    let mut claims = Map::new();
    if has_scope(scope, "profile") {
        let (first, rest) = match user.name.split_once(' ') {
            Some((first, rest)) => (first, Some(rest)),
            None => (user.name.as_str(), None),
        };
        claims.insert("name".into(), json!(user.name));
        claims.insert(
            "given_name".into(),
            json!(user.given_name.as_deref().unwrap_or(first)),
        );
        if let Some(family) = user.family_name.as_deref().or(rest) {
            claims.insert("family_name".into(), json!(family));
        }
        claims.insert(
            "preferred_username".into(),
            json!(user.preferred_username.as_deref().unwrap_or(&user.id)),
        );
        if let Some(picture) = &user.picture {
            claims.insert("picture".into(), json!(picture));
        }
    }
    if has_scope(scope, "email")
        && let Some(email) = &user.email
    {
        claims.insert("email".into(), json!(email));
        claims.insert("email_verified".into(), json!(true));
    }
    claims
}

/// The user's own claims, then the per-login extras on top.
pub fn custom_claims(user: &User, extra: &Map<String, Value>) -> Map<String, Value> {
    let mut claims = user.claims.clone();
    claims.extend(extra.clone());
    claims
}

/// Parses the picker's "extra claims" field: empty, or a JSON object without reserved claims.
pub fn parse_extra_claims(text: &str) -> Result<Map<String, Value>, String> {
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    let Ok(Value::Object(map)) = serde_json::from_str(text) else {
        return Err("Extra claims must be a JSON object, like {\"roles\": [\"admin\"]}.".into());
    };
    if let Some(reserved) = map.keys().find(|k| RESERVED_CLAIMS.contains(&k.as_str())) {
        return Err(format!(
            "\"{reserved}\" is set by dev-idp and can't be overridden."
        ));
    }
    Ok(map)
}

pub struct Issued {
    pub id_token: String,
    pub access_token: String,
}

pub fn issue(
    config: &Config,
    key: &SigningKey,
    client: &Client,
    user: &User,
    grant: &Grant,
) -> Issued {
    let iat = now();
    let custom = custom_claims(user, &grant.extra_claims);

    let mut id = Map::new();
    id.insert("iss".into(), json!(config.issuer));
    id.insert("sub".into(), json!(user.id));
    id.insert("aud".into(), json!(client.id));
    id.insert("exp".into(), json!(iat + config.id_token_ttl.as_secs()));
    id.insert("iat".into(), json!(iat));
    id.insert("auth_time".into(), json!(grant.auth_time));
    if let Some(nonce) = &grant.nonce {
        id.insert("nonce".into(), json!(nonce));
    }
    id.extend(standard_claims(user, &grant.scope));
    id.extend(custom.clone());

    let audience = client
        .audience
        .clone()
        .unwrap_or_else(|| vec![client.id.clone(), config.issuer.clone()]);
    let mut access = Map::new();
    access.insert("iss".into(), json!(config.issuer));
    access.insert("sub".into(), json!(user.id));
    access.insert("aud".into(), json!(audience));
    access.insert("client_id".into(), json!(client.id));
    access.insert("exp".into(), json!(iat + config.access_token_ttl.as_secs()));
    access.insert("iat".into(), json!(iat));
    access.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string()));
    access.insert("scope".into(), json!(grant.scope));
    if client.scp {
        access.insert(
            "scp".into(),
            json!(grant.scope.split_whitespace().collect::<Vec<_>>()),
        );
    }
    access.extend(custom);

    Issued {
        id_token: sign(key, "JWT", &id),
        access_token: sign(key, "at+jwt", &access),
    }
}

fn sign(key: &SigningKey, typ: &str, claims: &Map<String, Value>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some(typ.into());
    header.kid = Some(key.kid.clone());
    jsonwebtoken::encode(&header, claims, &key.encoding).expect("RS256 signing cannot fail")
}

/// Verifies a token this issuer signed. `check_exp` is off for logout's id_token_hint.
pub fn verify(
    config: &Config,
    key: &SigningKey,
    token: &str,
    check_exp: bool,
) -> Option<Map<String, Value>> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&config.issuer]);
    validation.validate_aud = false;
    validation.validate_exp = check_exp;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<Map<String, Value>>(token, &key.decoding, &validation)
        .ok()
        .map(|data| data.claims)
}

/// Userinfo: subject, standard claims for the token's scope, and the token's custom claims.
pub fn userinfo(config: &Config, access: &Map<String, Value>) -> Map<String, Value> {
    let sub = access
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let scope = access
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut info = Map::new();
    info.insert("sub".into(), json!(sub));
    if let Some(user) = config.user(sub) {
        info.extend(standard_claims(user, scope));
    }
    for (k, v) in access {
        if !RESERVED_CLAIMS.contains(&k.as_str()) {
            info.insert(k.clone(), v.clone());
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        User {
            id: "alice".into(),
            name: "Alice Admin".into(),
            email: Some("alice@example.com".into()),
            picture: None,
            given_name: None,
            family_name: None,
            preferred_username: None,
            claims: serde_json::from_value(json!({"roles": ["admin"]})).unwrap(),
        }
    }

    #[test]
    fn standard_claims_follow_scope() {
        let p = user();
        let all = standard_claims(&p, "openid profile email");
        assert_eq!(all["given_name"], "Alice");
        assert_eq!(all["family_name"], "Admin");
        assert_eq!(all["preferred_username"], "alice");
        assert_eq!(all["email_verified"], true);
        assert!(standard_claims(&p, "openid").is_empty());
        assert!(!standard_claims(&p, "openid profile").contains_key("email"));
    }

    #[test]
    fn extra_claims_override_user_claims() {
        let extra = parse_extra_claims(r#"{"roles": ["viewer"], "tenant": "acme"}"#).unwrap();
        let claims = custom_claims(&user(), &extra);
        assert_eq!(claims["roles"], json!(["viewer"]));
        assert_eq!(claims["tenant"], "acme");
        assert!(parse_extra_claims("").unwrap().is_empty());
        assert!(parse_extra_claims("[1]").is_err());
        assert!(parse_extra_claims(r#"{"sub": "x"}"#).is_err());
    }
}
