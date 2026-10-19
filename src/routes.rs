use std::time::{Duration, Instant};

use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::{Client, Config, is_localhost_uri};
use crate::state::{AppState, Grant};
use crate::tokens;

const SESSION_COOKIE: &str = "dev_idp_session";
const CODE_TTL: Duration = Duration::from_secs(60);

pub fn router(state: AppState) -> Router {
    let base = base_path(&state.config().issuer);
    let routes = Router::new()
        .route("/", get(index))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize).post(choose_persona))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo).post(userinfo))
        .route("/logout", get(logout).post(logout_form));
    let app = if base.is_empty() {
        routes
    } else {
        Router::new().nest(&base, routes)
    };
    app.with_state(state)
}

/// The issuer's path, so an issuer like `http://localhost:5556/dex` serves under `/dex`.
fn base_path(issuer: &str) -> String {
    Url::parse(issuer)
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default()
}

// ---------- discovery ----------

async fn discovery(State(state): State<AppState>) -> Json<Value> {
    let iss = state.config().issuer.clone();
    Json(json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/authorize"),
        "token_endpoint": format!("{iss}/token"),
        "userinfo_endpoint": format!("{iss}/userinfo"),
        "jwks_uri": format!("{iss}/jwks"),
        "end_session_endpoint": format!("{iss}/logout"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name",
            "family_name", "preferred_username", "picture", "email", "email_verified"
        ],
    }))
}

async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "keys": [state.key.jwk] }))
}

// ---------- authorize ----------

#[derive(Debug, Default, Deserialize)]
struct AuthorizeParams {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    response_mode: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    prompt: Option<String>,
    // Only sent by the picker form.
    persona: Option<String>,
    extra_claims: Option<String>,
}

struct ValidRequest {
    client: Client,
    redirect_uri: String,
    scope: String,
}

/// Checks an authorization request. Errors before the redirect URI is trusted
/// are shown as a page; later ones are redirected back to the app.
#[allow(clippy::result_large_err)]
fn validate(config: &Config, p: &AuthorizeParams) -> Result<ValidRequest, Response> {
    let Some(client_id) = p.client_id.as_deref() else {
        return Err(error_page(
            &config.issuer,
            "Bad request",
            "The request has no client_id.",
        ));
    };
    let configured = config.client(client_id).cloned();
    let Some(client) = configured
        .clone()
        .or_else(|| config.lenient.then(|| Client::lenient(client_id)))
    else {
        return Err(error_page(
            &config.issuer,
            "Unknown client",
            &format!(
                "No client \"{client_id}\" in the config. Add it under clients, or set lenient: true."
            ),
        ));
    };

    let redirect_uri = match (&p.redirect_uri, client.redirect_uris.as_slice()) {
        (Some(uri), _) => uri.clone(),
        (None, [only]) => only.clone(),
        (None, _) => {
            return Err(error_page(
                &config.issuer,
                "Bad request",
                "The request has no redirect_uri.",
            ));
        }
    };
    let registered = client.redirect_uris.contains(&redirect_uri);
    if !registered && !(config.lenient && is_localhost_uri(&redirect_uri)) {
        return Err(error_page(
            &config.issuer,
            "Redirect URI not allowed",
            &format!("\"{redirect_uri}\" isn't in redirect_uris for client \"{client_id}\"."),
        ));
    }

    let fail = |error: &str, description: &str| {
        Err(error_redirect(
            &redirect_uri,
            error,
            description,
            p.state.as_deref(),
        ))
    };
    if p.response_type.as_deref() != Some("code") {
        return fail(
            "unsupported_response_type",
            "Only response_type=code is supported.",
        );
    }
    if p.response_mode.as_deref().is_some_and(|m| m != "query") {
        return fail("invalid_request", "Only response_mode=query is supported.");
    }
    let scope = p.scope.clone().unwrap_or_default();
    if !tokens::has_scope(&scope, "openid") {
        return fail("invalid_scope", "The openid scope is required.");
    }
    if p.code_challenge.is_some() && p.code_challenge_method.as_deref() != Some("S256") {
        return fail(
            "invalid_request",
            "Only code_challenge_method=S256 is supported.",
        );
    }
    let public = configured.is_some_and(|c| c.secret.is_none());
    if public && p.code_challenge.is_none() {
        return fail("invalid_request", "Clients without a secret must use PKCE.");
    }
    Ok(ValidRequest {
        client,
        redirect_uri,
        scope,
    })
}

async fn authorize(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    let config = state.config();
    let req = match validate(&config, &p) {
        Ok(req) => req,
        Err(response) => return response,
    };
    let prompts: Vec<&str> = p
        .prompt
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let force_picker = prompts
        .iter()
        .any(|&p| p == "login" || p == "select_account");

    let session = session(&jar, &config).filter(|(id, _)| req.client.allows_persona(id));
    match session {
        Some((persona, auth_time)) if !force_picker => {
            issue_code(&state, &req, &p, persona, auth_time, Map::new()).into_response()
        }
        _ if prompts.contains(&"none") => error_redirect(
            &req.redirect_uri,
            "login_required",
            "No dev-idp session.",
            p.state.as_deref(),
        ),
        _ => picker(&config, &req, &p, None),
    }
}

async fn choose_persona(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(p): Form<AuthorizeParams>,
) -> Response {
    let config = state.config();
    let req = match validate(&config, &p) {
        Ok(req) => req,
        Err(response) => return response,
    };
    let persona = p.persona.as_deref().unwrap_or_default();
    if config.persona(persona).is_none() || !req.client.allows_persona(persona) {
        return picker(
            &config,
            &req,
            &p,
            Some(format!("Unknown persona \"{persona}\".")),
        );
    }
    let extra = match tokens::parse_extra_claims(p.extra_claims.as_deref().unwrap_or_default()) {
        Ok(extra) => extra,
        Err(error) => return picker(&config, &req, &p, Some(error)),
    };

    let auth_time = tokens::now();
    let cookie = Cookie::build((SESSION_COOKIE, format!("{persona}:{auth_time}")))
        .path(cookie_path(&config.issuer))
        .http_only(true)
        .secure(config.issuer.starts_with("https://"))
        .same_site(SameSite::Lax);
    let redirect = issue_code(&state, &req, &p, persona.to_string(), auth_time, extra);
    (jar.add(cookie), redirect).into_response()
}

fn issue_code(
    state: &AppState,
    req: &ValidRequest,
    p: &AuthorizeParams,
    persona_id: String,
    auth_time: u64,
    extra_claims: Map<String, Value>,
) -> Redirect {
    let code = state.store_code(Grant {
        client_id: req.client.id.clone(),
        persona_id,
        scope: req.scope.clone(),
        redirect_uri: req.redirect_uri.clone(),
        nonce: p.nonce.clone(),
        code_challenge: p.code_challenge.clone(),
        extra_claims,
        auth_time,
        expires: Instant::now() + CODE_TTL,
    });
    let mut params = vec![("code", code.as_str())];
    if let Some(s) = p.state.as_deref() {
        params.push(("state", s));
    }
    Redirect::to(&with_query(&req.redirect_uri, &params))
}

/// The signed-in persona and when they picked it, if the persona still exists.
fn session(jar: &SignedCookieJar, config: &Config) -> Option<(String, u64)> {
    let cookie = jar.get(SESSION_COOKIE)?;
    let (persona, auth_time) = cookie.value().rsplit_once(':')?;
    config.persona(persona)?;
    Some((persona.to_string(), auth_time.parse().ok()?))
}

fn cookie_path(issuer: &str) -> String {
    let base = base_path(issuer);
    if base.is_empty() { "/".into() } else { base }
}

#[derive(Template)]
#[template(path = "picker.html")]
struct PickerPage {
    client: String,
    personas: Vec<PersonaCard>,
    hidden: Vec<(&'static str, String)>,
    extra_claims: String,
    error: Option<String>,
}

struct PersonaCard {
    id: String,
    name: String,
    detail: String,
    claims: String,
}

fn picker(
    config: &Config,
    req: &ValidRequest,
    p: &AuthorizeParams,
    error: Option<String>,
) -> Response {
    let personas = config
        .personas
        .iter()
        .filter(|persona| req.client.allows_persona(&persona.id))
        .map(|persona| PersonaCard {
            id: persona.id.clone(),
            name: persona.name.clone(),
            detail: persona.email.clone().unwrap_or_default(),
            claims: if persona.claims.is_empty() {
                String::new()
            } else {
                Value::Object(persona.claims.clone()).to_string()
            },
        })
        .collect();
    let mut hidden = vec![
        ("client_id", req.client.id.clone()),
        ("redirect_uri", req.redirect_uri.clone()),
        ("response_type", "code".to_string()),
        ("scope", req.scope.clone()),
    ];
    let optional = [
        ("response_mode", &p.response_mode),
        ("state", &p.state),
        ("nonce", &p.nonce),
        ("code_challenge", &p.code_challenge),
        ("code_challenge_method", &p.code_challenge_method),
    ];
    hidden.extend(
        optional
            .into_iter()
            .filter_map(|(k, v)| v.clone().map(|v| (k, v))),
    );

    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = PickerPage {
        client: req.client.display_name().to_string(),
        personas,
        hidden,
        extra_claims: p.extra_claims.clone().unwrap_or_default(),
        error,
    };
    (status, render(page)).into_response()
}

// ---------- token ----------

#[derive(Debug, Deserialize)]
struct TokenParams {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(p): Form<TokenParams>,
) -> Response {
    let config = state.config();
    let (client_id, secret) = match basic_auth(&headers) {
        Some((id, secret)) => (Some(id), Some(secret)),
        None => (p.client_id.clone(), p.client_secret.clone()),
    };

    let grant = match p.grant_type.as_deref() {
        Some("authorization_code") => {
            let Some(grant) = p.code.as_deref().and_then(|c| state.take_code(c)) else {
                return token_error("invalid_grant", "Unknown, used or expired code.");
            };
            if p.redirect_uri
                .as_ref()
                .is_some_and(|uri| *uri != grant.redirect_uri)
            {
                return token_error(
                    "invalid_grant",
                    "redirect_uri doesn't match the authorization request.",
                );
            }
            if let Some(challenge) = &grant.code_challenge {
                let Some(verifier) = &p.code_verifier else {
                    return token_error("invalid_grant", "Missing code_verifier.");
                };
                if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != *challenge {
                    return token_error(
                        "invalid_grant",
                        "code_verifier doesn't match code_challenge.",
                    );
                }
            }
            grant
        }
        Some("refresh_token") => {
            let Some(grant) = p
                .refresh_token
                .as_deref()
                .and_then(|t| state.take_refresh_token(t))
            else {
                return token_error("invalid_grant", "Unknown, used or expired refresh token.");
            };
            grant
        }
        _ => {
            return token_error(
                "unsupported_grant_type",
                "Use authorization_code or refresh_token.",
            );
        }
    };

    let client_id = client_id.unwrap_or_else(|| grant.client_id.clone());
    if client_id != grant.client_id {
        return token_error("invalid_grant", "The grant was issued to another client.");
    }
    let client = match config.client(&client_id) {
        Some(client) => {
            if client.secret.is_some() && secret != client.secret {
                return token_error("invalid_client", "Wrong or missing client secret.");
            }
            client.clone()
        }
        None if config.lenient => Client::lenient(&client_id),
        None => return token_error("invalid_client", "Unknown client."),
    };
    let Some(persona) = config
        .persona(&grant.persona_id)
        .filter(|p| client.allows_persona(&p.id))
    else {
        return token_error(
            "invalid_grant",
            "The persona no longer exists or isn't allowed for this client.",
        );
    };

    let issued = tokens::issue(&config, &state.key, &client, persona, &grant);
    let refresh_token = state.store_refresh_token(Grant {
        redirect_uri: String::new(),
        nonce: None,
        code_challenge: None,
        expires: Instant::now() + config.refresh_token_ttl,
        ..grant.clone()
    });
    let body = json!({
        "access_token": issued.access_token,
        "token_type": "Bearer",
        "expires_in": config.access_token_ttl.as_secs(),
        "id_token": issued.id_token,
        "refresh_token": refresh_token,
        "scope": grant.scope,
    });
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

/// Client credentials from `Authorization: Basic`, form-urlencoded per RFC 6749 §2.3.1.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let unescape = |s: &str| {
        url::form_urlencoded::parse(s.as_bytes())
            .next()
            .map(|(k, _)| k.into_owned())
    };
    Some((
        unescape(id).unwrap_or_default(),
        unescape(secret).unwrap_or_default(),
    ))
}

fn token_error(error: &str, description: &str) -> Response {
    let status = if error == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
    let body = Json(json!({ "error": error, "error_description": description }));
    let mut response = (status, [(header::CACHE_CONTROL, "no-store")], body).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"dev-idp\"".parse().unwrap(),
        );
    }
    response
}

// ---------- userinfo ----------

async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let config = state.config();
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });
    let is_access_token =
        |t: &str| jsonwebtoken::decode_header(t).is_ok_and(|h| h.typ.as_deref() == Some("at+jwt"));
    let claims = token
        .filter(|t| is_access_token(t))
        .and_then(|t| tokens::verify(&config, &state.key, t, true));
    match claims {
        Some(claims) => Json(tokens::userinfo(&config, &claims)).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
            Json(json!({ "error": "invalid_token" })),
        )
            .into_response(),
    }
}

// ---------- logout ----------

#[derive(Debug, Default, Deserialize)]
struct LogoutParams {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
}

async fn logout_form(
    state: State<AppState>,
    jar: SignedCookieJar,
    Form(p): Form<LogoutParams>,
) -> Response {
    logout(state, jar, Query(p)).await
}

async fn logout(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(p): Query<LogoutParams>,
) -> Response {
    let config = state.config();
    let jar = jar.remove(Cookie::build(SESSION_COOKIE).path(cookie_path(&config.issuer)));

    let Some(uri) = &p.post_logout_redirect_uri else {
        let page = error_page(
            &config.issuer,
            "Signed out",
            "The next login shows the persona picker again.",
        );
        return (jar, page).into_response();
    };
    // The client comes from client_id, or from the aud of an id_token_hint (expired is fine).
    let client_id = p.client_id.clone().or_else(|| {
        let hint = tokens::verify(&config, &state.key, p.id_token_hint.as_deref()?, false)?;
        hint.get("aud")?.as_str().map(str::to_string)
    });
    let registered = config
        .clients
        .iter()
        .filter(|c| client_id.as_ref().is_none_or(|id| *id == c.id))
        .any(|c| c.post_logout_redirect_uris.contains(uri));
    if !registered && !(config.lenient && is_localhost_uri(uri)) {
        let message =
            format!("Signed out, but \"{uri}\" isn't in any client's post_logout_redirect_uris.");
        return (jar, error_page(&config.issuer, "Signed out", &message)).into_response();
    }
    let params: Vec<_> = p
        .state
        .as_deref()
        .map(|s| ("state", s))
        .into_iter()
        .collect();
    (jar, Redirect::to(&with_query(uri, &params))).into_response()
}

// ---------- index and helpers ----------

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    issuer: String,
    lenient: bool,
    signed_in: Option<String>,
    logout: String,
    discovery: String,
    personas: Vec<String>,
    clients: Vec<String>,
}

async fn index(State(state): State<AppState>, jar: SignedCookieJar) -> Response {
    let config = state.config();
    let signed_in = session(&jar, &config)
        .and_then(|(id, _)| config.persona(&id))
        .map(|p| p.name.clone());
    render(IndexPage {
        issuer: config.issuer.clone(),
        lenient: config.lenient,
        signed_in,
        logout: format!("{}/logout", config.issuer),
        discovery: format!("{}/.well-known/openid-configuration", config.issuer),
        personas: config.personas.iter().map(|p| p.id.clone()).collect(),
        clients: config.clients.iter().map(|c| c.id.clone()).collect(),
    })
    .into_response()
}

#[derive(Template)]
#[template(path = "message.html")]
struct MessagePage<'a> {
    title: &'a str,
    message: &'a str,
    home: String,
}

fn error_page(issuer: &str, title: &str, message: &str) -> Response {
    let status = if title == "Signed out" {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    let page = MessagePage {
        title,
        message,
        home: format!("{issuer}/"),
    };
    (status, render(page)).into_response()
}

fn error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut params = vec![("error", error), ("error_description", description)];
    if let Some(s) = state {
        params.push(("state", s));
    }
    Redirect::to(&with_query(redirect_uri, &params)).into_response()
}

fn with_query(uri: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return uri.to_string();
    }
    let mut url = Url::parse(uri).expect("redirect URIs are validated");
    url.query_pairs_mut().extend_pairs(params);
    url.to_string()
}

fn render(template: impl Template) -> Html<String> {
    Html(template.render().expect("templates render"))
}
