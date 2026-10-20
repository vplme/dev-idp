//! A server-side web app that logs in through dev-idp with the `openidconnect` crate:
//! authorization code flow with PKCE, nonce and state, then userinfo, refresh and
//! RP-initiated logout. Sessions live in memory behind a random cookie.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow};
use askama::Template;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use openidconnect::core::{
    CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreTokenResponse,
};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndSessionUrl,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, LogoutRequest, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, RefreshToken, Scope, TokenResponse, reqwest,
};
use serde_json::Value;

#[derive(Parser)]
struct Args {
    /// The dev-idp issuer.
    #[arg(long, env = "SAMPLE_ISSUER", default_value = "http://localhost:5556")]
    issuer: String,
    #[arg(long, env = "SAMPLE_CLIENT_ID", default_value = "sample-app")]
    client_id: String,
    #[arg(long, env = "SAMPLE_CLIENT_SECRET", default_value = "dev")]
    client_secret: String,
    /// Where the browser reaches this app; the callback is `<url>/callback`.
    #[arg(long, env = "SAMPLE_URL", default_value = "http://localhost:4000")]
    url: String,
    #[arg(long, env = "SAMPLE_LISTEN", default_value = "127.0.0.1:4000")]
    listen: String,
}

/// What discovery gives `from_provider_metadata`: an auth URL, and maybe token and userinfo URLs.
type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

struct App {
    client: OidcClient,
    end_session: Option<EndSessionUrl>,
    http: reqwest::Client,
    url: String,
    sessions: Mutex<HashMap<String, Session>>,
}

#[derive(Default)]
struct Session {
    /// Set between /login and /callback.
    pending: Option<Pending>,
    user: Option<User>,
}

struct Pending {
    state: CsrfToken,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
}

struct User {
    id_token: CoreIdToken,
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<Duration>,
}

const SESSION_COOKIE: &str = "sample_session";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    // Don't follow redirects: the OIDC endpoints must answer directly (SSRF guard).
    let http = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let issuer = IssuerUrl::new(args.issuer.clone())?;
    let metadata = discover(&issuer, &http).await?;
    let end_session = metadata.additional_metadata().end_session_endpoint.clone();
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(args.client_id),
        Some(ClientSecret::new(args.client_secret)),
    )
    .set_redirect_uri(RedirectUrl::new(format!("{}/callback", args.url))?);

    let app = Arc::new(App {
        client,
        end_session,
        http,
        url: args.url.clone(),
        sessions: Mutex::default(),
    });
    let router = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(
        "sample app on {} (listening on {}), issuer {}",
        args.url,
        args.listen,
        args.issuer
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;
    Ok(())
}

/// Discovery, retried for a few seconds in case dev-idp is still starting.
async fn discover(
    issuer: &IssuerUrl,
    http: &reqwest::Client,
) -> anyhow::Result<ProviderMetadataWithLogout> {
    let mut attempts = 0;
    loop {
        match ProviderMetadataWithLogout::discover_async(issuer.clone(), http).await {
            Ok(metadata) => return Ok(metadata),
            Err(e) if attempts < 20 => {
                attempts += 1;
                tracing::warn!("discovery failed, retrying: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e).context(format!("discovery at {}", issuer.as_str())),
        }
    }
}

type AppState = State<Arc<App>>;

/// The session id from the cookie, or a new one (with the cookie to set).
fn session_id(jar: CookieJar) -> (String, CookieJar) {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        return (cookie.value().to_owned(), jar);
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
    let cookie = Cookie::build((SESSION_COOKIE, id.clone()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    (id, jar.add(cookie))
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    user: Option<UserView>,
}

struct UserView {
    name: String,
    sub: String,
    expires_in: String,
    has_refresh_token: bool,
    id_token_claims: String,
    access_token_claims: String,
    userinfo: String,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    message: String,
}

async fn home(State(app): AppState, jar: CookieJar) -> Result<Response, AppError> {
    let (id, jar) = session_id(jar);
    let user = {
        let sessions = app.sessions.lock().unwrap();
        sessions.get(&id).and_then(|s| s.user.as_ref()).map(|u| {
            (
                u.id_token.clone(),
                u.access_token.clone(),
                u.refresh_token.is_some(),
                u.expires_in,
            )
        })
    };
    let user = match user {
        None => None,
        Some((id_token, access_token, has_refresh_token, expires_in)) => {
            // The id_token was verified at login; decode it again here just for display.
            let claims = jwt_payload(&id_token.to_string())?;
            let userinfo = fetch_userinfo(&app, &access_token).await;
            Some(UserView {
                name: claims["name"]
                    .as_str()
                    .unwrap_or("(no profile scope)")
                    .to_owned(),
                sub: claims["sub"].as_str().unwrap_or_default().to_owned(),
                expires_in: expires_in.map_or("unknown".into(), |d| format!("{}s", d.as_secs())),
                has_refresh_token,
                id_token_claims: pretty(&claims),
                access_token_claims: jwt_payload(&access_token)
                    .map_or_else(|e| e.0.to_string(), |c| pretty(&c)),
                userinfo: userinfo.map_or_else(|e| format!("error: {e:#}"), |c| pretty(&c)),
            })
        }
    };
    Ok((jar, Html(HomePage { user }.render()?)).into_response())
}

#[derive(serde::Deserialize)]
struct LoginQuery {
    /// `?prompt=login` asks dev-idp to show the picker even with a session.
    prompt: Option<String>,
}

async fn login(State(app): AppState, jar: CookieJar, Query(q): Query<LoginQuery>) -> Response {
    let (id, jar) = session_id(jar);
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = app
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("offline_access".into()))
        .set_pkce_challenge(pkce_challenge);
    if q.prompt.as_deref() == Some("login") {
        request = request.add_prompt(CoreAuthPrompt::Login);
    }
    let (url, state, nonce) = request.url();

    app.sessions.lock().unwrap().entry(id).or_default().pending = Some(Pending {
        state,
        nonce,
        pkce_verifier,
    });
    (jar, Redirect::to(url.as_str())).into_response()
}

#[derive(serde::Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(app): AppState,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let (id, jar) = session_id(jar);
    if let Some(error) = q.error {
        return Err(anyhow!(
            "dev-idp returned {error}: {}",
            q.error_description.unwrap_or_default()
        )
        .into());
    }
    let pending = app
        .sessions
        .lock()
        .unwrap()
        .get_mut(&id)
        .and_then(|s| s.pending.take())
        .context("no login in progress for this session; start again from the home page")?;
    if q.state.as_deref() != Some(pending.state.secret().as_str()) {
        return Err(anyhow!("state mismatch").into());
    }
    let code = q.code.context("callback without a code")?;

    let token = app
        .client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(pending.pkce_verifier)
        .request_async(&app.http)
        .await
        .context("token exchange")?;

    let id_token = token
        .id_token()
        .context("no id_token in the token response")?;
    let verifier = app.client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &pending.nonce)
        .context("id_token verification")?;
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            token.access_token(),
            id_token.signing_alg()?,
            id_token.signing_key(&verifier)?,
        )?;
        if &actual != expected {
            return Err(anyhow!("at_hash mismatch").into());
        }
    }
    tracing::info!("logged in as {}", claims.subject().as_str());

    let user = user_from(&token, None)?;
    app.sessions.lock().unwrap().entry(id).or_default().user = Some(user);
    Ok((jar, Redirect::to("/")).into_response())
}

async fn refresh(State(app): AppState, jar: CookieJar) -> Result<Response, AppError> {
    let (id, jar) = session_id(jar);
    let current = app
        .sessions
        .lock()
        .unwrap()
        .get(&id)
        .and_then(|s| s.user.as_ref())
        .map(|u| (u.refresh_token.clone(), u.id_token.clone()))
        .context("not logged in")?;
    let refresh_token = current
        .0
        .context("no refresh token (offline_access not granted)")?;

    let token = app
        .client
        .exchange_refresh_token(&RefreshToken::new(refresh_token))?
        .request_async(&app.http)
        .await
        .context("refresh")?;
    if let Some(id_token) = token.id_token() {
        // A refreshed id_token carries no new nonce to check.
        id_token
            .claims(&app.client.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
            .context("refreshed id_token verification")?;
    }

    let user = user_from(&token, Some(current.1))?;
    app.sessions.lock().unwrap().entry(id).or_default().user = Some(user);
    Ok((jar, Redirect::to("/")).into_response())
}

/// Forgets the local session, then sends the browser to dev-idp to end its session too.
async fn logout(State(app): AppState, jar: CookieJar) -> Result<Response, AppError> {
    let (id, jar) = session_id(jar);
    let user = app
        .sessions
        .lock()
        .unwrap()
        .remove(&id)
        .and_then(|s| s.user);
    let (Some(user), Some(end_session)) = (user, app.end_session.clone()) else {
        return Ok((jar, Redirect::to("/")).into_response());
    };
    let url = LogoutRequest::from(end_session)
        .set_id_token_hint(&user.id_token)
        .set_post_logout_redirect_uri(PostLogoutRedirectUrl::new(format!("{}/", app.url))?)
        .http_get_url();
    Ok((jar, Redirect::to(url.as_str())).into_response())
}

/// Keeps the previous id_token when a refresh response has none.
fn user_from(
    token: &CoreTokenResponse,
    previous_id_token: Option<CoreIdToken>,
) -> anyhow::Result<User> {
    Ok(User {
        id_token: token
            .id_token()
            .cloned()
            .or(previous_id_token)
            .context("no id_token")?,
        access_token: token.access_token().secret().clone(),
        refresh_token: token.refresh_token().map(|t| t.secret().clone()),
        expires_in: token.expires_in(),
    })
}

/// Userinfo as raw JSON, so custom claims like `roles` show up too.
async fn fetch_userinfo(app: &App, access_token: &str) -> anyhow::Result<Value> {
    let url = app
        .client
        .user_info_url()
        .context("dev-idp advertises no userinfo endpoint")?;
    let response = app
        .http
        .get(url.as_str())
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?;
    Ok(serde_json::from_slice(&response.bytes().await?)?)
}

/// A JWT's payload, without checking the signature. For display only.
fn jwt_payload(jwt: &str) -> Result<Value, AppError> {
    let payload = jwt.split('.').nth(1).context("not a JWT")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::warn!("{:#}", self.0);
        let page = ErrorPage {
            message: format!("{:#}", self.0),
        };
        (
            StatusCode::BAD_REQUEST,
            Html(page.render().unwrap_or_default()),
        )
            .into_response()
    }
}
