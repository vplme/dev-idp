//! End-to-end tests of the OIDC flows, run against the router without a network.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use dev_idp::{AppState, Config, SigningKey, tokens};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;

const CONFIG: &str = r#"
key_seed: test
clients:
  - id: spa
    redirect_uris: [http://localhost:3000/cb]
    post_logout_redirect_uris: [http://localhost:3000/]
  - id: web
    secret: s3cret
    redirect_uris: [http://localhost:8080/cb]
    users: [bob]
    audience: [https://api.example.com]
    scp: true
users:
  - id: alice
    name: Alice Admin
    email: alice@example.com
    claims: {roles: [admin], tenant: acme}
  - id: bob
    name: Bob Editor
"#;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Idp {
    app: Router,
    state: AppState,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> Url {
        let location = self.headers[header::LOCATION].to_str().unwrap();
        Url::parse(location).unwrap()
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }

    fn session_cookie(&self) -> String {
        let set = self.headers[header::SET_COOKIE].to_str().unwrap();
        set.split(';').next().unwrap().to_string()
    }
}

fn param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

fn spa_authorize(extra: &str) -> String {
    format!(
        "/authorize?client_id=spa&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&response_type=code\
         &scope=openid%20profile%20email&state=xyz&nonce=n-0S6&code_challenge={}&code_challenge_method=S256{extra}",
        challenge()
    )
}

/// The same parameters as `spa_authorize`, as the picker form posts them.
fn spa_form(user: &str, extra_claims: &str) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.extend_pairs([
        ("client_id", "spa"),
        ("redirect_uri", "http://localhost:3000/cb"),
        ("response_type", "code"),
        ("scope", "openid profile email"),
        ("state", "xyz"),
        ("nonce", "n-0S6"),
        ("code_challenge", &challenge()),
        ("code_challenge_method", "S256"),
        ("user", user),
        ("extra_claims", extra_claims),
    ]);
    form.finish()
}

impl Idp {
    fn new(yaml: &str) -> Idp {
        let mut config = Config::parse(yaml).unwrap();
        config.validate().unwrap();
        let key = SigningKey::from_config(&config).unwrap();
        let state = AppState::new(config, key);
        Idp {
            app: dev_idp::router(state.clone()),
            state,
        }
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        }
    }

    async fn get(&self, uri: &str, cookie: Option<&str>) -> Reply {
        let mut request = Request::get(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn post(&self, uri: &str, form: &str, auth: Option<&str>) -> Reply {
        let mut request =
            Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        self.send(request.body(Body::from(form.to_string())).unwrap())
            .await
    }

    /// Picks a user in the SPA's picker; returns the redirect and the session cookie.
    async fn login(&self, user: &str, extra_claims: &str) -> (Url, String) {
        let reply = self
            .post("/authorize", &spa_form(user, extra_claims), None)
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        (reply.location(), reply.session_cookie())
    }

    async fn exchange_spa_code(&self, code: &str) -> Reply {
        let form = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb\
             &client_id=spa&code_verifier={VERIFIER}"
        );
        self.post("/token", &form, None).await
    }

    fn verify(&self, token: &str) -> Map<String, Value> {
        tokens::verify(&self.state.config(), &self.state.key, token, true).expect("valid token")
    }
}

fn typ(token: &str) -> String {
    jsonwebtoken::decode_header(token).unwrap().typ.unwrap()
}

#[tokio::test]
async fn discovery_and_jwks() {
    let idp = Idp::new(CONFIG);
    let discovery = idp
        .get("/.well-known/openid-configuration", None)
        .await
        .json();
    assert_eq!(discovery["issuer"], "http://localhost:5556");
    assert_eq!(discovery["token_endpoint"], "http://localhost:5556/token");
    assert_eq!(
        discovery["code_challenge_methods_supported"],
        json!(["S256"])
    );

    let jwks = idp.get("/jwks", None).await.json();
    assert_eq!(jwks["keys"][0]["kid"], json!(idp.state.key.kid));
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
}

#[tokio::test]
async fn code_flow_with_pkce() {
    let idp = Idp::new(CONFIG);

    let picker = idp.get(&spa_authorize(""), None).await;
    assert_eq!(picker.status, StatusCode::OK);
    assert!(picker.body.contains("Alice Admin") && picker.body.contains("Bob Editor"));

    let (redirect, _) = idp.login("alice", "").await;
    assert_eq!(redirect.path(), "/cb");
    assert_eq!(param(&redirect, "state").as_deref(), Some("xyz"));
    let code = param(&redirect, "code").unwrap();

    let reply = idp.exchange_spa_code(&code).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    let tokens = reply.json();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 3600);

    let id_token = tokens["id_token"].as_str().unwrap();
    assert_eq!(typ(id_token), "JWT");
    let id = idp.verify(id_token);
    assert_eq!(id["sub"], "alice");
    assert_eq!(id["aud"], "spa");
    assert_eq!(id["nonce"], "n-0S6");
    assert_eq!(id["email"], "alice@example.com");
    assert_eq!(id["given_name"], "Alice");
    assert_eq!(id["roles"], json!(["admin"]));
    assert!(id["exp"].is_u64() && id["iat"].is_u64() && id["auth_time"].is_u64());

    let access_token = tokens["access_token"].as_str().unwrap();
    assert_eq!(typ(access_token), "at+jwt");
    let access = idp.verify(access_token);
    assert_eq!(access["aud"], json!(["spa", "http://localhost:5556"]));
    assert_eq!(access["client_id"], "spa");
    assert_eq!(access["scope"], "openid profile email");
    assert_eq!(access["tenant"], "acme");
    assert!(access.get("scp").is_none() && access.get("email").is_none());

    let request = Request::get("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let info = idp.send(request).await.json();
    assert_eq!(info["sub"], "alice");
    assert_eq!(info["name"], "Alice Admin");
    assert_eq!(info["roles"], json!(["admin"]));
    assert!(info.get("jti").is_none() && info.get("aud").is_none());

    let request = Request::get("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {id_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        idp.send(request).await.status,
        StatusCode::UNAUTHORIZED,
        "id_token is not an access token"
    );

    let reused = idp.exchange_spa_code(&code).await;
    assert_eq!(
        reused.json()["error"],
        "invalid_grant",
        "codes are single use"
    );
}

#[tokio::test]
async fn wrong_pkce_verifier_is_rejected() {
    let idp = Idp::new(CONFIG);
    let (redirect, _) = idp.login("alice", "").await;
    let code = param(&redirect, "code").unwrap();
    let form =
        format!("grant_type=authorization_code&code={code}&client_id=spa&code_verifier=wrong");
    assert_eq!(
        idp.post("/token", &form, None).await.json()["error"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn refresh_tokens_rotate() {
    let idp = Idp::new(CONFIG);
    let (redirect, _) = idp.login("alice", "").await;
    let first = idp
        .exchange_spa_code(&param(&redirect, "code").unwrap())
        .await
        .json();
    let refresh = first["refresh_token"].as_str().unwrap();

    let form = format!("grant_type=refresh_token&refresh_token={refresh}&client_id=spa");
    let second = idp.post("/token", &form, None).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    let second = second.json();
    let id = idp.verify(second["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], "alice");
    assert!(
        id.get("nonce").is_none(),
        "refreshed id_tokens carry no nonce"
    );
    assert_ne!(second["refresh_token"], first["refresh_token"]);

    assert_eq!(
        idp.post("/token", &form, None).await.json()["error"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn confidential_client_needs_its_secret() {
    let idp = Idp::new(CONFIG);
    let authorize = "/authorize?client_id=web&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb\
                     &response_type=code&scope=openid";
    let picker = idp.get(authorize, None).await;
    assert_eq!(
        picker.status,
        StatusCode::OK,
        "confidential clients don't need PKCE"
    );
    assert!(picker.body.contains("Bob Editor") && !picker.body.contains("Alice Admin"));

    let login = "client_id=web&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb&response_type=code\
                 &scope=openid&user=";
    let denied = idp.post("/authorize", &format!("{login}alice"), None).await;
    assert_eq!(
        denied.status,
        StatusCode::BAD_REQUEST,
        "alice isn't allowed for this client"
    );

    let code_for = |reply: Reply| param(&reply.location(), "code").unwrap();
    let code = code_for(idp.post("/authorize", &format!("{login}bob"), None).await);
    let wrong = format!("Basic {}", STANDARD.encode("web:nope"));
    let form = format!("grant_type=authorization_code&code={code}");
    let reply = idp.post("/token", &form, Some(&wrong)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "invalid_client");

    let code = code_for(idp.post("/authorize", &format!("{login}bob"), None).await);
    let right = format!("Basic {}", STANDARD.encode("web:s3cret"));
    let form = format!("grant_type=authorization_code&code={code}");
    let reply = idp.post("/token", &form, Some(&right)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let access = idp.verify(reply.json()["access_token"].as_str().unwrap());
    assert_eq!(access["aud"], json!(["https://api.example.com"]));
    assert_eq!(access["scp"], json!(["openid"]));

    let code = code_for(idp.post("/authorize", &format!("{login}bob"), None).await);
    let form =
        format!("grant_type=authorization_code&code={code}&client_id=web&client_secret=s3cret");
    assert_eq!(
        idp.post("/token", &form, None).await.status,
        StatusCode::OK,
        "client_secret_post"
    );
}

#[tokio::test]
async fn session_skips_the_picker() {
    let idp = Idp::new(CONFIG);
    let (_, cookie) = idp.login("alice", "").await;

    let silent = idp.get(&spa_authorize(""), Some(&cookie)).await;
    assert_eq!(silent.status, StatusCode::SEE_OTHER);
    let code = param(&silent.location(), "code").unwrap();
    let id = idp.verify(
        idp.exchange_spa_code(&code).await.json()["id_token"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(id["sub"], "alice");

    let none = idp.get(&spa_authorize("&prompt=none"), Some(&cookie)).await;
    assert!(param(&none.location(), "code").is_some());

    let forced = idp
        .get(&spa_authorize("&prompt=login"), Some(&cookie))
        .await;
    assert_eq!(
        forced.status,
        StatusCode::OK,
        "prompt=login shows the picker"
    );

    let anonymous = idp.get(&spa_authorize("&prompt=none"), None).await;
    assert_eq!(
        param(&anonymous.location(), "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(
        param(&anonymous.location(), "state").as_deref(),
        Some("xyz")
    );
}

#[tokio::test]
async fn extra_claims_from_the_picker() {
    let idp = Idp::new(CONFIG);
    let bad = idp
        .post("/authorize", &spa_form("alice", "{not json"), None)
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(bad.body.contains("must be a JSON object"));
    assert!(bad.body.contains("{not json"), "the typed text is kept");

    let (redirect, _) = idp
        .login("alice", r#"{"roles": ["viewer"], "beta": true}"#)
        .await;
    let tokens = idp
        .exchange_spa_code(&param(&redirect, "code").unwrap())
        .await
        .json();
    let access = idp.verify(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["roles"], json!(["viewer"]));
    assert_eq!(access["beta"], true);
    assert_eq!(access["tenant"], "acme");
}

#[tokio::test]
async fn strict_and_lenient_clients() {
    let strict = Idp::new(CONFIG);
    let unknown = "/authorize?client_id=new-app&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcb\
                   &response_type=code&scope=openid";
    let reply = strict.get(unknown, None).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("Unknown client"));

    let wrong_redirect = spa_authorize("").replace("3000%2Fcb", "3000%2Fevil");
    let reply = strict.get(&wrong_redirect, None).await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "never redirect to an unregistered URI"
    );

    let no_pkce = "/authorize?client_id=spa&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb\
                   &response_type=code&scope=openid";
    let reply = strict.get(no_pkce, None).await;
    assert_eq!(
        param(&reply.location(), "error").as_deref(),
        Some("invalid_request")
    );

    let no_openid = spa_authorize("").replace("scope=openid%20", "scope=");
    let reply = strict.get(&no_openid, None).await;
    assert_eq!(
        param(&reply.location(), "error").as_deref(),
        Some("invalid_scope")
    );

    let lenient = Idp::new(&format!("lenient: true\n{CONFIG}"));
    assert_eq!(lenient.get(unknown, None).await.status, StatusCode::OK);
    let external = unknown.replace("localhost%3A4000", "example.com");
    assert_eq!(
        lenient.get(&external, None).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn logout_clears_the_session() {
    let idp = Idp::new(CONFIG);
    let (redirect, cookie) = idp.login("alice", "").await;
    let id_token = idp
        .exchange_spa_code(&param(&redirect, "code").unwrap())
        .await
        .json()["id_token"]
        .as_str()
        .unwrap()
        .to_string();

    let uri = format!(
        "/logout?id_token_hint={id_token}&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2F&state=bye"
    );
    let reply = idp.get(&uri, Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.location().as_str(),
        "http://localhost:3000/?state=bye"
    );
    assert!(
        reply.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );

    let unregistered = idp
        .get(
            "/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.example%2F",
            None,
        )
        .await;
    assert_eq!(unregistered.status, StatusCode::OK);
    assert!(unregistered.body.contains("in any client"));
}

#[tokio::test]
async fn issuer_path_is_the_route_prefix() {
    let idp = Idp::new(&format!("issuer: http://localhost:5556/dex/\n{CONFIG}"));
    let discovery = idp
        .get("/dex/.well-known/openid-configuration", None)
        .await
        .json();
    assert_eq!(discovery["issuer"], "http://localhost:5556/dex");
    assert_eq!(
        discovery["authorization_endpoint"],
        "http://localhost:5556/dex/authorize"
    );
    assert_eq!(
        idp.get("/.well-known/openid-configuration", None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn reload_keeps_restart_only_fields() {
    let idp = Idp::new(CONFIG);
    let mut new = Config::parse(&format!("issuer: http://elsewhere\n{CONFIG}")).unwrap();
    new.validate().unwrap();
    new.users.retain(|p| p.id == "bob");
    idp.state.reload(new);

    let config = idp.state.config();
    assert_eq!(config.issuer, "http://localhost:5556");
    assert!(config.user("alice").is_none());
    let picker = idp.get(&spa_authorize(""), None).await;
    assert!(!picker.body.contains("Alice Admin"));
}
