use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use serde_json::{Map, Value};

use crate::config::Config;
use crate::keys::SigningKey;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    config: ArcSwap<Config>,
    pub key: SigningKey,
    codes: Mutex<HashMap<String, Grant>>,
    refresh_tokens: Mutex<HashMap<String, Grant>>,
}

/// What a login granted; stored behind an auth code or a refresh token.
#[derive(Debug, Clone)]
pub struct Grant {
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    /// Only set for auth codes.
    pub redirect_uri: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    /// Claims typed into the picker's "extra claims" field.
    pub extra_claims: Map<String, Value>,
    pub auth_time: u64,
    pub expires: Instant,
}

impl std::ops::Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Key {
        state.key.cookie_key.clone()
    }
}

impl AppState {
    pub fn new(config: Config, key: SigningKey) -> AppState {
        AppState(Arc::new(Inner {
            config: ArcSwap::from_pointee(config),
            key,
            codes: Mutex::default(),
            refresh_tokens: Mutex::default(),
        }))
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Swaps in a reloaded config, keeping the restart-only fields of the running one.
    pub fn reload(&self, mut new: Config) {
        let current = self.config();
        let ignored = current.restart_only_changes(&mut new);
        if !ignored.is_empty() {
            tracing::warn!(
                "changes to {} are ignored until restart",
                ignored.join(", ")
            );
        }
        self.config.store(Arc::new(new));
        tracing::info!("config reloaded");
    }

    pub fn store_code(&self, grant: Grant) -> String {
        insert(&self.codes, grant)
    }

    /// Codes are single use: taking one removes it.
    pub fn take_code(&self, code: &str) -> Option<Grant> {
        take(&self.codes, code)
    }

    pub fn store_refresh_token(&self, grant: Grant) -> String {
        insert(&self.refresh_tokens, grant)
    }

    /// Refresh tokens rotate: taking one removes it, and a new one is issued.
    pub fn take_refresh_token(&self, token: &str) -> Option<Grant> {
        take(&self.refresh_tokens, token)
    }
}

fn insert(map: &Mutex<HashMap<String, Grant>>, grant: Grant) -> String {
    let token = random_token();
    let mut map = map.lock().unwrap();
    let now = Instant::now();
    map.retain(|_, g| g.expires > now);
    map.insert(token.clone(), grant);
    token
}

fn take(map: &Mutex<HashMap<String, Grant>>, token: &str) -> Option<Grant> {
    let grant = map.lock().unwrap().remove(token)?;
    (grant.expires > Instant::now()).then_some(grant)
}

pub fn random_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}
