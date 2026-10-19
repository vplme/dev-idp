use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use dev_idp::{AppState, Config, SigningKey};
use notify_debouncer_full::notify::RecursiveMode;
use notify_debouncer_full::{DebounceEventResult, new_debouncer};

/// A local OIDC provider for development: pick a persona instead of typing a password.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the YAML config.
    #[arg(short, long, env = "DEV_IDP_CONFIG", default_value = "dev-idp.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dev_idp=info".into()),
        )
        .init();

    if let Err(e) = run(Args::parse()).await {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let config = Config::load(&args.config)?;
    let started = Instant::now();
    let key = SigningKey::from_config(&config)?;
    tracing::info!(kid = %key.kid, "signing key ready in {:.1?}", started.elapsed());

    let listen = config.listen;
    if !listen.ip().is_loopback() {
        tracing::warn!("listening on {listen}: anyone who can reach it can log in as any persona");
    }
    let issuer = config.issuer.clone();
    let state = AppState::new(config, key);
    let _watcher = watch(&args.config, state.clone())?;

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    tracing::info!("dev-idp (DEV ONLY) serving {issuer} on http://{listen}");
    axum::serve(listener, dev_idp::router(state))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await
        .map_err(|e| format!("server error: {e}"))
}

/// Reloads the config when the file changes. Watches the directory, because
/// many editors save by writing a new file and renaming it over the old one.
fn watch(path: &Path, state: AppState) -> Result<impl Drop, String> {
    let path = std::path::absolute(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let file = path.clone();
    let mut debouncer = new_debouncer(
        Duration::from_millis(300),
        None,
        move |result: DebounceEventResult| {
            let Ok(events) = result else { return };
            if !events.iter().any(|e| e.paths.contains(&file)) {
                return;
            }
            match Config::load(&file) {
                Ok(config) => state.reload(config),
                Err(e) => tracing::error!("config not reloaded, keeping the previous one: {e}"),
            }
        },
    )
    .map_err(|e| format!("cannot watch config: {e}"))?;
    debouncer
        .watch(&dir, RecursiveMode::NonRecursive)
        .map_err(|e| format!("cannot watch {}: {e}", dir.display()))?;
    Ok(debouncer)
}
