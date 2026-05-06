use std::process::ExitCode;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use zz_drop_server_minimal::routes::ProfileLimits;
use zz_drop_server_minimal::{Database, ServerConfig, build_router};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let config = match ServerConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return ExitCode::from(2);
        }
    };

    tracing::info!(
        bind = %config.bind,
        database_url = %redact_db_url(&config.database_url),
        "starting zz-drop-server-minimal"
    );
    eprintln!(
        "WARNING: zz-drop-server-minimal is a reference implementation, not production-ready. \
         See README for the full warning list."
    );

    let db = match Database::connect(&config.database_url).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("db error: {e}");
            return ExitCode::from(3);
        }
    };

    if config.totp_master_key_was_random() {
        eprintln!(
            "WARNING: ZZDROP_TOTP_KEY not set — TOTP master key generated in memory; \
             enrollments will not survive a restart."
        );
    }
    let app = build_router(
        db,
        config.implementation.clone(),
        config.totp_master_key,
        ProfileLimits {
            max_aliases_free: config.max_aliases_free,
            blob_max_bytes: config.blob_max_bytes,
        },
    );

    let listener = match TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {addr}: {e}", addr = config.bind);
            return ExitCode::from(4);
        }
    };
    tracing::info!(bind = %config.bind, "listening");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("server error: {e}");
        return ExitCode::from(5);
    }
    ExitCode::SUCCESS
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("zz_drop_server_minimal=info,tower_http=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// Hide query strings (e.g. SQLite passwords if a connector ever
/// supports them) from the startup log line.
fn redact_db_url(url: &str) -> String {
    match url.find('?') {
        Some(i) => format!("{}?[redacted]", &url[..i]),
        None => url.to_string(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
