use sqlx::sqlite::SqlitePoolOptions;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::info;
use voidvault_server::{create_app, init_db, AppState, RateLimiter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info,tower_http=info")
        .init();

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        if let Ok(path) = std::env::var("DATABASE_PATH") {
            format!("sqlite://{}?mode=rwc", path)
        } else {
            "sqlite://voidvault.db?mode=rwc".to_string()
        }
    });

    let max_creations: usize = std::env::var("VOIDVAULT_MAX_NEW_VAULTS_PER_HOUR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    let window_secs: u64 = std::env::var("VOIDVAULT_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600); // 1 hour window

    info!("Initializing SQLite database at: {}", db_url);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    init_db(&pool).await?;

    let limiter = RateLimiter::new(max_creations, Duration::from_secs(window_secs));
    info!(
        max_creations_per_window = max_creations,
        window_seconds = window_secs,
        "Anti-abuse IP rate limiter active for new vault creations"
    );

    let state = AppState { db: pool, limiter };
    let app = create_app(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_str = std::env::var("BIND_ADDR").unwrap_or_else(|_| format!("0.0.0.0:{}", port));
    let bind_addr: SocketAddr = bind_str.parse()?;
    info!("VoidVault Minimal Server listening on http://{}", bind_addr);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("VoidVault Server shut down cleanly");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Termination signal received, shutting down gracefully");
}
