use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

/// In-memory sliding-window IP rate limiter for new vault creations.
#[derive(Clone)]
struct RateLimiter {
    creations: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_creations: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(max_creations: usize, window: Duration) -> Self {
        Self {
            creations: Arc::new(Mutex::new(HashMap::new())),
            max_creations,
            window,
        }
    }

    /// Validates if an IP can create a new vault.
    /// If allowed, records the timestamp and returns Ok(()).
    /// If limit reached, returns Err(retry_after_seconds).
    fn check_and_record(&self, ip: IpAddr) -> Result<(), u64> {
        let mut map = self.creations.lock().unwrap();
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);

        let timestamps = map.entry(ip).or_default();
        timestamps.retain(|&t| t > cutoff);

        if timestamps.len() >= self.max_creations {
            let oldest = timestamps[0];
            let elapsed = now.duration_since(oldest);
            let retry_after = self.window.saturating_sub(elapsed).as_secs() + 1;
            return Err(retry_after);
        }

        timestamps.push(now);
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    db: Pool<Sqlite>,
    limiter: RateLimiter,
}

#[derive(Serialize, Deserialize)]
struct VaultPayload {
    version: i64,
    capsule: Value,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info,tower_http=info")
        .init();

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://voidvault.db?mode=rwc".to_string());

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

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vaults (
            locator TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            capsule TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vault_locators (
            locator TEXT PRIMARY KEY,
            canonical_locator TEXT NOT NULL
        );
        "#,
    )
    .execute(&pool)
    .await?;

    let limiter = RateLimiter::new(max_creations, Duration::from_secs(window_secs));
    info!(
        max_creations_per_window = max_creations,
        window_seconds = window_secs,
        "Anti-abuse IP rate limiter active for new vault creations"
    );

    let state = AppState { db: pool, limiter };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/health", get(health))
        .route("/api/vault/{locator}", get(get_vault).post(save_vault))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // Strict 1MB max body limit
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind_addr: SocketAddr = "0.0.0.0:8080".parse()?;
    info!("VoidVault Minimal Server listening on http://{}", bind_addr);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "VoidVault Minimal Prototype 2",
        "version": "0.2.0",
        "rate_limiting": "IP-throttled for new vault creations"
    }))
}

async fn get_vault(
    State(state): State<AppState>,
    Path(locator): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    use sqlx::Row;

    // 1. Check if directly in vaults
    let mut row = sqlx::query("SELECT version, capsule FROM vaults WHERE locator = ?")
        .bind(&locator)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    // 2. If not found directly, resolve secondary locator alias
    if row.is_none() {
        let canonical: Option<String> =
            sqlx::query_scalar("SELECT canonical_locator FROM vault_locators WHERE locator = ?")
                .bind(&locator)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": e.to_string() })),
                    )
                })?;

        if let Some(ref canon) = canonical {
            row = sqlx::query("SELECT version, capsule FROM vaults WHERE locator = ?")
                .bind(canon)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": e.to_string() })),
                    )
                })?;
        }
    }

    match row {
        Some(r) => {
            let version: i64 = r.try_get("version").unwrap_or(1);
            let capsule_raw: String = r.try_get("capsule").unwrap_or_default();
            let capsule_val: Value = serde_json::from_str(&capsule_raw).unwrap_or(Value::Null);
            Ok(Json(json!({
                "locator": locator,
                "version": version,
                "capsule": capsule_val
            })))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Vault not found for locator" })),
        )),
    }
}

fn extract_all_locators(payload: &VaultPayload, primary_locator: &str) -> Vec<String> {
    let mut locators = vec![primary_locator.to_string()];
    if let Some(key_slots) = payload.capsule.get("keySlots").and_then(|v| v.as_array()) {
        for slot in key_slots {
            if let Some(loc) = slot.get("locator").and_then(|l| l.as_str()) {
                let clean = loc.trim().to_string();
                if !clean.is_empty() && !locators.contains(&clean) {
                    locators.push(clean);
                }
            }
        }
    }
    locators
}

async fn save_vault(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(locator): Path<String>,
    Json(payload): Json<VaultPayload>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let client_ip = extract_client_ip(&headers, addr.ip());

    // 1. Resolve canonical locator if this is an existing alias
    let existing_canonical: Option<String> =
        sqlx::query_scalar("SELECT canonical_locator FROM vault_locators WHERE locator = ?")
            .bind(&locator)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

    let canonical_locator = existing_canonical.unwrap_or_else(|| locator.clone());

    // 2. Check if canonical vault already exists
    let exists: bool = sqlx::query_scalar::<_, i32>("SELECT 1 FROM vaults WHERE locator = ?")
        .bind(&canonical_locator)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?
        .is_some();

    // 3. If this is a BRAND NEW vault creation, enforce IP rate limit
    if !exists {
        if let Err(retry_after) = state.limiter.check_and_record(client_ip) {
            warn!(
                client_ip = %client_ip,
                locator = %canonical_locator,
                retry_after_seconds = retry_after,
                "Throttled: New vault creation limit reached for this IP"
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "Rate limit exceeded. Too many new vaults created from this IP.",
                    "retry_after_seconds": retry_after
                })),
            ));
        }
        info!(client_ip = %client_ip, locator = %canonical_locator, "Authorized new vault creation slot");
    }

    let capsule_str = payload.capsule.to_string();
    let now = chrono_or_now();

    // 4. Upsert canonical vault entry
    sqlx::query(
        r#"
        INSERT INTO vaults (locator, version, capsule, updated_at)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(locator) DO UPDATE SET
            version = excluded.version,
            capsule = excluded.capsule,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&canonical_locator)
    .bind(payload.version)
    .bind(&capsule_str)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
    })?;

    // 5. Update multi-locator links
    let all_locators = extract_all_locators(&payload, &canonical_locator);
    let _ = sqlx::query("DELETE FROM vault_locators WHERE canonical_locator = ?")
        .bind(&canonical_locator)
        .execute(&state.db)
        .await;

    for loc in &all_locators {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO vault_locators (locator, canonical_locator) VALUES (?1, ?2)",
        )
        .bind(loc)
        .bind(&canonical_locator)
        .execute(&state.db)
        .await;
    }

    info!(
        canonical_locator = %canonical_locator,
        total_locators = all_locators.len(),
        version = payload.version,
        is_new = !exists,
        "Vault capsule persisted with multi-key locators"
    );

    Ok(Json(json!({
        "status": "ok",
        "locator": canonical_locator,
        "version": payload.version,
        "enrolled_locators": all_locators.len()
    })))
}

fn extract_client_ip(headers: &HeaderMap, fallback_ip: IpAddr) -> IpAddr {
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = forwarded.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    fallback_ip
}

fn chrono_or_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_allows_under_limit_and_blocks_over_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(3600));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(limiter.check_and_record(ip).is_ok());
        assert!(limiter.check_and_record(ip).is_ok());
        assert!(limiter.check_and_record(ip).is_ok());

        // 4th should be blocked
        let err = limiter.check_and_record(ip);
        assert!(err.is_err());
        assert!(err.unwrap_err() <= 3601);

        // Different IP should still be allowed
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(limiter.check_and_record(ip2).is_ok());
    }

    #[test]
    fn test_extract_all_locators_deduplication() {
        let payload = VaultPayload {
            version: 1,
            capsule: json!({
                "keySlots": [
                    { "locator": "primary-loc" },
                    { "locator": "secondary-loc" },
                    { "locator": "primary-loc" }, // duplicate
                    { "locator": "   " } // blank
                ]
            }),
        };

        let locators = extract_all_locators(&payload, "primary-loc");
        assert_eq!(locators.len(), 2);
        assert_eq!(locators[0], "primary-loc");
        assert_eq!(locators[1], "secondary-loc");
    }

    #[test]
    fn test_chrono_or_now_valid() {
        let ts = chrono_or_now();
        let secs: u64 = ts.parse().expect("Valid integer timestamp");
        assert!(secs > 1700000000);
    }
}
