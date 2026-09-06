use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Sqlite};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

/// In-memory sliding-window IP rate limiter for new vault creations.
#[derive(Clone)]
pub struct RateLimiter {
    pub creations: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    pub max_creations: usize,
    pub window: Duration,
}

impl RateLimiter {
    pub fn new(max_creations: usize, window: Duration) -> Self {
        Self {
            creations: Arc::new(Mutex::new(HashMap::new())),
            max_creations,
            window,
        }
    }

    /// Validates if an IP can create a new vault.
    /// If allowed, records the timestamp and returns Ok(()).
    /// If limit reached, returns Err(retry_after_seconds).
    pub fn check_and_record(&self, ip: IpAddr) -> Result<(), u64> {
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
pub struct AppState {
    pub db: Pool<Sqlite>,
    pub limiter: RateLimiter,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultPayload {
    pub version: i64,
    pub capsule: Value,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

pub async fn init_db(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vaults (
            locator TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            capsule TEXT NOT NULL,
            public_key TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vault_locators (
            locator TEXT PRIMARY KEY,
            canonical_locator TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    let _ = sqlx::query("ALTER TABLE vaults ADD COLUMN public_key TEXT;")
        .execute(pool)
        .await;

    Ok(())
}

pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/health", get(health))
        .route("/api/vault/{locator}", get(get_vault).post(save_vault))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // Strict 1MB max body limit
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "VoidVault Minimal Prototype 2",
        "version": "0.2.0",
        "rate_limiting": "IP-throttled for new vault creations"
    }))
}

pub async fn get_vault(
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

            let mut hasher = Sha256::new();
            hasher.update(capsule_raw.as_bytes());
            let sha256_hex = format!("{:x}", hasher.finalize());

            Ok(Json(json!({
                "locator": locator,
                "version": version,
                "capsule_sha256": sha256_hex,
                "capsule": capsule_val
            })))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Vault not found for locator" })),
        )),
    }
}

pub fn extract_all_locators(payload: &VaultPayload, primary_locator: &str) -> Vec<String> {
    let mut locators = vec![primary_locator.to_string()];
    if let Some(key_slots) = payload.capsule.get("keySlots").and_then(|v| v.as_array()) {
        for slot in key_slots {
            let loc = match slot.get("locator").and_then(|l| l.as_str()) {
                Some(l) => l.trim(),
                None => continue,
            };
            if loc.is_empty()
                || loc == primary_locator
                || locators.iter().any(|existing| existing == loc)
            {
                continue;
            }

            // Verify per-slot cryptographic authorization
            let slot_pk_hex = match slot.get("publicKey").and_then(|p| p.as_str()) {
                Some(p) => p.trim(),
                None => {
                    warn!(locator = %loc, "Skipping keySlot alias: missing publicKey");
                    continue;
                }
            };
            let slot_sig_hex = match slot.get("aliasSignature").and_then(|s| s.as_str()) {
                Some(s) => s.trim(),
                None => {
                    warn!(locator = %loc, "Skipping keySlot alias: missing aliasSignature");
                    continue;
                }
            };

            // 1. Verify self-certification: SHA256(publicKey) == slot.locator
            let pk_bytes = match hex::decode(slot_pk_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    warn!(locator = %loc, "Skipping keySlot alias: invalid publicKey hex");
                    continue;
                }
            };
            if hex::encode(Sha256::digest(pk_bytes)) != loc {
                warn!(locator = %loc, "Skipping keySlot alias: publicKey hash commitment mismatch");
                continue;
            }

            // 2. Verify authorization signature: Ed25519.verify(pk, "voidvault-alias-authorization-v1:<loc>:<primary_locator>", sig)
            let sig_bytes = match hex::decode(slot_sig_hex) {
                Ok(b) if b.len() == 64 => {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    warn!(locator = %loc, "Skipping keySlot alias: invalid aliasSignature hex");
                    continue;
                }
            };

            let vk = match VerifyingKey::from_bytes(&pk_bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let sig = Signature::from_bytes(&sig_bytes);
            let auth_msg = format!(
                "voidvault-alias-authorization-v1:{}:{}",
                loc, primary_locator
            );
            if vk.verify_strict(auth_msg.as_bytes(), &sig).is_ok() {
                info!(alias_locator = %loc, canonical = %primary_locator, "Verified cryptographic keySlot alias authorization");
                locators.push(loc.to_string());
            } else {
                warn!(alias_locator = %loc, "Cryptographic keySlot alias signature rejected");
            }
        }
    }
    locators
}

pub async fn save_vault(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(locator): Path<String>,
    Json(payload): Json<VaultPayload>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let client_ip = extract_client_ip(&headers, addr.ip());

    // 1. Validate self-certifying public key and signature
    let pk_hex = match &payload.public_key {
        Some(pk) if !pk.trim().is_empty() => pk.trim(),
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Self-certifying public_key is required for vault writes" })),
            ));
        }
    };

    let sig_hex = match &payload.signature {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Cryptographic signature is required for vault writes" })),
            ));
        }
    };

    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid public_key: must be 32 bytes hex" })),
            ));
        }
    };

    // Self-certification check: SHA256(publicKey) == locator
    let computed_locator = hex::encode(Sha256::digest(pk_bytes));
    if computed_locator != locator {
        warn!(locator = %locator, computed = %computed_locator, "Self-certifying public key hash commitment mismatch");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Public key does not match locator hash commitment" })),
        ));
    }

    // 2. Verify Ed25519 signature over (locator || version (8 bytes LE) || sha256(capsule))
    let capsule_str = payload.capsule.to_string();
    let mut hasher = Sha256::new();
    hasher.update(capsule_str.as_bytes());
    let capsule_sha = hasher.finalize();

    let mut msg = Vec::with_capacity(locator.len() + 8 + 32);
    msg.extend_from_slice(locator.as_bytes());
    msg.extend_from_slice(&payload.version.to_le_bytes());
    msg.extend_from_slice(&capsule_sha);

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid signature: must be 64 bytes hex" })),
            ));
        }
    };

    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Invalid Ed25519 public key: {}", e) })),
        )
    })?;
    let sig = Signature::from_bytes(&sig_bytes);

    if let Err(e) = vk.verify_strict(&msg, &sig) {
        warn!(locator = %locator, error = %e, "Invalid Ed25519 write signature");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid cryptographic signature for vault write" })),
        ));
    }

    // 3. Resolve canonical locator if this is an existing alias
    let existing_canonical: Option<String> =
        sqlx::query_scalar("SELECT canonical_locator FROM vault_locators WHERE locator = ?")
            .bind(&locator)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

    let canonical_locator = existing_canonical.unwrap_or_else(|| locator.clone());

    // 4. Check if canonical vault already exists
    let existing_row: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT version, public_key FROM vaults WHERE locator = ?")
            .bind(&canonical_locator)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                )
            })?;

    let exists = existing_row.is_some();

    // 5. If vault exists, verify public_key immutability and anti-rollback version check
    if let Some((curr_ver, stored_pk_opt)) = existing_row {
        if canonical_locator == locator {
            if let Some(stored_pk) = stored_pk_opt {
                if stored_pk != pk_hex {
                    warn!(
                        canonical = %canonical_locator,
                        "Public key mismatch for existing canonical vault"
                    );
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({ "error": "Public key does not match existing vault key" })),
                    ));
                }
            }
        }

        if payload.version < curr_ver {
            warn!(
                canonical_locator = %canonical_locator,
                submitted_version = payload.version,
                current_version = curr_ver,
                "State rollback rejected: submitted version is older than current vault version"
            );
            return Err((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "State rollback rejected: submitted version is older than current vault version",
                    "current_version": curr_ver,
                    "submitted_version": payload.version
                })),
            ));
        }
    }

    // 6. If this is a BRAND NEW vault creation, enforce IP rate limit
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

    let now = chrono_or_now();

    // 7. Upsert canonical vault entry
    sqlx::query(
        r#"
        INSERT INTO vaults (locator, version, capsule, public_key, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(locator) DO UPDATE SET
            version = excluded.version,
            capsule = excluded.capsule,
            public_key = COALESCE(vaults.public_key, excluded.public_key),
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&canonical_locator)
    .bind(payload.version)
    .bind(&capsule_str)
    .bind(pk_hex)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
    })?;

    // 8. Update multi-locator links with cryptographic authorization
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

    let capsule_sha256 = format!("{:x}", capsule_sha);

    info!(
        canonical_locator = %canonical_locator,
        total_locators = all_locators.len(),
        version = payload.version,
        sha256 = %capsule_sha256,
        is_new = !exists,
        "Vault capsule signed and persisted with cryptographic self-certification"
    );

    Ok(Json(json!({
        "status": "success",
        "locator": canonical_locator,
        "version": payload.version,
        "capsule_sha256": capsule_sha256,
        "total_locators": all_locators.len(),
        "is_new": !exists
    })))
}

pub fn extract_client_ip(headers: &HeaderMap, fallback_ip: IpAddr) -> IpAddr {
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

pub fn chrono_or_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
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
    fn test_extract_all_locators_cryptographic_authorization() {
        use ed25519_dalek::SigningKey;

        let primary_sk = SigningKey::from_bytes(&[10u8; 32]);
        let primary_vk = primary_sk.verifying_key();
        let primary_loc = hex::encode(Sha256::digest(primary_vk.as_bytes()));

        let secondary_sk = SigningKey::from_bytes(&[20u8; 32]);
        let secondary_vk = secondary_sk.verifying_key();
        let secondary_loc = hex::encode(Sha256::digest(secondary_vk.as_bytes()));

        let auth_msg = format!(
            "voidvault-alias-authorization-v1:{}:{}",
            secondary_loc, primary_loc
        );
        let alias_sig = secondary_sk.sign(auth_msg.as_bytes());

        let invalid_curve_pk = [0xffu8; 32];
        let invalid_curve_loc = hex::encode(Sha256::digest(invalid_curve_pk));

        let payload = VaultPayload {
            version: 1,
            capsule: json!({
                "keySlots": [
                    {
                        "locator": secondary_loc,
                        "publicKey": hex::encode(secondary_vk.as_bytes()),
                        "aliasSignature": hex::encode(alias_sig.to_bytes())
                    },
                    {
                        "locator": primary_loc, // duplicate of primary
                        "publicKey": hex::encode(primary_vk.as_bytes()),
                        "aliasSignature": "00".repeat(64)
                    },
                    {
                        "locator": "unauthorized-sig",
                        "publicKey": hex::encode(secondary_vk.as_bytes()),
                        "aliasSignature": "00".repeat(64) // Forged signature
                    },
                    {
                        "locator": "missing-pk",
                        "aliasSignature": "00".repeat(64)
                    },
                    {
                        "locator": "missing-sig",
                        "publicKey": hex::encode(secondary_vk.as_bytes())
                    },
                    {
                        "locator": "invalid-hex-pk",
                        "publicKey": "not-a-hex",
                        "aliasSignature": "00".repeat(64)
                    },
                    {
                        "locator": "invalid-len-pk",
                        "publicKey": "abcd",
                        "aliasSignature": "00".repeat(64)
                    },
                    {
                        "locator": secondary_loc.clone() + "-other",
                        "publicKey": hex::encode(secondary_vk.as_bytes()), // hash won't match
                        "aliasSignature": "00".repeat(64)
                    },
                    {
                        "locator": secondary_loc.clone(),
                        "publicKey": hex::encode(secondary_vk.as_bytes()),
                        "aliasSignature": "not-hex"
                    },
                    {
                        "locator": secondary_loc.clone(),
                        "publicKey": hex::encode(secondary_vk.as_bytes()),
                        "aliasSignature": "1234"
                    },
                    {
                        "locator": invalid_curve_loc,
                        "publicKey": hex::encode(invalid_curve_pk),
                        "aliasSignature": "00".repeat(64)
                    },
                    {
                        "locator": "   " // blank
                    },
                    {
                        "no_locator_field": 123
                    }
                ]
            }),
            public_key: Some(hex::encode(primary_vk.as_bytes())),
            signature: Some("00".repeat(64)),
        };

        let locators = extract_all_locators(&payload, &primary_loc);
        assert_eq!(locators.len(), 2);
        assert_eq!(locators[0], primary_loc);
        assert_eq!(locators[1], secondary_loc);
    }

    #[test]
    fn test_vk_from_bytes_failure() {
        let mut found = None;
        for i in 1..255u8 {
            let mut b = [0u8; 32];
            b[0] = i;
            if VerifyingKey::from_bytes(&b).is_err() {
                found = Some(i);
                break;
            }
        }
        println!("Found invalid point at b[0] = {:?}", found);
        assert!(found.is_some());
    }

    #[test]
    fn test_chrono_or_now_valid() {
        let ts = chrono_or_now();
        let secs: u64 = ts.parse().expect("Valid integer timestamp");
        assert!(secs > 1700000000);
    }

    #[test]
    fn test_capsule_sha256_deterministic() {
        let raw = r#"{"keySlots":[],"payload":{"ciphertext":"abc","iv":"123"}}"#;
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_extract_client_ip_headers() {
        let mut headers = HeaderMap::new();
        let fallback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // No headers: fallback
        assert_eq!(extract_client_ip(&headers, fallback), fallback);

        // X-Real-IP
        headers.insert("x-real-ip", "10.0.0.5".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, fallback),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );

        // X-Forwarded-For overrides X-Real-IP
        headers.insert(
            "x-forwarded-for",
            "198.51.100.42, 10.0.0.1".parse().unwrap(),
        );
        assert_eq!(
            extract_client_ip(&headers, fallback),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))
        );

        // Invalid X-Forwarded-For falls through to X-Real-IP
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, fallback),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );

        // Invalid X-Real-IP falls through to fallback
        headers.insert("x-real-ip", "still-not-an-ip".parse().unwrap());
        assert_eq!(extract_client_ip(&headers, fallback), fallback);
    }
}
