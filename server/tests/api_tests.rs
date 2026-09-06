use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePoolOptions;
use std::net::SocketAddr;
use std::time::Duration;
use tower::ServiceExt;
use voidvault_server::{create_app, init_db, AppState, RateLimiter, VaultPayload};

/// Helper to set up an in-memory SQLite database and test app
async fn setup_test_app(max_creations: usize) -> (axum::Router, sqlx::Pool<sqlx::Sqlite>) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to in-memory sqlite");

    init_db(&pool).await.expect("Failed to init db schema");

    let limiter = RateLimiter::new(max_creations, Duration::from_secs(3600));
    let state = AppState {
        db: pool.clone(),
        limiter,
    };
    (create_app(state), pool)
}

/// Helper to construct and sign a valid VaultPayload
fn make_signed_payload(sk: &SigningKey, version: i64, capsule: Value) -> (String, VaultPayload) {
    let vk = sk.verifying_key();
    let vk_bytes = vk.as_bytes();
    let pk_hex = hex::encode(vk_bytes);
    let locator = hex::encode(Sha256::digest(vk_bytes));

    let capsule_str = capsule.to_string();
    let capsule_sha = Sha256::digest(capsule_str.as_bytes());

    let mut msg = Vec::with_capacity(locator.len() + 8 + 32);
    msg.extend_from_slice(locator.as_bytes());
    msg.extend_from_slice(&version.to_le_bytes());
    msg.extend_from_slice(&capsule_sha);

    let sig = sk.sign(&msg);
    let sig_hex = hex::encode(sig.to_bytes());

    (
        locator,
        VaultPayload {
            version,
            capsule,
            public_key: Some(pk_hex),
            signature: Some(sig_hex),
        },
    )
}

fn build_post_request(
    locator: &str,
    payload: &VaultPayload,
    client_ip: &str,
    forwarded_for: Option<&str>,
    real_ip: Option<&str>,
) -> Request<Body> {
    let body_bytes = serde_json::to_vec(payload).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/api/vault/{}", locator))
        .header("content-type", "application/json");

    if let Some(fwd) = forwarded_for {
        builder = builder.header("x-forwarded-for", fwd);
    }
    if let Some(rip) = real_ip {
        builder = builder.header("x-real-ip", rip);
    }

    let mut req = builder.body(Body::from(body_bytes)).unwrap();
    let sock: SocketAddr = format!("{}:12345", client_ip).parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(sock));
    req
}

#[tokio::test]
async fn test_health_check() {
    let (app, _) = setup_test_app(5).await;

    // Test /health
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["version"], "0.2.0");

    // Test /api/health alias
    let req2 = Request::builder()
        .method("GET")
        .uri("/api/health")
        .body(Body::empty())
        .unwrap();

    let res2 = app.oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_vault_not_found() {
    let (app, _) = setup_test_app(5).await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/vault/nonexistent_locator_12345")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["error"].as_str().unwrap().contains("Vault not found"));
}

#[tokio::test]
async fn test_save_vault_missing_public_key_or_signature() {
    let (app, _) = setup_test_app(5).await;
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let (loc, mut payload) = make_signed_payload(&sk, 1, json!({"test": "data"}));

    // Missing public key
    payload.public_key = None;
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Empty public key
    payload.public_key = Some("   ".to_string());
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Restore public key, missing signature
    let (_, full_payload) = make_signed_payload(&sk, 1, json!({"test": "data"}));
    payload.public_key = full_payload.public_key;
    payload.signature = None;
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Empty signature
    payload.signature = Some("   ".to_string());
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_save_vault_invalid_key_formats_and_commitment() {
    let (app, _) = setup_test_app(5).await;
    let sk = SigningKey::from_bytes(&[2u8; 32]);
    let (loc, mut payload) = make_signed_payload(&sk, 1, json!({"test": "data"}));

    // Invalid public key hex length (10 bytes instead of 32)
    payload.public_key = Some("abcdef1234".to_string());
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Non-hex characters in public key
    payload.public_key = Some("zzzz".repeat(16));
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Valid 32-byte public key hex, but does NOT match locator commitment (SHA256)
    let different_sk = SigningKey::from_bytes(&[3u8; 32]);
    payload.public_key = Some(hex::encode(different_sk.verifying_key().as_bytes()));
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Restore valid public key, test invalid signature length
    let (_, full_payload) = make_signed_payload(&sk, 1, json!({"test": "data"}));
    payload.public_key = full_payload.public_key;
    payload.signature = Some("abcdef".to_string());
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Tampered 64-byte signature
    payload.signature = Some("00".repeat(64));
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_save_and_retrieve_vault_lifecycle() {
    let (app, _) = setup_test_app(5).await;
    let sk = SigningKey::from_bytes(&[4u8; 32]);
    let capsule = json!({
        "encryptedData": "cipher12345",
        "keySlots": []
    });
    let (loc, payload) = make_signed_payload(&sk, 1, capsule.clone());

    // 1. Initial creation
    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["status"], "success");
    assert_eq!(v["is_new"], true);
    assert_eq!(v["version"], 1);
    assert_eq!(v["locator"], loc);

    // 2. Fetch created vault
    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/api/vault/{}", loc))
        .body(Body::empty())
        .unwrap();
    let get_res = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);

    let get_bytes = get_res.into_body().collect().await.unwrap().to_bytes();
    let get_v: Value = serde_json::from_slice(&get_bytes).unwrap();
    assert_eq!(get_v["version"], 1);
    assert_eq!(get_v["locator"], loc);
    assert_eq!(get_v["capsule"], capsule);
    assert_eq!(get_v["capsule_sha256"], v["capsule_sha256"]);

    // 3. Update to version 2
    let updated_capsule = json!({
        "encryptedData": "cipher-version-2",
        "keySlots": []
    });
    let (_, payload_v2) = make_signed_payload(&sk, 2, updated_capsule.clone());
    let req2 = build_post_request(&loc, &payload_v2, "127.0.0.1", None, None);
    let res2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK);

    let v2: Value =
        serde_json::from_slice(&res2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v2["version"], 2);
    assert_eq!(v2["is_new"], false);

    // 3b. Update with same version (version 2 to version 2)
    let updated_capsule_same_ver = json!({
        "encryptedData": "cipher-version-2-repeat",
        "keySlots": []
    });
    let (_, payload_v2_repeat) = make_signed_payload(&sk, 2, updated_capsule_same_ver);
    let req2_repeat = build_post_request(&loc, &payload_v2_repeat, "127.0.0.1", None, None);
    let res2_repeat = app.clone().oneshot(req2_repeat).await.unwrap();
    assert_eq!(res2_repeat.status(), StatusCode::OK);

    // 4. Anti-rollback: attempt to write version 1 over version 2
    let (_, rollback_payload) = make_signed_payload(&sk, 1, capsule.clone());
    let rollback_req = build_post_request(&loc, &rollback_payload, "127.0.0.1", None, None);
    let rollback_res = app.clone().oneshot(rollback_req).await.unwrap();
    assert_eq!(rollback_res.status(), StatusCode::CONFLICT);

    let rollback_val: Value =
        serde_json::from_slice(&rollback_res.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(rollback_val["error"]
        .as_str()
        .unwrap()
        .contains("State rollback rejected"));
    assert_eq!(rollback_val["current_version"], 2);
    assert_eq!(rollback_val["submitted_version"], 1);
}

#[tokio::test]
async fn test_rate_limiting_and_existing_vault_bypass() {
    let (app, _) = setup_test_app(2).await; // Only 2 creations per hour allowed

    let sk1 = SigningKey::from_bytes(&[11u8; 32]);
    let (loc1, p1) = make_signed_payload(&sk1, 1, json!({"slot": 1}));

    let sk2 = SigningKey::from_bytes(&[12u8; 32]);
    let (loc2, p2) = make_signed_payload(&sk2, 1, json!({"slot": 2}));

    let sk3 = SigningKey::from_bytes(&[13u8; 32]);
    let (loc3, p3) = make_signed_payload(&sk3, 1, json!({"slot": 3}));

    // 1st creation from IP 192.168.1.50 -> OK
    let req1 = build_post_request(&loc1, &p1, "192.168.1.50", None, None);
    assert_eq!(
        app.clone().oneshot(req1).await.unwrap().status(),
        StatusCode::OK
    );

    // 2nd creation from IP 192.168.1.50 -> OK
    let req2 = build_post_request(&loc2, &p2, "192.168.1.50", None, None);
    assert_eq!(
        app.clone().oneshot(req2).await.unwrap().status(),
        StatusCode::OK
    );

    // 3rd creation from same IP -> 429 TOO_MANY_REQUESTS
    let req3 = build_post_request(&loc3, &p3, "192.168.1.50", None, None);
    let res3 = app.clone().oneshot(req3).await.unwrap();
    assert_eq!(res3.status(), StatusCode::TOO_MANY_REQUESTS);
    let v3: Value =
        serde_json::from_slice(&res3.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(v3["error"]
        .as_str()
        .unwrap()
        .contains("Rate limit exceeded"));
    assert!(v3["retry_after_seconds"].as_u64().unwrap() > 0);

    // Different IP (192.168.1.99) can still create
    let req3_alt = build_post_request(&loc3, &p3, "192.168.1.99", None, None);
    assert_eq!(
        app.clone().oneshot(req3_alt).await.unwrap().status(),
        StatusCode::OK
    );

    // EXISTING vault update from throttled IP 192.168.1.50 MUST SUCCEED (bypass rate limiting)
    let (_, p1_v2) = make_signed_payload(&sk1, 2, json!({"slot": 1, "update": true}));
    let req1_update = build_post_request(&loc1, &p1_v2, "192.168.1.50", None, None);
    let res1_update = app.oneshot(req1_update).await.unwrap();
    assert_eq!(res1_update.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_multi_keyslot_cryptographic_aliasing() {
    let (app, _) = setup_test_app(5).await;

    // Primary key
    let primary_sk = SigningKey::from_bytes(&[21u8; 32]);
    let primary_vk = primary_sk.verifying_key();
    let primary_loc = hex::encode(Sha256::digest(primary_vk.as_bytes()));

    // Secondary authorized key
    let secondary_sk = SigningKey::from_bytes(&[22u8; 32]);
    let secondary_vk = secondary_sk.verifying_key();
    let secondary_loc = hex::encode(Sha256::digest(secondary_vk.as_bytes()));

    // Cryptographic alias signature: secondary key signs "voidvault-alias-authorization-v1:<secondary_loc>:<primary_loc>"
    let auth_msg = format!(
        "voidvault-alias-authorization-v1:{}:{}",
        secondary_loc, primary_loc
    );
    let alias_sig = secondary_sk.sign(auth_msg.as_bytes());

    // Unauthorized fake key (forged signature)
    let fake_sk = SigningKey::from_bytes(&[23u8; 32]);
    let fake_vk = fake_sk.verifying_key();
    let fake_loc = hex::encode(Sha256::digest(fake_vk.as_bytes()));

    let capsule = json!({
        "encryptedData": "multi-key-capsule",
        "keySlots": [
            {
                "locator": secondary_loc,
                "publicKey": hex::encode(secondary_vk.as_bytes()),
                "aliasSignature": hex::encode(alias_sig.to_bytes())
            },
            {
                "locator": fake_loc,
                "publicKey": hex::encode(fake_vk.as_bytes()),
                "aliasSignature": "00".repeat(64) // Forged/invalid signature
            }
        ]
    });

    let (loc, payload) = make_signed_payload(&primary_sk, 1, capsule);
    assert_eq!(loc, primary_loc);

    // Save primary vault
    let req = build_post_request(&primary_loc, &payload, "127.0.0.1", None, None);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 1. Resolve via primary locator -> OK
    let req_primary = Request::builder()
        .method("GET")
        .uri(format!("/api/vault/{}", primary_loc))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req_primary).await.unwrap().status(),
        StatusCode::OK
    );

    // 2. Resolve via authorized secondary locator alias -> OK
    let req_secondary = Request::builder()
        .method("GET")
        .uri(format!("/api/vault/{}", secondary_loc))
        .body(Body::empty())
        .unwrap();
    let res_secondary = app.clone().oneshot(req_secondary).await.unwrap();
    assert_eq!(res_secondary.status(), StatusCode::OK);
    let v_sec: Value = serde_json::from_slice(
        &res_secondary
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(v_sec["capsule"]["encryptedData"], "multi-key-capsule");

    // 3. Resolve via forged/unauthorized locator -> 404 NOT_FOUND
    let req_fake = Request::builder()
        .method("GET")
        .uri(format!("/api/vault/{}", fake_loc))
        .body(Body::empty())
        .unwrap();
    let res_fake = app.oneshot(req_fake).await.unwrap();
    assert_eq!(res_fake.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_large_body_limit_rejection() {
    let (app, _) = setup_test_app(5).await;
    let sk = SigningKey::from_bytes(&[31u8; 32]);
    let (loc, _) = make_signed_payload(&sk, 1, json!({}));

    // Create 1.5MB body
    let oversized_string = "A".repeat(1024 * 1024 + 500 * 1024);
    let oversized_body = format!(
        r#"{{"version": 1, "capsule": {{"data": "{}"}}, "public_key": "{}", "signature": "{}"}}"#,
        oversized_string,
        hex::encode(sk.verifying_key().as_bytes()),
        "00".repeat(64)
    );

    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/vault/{}", loc))
        .header("content-type", "application/json")
        .body(Body::from(oversized_body))
        .unwrap();
    let sock: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(sock));

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_immutability_of_public_key_rejection() {
    let (app, pool) = setup_test_app(5).await;
    let sk1 = SigningKey::from_bytes(&[41u8; 32]);
    let (loc, payload1) = make_signed_payload(&sk1, 1, json!({"data": "initial"}));

    // Save initial vault with sk1
    let req = build_post_request(&loc, &payload1, "127.0.0.1", None, None);
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // Modify stored public_key directly in database to simulate mismatch
    let altered_pk = "99".repeat(32);
    sqlx::query("UPDATE vaults SET public_key = ? WHERE locator = ?")
        .bind(&altered_pk)
        .bind(&loc)
        .execute(&pool)
        .await
        .unwrap();

    // Try updating vault: submitted public key does not match stored public key
    let (_, payload2) = make_signed_payload(&sk1, 2, json!({"data": "updated"}));
    let req2 = build_post_request(&loc, &payload2, "127.0.0.1", None, None);
    let res2 = app.oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::UNAUTHORIZED);
    let val: Value =
        serde_json::from_slice(&res2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(val["error"]
        .as_str()
        .unwrap()
        .contains("Public key does not match existing vault key"));
}

#[tokio::test]
async fn test_save_vault_invalid_curve_point() {
    let (app, _) = setup_test_app(5).await;
    let mut invalid_curve_pk = [0u8; 32];
    invalid_curve_pk[0] = 2;
    let loc = hex::encode(Sha256::digest(invalid_curve_pk));

    let payload = VaultPayload {
        version: 1,
        capsule: json!({"test": 1}),
        public_key: Some(hex::encode(invalid_curve_pk)),
        signature: Some("00".repeat(64)),
    };

    let req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let val: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(val["error"]
        .as_str()
        .unwrap()
        .contains("Invalid Ed25519 public key"));
}

#[tokio::test]
async fn test_binary_server_process() {
    let bin_path = env!("CARGO_BIN_EXE_voidvault-server");
    let test_db_path = format!(
        "/tmp/test_voidvault_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let test_port = "18099";

    let mut child = std::process::Command::new(bin_path)
        .env("DATABASE_PATH", &test_db_path)
        .env("PORT", test_port)
        .env("VOIDVAULT_MAX_NEW_VAULTS_PER_HOUR", "5")
        .env("VOIDVAULT_WINDOW_SECS", "1800")
        .spawn()
        .expect("Failed to spawn voidvault-server binary");

    let pid = child.id();

    // Poll until server starts responding
    let mut up = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(stream) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", test_port)).await
        {
            drop(stream);
            up = true;
            break;
        }
    }
    assert!(up, "Server failed to start in time");

    // Send SIGINT (Ctrl+C) to trigger ctrl_c shutdown branch
    let _ = std::process::Command::new("kill")
        .arg("-2")
        .arg(pid.to_string())
        .status();

    let status = child.wait().expect("Failed to wait on child");
    assert!(status.success());

    let _ = std::fs::remove_file(&test_db_path);
}

#[tokio::test]
async fn test_database_internal_errors() {
    let (app, pool) = setup_test_app(5).await;
    pool.close().await; // Close the pool to trigger database query errors

    let get_req = Request::builder()
        .method("GET")
        .uri("/api/vault/any_locator")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let sk = SigningKey::from_bytes(&[55u8; 32]);
    let (loc, payload) = make_signed_payload(&sk, 1, json!({"test": 1}));
    let post_req = build_post_request(&loc, &payload, "127.0.0.1", None, None);
    let post_res = app.oneshot(post_req).await.unwrap();
    assert_eq!(post_res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
