use std::time::Duration;
use reqwest::Client;
use crate::model::{ServerVaultPushPayload, ServerVaultResponse, VaultCapsule};

pub struct VaultClient {
    client: Client,
    server_base: String,
}

impl VaultClient {
    pub fn new(server_base: String) -> Self {
        let base = server_base.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { client, server_base: base }
    }

    pub async fn check_health(&self) -> Result<String, String> {
        let url = format!("{}/health", self.server_base);
        let res = self.client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Health check failed: {}", e))?;

        if res.status().is_success() {
            Ok("OK".to_string())
        } else {
            Err(format!("Server returned HTTP {}", res.status()))
        }
    }

    pub async fn pull_vault(&self, locator: &str) -> Result<Option<ServerVaultResponse>, String> {
        let url = format!("{}/api/vault/{}", self.server_base, locator);
        let res = self.client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Network error while pulling vault: {}", e))?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !res.status().is_success() {
            return Err(format!("Server returned HTTP error {}", res.status()));
        }

        let body = res.json::<ServerVaultResponse>()
            .await
            .map_err(|e| format!("Failed to parse server response: {}", e))?;

        Ok(Some(body))
    }

    pub async fn push_vault(&self, locator: &str, version: i64, capsule: &VaultCapsule) -> Result<(), String> {
        let url = format!("{}/api/vault/{}", self.server_base, locator);
        let payload = ServerVaultPushPayload {
            version,
            capsule: capsule.clone(),
        };

        let res = self.client.post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Network error while pushing vault: {}", e))?;

        if res.status() == reqwest::StatusCode::CONFLICT {
            return Err("Conflict (409): The server has a newer version of the vault. Run 'voidvault pull' first to synchronize.".to_string());
        }

        if !res.status().is_success() {
            let status = res.status();
            let err_text = res.text().await.unwrap_or_default();
            return Err(format!("Server push failed with HTTP {}: {}", status, err_text));
        }

        Ok(())
    }
}
