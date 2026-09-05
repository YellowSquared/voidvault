use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntry {
    #[serde(default = "generate_entry_id")]
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default = "default_timestamp", rename = "updatedAt")]
    pub updated_at: String,
}

fn generate_entry_id() -> String {
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().gen();
    format!("sec_{}", hex::encode(bytes))
}

fn default_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedVmk {
    pub iv: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    pub id: String,
    pub name: String,
    pub locator: String,
    #[serde(rename = "wrappedVmk")]
    pub wrapped_vmk: WrappedVmk,
    #[serde(rename = "enrolledAt")]
    pub enrolled_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub iv: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCapsule {
    pub format: String,
    #[serde(rename = "keySlots")]
    pub key_slots: Vec<KeySlot>,
    pub payload: EncryptedPayload,
    #[serde(default = "default_version")]
    pub version: i64,
    #[serde(default = "default_timestamp", rename = "updatedAt")]
    pub updated_at: String,
}

fn default_version() -> i64 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerVaultResponse {
    pub locator: String,
    pub version: i64,
    pub capsule_sha256: Option<String>,
    pub capsule: VaultCapsule,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerVaultPushPayload {
    pub version: i64,
    pub capsule: VaultCapsule,
}
