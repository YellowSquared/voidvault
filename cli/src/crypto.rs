use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::model::{EncryptedPayload, VaultEntry, WrappedVmk};

pub const DEFAULT_HKDF_SALT: &[u8] = b"voidvault-prf-hkdf-salt-v2";
pub const HKDF_INFO: &[u8] = b"voidvault-aes256-gcm-key-v2";
pub const DEFAULT_DEV_PASSPHRASE: &str = "voidvault-dev-simulated-key";

pub fn calculate_locator(credential_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(credential_id.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn derive_prf_key(prf_secret: &[u8; 32]) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(DEFAULT_HKDF_SALT), prf_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut derived_key)
        .map_err(|e| format!("HKDF expand error: {:?}", e))?;
    Ok(derived_key)
}

pub fn derive_simulated_prf(passphrase: &str) -> [u8; 32] {
    let mut prf_output = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        DEFAULT_HKDF_SALT,
        100_000,
        &mut prf_output,
    );
    prf_output
}

pub fn generate_vmk() -> [u8; 32] {
    use rand::RngCore;
    let mut vmk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut vmk);
    vmk
}

pub fn wrap_vmk(raw_vmk: &[u8; 32], prf_key: &[u8; 32]) -> Result<WrappedVmk, String> {
    use rand::RngCore;
    let cipher = Aes256Gcm::new_from_slice(prf_key).map_err(|e| e.to_string())?;
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, raw_vmk.as_ref())
        .map_err(|e| format!("VMK wrap encryption failed: {:?}", e))?;

    Ok(WrappedVmk {
        iv: BASE64.encode(iv),
        ciphertext: BASE64.encode(ciphertext),
    })
}

pub fn unwrap_vmk(wrapped: &WrappedVmk, prf_key: &[u8; 32]) -> Result<[u8; 32], String> {
    let cipher = Aes256Gcm::new_from_slice(prf_key).map_err(|e| e.to_string())?;
    let iv_bytes = BASE64
        .decode(&wrapped.iv)
        .map_err(|e| format!("Invalid IV base64: {}", e))?;
    let ct_bytes = BASE64
        .decode(&wrapped.ciphertext)
        .map_err(|e| format!("Invalid ciphertext base64: {}", e))?;

    if iv_bytes.len() != 12 {
        return Err("IV must be exactly 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(&iv_bytes);

    let mut decrypted = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|_| "Decryption failed (incorrect key or corrupted ciphertext)".to_string())?;

    if decrypted.len() != 32 {
        decrypted.zeroize();
        return Err("Decrypted VMK must be 32 bytes".to_string());
    }

    let mut vmk = [0u8; 32];
    vmk.copy_from_slice(&decrypted);
    decrypted.zeroize();
    Ok(vmk)
}

pub fn encrypt_entries(entries: &[VaultEntry], vmk: &[u8; 32]) -> Result<EncryptedPayload, String> {
    use rand::RngCore;
    let json_bytes = serde_json::to_vec(entries)
        .map_err(|e| format!("Failed to serialize entries: {}", e))?;

    let cipher = Aes256Gcm::new_from_slice(vmk).map_err(|e| e.to_string())?;
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, json_bytes.as_ref())
        .map_err(|e| format!("Payload encryption failed: {:?}", e))?;

    Ok(EncryptedPayload {
        iv: BASE64.encode(iv),
        ciphertext: BASE64.encode(ciphertext),
    })
}

pub fn decrypt_entries(payload: &EncryptedPayload, vmk: &[u8; 32]) -> Result<Vec<VaultEntry>, String> {
    let cipher = Aes256Gcm::new_from_slice(vmk).map_err(|e| e.to_string())?;
    let iv_bytes = BASE64
        .decode(&payload.iv)
        .map_err(|e| format!("Invalid payload IV base64: {}", e))?;
    let ct_bytes = BASE64
        .decode(&payload.ciphertext)
        .map_err(|e| format!("Invalid payload ciphertext base64: {}", e))?;

    if iv_bytes.len() != 12 {
        return Err("Payload IV must be exactly 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(&iv_bytes);

    let mut decrypted = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|_| "Failed to decrypt vault payload (corrupted or wrong VMK)".to_string())?;

    let entries: Vec<VaultEntry> = serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to parse decrypted entries JSON: {}", e))?;

    decrypted.zeroize();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_derivation_and_vmk_roundtrip() {
        let prf_secret = derive_simulated_prf("test-passphrase");
        let derived_key = derive_prf_key(&prf_secret).expect("derive prf key");

        let vmk = generate_vmk();
        let wrapped = wrap_vmk(&vmk, &derived_key).expect("wrap vmk");
        let unwrapped = unwrap_vmk(&wrapped, &derived_key).expect("unwrap vmk");

        assert_eq!(vmk, unwrapped);
    }

    #[test]
    fn test_entries_encrypt_decrypt_roundtrip() {
        let vmk = generate_vmk();
        let entries = vec![VaultEntry {
            id: "sec_1".to_string(),
            title: "GitHub".to_string(),
            domain: "github.com".to_string(),
            username: "alice".to_string(),
            password: "supersecretpassword123".to_string(),
            notes: "Test notes".to_string(),
            updated_at: "2026-09-05T19:00:00Z".to_string(),
        }];

        let payload = encrypt_entries(&entries, &vmk).expect("encrypt");
        let decrypted = decrypt_entries(&payload, &vmk).expect("decrypt");

        assert_eq!(entries, decrypted);
    }
}
