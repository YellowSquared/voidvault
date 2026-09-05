use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::model::{EncryptedPayload, VaultEntry, WrappedVmk};

pub const DEFAULT_HKDF_SALT: &[u8] = b"voidvault-prf-hkdf-salt-v2";
pub const HKDF_INFO: &[u8] = b"voidvault-aes256-gcm-key-v2";
pub const ED25519_HKDF_INFO: &[u8] = b"voidvault-ed25519-seed-v1";
pub const DEFAULT_DEV_PASSPHRASE: &str = "voidvault-dev-simulated-key";

pub fn derive_signing_key(prf_secret: &[u8; 32]) -> Result<SigningKey, String> {
    let hkdf = Hkdf::<Sha256>::new(Some(DEFAULT_HKDF_SALT), prf_secret);
    let mut seed = [0u8; 32];
    hkdf.expand(ED25519_HKDF_INFO, &mut seed)
        .map_err(|e| format!("HKDF expand error for Ed25519 seed: {:?}", e))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn derive_public_key_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

pub fn calculate_locator_from_signing_key(signing_key: &SigningKey) -> (String, String) {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);
    let locator = hex::encode(Sha256::digest(&pubkey_bytes));
    (locator, pubkey_hex)
}

#[allow(dead_code)]
pub fn calculate_locator(pubkey_bytes: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(pubkey_bytes))
}

pub fn sign_vault_write(signing_key: &SigningKey, locator: &str, version: i64, capsule_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(capsule_json.as_bytes());
    let capsule_sha = hasher.finalize();

    let mut msg = Vec::with_capacity(locator.len() + 8 + 32);
    msg.extend_from_slice(locator.as_bytes());
    msg.extend_from_slice(&version.to_le_bytes());
    msg.extend_from_slice(&capsule_sha);

    let sig = signing_key.sign(&msg);
    hex::encode(sig.to_bytes())
}

#[allow(dead_code)]
pub fn sign_alias_authorization(signing_key: &SigningKey, slot_locator: &str, canonical_locator: &str) -> String {
    let auth_msg = format!("voidvault-alias-authorization-v1:{}:{}", slot_locator, canonical_locator);
    let sig = signing_key.sign(auth_msg.as_bytes());
    hex::encode(sig.to_bytes())
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

    #[test]
    fn test_self_certifying_locator_and_ed25519_signatures() {
        use ed25519_dalek::Signature;

        let prf_secret = derive_simulated_prf("test-signing-passphrase");
        let signing_key = derive_signing_key(&prf_secret).expect("derive signing key");
        let (locator, pubkey_hex) = calculate_locator_from_signing_key(&signing_key);

        // 1. Verify self-certification: SHA256(pubkey) == locator
        let pubkey_bytes = hex::decode(&pubkey_hex).expect("decode pubkey");
        assert_eq!(calculate_locator(&pubkey_bytes.try_into().unwrap()), locator);

        // 2. Sign write payload and verify
        let version = 42;
        let capsule_json = r#"{"format":"voidvault-multi-keyslot-v1","keySlots":[]}"#;
        let sig_hex = sign_vault_write(&signing_key, &locator, version, capsule_json);

        let mut hasher = Sha256::new();
        hasher.update(capsule_json.as_bytes());
        let capsule_sha = hasher.finalize();

        let mut msg = Vec::new();
        msg.extend_from_slice(locator.as_bytes());
        msg.extend_from_slice(&version.to_le_bytes());
        msg.extend_from_slice(&capsule_sha);

        let sig_bytes = hex::decode(&sig_hex).expect("decode sig");
        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        let vk = signing_key.verifying_key();
        assert!(vk.verify_strict(&msg, &sig).is_ok());

        // 3. Sign alias authorization and verify
        let alias_sig_hex = sign_alias_authorization(&signing_key, "alias_loc_123", &locator);
        let alias_msg = format!("voidvault-alias-authorization-v1:{}:{}", "alias_loc_123", locator);
        let alias_sig_bytes = hex::decode(&alias_sig_hex).expect("decode alias sig");
        let alias_sig = Signature::from_bytes(&alias_sig_bytes.try_into().unwrap());
        assert!(vk.verify_strict(alias_msg.as_bytes(), &alias_sig).is_ok());
    }
}
