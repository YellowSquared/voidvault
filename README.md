# VoidVault

> **Zero-Knowledge, Blind Hardware Password Vault Powered by WebAuthn PRF**

VoidVault is an anonymous, zero-knowledge password vault designed around a radical security principle: **the server is 100% blind and holds zero user metadata**. 

Unlike conventional vaults (Bitwarden, 1Password, KeePass) that rely on user-chosen master passwords stretched with PBKDF2/Argon2, VoidVault derives its 256-bit AES encryption keys directly inside the physical silicon of a **FIDO2 Security Key (YubiKey 5 / Nitrokey)** via the W3C WebAuthn Level 3 PRF extension (`hmac-secret`).

---

## 🛡️ Core Security Architecture

```
┌────────────────────────┐
│  Physical Security Key │  (1) Evaluates CTAP2 hmac-secret PRF inside chip
│   (YubiKey via USB/NFC)│      (Master keys NEVER leave the silicon)
└───────────┬────────────┘
            │ 32-byte hardware seed
            ▼
┌────────────────────────┐
│  Your Local Browser    │  (2) Derives non-extractable AES-256-GCM key via WebCrypto HKDF
│   (Firefox MV3 Plugin) │  (3) Decrypts vault capsule strictly in volatile RAM
│                        │  (4) Zeroes all memory buffers immediately on lock
└───────────▲────────────┘
            │ Opaque Ciphertext Only (Base64 random bytes)
            │ (Keys NEVER touch the network)
            ▼
┌────────────────────────┐
│  VoidVault Server      │  (5) Stores only:
│   (Axum Rust + SQLite) │      - Blind locator hash (SHA-256)
│                        │      - Encrypted capsule (ciphertext)
│                        │      - Version sequence number
└────────────────────────┘
```

### Key Security Invariants:
1. **Phishing & Keylogger Immunity:** There is **no master password**. Keyloggers, phishing sites, and shoulder-surfers cannot steal the vault key because it only exists transiently when your physical finger presses the hardware key contact.
2. **100% Blind Server:** The server stores zero usernames, emails, website domains, secret titles, or directory paths. If the server is seized, subpoenaed, or fully hacked, the attacker gets only meaningless high-entropy ciphertext.
3. **Non-Extractable In-Memory Keys:** Derived via native browser `crypto.subtle.deriveKey(..., extractable: false)`. Even browser devtools or rogue scripts cannot export raw symmetric key bytes.
4. **Anti-Abuse IP Rate Limiting:** Built-in sliding-window rate limiter prevents blob flooding (max 3 new vault creations per IP per hour; existing vault updates are unlimited). Payloads are strictly clamped to 1MB max.

---

## 📂 Project Structure

```
voidvault/
├── extension/             # Firefox Manifest V3 WebExtension
│   ├── manifest.json      # MV3 configuration (100% AMO compliant, 0 warnings)
│   ├── crypto.js          # WebAuthn PRF + WebCrypto HKDF + AES-256-GCM
│   ├── background.js      # Volatile in-memory vault, auto-lock, remote sync
│   ├── popup.html/css/js  # Clean minimalist white/black UX (zero animations)
│   ├── content.js/css     # Non-intrusive in-input badge and autofill
│   └── test-page.html     # Minimal test bench portal
└── server/                # Lightweight Blind Daemon
    ├── Cargo.toml         # Axum 0.8, Tokio, SQLx SQLite, Tower-HTTP
    └── src/
        └── main.rs        # Blind vault API + IP rate limiter + SQLite store
```

---

## 🚀 Quickstart Guide

### 1. Build and Run the Server

Prerequisites: Rust (1.80+)

```bash
cd server
cargo run --release
```
The server listens on `http://0.0.0.0:8080`.

**Endpoints:**
- `GET /health` — Health check & status
- `GET /api/vault/:locator` — Unguarded public ciphertext read
- `POST /api/vault/:locator` — Guarded atomic ciphertext upsert (IP-throttled for new creations)

### 2. Load the Firefox Extension

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click **"Load Temporary Add-on..."**.
3. Select `extension/manifest.json`.
4. The **VoidVault** icon will appear in your Firefox toolbar.

### 3. Usage & Testing

1. If connecting to a remote server, forward ports via SSH:
   ```bash
   ssh -N -L 8080:localhost:8080 -L 8081:localhost:8081 user@your-server-ip
   ```
2. Open `http://localhost:8081/test-page.html` (or run `python3 -m http.server 8081 --directory extension`).
3. Click the VoidVault toolbar icon:
   - **Enroll Security Key:** Touch your YubiKey to register hardware PRF credentials.
   - **Dev Quick Unlock:** Headless testing fallback with simulated hardware PRF.
4. Click **"+ New"** to store credentials. They are encrypted client-side and synced blindly to the server.
5. Visit any login form—click the VoidVault key badge inside the password field to autofill!

---

## 📜 License

MIT or Apache-2.0. Zero-knowledge by design.
