# VoidVault

> ### 🛡️ Zero-Trust Baseline: Everything Outside Your PC is Hostile
> **VoidVault assumes that everything except your local PC and hardware key is 100% compromised:**
> - ❌ **The Server & Sysadmins:** The hosting provider, the SQLite database, seized cloud disks, and any rogue sysadmin with full root access.
> - ❌ **The Network & Transit:** The Wi-Fi router, malicious public hotspots, upstream ISPs, and adversaries sniffing packets.
> - ❌ **TLS & Certificate Authorities:** State actors or corporate proxies with installed Root CA certs on routers decrypting all HTTPS traffic.
> - ❌ **The Public Internet & DNS:** BGP hijacks, spoofed DNS, poisoned routes, and reverse proxy front-ends.
> - ❌ **The Database & Disk Backups:** Complete database dumps leaked on pastebin or subpoenaed by third parties.
> - ❌ **The Websites You Visit:** In-page scripts and XSS vulnerabilities attempting to probe DOM inputs (defeated by zero ambient autofill).
> - ❌ **Phishing Domains:** Fake clone sites trying to prompt for hardware touches (hardware-enforced `rpId` binding makes phished touches produce useless random bytes).
> 
> **What can an adversary with root on the server, rogue CA certs on the router, and a leaked database dump do?**  
> **Literally nothing.** They get:
> - **0** master passwords (none exist)
> - **0** cryptographic salts (none sent to server)
> - **0** decryption keys (keys never leave your YubiKey silicon)
> - **0** usernames or emails (server has no user records)
> - **0** website domains or folder paths (everything is encrypted client-side)
> - **0** entry counts or secret lengths (discrete bucket padding hides structure)
> 
> All they see is mathematically unbreakable noise. The server never even gets a salt or a password. It's all client-side. Decryption happens strictly inside your local browser using physical silicon inside your security key (YubiKey / WebAuthn PRF).

---

## 💡 What Makes VoidVault Different?

Most "zero-knowledge" password managers still send a hashed master password or salts to an authentication server to log you in. **VoidVault does not.**

* **Zero Passwords:** There is no master password to type, leak, keylog, or forget.
* **Zero Salts on Server:** The server never even receives the cryptographic salt. Salts and derivation parameters remain strictly client-side.
* **Zero Keys on Server:** Encryption keys are derived directly from the physical silicon of your security key inside your browser. They are marked `extractable: false` and are never transmitted over the wire.
* **Zero Metadata on Server:** The server has no user accounts, no email addresses, no domains, and no entry titles.
* **100% Blind Bit-Bucket:** All the server ever stores is a 32-byte blind locator hash and an opaque blob of encrypted bytes. If the server is seized, subpoenaed, or compromised, the attacker gets mathematically unbreakable noise.

---

## 🛡️ Core Security Architecture & Threat Model

> 📖 **Read the full formal threat specification:** [THREAT_MODEL.md](THREAT_MODEL.md) — Analyzes STRIDE threats, rogue CA/TLS interception, compromised server admin defenses, and cryptographic two-channel isolation.

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
            │ (Salt & Keys NEVER touch the network)
            ▼
┌────────────────────────┐
│  VoidVault Server      │  (5) Stores only:
│   (Axum Rust + SQLite) │      - Blind locator hash (SHA-256)
│                        │      - Encrypted capsule (ciphertext)
│                        │      - Version sequence number
└────────────────────────┘
```

### Key Security Invariants:
1. **The Server Never Gets a Salt or a Password:** Decryption is strictly local. The server cannot attempt offline brute-force attacks because it possesses neither the salt nor any password hash.
2. **Phishing & Keylogger Immunity:** Without a master password, keyloggers and phishing sites have nothing to steal. The vault unlocks only when your physical finger touches your hardware key.
3. **Non-Extractable In-Memory Keys:** Derived via native browser `crypto.subtle.deriveKey(..., extractable: false)`. Even browser devtools or rogue in-page scripts cannot export raw symmetric key bytes.
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
5. Click **"⚙️" (Settings)** in the header to change your relay server URL or test ping latency.
6. Click **"Backup"** to export your vault:
   - **Option 2 (Encrypted Capsule - Recommended):** Downloads a sealed `.voidvault` JSON backup with **zero metadata leaked** on disk.
   - **Option 3 (Unix `pass` Directory Export):** Downloads a standard `~/.password-store` `.zip` archive compatible with Unix `pass`.

---

## 📦 Packaging & AMO Signing

VoidVault is designed for 100% Mozilla AMO compliance (0 errors, 0 warnings, 0 notices on `web-ext lint`).

### Build Extension Package (.xpi)

```bash
npx web-ext build --source-dir extension --artifacts-dir dist --overwrite-dest --filename voidvault-v0.2.0.xpi
```

### Sign Unlisted Release (for GitHub Releases)

To distribute a signed `.xpi` that users can install in standard Firefox without developer mode:

1. Generate your API credentials at [addons.mozilla.org/developers/addon/api/key/](https://addons.mozilla.org/developers/addon/api/key/).
2. Run:
   ```bash
   npx web-ext sign \
     --source-dir extension \
     --artifacts-dir dist \
     --api-key "<YOUR_AMO_JWT_ISSUER>" \
     --api-secret "<YOUR_AMO_JWT_SECRET>" \
     --channel unlisted
   ```
3. Mozilla will automatically sign the package in ~2-5 minutes. Attach the resulting `.xpi` to your GitHub Release!

---

## 📜 License

MIT or Apache-2.0. Zero-knowledge by design.
