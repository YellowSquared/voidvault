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
5. **Anti-Rollback State Defense:** Client and server enforce monotonic state versioning. Replaying older valid snapshots (downgrade attacks) is strictly detected and rejected.
6. **Air-Gapped Disaster Recovery:** One-click encrypted `.voidvault` backup files allow offline restoration independently of any server.

---

## 📂 Project Structure & Branches

The VoidVault project is organized across dedicated, focused branches:

* **`main` (this branch):** High-performance, 95%+ verified zero-knowledge blind relay server, containers, and daemon packaging.
* **[`extension`](https://github.com/YellowSquared/voidvault/tree/extension):** Firefox Manifest V3 WebExtension (WebAuthn PRF, client-side zero-knowledge encryption, responsive popup & full-tab UX).
* **[`cli`](https://github.com/YellowSquared/voidvault/tree/cli):** Headless, stateless command-line interface with Ed25519 signed writes, self-certifying locators, and RPM packaging.

```
voidvault/ (main branch)
├── server/                # Lightweight Blind Relay Server (Axum, SQLite)
│   ├── Cargo.toml         # Axum 0.8, Tokio, SQLx, Tower-HTTP, Ed25519-dalek
│   ├── src/
│   │   ├── lib.rs         # Modular server library (router, rate limiting, crypto verification)
│   │   └── main.rs        # Production daemon entrypoint & signal handling
│   └── tests/
│       └── api_tests.rs   # Comprehensive integration test suite (95.51% coverage)
├── quadlet/               # Native Podman Quadlet (systemd generator)
│   ├── voidvault.container# Rootless container systemd specification
│   ├── voidvault-data.volume # Persistent volume definition
│   └── install.sh         # Turnkey Quadlet installer
├── Dockerfile             # Multi-stage minimal unprivileged container image
└── docker-compose.yml     # Turnkey Docker Compose configuration
```

---

## 🚀 Quickstart Guide

### Option A: Podman Quadlet (Recommended for Production / Systemd)

```bash
./quadlet/install.sh
# Check status: systemctl --user status voidvault.service
```

### Option B: Docker Compose

```bash
docker compose up -d
```

### Option C: Debian / Ubuntu Package (.deb)

Download the `.deb` package from GitHub Releases or compile locally:
```bash
sudo apt install ./voidvault-server_0.2.0-1_amd64.deb
sudo systemctl enable --now voidvault-server
```
Includes auto-configured unprivileged system user `voidvault`, hardened systemd unit, and config at `/etc/voidvault/voidvault.conf`.

### Option D: Nix / NixOS Flake

Run directly on any Nix system without cloning:
```bash
nix run github:YellowSquared/voidvault
```

Or enable the native NixOS daemon module in `configuration.nix`:
```nix
{ inputs, ... }: {
  imports = [ inputs.voidvault.nixosModules.default ];

  services.voidvault = {
    enable = true;
    port = 8080;
    bindAddr = "0.0.0.0";
  };
}
```

### Option E: Native Cargo Build

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

### 2. Client Interfaces

Client implementations are maintained on their respective dedicated branches:

* **Firefox WebExtension:** Switch to the [`extension`](https://github.com/YellowSquared/voidvault/tree/extension) branch to build, lint (`web-ext`), and test the browser extension.
* **Stateless CLI:** Switch to the [`cli`](https://github.com/YellowSquared/voidvault/tree/cli) branch to build the headless Rust CLI with Ed25519 signing and warning countdowns.

---

## 📦 Debian Package (.deb)

The relay server includes native Debian packaging:

```bash
cd server
cargo deb --no-build
# Output: target/debian/voidvault-server_0.2.0-1_amd64.deb
sudo dpkg -i target/debian/voidvault-server_0.2.0-1_amd64.deb
```

---

## 📜 License

MIT or Apache-2.0. Zero-knowledge by design.
