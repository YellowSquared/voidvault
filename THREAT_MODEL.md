# VoidVault Threat Model & Security Axioms

> ### 🛡️ The Zero-Trust Baseline
> **VoidVault assumes the following are 100% fully compromised:**
> - ❌ **The Server:** The hosting provider, the SQLite database, and any sysadmin with full root access.
> - ❌ **The Network:** The Wi-Fi router, the ISP, and state actors with rogue Root CA certs intercepting TLS.
> 
> **What can an attacker with full root access and rogue CA certs do?**  
> **Literally nothing.** They get:
> - **0** master passwords
> - **0** cryptographic salts
> - **0** decryption keys
> - **0** usernames or emails
> - **0** website domains or entry titles
> 
> All they see is mathematically unbreakable noise. Decryption happens strictly in your browser using the physical silicon inside your security key.

---

Traditional password managers (e.g. 1Password, Bitwarden, LastPass) rely on a user-chosen master password stretched via compute-intensive key derivation functions (PBKDF2, Argon2id). Even with high iteration counts, master passwords remain vulnerable to:
1. **Low Human Entropy:** Most passwords chosen by humans contain <45 bits of true entropy.
2. **Offline Mass GPU Cracking:** Leaked server ciphertext databases can be cracked offline at billions of guesses per second.
3. **Phishing & AitM Reverse Proxies:** Attackers can intercept typed master passwords via transparent reverse proxies (e.g., Evilginx).
4. **Relational Metadata Leakage:** Servers store user accounts, email addresses, billing records, entry counts, and domain names.

VoidVault fundamentally decouples cryptographic security from human memorization by anchoring vault master keys in physical hardware security tokens via the **W3C WebAuthn Level 3 PRF Extension (`hmac-secret`)**. Vault encryption keys are generated directly inside the tamper-resistant hardware microcontroller of FIDO2 authenticators (e.g., YubiKey 5 Series).

---

## 2. Two-Channel Separation of Concerns

A foundational design mandate of VoidVault is the **strict two-channel separation between server-side authorization and client-side decryption**:

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│               CHANNEL 1: SERVER AUTHORIZATION (Network Transmitted)               │
│                                                                                   │
│  Client (WebExtension)                             VoidVault Server (Axum)        │
│  ---------------------                             -----------------------        │
│  Standard WebAuthn Assertion  ─── Assertion ───►   Verifies signature over        │
│  (ECDSA P-256 / Ed25519)                           challenge using public key     │
│                                                    [ Authorizes GET/POST ]        │
└───────────────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────────────────┐
│            CHANNEL 2: HARDWARE VAULT DECRYPTION (STRICTLY CLIENT-SIDE)            │
│                                                                                   │
│  FIDO2 Hardware Key (YubiKey)                      Client Memory (WebExtension)   │
│  ----------------------------                      ----------------------------   │
│  CTAP 2.1 `hmac-secret` PRF   ─── Ephemeral ───►   Derives Vault Master Key (VMK) │
│  Evaluated inside silicon         ECDH Wire        Transient Uint8Array Only      │
│                                                                                   │
│  *** ZERO TRANSMISSION: PRF Output & VMK are NEVER sent over the network! ***     │
│  *** The Server NEVER receives salts, passwords, or keys under any circumstance!  │
└───────────────────────────────────────────────────────────────────────────────────┘
```

1. **Channel 1 (Network Authorization):**
   - The client executes a standard WebAuthn public-key ceremony.
   - The security key signs the server challenge using an asymmetric private key.
   - The server verifies the signature to authorize storing or fetching the ciphertext capsule.
   - The server learns only: *"An authorized hardware touch occurred for this vault locator."*
2. **Channel 2 (Hardware Decryption):**
   - In parallel, the authenticator evaluates the PRF extension (`hmac-secret`) directly inside its tamper-resistant secure element.
   - The 32-byte pseudo-random output is returned to the browser over the local ephemeral USB/NFC channel.
   - **Zero Transmission Guarantee:** Neither the PRF output, the salt parameters, nor the derived Vault Master Key (VMK) are ever transmitted over the network. They never appear in HTTP headers, JSON payloads, or server logs.
   - **Strict Client-Side Decryption:** Decryption occurs 100% inside client memory using WebCrypto AES-256-GCM.

---

## 3. Trust Boundaries & Architecture

```
                                      TRUST BOUNDARIES
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    CLIENT ENVIRONMENT                                   │
│                                                                                         │
│  [ Untrusted Webpage DOM ]                                                              │
│            │                                                                            │
│   (XSS / DOM Scraping)                                                                  │
│            ▼  [TB-1: DOM / Extension Boundary]                                          │
│  [ WebExtension Content Script ]                                                        │
│            │                                                                            │
│   (Message Passing / Port)                                                              │
│            ▼  [TB-2: Script / Service Worker Boundary]                                  │
│  [ Background Service Worker (In-Memory Volatile Crypto) ]                              │
│            │                                                                            │
│   (WebAuthn API / CTAP2 over USB/NFC)                                                   │
│            ▼  [TB-3: Host / Hardware Token Boundary]                                    │
│  [ FIDO2 Hardware Authenticator (YubiKey Secure Element) ]                              │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                     │
               (Opaque Ciphertext)   │  [TB-4: Client / Server Boundary]
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                HOSTILE / COMPROMISED SERVER                             │
│                                                                                         │
│  [ SQLite Blind Store: `locator` -> `encrypted_capsule` ]                               │
│  [ Malicious DB Admin / State-Sponsored Interception / Rogue CA Proxies ]              │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Concrete Threat Scenarios & Mitigations

### Scenario 1: Total Server Database Compromise & Malicious DB Admin
* **Adversary Capability:** An attacker gains full root access to the server, extracts the entire SQLite database, or the hosting provider acts maliciously.
* **Adversary Gain:** **Zero.**
* **Mitigation:**
  - The server maintains no user accounts, emails, master passwords, or salts.
  - The database contains only blind locator hashes (`SHA-256(credential_id)`) and opaque AES-256-GCM ciphertext capsules.
  - Without physical possession and physical finger touch of the enrolled hardware security key, the database consists of mathematically unbreakable pseudorandom noise.

### Scenario 2: TLS Interception, ISP Snooping & Rogue Root CA
* **Adversary Capability:** A state adversary or corporate network installs a rogue Root CA certificate on the user's router or machine, terminating TLS and inspecting all plaintext network traffic.
* **Adversary Gain:** **Zero plaintext passwords or keys.**
* **Mitigation:**
  - Unlike traditional password managers that transmit password hashes or session tokens over HTTPS, VoidVault never sends keys over the wire.
  - Even if TLS is completely decrypted by a corporate proxy, the network payload consists strictly of client-side encrypted AES-256-GCM capsules.

### Scenario 3: Malicious Server Code Injection (WebExtension vs. Web Vaults)
* **Adversary Capability:** A compromised server attempts to inject malicious JavaScript to hook decryption functions and exfiltrate credentials.
* **Why Traditional Web Vaults Fail:** In web vaults (e.g. `vault.example.com`), JavaScript is loaded dynamically over the network on every login. A compromised server modifies the script bundle to steal the master key.
* **VoidVault Defense:**
  - VoidVault's frontend executes strictly as an installed, tamper-evident **local Firefox WebExtension (Manifest V3)** signed by Mozilla.
  - The server cannot inject code or alter the extension's execution environment.
  - The extension enforces a strict Content Security Policy banning remote scripts (`script-src 'self'; object-src 'none'`).
  - The server is relegated to a dumb storage endpoint. If it returns altered ciphertext, AES-256-GCM authentication tag verification fails and the extension aborts instantly.

### Scenario 4: Phishing & Malicious Origin WebAuthn Spoofing
* **Adversary Capability:** An attacker tricks a user into visiting `evil-vault.com` and prompts for a security key touch to obtain the PRF decryption secret.
* **Mitigation:**
  - WebAuthn cryptographically binds every ceremony to the caller's Relying Party ID (`rpId`).
  - The security key evaluates PRF using an HMAC incorporating `SHA-256(rpId)`.
  - Touching the key on `evil-vault.com` produces completely different, domain-isolated pseudo-random bytes that cannot decrypt VoidVault capsules.

### Scenario 5: DOM Scraping & In-Page Cross-Site Scripting (XSS)
* **Adversary Capability:** A target website has an XSS vulnerability that attempts to steal credentials as they are autofilled.
* **Mitigation:**
  - **Zero Ambient Autofill:** VoidVault strictly prohibits automatic form filling on page load.
  - **Explicit User Intent:** Credentials are only injected after an explicit user click on the in-input badge or via the extension popup.
  - Synthetic DOM events (`InputEvent`, `change`) are dispatched directly to the target input without leaking extension object references into the page's global `window` scope.

### Scenario 6: Memory Scraping & Inactivity
* **Adversary Capability:** An attacker inspects browser process memory or heap dumps.
* **Mitigation:**
  - All intermediate cryptographic buffers and decrypted credentials reside strictly in mutable `Uint8Array` buffers.
  - On vault lock, the extension explicitly zeroes all buffers (`Uint8Array.fill(0)`).
  - Derived AES keys are flagged `extractable: false`.
  - Automatic lock timer scrubs volatile memory after 15 minutes of user inactivity.

---

## 5. STRIDE Threat Analysis Matrix

| Threat Category | Potential Attack Vector | VoidVault Architectural Defense |
| :--- | :--- | :--- |
| **Spoofing** | Attacker spoofs server challenge or creates fake origin. | Cryptographic WebAuthn `rpId` binding in hardware; signed challenges. |
| **Tampering** | Malicious server modifies ciphertext or rolls back database. | AES-256-GCM 128-bit authentication tags detect byte corruption; client monotonic version checking rejects rollback. |
| **Repudiation** | Cloned hardware authenticator attempts synchronization. | Hardware monotonic signature counters (`sign_counter`) detect cloned authenticators. |
| **Information Disclosure** | Server database leak, network packet sniffing, or rogue CA proxy. | Blind locators; AES-256-GCM encryption with hardware PRF derivation; zero salts or keys transmitted. |
| **Denial of Service** | Rogue IP attempts to flood server with bogus vaults. | In-memory sliding-window IP rate limiter (max 3 new vaults/hour/IP) + strict 1MB body limit. |
| **Elevation of Privilege** | Compromised web server tries to execute remote code in client. | Installed WebExtension execution context; signed XPI package; strict CSP banning remote script injection. |

---

## 6. Out of Scope / Explicit Non-Goals

The following attack vectors are explicitly out of scope and cannot be defended against by any software-layer password manager:
1. **Compromised Client Operating System:** If an attacker has ring-0 root/kernel access, hardware keyloggers, or arbitrary process injection capabilities on the client PC itself.
2. **Physical Coercion / Rubber-Hose Cryptanalysis:** Physical duress compelling the user to touch their security key.
3. **Loss of All Hardware Tokens without Backup:** Physical loss of hardware keys without enrolling a secondary backup key will result in permanent, irrecoverable data loss.

---

## 7. Cryptographic Algorithms & Standards

* **Hardware Key Derivation:** FIDO CTAP 2.1 `hmac-secret` / W3C WebAuthn Level 3 PRF Extension
* **Key Derivation Function:** WebCrypto HKDF (`SHA-256`, 32-byte salt, domain-separated info)
* **Symmetric Encryption:** AES-256-GCM with 96-bit random IV and 128-bit authentication tag
* **Blind Index Hashing:** SHA-256 (`SHA-256(credential_id)`)
* **Transport:** Client-side local WebCrypto; Axum 0.8 REST API (HTTPS recommended for network integrity)
