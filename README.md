# VoidVault Official Website

> **Branch:** `website`  
> Zero-knowledge hardware-derived password manager presentation and documentation portal.

---

## 🌐 Overview

This branch hosts the static website for [VoidVault](https://github.com/YellowSquared/voidvault), designed with pure HTML5, modern obsidian CSS, and vanilla JavaScript. Zero npm dependencies, zero build steps, and instantaneous sub-50ms load times.

### Key Sections:
- **Hero & Trust Invariants:** Core value proposition and hardware PRF guarantees.
- **Interactive Security Simulator:** Real-time demonstration comparing local unlocked browser memory with what an adversary sees on a compromised server or seized database dump.
- **Three-Channel Architecture Pipeline:** Step-by-step cryptographic breakdown of physical silicon, volatile RAM, and blind bit-bucket relay.
- **Architectural Comparison Table:** VoidVault vs. traditional password managers (1Password, Bitwarden, KeePass).
- **Ecosystem & Branches:** Dedicated component index pointing to `main` (Server), `extension` (Firefox Addon), and `cli` (Headless CLI).
- **Turnkey Quickstart:** Production deployment commands for Podman Quadlet, Docker Compose, Cargo, and Debian packages.

---

## 🚀 Local Preview

To preview the website locally on any machine:

```bash
# Clone the website branch
git clone -b website https://github.com/YellowSquared/voidvault.git voidvault-site
cd voidvault-site

# Run a lightweight local HTTP server
python3 -m http.server 8082
```

Open `http://localhost:8082` in your browser.

---

## 📦 Deployment (GitHub Pages)

The website is structured for zero-configuration deployment via GitHub Pages:
1. Go to repository **Settings** &rarr; **Pages**.
2. Set **Source** to `Deploy from a branch`.
3. Select branch `website` and folder `/ (root)`.
4. GitHub Pages will build and publish the site instantly.

---

## 📜 License

MIT or Apache-2.0.
