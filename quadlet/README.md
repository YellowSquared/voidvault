# VoidVault Server Deployment: Docker & Podman Quadlet

This directory provides declarative configuration files to run the **VoidVault Minimal Server** as an unprivileged, hardened container using **Docker Compose** or **Podman Quadlet** (systemd integration).

---

## 1. Quick Start: Podman Quadlet (Recommended)

Podman Quadlet integrates container lifecycles directly into `systemd`, providing native service supervision, auto-restarts, journald logging, and zero-privilege rootless isolation.

### Rootless User Deployment (Recommended)

1. **Run the Turnkey Installer:**
   ```bash
   ./quadlet/install.sh
   ```

2. **Manual Step-by-Step Installation:**
   ```bash
   # 1. Build the local image
   podman build -t localhost/voidvault-server:latest -f Dockerfile .

   # 2. Copy Quadlet units to your user systemd directory
   mkdir -p ~/.config/containers/systemd
   cp quadlet/voidvault-data.volume ~/.config/containers/systemd/
   cp quadlet/voidvault.container ~/.config/containers/systemd/

   # 3. Reload systemd (triggers Quadlet generator)
   systemctl --user daemon-reload

   # 4. Start and enable the service
   systemctl --user enable --now voidvault.service
   ```

3. **Verify & Inspect:**
   ```bash
   # Check service status
   systemctl --user status voidvault.service

   # View live journal logs
   journalctl --user -u voidvault.service -f

   # Test health endpoint
   curl -s http://127.0.0.1:8080/health
   ```

4. **Enable Boot Persistence for Rootless Services:**
   To keep your rootless containers running when you log out:
   ```bash
   loginctl enable-linger $USER
   ```

---

## 2. Quick Start: Docker & Docker Compose

For traditional Docker environments:

1. **Start VoidVault Server:**
   ```bash
   docker compose up -d
   ```

2. **View Logs:**
   ```bash
   docker compose logs -f
   ```

3. **Check Container Status:**
   ```bash
   docker compose ps
   ```

4. **Stop the Service:**
   ```bash
   docker compose down
   ```

---

## 3. Container Security Hardening

Both the Docker and Podman specifications implement defense-in-depth:
- **Rootless & Non-Root Execution:** Runs under dedicated unprivileged user `voidvault` (`UID 10001:10001`).
- **Dropped Linux Capabilities:** All kernel capabilities are dropped (`cap_drop: [ALL]` / `DropCapability=ALL`).
- **No Privilege Escalation:** `no-new-privileges: true` prevents setuid binaries from gaining root.
- **Persistent Data Isolation:** The SQLite database is strictly isolated inside the `voidvault-data` named volume at `/data/voidvault.db`.
- **Automated Healthchecks:** Periodically polls `/health` to ensure service responsiveness.

---

## 4. Volume Backups & Disaster Recovery

Because VoidVault stores encrypted capsules in SQLite at `/data/voidvault.db`:

```bash
# Backup SQLite database directly from Podman volume:
podman volume export voidvault-data > voidvault-backup-$(date +%F).tar

# Or copy the database file out:
podman cp voidvault-server:/data/voidvault.db ./voidvault.db.bak
```
