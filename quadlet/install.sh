#!/usr/bin/env bash
# VoidVault Podman Quadlet Installation Script
# Installs rootless Podman Quadlet systemd service for VoidVault Server

set -euo pipefail

QUADLET_DIR="${HOME}/.config/containers/systemd"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== VoidVault Podman Quadlet Setup ==="

# 1. Ensure Podman is installed
if ! command -v podman &> /dev/null; then
    echo "Error: 'podman' binary not found. Please install podman first." >&2
    exit 1
fi

# 2. Pull prebuilt image or build locally
if [[ "${1:-}" == "--build" ]]; then
    echo "--> Building container image locally..."
    podman build -t yellowsquared/voidvault-server:latest -f "${REPO_DIR}/Dockerfile" "${REPO_DIR}"
else
    echo "--> Pulling pre-built container from Docker Hub: yellowsquared/voidvault-server:latest..."
    podman pull docker.io/yellowsquared/voidvault-server:latest || podman build -t yellowsquared/voidvault-server:latest -f "${REPO_DIR}/Dockerfile" "${REPO_DIR}"
fi

# 3. Create user quadlet directory
echo "--> Installing Quadlet units to ${QUADLET_DIR}..."
mkdir -p "${QUADLET_DIR}"
cp "${SCRIPT_DIR}/voidvault-data.volume" "${QUADLET_DIR}/"
cp "${SCRIPT_DIR}/voidvault.container" "${QUADLET_DIR}/"

# 4. Reload systemd user daemon
echo "--> Reloading user systemd daemon..."
systemctl --user daemon-reload

# 5. Enable and start the service
echo "--> Enabling and starting voidvault.service..."
systemctl --user enable --now voidvault.service

echo "=== VoidVault Quadlet Installation Complete ==="
echo "Check service status:  systemctl --user status voidvault.service"
echo "View live container logs: journalctl --user -u voidvault.service -f"
echo "Health check endpoint: curl http://127.0.0.1:8080/health"
