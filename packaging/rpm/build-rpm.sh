#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLI_DIR="${REPO_ROOT}/cli"
DIST_DIR="${REPO_ROOT}/dist"
SPEC_FILE="${SCRIPT_DIR}/voidvault.spec"

echo "=== VoidVault RPM Package Builder ==="

if ! command -v rpmbuild &>/dev/null; then
    echo "[-] Error: 'rpmbuild' not found. Please install rpm build tools (e.g., 'sudo apt install rpm' or 'sudo dnf install rpm-build')." >&2
    exit 1
fi

if ! command -v cargo &>/dev/null; then
    echo "[-] Error: 'cargo' not found in PATH." >&2
    exit 1
fi

echo "[1/4] Compiling release binary in ${CLI_DIR}..."
cargo build --release --manifest-path "${CLI_DIR}/Cargo.toml"

RELEASE_BIN="${CLI_DIR}/target/release/voidvault"
if [ ! -f "${RELEASE_BIN}" ]; then
    echo "[-] Error: Expected binary not found at ${RELEASE_BIN}" >&2
    exit 1
fi

echo "[2/4] Stripping binary symbols..."
strip "${RELEASE_BIN}"

BUILD_DIR="$(mktemp -d /tmp/voidvault-rpmbuild-XXXXXX)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

mkdir -p "${BUILD_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,rpmdb}
mkdir -p "${DIST_DIR}"

cp "${RELEASE_BIN}" "${BUILD_DIR}/SOURCES/voidvault"
cp "${SPEC_FILE}" "${BUILD_DIR}/SPECS/voidvault.spec"

echo "[3/4] Building RPM package via rpmbuild..."
rpmbuild \
    --define "_topdir ${BUILD_DIR}" \
    --define "_sourcedir ${BUILD_DIR}/SOURCES" \
    --define "_specdir ${BUILD_DIR}/SPECS" \
    --define "_dbpath ${BUILD_DIR}/rpmdb" \
    -bb "${BUILD_DIR}/SPECS/voidvault.spec" >/dev/null

BUILT_RPM="$(find "${BUILD_DIR}/RPMS" -type f -name "*.rpm" | head -n 1)"
if [ -z "${BUILT_RPM}" ]; then
    echo "[-] Error: rpmbuild failed to produce an RPM package." >&2
    exit 1
fi

RPM_FILENAME="$(basename "${BUILT_RPM}")"
cp "${BUILT_RPM}" "${DIST_DIR}/${RPM_FILENAME}"

echo "[4/4] Package generated successfully:"
echo "      => ${DIST_DIR}/${RPM_FILENAME} ($(du -h "${DIST_DIR}/${RPM_FILENAME}" | cut -f1))"
echo ""
echo "RPM Package Information:"
rpm -D "_dbpath ${BUILD_DIR}/rpmdb" -qip "${DIST_DIR}/${RPM_FILENAME}"
echo ""
echo "RPM Package Contents:"
rpm -D "_dbpath ${BUILD_DIR}/rpmdb" -qlp "${DIST_DIR}/${RPM_FILENAME}"

echo ""
echo "[✓] VoidVault RPM build complete!"
