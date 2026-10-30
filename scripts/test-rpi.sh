#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[✗] Failed at line $LINENO"; exit 1' ERR

# Run root-only Go tests on the RPi.
# Usage: ./scripts/test-rpi.sh [package] [test flags...]
#   ./scripts/test-rpi.sh
#   ./scripts/test-rpi.sh ./source/infrastructure/firewall -test.run TestSetupAndTeardown

# Always run from repo root
cd "$(dirname "$0")/.."

if [ -f deploy.env ]; then
    set -a
    source deploy.env
    set +a
fi

RPI_HOST="${RPI_HOST:-rpi.local}"
RPI_USER="${RPI_USER:-rpi}"

PACKAGE="${1:-./source/infrastructure/firewall}"
TEST_FLAGS="${*:2}"
LOCAL_BINARY="/tmp/ntc-rpi.test"
REMOTE_BINARY="/tmp/ntc-rpi.test"

echo "[*] Building test binary for ${PACKAGE} (linux/arm64)..."
GOOS=linux GOARCH=arm64 go test -c -o "$LOCAL_BINARY" "$PACKAGE"

echo "[*] Copying test binary to ${RPI_USER}@${RPI_HOST}..."
scp -q "$LOCAL_BINARY" "${RPI_USER}@${RPI_HOST}:${REMOTE_BINARY}"

echo "[*] Running tests on RPi as root..."
if ssh -t "${RPI_USER}@${RPI_HOST}" "sudo ${REMOTE_BINARY} -test.v ${TEST_FLAGS}; status=\$?; rm -f ${REMOTE_BINARY}; exit \$status"; then
    echo "[✓] Tests passed"
else
    echo "[✗] Tests failed"
    exit 1
fi
