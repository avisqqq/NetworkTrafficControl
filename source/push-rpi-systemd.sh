#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[x] failed at line $LINENO"; exit 1' ERR

TARGET="${1:-rpi-build}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [ -f deploy.env ]; then
    set -a
    source deploy.env
    set +a
fi

RPI_HOST="${RPI_HOST:-192.168.0.143}"
RPI_USER="${RPI_USER:-admin}"
RPI_DIR="${RPI_DIR:-/home/${RPI_USER}/ntc-source}"
RPI_SRC_DIR="${RPI_SRC_DIR:-${RPI_DIR}/src}"
NTC_BIN="${NTC_BIN:-ntc_source_bin}"
NTC_PORT="${NTC_PORT:-8086}"
RPI_SSH="${RPI_USER}@${RPI_HOST}"
SSH_CONTROL_PATH="${SSH_CONTROL_PATH:-$REPO_ROOT/.ntc-ssh-${RPI_HOST}}"
SSH_OPTS=(
    -o ControlMaster=auto
    -o ControlPersist=10m
    -o ControlPath="$SSH_CONTROL_PATH"
)
RSYNC_RSH="ssh ${SSH_OPTS[*]}"

cleanup_ssh() {
    ssh -O exit "${SSH_OPTS[@]}" "$RPI_SSH" >/dev/null 2>&1 || true
}

echo "[*] Target: $TARGET"

if [ "$TARGET" = "rpi-build" ]; then
    echo "[*] Building frontend..."
    (cd web && npm run build)
    if [ ! -d dist ]; then
        echo "[x] frontend build did not create dist/"
        exit 1
    fi

    echo "[*] Copying sources to RPi..."
    trap cleanup_ssh EXIT
    ssh "${SSH_OPTS[@]}" "$RPI_SSH" "mkdir -p ${RPI_SRC_DIR} ${RPI_DIR}"
    rsync -az --delete \
        -e "$RSYNC_RSH" \
        --exclude='node_modules/' \
        --exclude='web/node_modules/' \
        --exclude='.git/' \
        --exclude='execute/' \
        --exclude='main' \
        --exclude='ntc_bin' \
        --exclude='ntc_source_bin' \
        --exclude='*.log' \
        --exclude='.DS_Store' \
        . "$RPI_SSH:${RPI_SRC_DIR}/"

    printf "sudo password for %s: " "$RPI_SSH"
    read -rs RPI_SUDO_PASS
    printf "\n"
    RPI_SUDO_PASS_B64="$(printf '%s' "$RPI_SUDO_PASS" | base64 | tr -d '\n')"

    echo "[*] Building and starting source app on RPi..."
    ssh "${SSH_OPTS[@]}" "$RPI_SSH" \
        "RPI_DIR='$RPI_DIR' RPI_SRC_DIR='$RPI_SRC_DIR' NTC_PORT='$NTC_PORT' SUDO_PASS_B64='$RPI_SUDO_PASS_B64' bash -s" <<'REMOTE'
set -euo pipefail
SUDO_PASS="$(printf '%s' "$SUDO_PASS_B64" | base64 -d)"

sudo_do() {
    printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"
}

GO_BIN="$(command -v go || true)"
if [ -z "$GO_BIN" ] && [ -x /usr/local/go/bin/go ]; then
    GO_BIN=/usr/local/go/bin/go
fi
if [ -z "$GO_BIN" ]; then
    echo "[x] go not found on RPi" >&2
    exit 1
fi

echo "[*] compiling eBPF"
cd "$RPI_SRC_DIR/source/infrastructure/packet/c"
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
  -I/usr/include/aarch64-linux-gnu \
  -c tc_filter.bpf.c -o "$RPI_DIR/tc_filter.bpf.o"

echo "[*] compiling Go"
cd "$RPI_SRC_DIR"
"$GO_BIN" build -o "$RPI_DIR/ntc" ./source
chmod +x "$RPI_DIR/ntc"
rm -rf "$RPI_DIR/dist"
cp -r "$RPI_SRC_DIR/dist" "$RPI_DIR/dist"
if [ -f "$RPI_SRC_DIR/config.yaml" ]; then
    cp "$RPI_SRC_DIR/config.yaml" "$RPI_DIR/config.yaml"
fi

echo "[*] installing and restarting service"
sudo_do true
SERVICE_FILE="$(mktemp)"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Network Traffic Control Source Refactor
After=network.target

[Service]
Type=simple
WorkingDirectory=$RPI_DIR
ExecStart=$RPI_DIR/ntc
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo_do cp "$SERVICE_FILE" /etc/systemd/system/ntc-source.service
rm -f "$SERVICE_FILE"
sudo_do systemctl daemon-reload
sudo_do systemctl enable ntc-source
sudo_do systemctl restart ntc-source
sleep 2

if ! sudo_do systemctl is-active --quiet ntc-source; then
    echo "[x] ntc-source service failed" >&2
    sudo_do systemctl --no-pager --full status ntc-source >&2 || true
    sudo_do journalctl -u ntc-source -n 80 --no-pager >&2 || true
    exit 1
fi

curl -fsS "http://127.0.0.1:${NTC_PORT}/blacklist" >/dev/null
echo "[ok] running on :${NTC_PORT}"
REMOTE
    unset RPI_SUDO_PASS RPI_SUDO_PASS_B64

    echo "[ok] Done - running at http://${RPI_HOST}:${NTC_PORT}"
    echo ""
    echo "Logs: ssh $RPI_SSH 'tail -f ${RPI_DIR}/ntc.log'"
    exit 0
elif [ "$TARGET" = "rpi" ]; then
    GOARCH=arm64
    BPF_ARCH=arm64
    DEST="${RPI_USER}@${RPI_HOST}:${RPI_DIR}/"
elif [ "$TARGET" = "local" ]; then
    if [ "$(uname -s)" != "Linux" ]; then
        echo "[x] local eBPF build requires Linux headers; use: $0 rpi-build"
        exit 1
    fi
    GOARCH=amd64
    BPF_ARCH=x86
    DEST="./execute/source/"
else
    echo "Unknown target: $TARGET"
    echo "Usage: source/push-rpi-systemd.sh [rpi-build|local|rpi]"
    exit 1
fi

cleanup() {
    rm -f "$NTC_BIN"
}
trap cleanup EXIT

echo "[*] Compiling source eBPF..."
cd source/infrastructure/packet/c
clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} \
  -c tc_filter.bpf.c -o tc_filter.bpf.o
cd "$REPO_ROOT"

echo "[*] Compiling source Go..."
GOOS=linux GOARCH=$GOARCH go build -o "$NTC_BIN" ./source

echo "[*] Building frontend..."
(cd web && npm run build)
if [ ! -d dist ]; then
    echo "[x] frontend build did not create dist/"
    exit 1
fi

echo "[*] Copying artifacts..."
if [ "$TARGET" = "rpi" ]; then
    ssh "${RPI_USER}@${RPI_HOST}" "mkdir -p ${RPI_DIR}"
    scp source/infrastructure/packet/c/tc_filter.bpf.o "$NTC_BIN" config.yaml "$DEST"
    rsync -az --delete dist/ "${RPI_USER}@${RPI_HOST}:${RPI_DIR}/dist/"
    ssh "${RPI_USER}@${RPI_HOST}" "mv ${RPI_DIR}/${NTC_BIN} ${RPI_DIR}/ntc && chmod +x ${RPI_DIR}/ntc"
else
    mkdir -p execute/source
    rm -rf execute/source/*
    cp source/infrastructure/packet/c/tc_filter.bpf.o execute/source/
    cp "$NTC_BIN" execute/source/ntc
    cp config.yaml execute/source/
    cp -r dist execute/source/
fi

echo "[ok] Done - deployed to $DEST"
echo ""
if [ "$TARGET" = "rpi" ]; then
    echo "Run: ssh ${RPI_USER}@${RPI_HOST} 'cd ${RPI_DIR} && sudo ./ntc'"
else
    echo "Run: cd execute/source && sudo ./ntc"
fi
