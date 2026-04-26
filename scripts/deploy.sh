#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[✗] Failed at line $LINENO"; exit 1' ERR

TARGET="${1:-local}"

# Always run from repo root
cd "$(dirname "$0")/.."

if [ -f deploy.env ]; then
    set -a
    source deploy.env
    set +a
fi

echo "[*] Target: $TARGET"

RPI_HOST="${RPI_HOST:-rpi.local}"
RPI_USER="${RPI_USER:-rpi}"
RPI_DIR="${RPI_DIR:-/home/${RPI_USER}/ntc}"
NTC_PORT="${NTC_PORT:-8086}"

if [ "$TARGET" = "rpi" ]; then
    GOARCH=arm64
    BPF_ARCH=arm64
    DEST="${RPI_USER}@${RPI_HOST}:${RPI_DIR}/"
elif [ "$TARGET" = "rpi-install-dependencies" ]; then
    :
elif [ "$TARGET" = "rpi-install-service" ]; then
    :
elif [ "$TARGET" = "rpi-install-stack" ]; then
    :
elif [ "$TARGET" = "rpi-build" ]; then
    :
elif [ "$TARGET" = "local" ]; then
    GOARCH=amd64
    BPF_ARCH=x86
    DEST="./execute/"
else
    echo "Unknown target: $TARGET"
    exit 1
fi

# ── rpi-install-dependencies ──────────────────────────────────────────────────
if [ "$TARGET" = "rpi-install-dependencies" ]; then
    echo "[*] Installing dependencies on RPi..."
    ssh -t "${RPI_USER}@${RPI_HOST}" "
        set -e
        sudo apt-get update -qq

        echo '[*] Installing clang, llvm, linux headers...'
        sudo apt-get install -y clang llvm linux-headers-\$(uname -r) libbpf-dev libc6-dev

        echo '[*] Installing Go...'
        if [ ! -x /usr/local/go/bin/go ]; then
            GO_VERSION=1.23.4
            curl -fsSL https://go.dev/dl/go\${GO_VERSION}.linux-arm64.tar.gz -o /tmp/go.tar.gz
            sudo tar -C /usr/local -xzf /tmp/go.tar.gz
            rm /tmp/go.tar.gz
            echo 'export PATH=\$PATH:/usr/local/go/bin' >> ~/.profile
            echo 'export PATH=\$PATH:/usr/local/go/bin' >> ~/.bashrc
        else
            echo 'Go already installed: '\$(/usr/local/go/bin/go version)
        fi

        echo '[*] Installing Docker...'
        if ! command -v docker &>/dev/null; then
            curl -fsSL https://get.docker.com | sudo sh
            sudo usermod -aG docker \$USER
            sudo systemctl enable docker
            sudo systemctl start docker
        else
            echo 'Docker already installed: '\$(docker --version)
        fi
    "
    echo "[✓] Done — reconnect SSH or run: source ~/.profile"
    exit 0
fi

# ── rpi-install-service ───────────────────────────────────────────────────────
if [ "$TARGET" = "rpi-install-service" ]; then
    echo "[*] Installing ntc systemd service on RPi..."
    ssh -t "${RPI_USER}@${RPI_HOST}" "sudo tee /etc/systemd/system/ntc.service > /dev/null << 'EOF'
[Unit]
Description=Network Traffic Control
After=network.target

[Service]
Type=simple
WorkingDirectory=${RPI_DIR}
ExecStart=${RPI_DIR}/ntc
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable ntc
    sudo systemctl restart ntc
    "
    echo "[✓] NTC service installed"
    echo ""
    echo "    sudo systemctl start ntc"
    echo "    sudo systemctl stop ntc"
    echo "    sudo systemctl restart ntc"
    echo "    sudo journalctl -u ntc -f"
    exit 0
fi

# ── rpi-install-stack ─────────────────────────────────────────────────────────
if [ "$TARGET" = "rpi-install-stack" ]; then
    echo "[*] Copying monitoring stack to RPi..."
    ssh "${RPI_USER}@${RPI_HOST}" "mkdir -p ${RPI_DIR}/monitoring"
    rsync -az monitoring/ "${RPI_USER}@${RPI_HOST}:${RPI_DIR}/monitoring/"

    echo "[*] Generating scrape config for RPi (localhost:${NTC_PORT})..."
    cat > /tmp/ntc-scrape.yaml << EOF
global:
  scrape_interval: 10s

scrape_configs:
  - job_name: ntc
    static_configs:
      - targets:
          - host.docker.internal:${NTC_PORT}
    metrics_path: /metrics
EOF
    scp /tmp/ntc-scrape.yaml "${RPI_USER}@${RPI_HOST}:${RPI_DIR}/monitoring/victoria/scrape.yaml"
    rm /tmp/ntc-scrape.yaml

    echo "[*] Starting monitoring stack on RPi..."
    ssh -t "${RPI_USER}@${RPI_HOST}" "
        cd ${RPI_DIR}/monitoring
        docker compose pull
        docker compose up -d
        docker compose ps
    "
    echo "[✓] Stack started"
    echo ""
    echo "    Grafana:         http://${RPI_HOST}:3000  (admin / admin)"
    echo "    VictoriaMetrics: http://${RPI_HOST}:8428"
    exit 0
fi

# ── rpi-build ─────────────────────────────────────────────────────────────────
if [ "$TARGET" = "rpi-build" ]; then
    echo "[*] Building frontend (Svelte)..."
    cd web && npm run build && cd ..

    echo "[*] Copying sources to RPi..."
    ssh "${RPI_USER}@${RPI_HOST}" "mkdir -p ${RPI_DIR}/src"
    rsync -az --delete \
        --exclude='node_modules/' \
        --exclude='.git/' \
        --exclude='execute/' \
        . "${RPI_USER}@${RPI_HOST}:${RPI_DIR}/src/"

    echo "[*] Building eBPF on RPi..."
    ssh "${RPI_USER}@${RPI_HOST}" "
        cd ${RPI_DIR}/src/internal/bpf/c &&
        clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
          -I/usr/include/aarch64-linux-gnu \
          -c tc_filter.bpf.c -o tc_filter.bpf.o
    "

    echo "[*] Building Go on RPi..."
    ssh "${RPI_USER}@${RPI_HOST}" "
        cd ${RPI_DIR}/src &&
        /usr/local/go/bin/go build -o ${RPI_DIR}/ntc ./cmd/ntc &&
        chmod +x ${RPI_DIR}/ntc &&
        cp ${RPI_DIR}/src/internal/bpf/c/tc_filter.bpf.o ${RPI_DIR}/tc_filter.bpf.o &&
        rm -rf ${RPI_DIR}/dist &&
        cp -r ${RPI_DIR}/src/dist ${RPI_DIR}/dist
    "

    echo "[✓] Done"
    echo ""
    echo "    Run: ssh ${RPI_USER}@${RPI_HOST} 'cd ${RPI_DIR} && sudo ./ntc'"
    exit 0
fi

# ── local / rpi (cross-compile) ───────────────────────────────────────────────

echo "[*] Building frontend (Svelte)..."
cd web && npm run build && cd ..

echo "[*] Compiling eBPF..."
cd internal/bpf/c
clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} \
  -c tc_filter.bpf.c -o tc_filter.bpf.o
cd ../../..

echo "[*] Compiling Go..."
GOOS=linux GOARCH=$GOARCH go build -o ntc_bin ./cmd/ntc

if [ "$TARGET" = "local" ]; then
    mkdir -p execute
    rm -rf execute/*
fi

echo "[*] Copying artifacts..."

if [ "$TARGET" = "rpi" ]; then
    ssh "${RPI_USER}@${RPI_HOST}" "mkdir -p ${RPI_DIR}"
    scp -r dist internal/bpf/c/tc_filter.bpf.o ntc_bin config.yaml "$DEST"
    ssh "${RPI_USER}@${RPI_HOST}" "mv ${RPI_DIR}/ntc_bin ${RPI_DIR}/ntc && chmod +x ${RPI_DIR}/ntc"
else
    cp -r dist execute/
    cp internal/bpf/c/tc_filter.bpf.o execute/
    cp ntc_bin execute/ntc
    cp config.yaml execute/
fi

rm -f ntc_bin

echo "[✓] Done — deployed to $DEST"
echo ""
if [ "$TARGET" = "rpi" ]; then
    echo "    Run: ssh ${RPI_USER}@${RPI_HOST} 'sudo ${RPI_DIR}/ntc'"
else
    echo "    Run: ./execute/ntc"
fi