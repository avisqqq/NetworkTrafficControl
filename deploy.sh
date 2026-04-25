#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[✗] Failed at line $LINENO"; exit 1' ERR

TARGET="${1:-local}"

cd "$(dirname "$0")"

echo "[*] Target: $TARGET"

if [ "$TARGET" = "rpi" ]; then
    GOARCH=arm64
    BPF_ARCH=arm64
    DEST="admin@192.168.0.143:/home/admin/execute/"
elif [ "$TARGET" = "local" ]; then
    GOARCH=amd64
    BPF_ARCH=x86
    DEST="./execute/"
else
    echo "Unknown target: $TARGET"
    exit 1
fi

# --- Compile eBPF ---
echo "[*] Compiling eBPF..."
cd eBPF
clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} \
  -c xdp_ring.bpf.c -o xdp_ring.bpf.o
cd ..

# --- Compile Go ---
echo "[*] Compiling Go..."
cd client
GOOS=linux GOARCH=$GOARCH go build -o ntc ./ntc
cd ..

# --- Prepare local execute dir ---
if [ "$TARGET" = "local" ]; then
    mkdir -p execute
    rm -rf execute/*
fi

# --- Copy ---
echo "[*] Copying artifacts..."

if [ "$TARGET" = "rpi" ]; then
    scp -r client/web eBPF/xdp_ring.bpf.o client/ntc/ntc "$DEST"
else
    cp -r client/web "$DEST"
    cp eBPF/xdp_ring.bpf.o "$DEST"
    cp client/ntc/ntc "$DEST"
fi

echo "[✓] Done"
