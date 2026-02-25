#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[✗] Failed at line $LINENO"; exit 1' ERR

cd "$(dirname "$0")"

echo "[*] Compiling eBPF..."
cd eBPF
sh compile.log
cd ..

echo "[*] Compiling Go..."
cd client
sh compile.log
cd ..

echo "[*] Copying to RPi..."
scp -r client/web eBPF/xdp_ring.bpf.o client/ringdemo admin@rpi.local:/home/admin/execute/
echo "[✓] Deploy successful"
