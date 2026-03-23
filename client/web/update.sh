#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[✗] Failed at line $LINENO"; exit 1' ERR

cd "$(dirname "$0")"

cd ..
cd ..


echo "[*] Copying to RPi WebAPP..."
scp -r client/web admin@192.168.0.143:/home/admin/execute/

echo "[✓] Deploy successful"
