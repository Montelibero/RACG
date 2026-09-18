#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
OUT="${1:-$PWD/dist}"
mkdir -p "$OUT"
docker build --target apk-export --output type=local,dest="$OUT" .
printf 'Debug APK: %s/racg-approver-debug.apk\n' "$OUT"
printf 'Release APK: %s/racg-approver-release-unsigned.apk\n' "$OUT"
