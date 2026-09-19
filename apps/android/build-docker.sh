#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
OUT="${1:-$PWD/dist}"
mkdir -p "$OUT"
SOURCE_REVISION=$(git rev-parse HEAD 2>/dev/null || date +%s)
docker build --build-arg SOURCE_REVISION="$SOURCE_REVISION" --target apk-export --output type=local,dest="$OUT" .
printf 'Debug APK: %s/racg-approver-debug.apk\n' "$OUT"
printf 'Release APK: %s/racg-approver-release-unsigned.apk\n' "$OUT"
