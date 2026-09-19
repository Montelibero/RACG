#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
OUT="${1:-$PWD/dist}"
mkdir -p "$OUT"
rm -f \
  "$OUT/racg-approver-debug.apk" \
  "$OUT/racg-approver-release.apk" \
  "$OUT/racg-approver-release-unsigned.apk"
SOURCE_REVISION=$(git rev-parse HEAD 2>/dev/null || date +%s)
secret_args=()
if [[ -f docker/release.keystore || -f docker/release.properties ]]; then
  [[ -f docker/release.keystore && -f docker/release.properties ]] || {
    printf '%s\n' 'Release signing is incomplete: docker/release.keystore and docker/release.properties are both required.' >&2
    exit 2
  }
  chmod 600 docker/release.keystore docker/release.properties
  secret_args=(
    --secret id=racg_release_keystore,src="$PWD/docker/release.keystore"
    --secret id=racg_release_properties,src="$PWD/docker/release.properties"
  )
fi
docker build \
  --build-arg SOURCE_REVISION="$SOURCE_REVISION" \
  "${secret_args[@]+"${secret_args[@]}"}" \
  --target apk-export \
  --output type=local,dest="$OUT" \
  .
printf 'Debug APK: %s/racg-approver-debug.apk\n' "$OUT"
for apk in racg-approver-release.apk racg-approver-release-unsigned.apk; do
  if [[ -f "$OUT/$apk" ]]; then
    printf 'Release APK: %s/%s\n' "$OUT" "$apk"
  fi
done
