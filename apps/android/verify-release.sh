#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

apk="${1:-dist/racg-approver-release.apk}"
[[ -f "$apk" ]] || { printf 'APK not found: %s\n' "$apk" >&2; exit 2; }

docker build --target android-sdk -t racg-android-verify:local .
docker run --rm -v "$PWD:/workspace" -w /workspace --entrypoint /opt/android-sdk/build-tools/35.0.0/apksigner \
  racg-android-verify:local verify --verbose "$apk"

checksums="$(dirname "$apk")/SHA256SUMS"
if [[ -f "$checksums" ]]; then
  (cd "$(dirname "$apk")" && grep " $(basename "$apk")$" SHA256SUMS | sha256sum -c -)
fi
