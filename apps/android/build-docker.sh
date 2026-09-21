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
# Version name: release tag in CI, git describe for local builds. The APK
# versionCode is derived from the version name inside app/build.gradle.kts.
VERSION_TAG="${RACG_VERSION_TAG:-$(git describe --tags 2>/dev/null || true)}"
VERSION_NAME="${VERSION_TAG#v}"
[[ -n "${VERSION_NAME}" ]] || VERSION_NAME="0.0.0-local"
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
  --build-arg ANDROID_VERSION_NAME="$VERSION_NAME" \
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
(
  cd "$OUT"
  artifacts=()
  [[ -f racg-approver-debug.apk ]] && artifacts+=(racg-approver-debug.apk)
  [[ -f racg-approver-release.apk ]] && artifacts+=(racg-approver-release.apk)
  [[ -f racg-approver-release-unsigned.apk ]] && artifacts+=(racg-approver-release-unsigned.apk)
  if ((${#artifacts[@]})); then
    sha256sum "${artifacts[@]}" > SHA256SUMS
    printf 'Checksums: %s/SHA256SUMS\n' "$OUT"
  fi
)
