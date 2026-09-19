#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

store="$PWD/docker/release.keystore"
properties="$PWD/docker/release.properties"
if [[ -e "$store" || -e "$properties" ]]; then
  printf '%s\n' 'A release signing identity already exists. Refusing to overwrite it.' >&2
  exit 2
fi

mkdir -p docker
password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
alias=racg-release

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/docker:/keystore" \
  eclipse-temurin:17-jdk-jammy \
  keytool -genkeypair -v \
  -keystore /keystore/release.keystore \
  -storetype PKCS12 \
  -storepass "$password" \
  -keypass "$password" \
  -alias "$alias" \
  -keyalg RSA -keysize 4096 -validity 10950 \
  -dname 'CN=RACG Approver,O=RACG,C=US'

umask 077
cat > "$properties" <<EOF
RACG_RELEASE_STORE_PASSWORD=$password
RACG_RELEASE_KEY_ALIAS=$alias
RACG_RELEASE_KEY_PASSWORD=$password
EOF
chmod 600 "$store" "$properties"
printf 'Release signing identity created in docker/release.keystore.\n'
