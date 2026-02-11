#!/usr/bin/env bash
set -euo pipefail

REPO="${RACG_REPO:-Montelibero/RACG}"
VERSION="${RACG_VERSION:-latest}"
PREFIX="${RACG_PREFIX:-/usr/local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "${arch}" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: ${arch}" >&2
    exit 1
    ;;
esac

if [[ "${os}" != "linux" ]]; then
  echo "Unsupported OS: ${os}. This installer currently supports linux only." >&2
  exit 1
fi

if [[ "${VERSION}" == "latest" ]]; then
  tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [[ -z "${tag}" ]]; then
    echo "Failed to resolve latest release tag for ${REPO}" >&2
    exit 1
  fi
else
  tag="${VERSION}"
  if [[ "${tag}" != v* ]]; then
    tag="v${tag}"
  fi
fi

version_no_v="${tag#v}"
asset="racg_${version_no_v}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${tag}/${asset}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

curl -fL "${url}" -o "${tmp_dir}/${asset}"
tar -xzf "${tmp_dir}/${asset}" -C "${tmp_dir}"

if [[ ! -f "${tmp_dir}/racg" ]]; then
  echo "Archive does not contain racg binary" >&2
  exit 1
fi

if [[ -w "${PREFIX}" ]]; then
  install -m 0755 "${tmp_dir}/racg" "${PREFIX}/racg"
else
  sudo install -m 0755 "${tmp_dir}/racg" "${PREFIX}/racg"
fi

echo "Installed racg to ${PREFIX}/racg"
"${PREFIX}/racg" --version
