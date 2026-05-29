#!/usr/bin/env bash
set -euo pipefail

GLIBC_BASELINE="${GLIBC_BASELINE:-2.28}"
TARGET_ARCH="${TARGET_ARCH:-}"
YARA_BASELINE_NAME="${YARA_BASELINE_NAME:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YARA_SRC="$ROOT/third_party/yara-x-src"

detect_host_arch() {
  local raw
  raw="$(uname -m 2>/dev/null || true)"
  case "$raw" in
    x86_64|amd64)
      echo "amd64"
      ;;
    aarch64|arm64)
      echo "arm64"
      ;;
    *)
      echo ""
      ;;
  esac
}

HOST_ARCH="$(detect_host_arch)"
if [[ -z "$TARGET_ARCH" ]]; then
  TARGET_ARCH="$HOST_ARCH"
fi

case "$TARGET_ARCH" in
  amd64|arm64)
    ;;
  *)
    echo "unsupported target architecture: $TARGET_ARCH" >&2
    echo "Supported target architectures: amd64, arm64" >&2
    exit 1
    ;;
esac

if [[ -z "$YARA_BASELINE_NAME" ]]; then
  YARA_BASELINE_NAME="yara-x-dist-linux-glibc-${GLIBC_BASELINE}-${TARGET_ARCH}"
fi

YARA_OUT="$ROOT/third_party/$YARA_BASELINE_NAME"
METADATA_FILE="$YARA_OUT/.linux-glibc-baseline"

detect_glibc_version() {
  local raw
  raw="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  if [[ -n "$raw" ]]; then
    echo "$raw" | awk '{print $2}'
    return
  fi

  raw="$(ldd --version 2>/dev/null | head -n 1 || true)"
  if [[ -n "$raw" ]]; then
    echo "$raw" | grep -oE '[0-9]+\.[0-9]+' | head -n 1
    return
  fi

  echo ""
}

current_glibc="$(detect_glibc_version)"
if [[ -z "$current_glibc" ]]; then
  echo "unable to detect current glibc version" >&2
  exit 1
fi

if [[ "$current_glibc" != "$GLIBC_BASELINE" ]]; then
  echo "refusing to rebuild baseline Linux YARA-X artifacts outside glibc $GLIBC_BASELINE (detected $current_glibc)" >&2
  exit 1
fi

if [[ ! -d "$YARA_SRC" ]]; then
  echo "yara-x-src not found: $YARA_SRC" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to rebuild baseline Linux YARA-X artifacts" >&2
  exit 1
fi

if ! cargo cinstall -h >/dev/null 2>&1; then
  echo "cargo-c is required. Install with: cargo install cargo-c" >&2
  exit 1
fi

rm -rf "$YARA_OUT"
mkdir -p "$YARA_OUT"
(cd "$YARA_SRC" && cargo cinstall -p yara-x-capi --release --prefix "$YARA_OUT")
printf '%s\n' "$GLIBC_BASELINE" > "$METADATA_FILE"

echo "Rebuilt baseline Linux YARA-X artifacts at: $YARA_OUT"
