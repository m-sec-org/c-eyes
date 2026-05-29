#!/usr/bin/env bash
set -euo pipefail

PLATFORM="linux"
ARCH="${TARGET_ARCH:-}"
GLIBC_BASELINE="${GLIBC_BASELINE:-2.28}"
FORCE=0
DISABLE_LOCAL_BUNDLE="${DISABLE_LOCAL_BUNDLE:-0}"
THIRD_PARTY_PROXY="${THIRD_PARTY_PROXY:-${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}}}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "$ARCH" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) ARCH="" ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      PLATFORM="${2:-}"
      shift 2
      ;;
    --arch)
      ARCH="${2:-}"
      shift 2
      ;;
    --glibc-baseline)
      GLIBC_BASELINE="${2:-}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "$PLATFORM" != "linux" ]]; then
  echo "ensure-third-party.sh currently supports only --platform linux" >&2
  exit 2
fi

if [[ "$ARCH" != "amd64" && "$ARCH" != "arm64" ]]; then
  echo "unsupported arch: $ARCH (expected amd64 or arm64)" >&2
  exit 2
fi

is_wsl() {
  grep -qi "microsoft" /proc/version 2>/dev/null
}

download_with_powershell_proxy() {
  local url="$1"
  local out="$2"
  local proxy="$3"

  if ! is_wsl; then
    return 1
  fi
  if ! command -v powershell.exe >/dev/null 2>&1; then
    return 1
  fi
  if ! command -v wslpath >/dev/null 2>&1; then
    return 1
  fi

  local out_win
  out_win="$(wslpath -w "$out")"
  powershell.exe -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '$url' -OutFile '$out_win' -Proxy '$proxy' -ProxyUseDefaultCredentials:\$false" >/dev/null
}

TARGET_BASE="$ROOT/third_party/yara-x-dist-linux-glibc-${GLIBC_BASELINE}-${ARCH}"
TARGET_LIB="$TARGET_BASE/lib64/libyara_x_capi.so"
if [[ "$FORCE" != "1" && -f "$TARGET_LIB" && -d "$TARGET_BASE/include" ]]; then
  echo "third_party already present: $TARGET_BASE"
  exit 0
fi

resolve_repo() {
  if [[ -n "${THIRD_PARTY_REPO:-}" ]]; then
    echo "$THIRD_PARTY_REPO"
    return
  fi
  local rf repo
  rf="$ROOT/third_party/repo.txt"
  if [[ -f "$rf" ]]; then
    repo="$(grep -Ev '^\s*($|#)' "$rf" | head -n 1 || true)"
    repo="$(echo "$repo" | tr -d '[:space:]')"
    if [[ "$repo" == */* ]]; then
      echo "$repo"
      return
    fi
  fi
  if command -v git >/dev/null 2>&1; then
    local remote
    remote="$(git -C "$ROOT" config --get remote.origin.url 2>/dev/null || true)"
    repo="$(echo "$remote" | sed -E 's#^git@github.com:##; s#^https://github.com/##; s#\.git$##')"
    if [[ "$repo" == */* ]]; then
      echo "$repo"
      return
    fi
  fi
  echo ""
}

resolve_tag() {
  if [[ -n "${THIRD_PARTY_TAG:-}" ]]; then
    echo "$THIRD_PARTY_TAG"
    return
  fi
  local vf tag
  vf="$ROOT/third_party/version.txt"
  if [[ -f "$vf" ]]; then
    tag="$(grep -Ev '^\s*($|#)' "$vf" | head -n 1 || true)"
    tag="$(echo "$tag" | tr -d '[:space:]')"
    if [[ -n "$tag" ]]; then
      echo "$tag"
      return
    fi
  fi
  if command -v git >/dev/null 2>&1; then
    tag="$(git -C "$ROOT" describe --tags --exact-match 2>/dev/null || true)"
    if [[ -n "$tag" ]]; then
      echo "$tag"
      return
    fi
  fi
  echo ""
}

ASSET="third_party-linux-glibc-${GLIBC_BASELINE}-${ARCH}.tar.gz"
SUMS="SHA256SUMS.txt"
RELEASE_BUNDLE_ASSET="c-eyes-third-party.zip"

download() {
  local url="$1"
  local out="$2"
  if [[ -n "$THIRD_PARTY_PROXY" ]]; then
    if curl -fL --retry 5 --retry-delay 3 --retry-all-errors --proxy "$THIRD_PARTY_PROXY" -o "$out" "$url"; then
      return 0
    fi
    if download_with_powershell_proxy "$url" "$out" "$THIRD_PARTY_PROXY"; then
      return 0
    fi
    return 1
  fi
  curl -fL --retry 5 --retry-delay 3 --retry-all-errors -o "$out" "$url"
}

restore_from_archive() {
  local archive_path="$1"
  local sums_path="$2"
  local extract_root="$3"
  local source_label="$4"

  if [[ ! -f "$archive_path" ]]; then
    echo "$source_label missing asset: $archive_path" >&2
    return 1
  fi
  if [[ ! -f "$sums_path" ]]; then
    echo "$source_label missing SHA256SUMS.txt: $sums_path" >&2
    return 1
  fi

  local expected_hash actual_hash extract_dir payload_root src_base
  expected_hash="$(tr -d '\r' < "$sums_path" | grep -E "[[:space:]]\\*?$ASSET$" | head -n 1 | awk '{print $1}' || true)"
  actual_hash="$(sha256sum "$archive_path" | awk '{print $1}')"
  if [[ -z "$expected_hash" || "$expected_hash" != "$actual_hash" ]]; then
    echo "$source_label checksum verification failed for $ASSET (expected=$expected_hash actual=$actual_hash)" >&2
    return 1
  fi

  extract_dir="$extract_root/extract-$ASSET"
  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  tar -xzf "$archive_path" -C "$extract_dir"

  payload_root="$extract_dir"
  if [[ -d "$extract_dir/third_party" ]]; then
    payload_root="$extract_dir/third_party"
  fi

  src_base="$payload_root/yara-x-dist-linux-glibc-${GLIBC_BASELINE}-${ARCH}"
  if [[ ! -d "$src_base" ]]; then
    echo "$source_label archive does not contain expected directory: yara-x-dist-linux-glibc-${GLIBC_BASELINE}-${ARCH}" >&2
    return 1
  fi

  mkdir -p "$ROOT/third_party"
  rm -rf "$TARGET_BASE"
  cp -a "$src_base" "$TARGET_BASE"

  if [[ ! -f "$TARGET_LIB" ]]; then
    echo "$source_label restored third_party is incomplete: missing $TARGET_LIB" >&2
    return 1
  fi

  return 0
}

restore_from_release_bundle_archive() {
  local bundle_archive="$1"
  local extract_root="$2"
  local source_label="$3"

  local bundle_extract_dir bundle_root local_archive local_sums
  bundle_extract_dir="$extract_root/extract-release-bundle"
  rm -rf "$bundle_extract_dir"
  mkdir -p "$bundle_extract_dir"

  if command -v unzip >/dev/null 2>&1; then
    unzip -qo "$bundle_archive" -d "$bundle_extract_dir"
  elif command -v bsdtar >/dev/null 2>&1; then
    bsdtar -xf "$bundle_archive" -C "$bundle_extract_dir"
  else
    echo "unable to extract $RELEASE_BUNDLE_ASSET: unzip (or bsdtar) is required" >&2
    return 1
  fi

  if [[ -d "$bundle_extract_dir/c-eyes-third-party/release-bundles" ]]; then
    bundle_root="$bundle_extract_dir/c-eyes-third-party/release-bundles"
  elif [[ -d "$bundle_extract_dir/c-eyes-third-party" ]]; then
    bundle_root="$bundle_extract_dir/c-eyes-third-party"
  else
    bundle_root="$bundle_extract_dir"
  fi

  local_archive="$bundle_root/$ASSET"
  local_sums="$bundle_root/$SUMS"
  restore_from_archive "$local_archive" "$local_sums" "$bundle_root" "$source_label"
}

LOCAL_ERRORS=()
LOCAL_CANDIDATES=(
  "$ROOT/c-eyes-third-party"
  "$(cd "$ROOT/.." && pwd)/c-eyes-third-party"
  "$(cd "$ROOT/.." && pwd)/release-assets/c-eyes-third-party"
  "$(pwd)/c-eyes-third-party"
)

if [[ "$DISABLE_LOCAL_BUNDLE" != "1" ]]; then
  for candidate in "${LOCAL_CANDIDATES[@]}"; do
    [[ -d "$candidate" ]] || continue
    bundle_root="$candidate"
    if [[ -d "$candidate/release-bundles" ]]; then
      bundle_root="$candidate/release-bundles"
    fi
    local_archive="$bundle_root/$ASSET"
    local_sums="$bundle_root/$SUMS"
    if [[ ! -f "$local_archive" || ! -f "$local_sums" ]]; then
      LOCAL_ERRORS+=("$candidate found but required files are missing ($ASSET and $SUMS)")
      continue
    fi
    if restore_from_archive "$local_archive" "$local_sums" "$bundle_root" "local bundle $candidate"; then
      echo "third_party ready from local bundle: $candidate"
      exit 0
    fi
    LOCAL_ERRORS+=("local bundle verification failed: $candidate")
  done
fi

if [[ -n "${THIRD_PARTY_CACHE_DIR:-}" ]]; then
  CACHE_ROOT="$THIRD_PARTY_CACHE_DIR"
elif [[ -d "/mnt/d/tmp" ]]; then
  CACHE_ROOT="/mnt/d/tmp/c-eyes-cache"
else
  CACHE_ROOT="$ROOT/tmp/third-party-cache"
fi

REPO="$(resolve_repo)"
TAG="$(resolve_tag)"
if [[ -z "$REPO" || -z "$TAG" ]]; then
  echo "unable to resolve third-party release source." >&2
  echo "Set env THIRD_PARTY_REPO=owner/repo and THIRD_PARTY_TAG=vX.Y.Z" >&2
  echo "or put a tag line in third_party/version.txt." >&2
  if [[ "${#LOCAL_ERRORS[@]}" -gt 0 ]]; then
    printf "local bundle errors:\n" >&2
    printf -- "- %s\n" "${LOCAL_ERRORS[@]}" >&2
  fi
  exit 1
fi

BASE_URL="https://github.com/$REPO/releases/download/$TAG"
CACHE_DIR="$CACHE_ROOT/$REPO/$TAG"
mkdir -p "$CACHE_DIR"
ARCHIVE_PATH="$CACHE_DIR/$ASSET"
SUMS_PATH="$CACHE_DIR/$SUMS"
BUNDLE_PATH="$CACHE_DIR/$RELEASE_BUNDLE_ASSET"

if [[ -n "$THIRD_PARTY_PROXY" ]]; then
  echo "Downloading third-party bundle: $RELEASE_BUNDLE_ASSET (repo=$REPO tag=$TAG proxy=$THIRD_PARTY_PROXY)"
else
  echo "Downloading third-party bundle: $RELEASE_BUNDLE_ASSET (repo=$REPO tag=$TAG)"
fi

if download "$BASE_URL/$RELEASE_BUNDLE_ASSET" "$BUNDLE_PATH" && \
   restore_from_release_bundle_archive "$BUNDLE_PATH" "$CACHE_DIR" "release bundle $REPO@$TAG"; then
  echo "third_party ready: $TARGET_BASE"
  exit 0
else
  BUNDLE_ERROR="release bundle unavailable or verification/extract failed"
fi

echo "release bundle unavailable; trying split asset: $ASSET"
if download "$BASE_URL/$ASSET" "$ARCHIVE_PATH" && download "$BASE_URL/$SUMS" "$SUMS_PATH" && \
   restore_from_archive "$ARCHIVE_PATH" "$SUMS_PATH" "$CACHE_DIR" "release $REPO@$TAG"; then
  echo "third_party ready: $TARGET_BASE"
  exit 0
fi

echo "failed to restore third_party from release $REPO@$TAG ($BUNDLE_ERROR; split asset unavailable or invalid)" >&2
if [[ "${#LOCAL_ERRORS[@]}" -gt 0 ]]; then
  printf "local bundle errors:\n" >&2
  printf -- "- %s\n" "${LOCAL_ERRORS[@]}" >&2
fi
exit 1
