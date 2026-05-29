#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-}"
OFFLINE="${OFFLINE:-0}"
LINK_MODE="${LINK_MODE:-static}"
COPY_RULES="${COPY_RULES:-0}"
BUILD_PROFILE="${BUILD_PROFILE:-release}"
GLIBC_BASELINE="${GLIBC_BASELINE:-2.28}"
ENFORCE_BASELINE_ENV="${ENFORCE_BASELINE_ENV:-0}"
VERIFY_GLIBC_BASELINE="${VERIFY_GLIBC_BASELINE:-0}"
ALLOW_ABI_DRIFT="${ALLOW_ABI_DRIFT:-0}"
ALLOW_CROSS_ARCH="${ALLOW_CROSS_ARCH:-0}"
AUTO_FETCH_THIRD_PARTY="${AUTO_FETCH_THIRD_PARTY:-1}"
YARA_BASELINE_NAME="${YARA_BASELINE_NAME:-}"
YARA_BASELINE_METADATA_FILE=".linux-glibc-baseline"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_TOOLCHAIN_ROOT="${GO_TOOLCHAIN_ROOT:-$ROOT/tmp/go-toolchain-local}"

write_default_cloud_config() {
  local output_path="$1"
  cat > "$output_path" <<'EOF'
{
  "proxy_url": "",
  "providers": {
    "virustotal": {
      "api_key": "",
      "base_url": "https://www.virustotal.com",
      "upload_enabled": true,
      "upload_rate_limit": "15s",
      "rate_limit": "2s",
      "timeout": "10s",
      "cache_ttl": "10m"
    },
    "hybrid_analysis": {
      "api_key": "",
      "base_url": "https://hybrid-analysis.com/api/v2",
      "upload_enabled": true,
      "upload_rate_limit": "5s",
      "rate_limit": "2s",
      "timeout": "10s",
      "cache_ttl": "10m"
    },
    "malwarebazaar": {
      "api_key": "",
      "base_url": "https://mb-api.abuse.ch/api/v1/",
      "upload_enabled": false,
      "rate_limit": "2s",
      "timeout": "10s",
      "cache_ttl": "10m"
    },
    "otx": {
      "api_key": "",
      "base_url": "https://otx.alienvault.com",
      "upload_enabled": false,
      "rate_limit": "2s",
      "timeout": "10s",
      "cache_ttl": "10m"
    },
    "triage": {
      "api_key": "",
      "base_url": "https://tria.ge/api/v0",
      "upload_enabled": true,
      "upload_rate_limit": "3s",
      "rate_limit": "2s",
      "timeout": "10s",
      "cache_ttl": "10m"
    }
  }
}
EOF
}

write_sanitized_cloud_config() {
  local source_path="$1"
  local output_path="$2"
  sed -E 's/("api_key"[[:space:]]*:[[:space:]]*")[^"]*"/\1"/g' "$source_path" > "$output_path"
}

version_ge() {
  local current="$1"
  local required="$2"
  [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n 1)" == "$required" ]]
}

version_gt() {
  local left="$1"
  local right="$2"
  [[ "$left" != "$right" ]] && version_ge "$left" "$right"
}

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

linux_multiarch_triplet() {
  local arch="$1"
  case "$arch" in
    amd64)
      echo "x86_64-linux-gnu"
      ;;
    arm64)
      echo "aarch64-linux-gnu"
      ;;
    *)
      echo ""
      ;;
  esac
}

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

detect_go_version() {
  local raw
  raw="$(go version 2>/dev/null || true)"
  if [[ -z "$raw" ]]; then
    echo ""
    return
  fi
  echo "$raw" | awk '{print $3}' | sed 's/^go//'
}

HOST_ARCH="$(detect_host_arch)"
TARGET_ARCH="${TARGET_ARCH:-$HOST_ARCH}"
HOST_GLIBC="$(detect_glibc_version)"

if [[ -z "$HOST_ARCH" ]]; then
  echo "unsupported host architecture: $(uname -m 2>/dev/null || echo unknown)" >&2
  echo "Supported host architectures: amd64, arm64" >&2
  exit 1
fi

if [[ -z "$TARGET_ARCH" ]]; then
  echo "unable to resolve target architecture" >&2
  exit 1
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

case "$BUILD_PROFILE" in
  release|host)
    ;;
  *)
    echo "unsupported BUILD_PROFILE: $BUILD_PROFILE" >&2
    echo "Supported BUILD_PROFILE values: release, host" >&2
    exit 1
    ;;
esac

if [[ "$TARGET_ARCH" != "$HOST_ARCH" && "$ALLOW_CROSS_ARCH" != "1" ]]; then
  echo "cross-architecture Linux packaging is disabled by default." >&2
  echo "Host architecture: $HOST_ARCH" >&2
  echo "Target architecture: $TARGET_ARCH" >&2
  echo "Build on a matching Linux machine, or set ALLOW_CROSS_ARCH=1 only if you have a working cross toolchain and matching native dependencies." >&2
  exit 1
fi

if [[ -z "$HOST_GLIBC" ]]; then
  echo "unable to detect host glibc version." >&2
  exit 1
fi
if ! version_ge "$HOST_GLIBC" "$GLIBC_BASELINE"; then
  echo "detected host glibc $HOST_GLIBC, but this build requires glibc >= $GLIBC_BASELINE." >&2
  echo "Use a host with compatible glibc, or keep using the published release binaries." >&2
  exit 1
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="dist-linux-${TARGET_ARCH}"
fi

YARA_BASELINE_NAME="${YARA_BASELINE_NAME:-yara-x-dist-linux-glibc-${GLIBC_BASELINE}-${TARGET_ARCH}}"

baseline_metadata_path() {
  local base="$1"
  echo "$base/$YARA_BASELINE_METADATA_FILE"
}

has_matching_baseline_metadata() {
  local base="$1"
  local expected_baseline="$2"
  local metadata
  metadata="$(baseline_metadata_path "$base")"
  [[ -f "$metadata" ]] && [[ "$(tr -d '[:space:]' < "$metadata")" == "$expected_baseline" ]]
}

resolve_yara_base() {
  local yara_name="$1"
  echo "$ROOT/third_party/$yara_name"
}

ensure_baseline_environment() {
  local required_glibc="$1"
  local current_glibc
  current_glibc="$(detect_glibc_version)"
  if [[ "$ENFORCE_BASELINE_ENV" != "1" || "$ALLOW_ABI_DRIFT" == "1" ]]; then
    return
  fi
  if [[ -z "$current_glibc" ]]; then
    echo "unable to detect current glibc version while baseline enforcement is enabled" >&2
    exit 1
  fi
  if [[ "$current_glibc" != "$required_glibc" ]]; then
    echo "baseline build requires glibc $required_glibc exactly; detected glibc $current_glibc" >&2
    echo "Use the pinned baseline build environment, or set ALLOW_ABI_DRIFT=1 only for non-release local builds." >&2
    exit 1
  fi
}

write_baseline_metadata() {
  local base="$1"
  mkdir -p "$base"
  printf '%s\n' "$GLIBC_BASELINE" > "$(baseline_metadata_path "$base")"
}

setup_offline_go() {
  if [[ "$OFFLINE" != "1" ]]; then
    return
  fi

  local required_go toolchain_tag toolchain_dir toolchain_zip go_ver
  required_go="$(awk '/^go / { print $2; exit }' "$ROOT/go.mod")"
  toolchain_tag="v0.0.1-go${required_go}.linux-${TARGET_ARCH}"
  toolchain_dir="$GO_TOOLCHAIN_ROOT/golang.org/toolchain@${toolchain_tag}"
  toolchain_zip="$ROOT/tmp/${toolchain_tag}.zip"

  export GOTOOLCHAIN=local
  export GOPROXY="${GOPROXY:-off}"
  export GOSUMDB="${GOSUMDB:-off}"

  if [[ -d "$toolchain_dir/bin" ]]; then
    export PATH="$toolchain_dir/bin:$PATH"
  elif [[ -f "$toolchain_zip" ]]; then
    if ! command -v unzip >/dev/null 2>&1; then
      echo "unzip is required to expand offline Go toolchain: $toolchain_zip" >&2
      exit 1
    fi
    mkdir -p "$GO_TOOLCHAIN_ROOT"
    unzip -qo "$toolchain_zip" -d "$GO_TOOLCHAIN_ROOT"
    if [[ -d "$toolchain_dir/bin" ]]; then
      export PATH="$toolchain_dir/bin:$PATH"
    fi
  fi

  if [[ -z "${GOMODCACHE:-}" ]]; then
    local cache_candidates=(
      "$ROOT/tmp/go-mod-cache"
      "/gomodcache"
      "/mnt/c/Users/Administrator/go/pkg/mod"
      "$HOME/go/pkg/mod"
    )
    local c
    for c in "${cache_candidates[@]}"; do
      if [[ -d "$c" ]] && [[ -n "$(ls -A "$c" 2>/dev/null)" ]]; then
        export GOMODCACHE="$c"
        break
      fi
    done
  fi

  go_ver="$(detect_go_version)"
  if [[ -z "$go_ver" ]]; then
    echo "go not found in PATH (offline mode)." >&2
    exit 1
  fi
  if ! version_ge "$go_ver" "$required_go"; then
    echo "offline mode requires go >= $required_go, found $go_ver." >&2
    echo "Provide local toolchain in: $toolchain_dir" >&2
    echo "Or place zip at: $toolchain_zip" >&2
    exit 1
  fi

  echo "Offline mode: ON"
  echo "Go: $(go version)"
  if [[ -n "${GOMODCACHE:-}" ]]; then
    echo "GOMODCACHE: $GOMODCACHE"
  fi
}

has_linux_so() {
  local lib_dir="$1"
  [[ -f "$lib_dir/libyara_x_capi.so" || -f "$lib_dir/libyara_x_capi.so.0" || -f "$lib_dir/libyara_x_capi.so.1" || -f "$lib_dir/libyara_x_capi.so.1.14.0" ]]
}

binary_needs_yara_shared() {
  local exe="$1"
  readelf -d "$exe" 2>/dev/null | grep -q 'libyara_x_capi\.so'
}

resolve_linux_lib_dir() {
  local base="$1"
  local roots=("$base/lib" "$base/lib64")
  local lib_root multiarch
  multiarch="$(linux_multiarch_triplet "$TARGET_ARCH")"
  for lib_root in "${roots[@]}"; do
    [[ -d "$lib_root" ]] || continue
    if [[ -n "$multiarch" && -d "$lib_root/$multiarch" ]]; then
      if has_linux_so "$lib_root/$multiarch"; then
        echo "$lib_root/$multiarch"
        return
      fi
      if ! has_linux_so "$lib_root"; then
        echo "$lib_root/$multiarch"
        return
      fi
    fi
    if has_linux_so "$lib_root" || [[ -f "$lib_root/libyara_x_capi.a" ]]; then
      echo "$lib_root"
      return
    fi
  done
  echo "$base/lib"
}

YARA_BASE="$(resolve_yara_base "$YARA_BASELINE_NAME")"
if [[ "$BUILD_PROFILE" == "release" ]]; then
  ensure_baseline_environment "$GLIBC_BASELINE"
fi

INCLUDE="$YARA_BASE/include"
LIB="$(resolve_linux_lib_dir "$YARA_BASE")"

if [[ "$AUTO_FETCH_THIRD_PARTY" == "1" ]] && [[ ! -d "$INCLUDE" || ! -d "$LIB" ]]; then
  bash "$ROOT/scripts/ensure-third-party.sh" --platform linux --arch "$TARGET_ARCH" --glibc-baseline "$GLIBC_BASELINE"
  INCLUDE="$YARA_BASE/include"
  LIB="$(resolve_linux_lib_dir "$YARA_BASE")"
fi

if [[ ! -d "$INCLUDE" || ! -d "$LIB" ]]; then
  echo "linux yara dist not found. Expected artifact tree at: $ROOT/third_party/$YARA_BASELINE_NAME" >&2
  exit 1
fi

if [[ "$ENFORCE_BASELINE_ENV" == "1" && "$ALLOW_ABI_DRIFT" != "1" ]] && ! has_matching_baseline_metadata "$YARA_BASE" "$GLIBC_BASELINE"; then
  echo "baseline metadata missing or mismatched for Linux YARA-X artifacts under: $YARA_BASE" >&2
  echo "Expected $(baseline_metadata_path "$YARA_BASE") to contain: $GLIBC_BASELINE" >&2
  echo "Regenerate baseline Linux YARA-X artifacts before packaging release builds." >&2
  exit 1
fi

if ! has_linux_so "$LIB"; then
  echo "linux yara dist is incomplete under: $YARA_BASE" >&2
  echo "Expected prebuilt shared objects in the packaged Linux dependency tree." >&2
  echo "This build path requires the full packaged dependency set and does not fall back to rebuilding YARA-X from source." >&2
  exit 1
fi

if ! command -v pkg-config >/dev/null 2>&1; then
  echo "pkg-config is required for cgo build on Linux." >&2
  exit 1
fi

setup_offline_go

export CGO_ENABLED=1
export GOOS=linux
export GOARCH="$TARGET_ARCH"
export CGO_CFLAGS="-I$INCLUDE"
export PKG_CONFIG="pkg-config"

if [[ "$LINK_MODE" == "static" ]]; then
  STATIC_ARCHIVE="$LIB/libyara_x_capi.a"
  if [[ ! -f "$STATIC_ARCHIVE" ]]; then
    echo "static archive not found: $STATIC_ARCHIVE" >&2
    exit 1
  fi
  STATIC_PKGCONFIG_PARENT="${TMPDIR:-/tmp}"
  if [[ ! -d "$STATIC_PKGCONFIG_PARENT" || ! -w "$STATIC_PKGCONFIG_PARENT" ]]; then
    STATIC_PKGCONFIG_PARENT="$ROOT/tmp"
    mkdir -p "$STATIC_PKGCONFIG_PARENT"
  fi
  STATIC_PKGCONFIG_DIR="$(mktemp -d "$STATIC_PKGCONFIG_PARENT/yara-static-pkgconfig.XXXXXX")"
  trap 'rm -rf "$STATIC_PKGCONFIG_DIR"' EXIT
  cat > "$STATIC_PKGCONFIG_DIR/yara_x_capi.pc" <<EOF
prefix=$YARA_BASE
exec_prefix=\${prefix}
libdir=$LIB
includedir=$INCLUDE

Name: yara_x_capi
Description: Static Linux YARA-X C API
Version: 1.14.0
Libs: \${libdir}/libyara_x_capi.a
Cflags: -I\${includedir}
Libs.private: -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
EOF
  export PKG_CONFIG_PATH="$STATIC_PKGCONFIG_DIR:$LIB/pkgconfig:${PKG_CONFIG_PATH:-}"
else
  export PKG_CONFIG_PATH="$LIB/pkgconfig:${PKG_CONFIG_PATH:-}"
  export CGO_LDFLAGS="-L$LIB -lyara_x_capi -Wl,-rpath,\$ORIGIN"
fi

OUT_DIR="$ROOT/$OUTPUT_DIR"
mkdir -p "$OUT_DIR"

EXE="$OUT_DIR/c-eyes"
BUILD_TAGS="yarax"
if [[ "$LINK_MODE" == "static" ]]; then
  BUILD_TAGS="$BUILD_TAGS static_link"
fi
(
  cd "$ROOT"
  go build -tags "$BUILD_TAGS" -o "$EXE" ./cmd/edr
)

NEEDS_YARA_SHARED=0
if binary_needs_yara_shared "$EXE"; then
  NEEDS_YARA_SHARED=1
fi

if [[ "$LINK_MODE" != "static" || "$NEEDS_YARA_SHARED" == "1" ]]; then
  shopt -s nullglob
  so_files=("$LIB/libyara_x_capi.so"*)
  if [[ ${#so_files[@]} -gt 0 ]]; then
    rm -f "$OUT_DIR/libyara_x_capi.so"*
    # Use -L to materialize symlinks as real files for portable distribution archives (zip/scp).
    cp -L "${so_files[@]}" "$OUT_DIR/"
  else
    echo "warning: libyara_x_capi.so not found under $LIB" >&2
  fi
  shopt -u nullglob
else
  rm -f "$OUT_DIR/libyara_x_capi.so"*
fi

if [[ "$COPY_RULES" == "1" ]]; then
  RULES_SRC="$ROOT/rules/yaraRules"
  if [[ -d "$RULES_SRC" ]]; then
    RULES_DEST="$OUT_DIR/rules/yaraRules"
    mkdir -p "$RULES_DEST"
    cp -a "$RULES_SRC/." "$RULES_DEST/"
    echo "Copied rules: $RULES_DEST"
  else
    echo "Rules not found at $RULES_SRC. Skipping rule copy."
  fi
else
  rm -rf "$OUT_DIR/rules"
  echo "Rules copy disabled (using embedded rules by default)."
fi

CLOUD_CFG_SRC="$ROOT/c-eyes-cloud.json"
if [[ -f "$CLOUD_CFG_SRC" ]]; then
  write_sanitized_cloud_config "$CLOUD_CFG_SRC" "$OUT_DIR/c-eyes-cloud.json"
  echo "Wrote: c-eyes-cloud.json (sanitized API key template)"
else
  write_default_cloud_config "$OUT_DIR/c-eyes-cloud.json"
  echo "Generated: c-eyes-cloud.json (default API key template)"
fi

if [[ "$VERIFY_GLIBC_BASELINE" == "1" ]]; then
  "$ROOT/scripts/verify-linux-glibc.sh" "$OUT_DIR" "$GLIBC_BASELINE"
fi

echo "Built: $EXE"
if [[ "$NEEDS_YARA_SHARED" == "1" ]]; then
  echo "Bundled: libyara_x_capi.so* (runtime dependency)"
elif [[ "$LINK_MODE" == "static" ]]; then
  echo "Linked: libyara_x_capi.a (static)"
else
  echo "Copied: libyara_x_capi.so*"
fi
echo "Build profile: $BUILD_PROFILE"
echo "Link mode: $LINK_MODE"
echo "glibc baseline: $GLIBC_BASELINE"
echo "host glibc detected: $HOST_GLIBC"
