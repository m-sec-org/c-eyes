#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-dist-linux-amd64}"
OFFLINE="${OFFLINE:-1}"
LINK_MODE="${LINK_MODE:-static}"
COPY_RULES="${COPY_RULES:-0}"
GLIBC_BASELINE="${GLIBC_BASELINE:-2.28}"
ENFORCE_BASELINE_ENV="${ENFORCE_BASELINE_ENV:-0}"
VERIFY_GLIBC_BASELINE="${VERIFY_GLIBC_BASELINE:-0}"
ALLOW_ABI_DRIFT="${ALLOW_ABI_DRIFT:-0}"
YARA_BASELINE_NAME="${YARA_BASELINE_NAME:-yara-x-dist-linux-glibc-${GLIBC_BASELINE}}"
YARA_BASELINE_METADATA_FILE=".linux-glibc-baseline"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_TOOLCHAIN_ROOT="${GO_TOOLCHAIN_ROOT:-$ROOT/tmp/go-toolchain-local}"

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

baseline_metadata_path() {
  local base="$1"
  echo "$base/$YARA_BASELINE_METADATA_FILE"
}

has_matching_baseline_metadata() {
  local base="$1"
  local metadata
  metadata="$(baseline_metadata_path "$base")"
  [[ -f "$metadata" ]] && [[ "$(tr -d '[:space:]' < "$metadata")" == "$GLIBC_BASELINE" ]]
}

resolve_yara_base() {
  local candidates=(
    "$ROOT/third_party/$YARA_BASELINE_NAME"
    "$ROOT/third_party/yara-x-dist-linux"
    "$ROOT/third_party/yara-x-dist"
  )
  local base
  for base in "${candidates[@]}"; do
    if [[ -d "$base/include" && ( -d "$base/lib" || -d "$base/lib64" ) ]]; then
      echo "$base"
      return
    fi
  done
  echo "$ROOT/third_party/$YARA_BASELINE_NAME"
}

ensure_baseline_environment() {
  local current_glibc
  current_glibc="$(detect_glibc_version)"
  if [[ "$ENFORCE_BASELINE_ENV" != "1" || "$ALLOW_ABI_DRIFT" == "1" ]]; then
    return
  fi
  if [[ -z "$current_glibc" ]]; then
    echo "unable to detect current glibc version while baseline enforcement is enabled" >&2
    exit 1
  fi
  if [[ "$current_glibc" != "$GLIBC_BASELINE" ]]; then
    echo "baseline build requires glibc $GLIBC_BASELINE exactly; detected glibc $current_glibc" >&2
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
  toolchain_tag="v0.0.1-go${required_go}.linux-amd64"
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
  for lib_root in "${roots[@]}"; do
    [[ -d "$lib_root" ]] || continue
    multiarch="$lib_root/x86_64-linux-gnu"
    if [[ -d "$multiarch" ]]; then
      if has_linux_so "$multiarch"; then
        echo "$multiarch"
        return
      fi
      if ! has_linux_so "$lib_root"; then
        echo "$multiarch"
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

YARA_BASE="$(resolve_yara_base)"
ensure_baseline_environment

INCLUDE="$YARA_BASE/include"
LIB="$(resolve_linux_lib_dir "$YARA_BASE")"

if [[ ! -d "$INCLUDE" || ! -d "$LIB" ]]; then
  echo "linux yara dist not found. Expected baseline artifact tree at: $ROOT/third_party/$YARA_BASELINE_NAME" >&2
  exit 1
fi

if [[ "$ENFORCE_BASELINE_ENV" == "1" && "$ALLOW_ABI_DRIFT" != "1" ]] && ! has_matching_baseline_metadata "$YARA_BASE"; then
  echo "baseline metadata missing or mismatched for Linux YARA-X artifacts under: $YARA_BASE" >&2
  echo "Expected $(baseline_metadata_path "$YARA_BASE") to contain: $GLIBC_BASELINE" >&2
  echo "Regenerate baseline Linux YARA-X artifacts before packaging release builds." >&2
  exit 1
fi

if ! has_linux_so "$LIB"; then
  if [[ ! -d "$ROOT/third_party/yara-x-src" ]]; then
    echo "yara-x-src not found. Clone YARA-X into third_party/yara-x-src first." >&2
    exit 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required to build yara-x-capi (Rust toolchain)." >&2
    exit 1
  fi
  if ! cargo cinstall -h >/dev/null 2>&1; then
    echo "cargo-c is required. Install with: cargo install cargo-c" >&2
    exit 1
  fi
  (cd "$ROOT/third_party/yara-x-src" && cargo cinstall -p yara-x-capi --release --prefix "$YARA_BASE")
  write_baseline_metadata "$YARA_BASE"
fi

if ! command -v pkg-config >/dev/null 2>&1; then
  echo "pkg-config is required for cgo build on Linux." >&2
  exit 1
fi

setup_offline_go

export CGO_ENABLED=1
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
printf 'glibc=%s\nruntime=systemd\n' "$GLIBC_BASELINE" > "$OUT_DIR/linux-build-baseline.txt"

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
  cp -a "$CLOUD_CFG_SRC" "$OUT_DIR/c-eyes-cloud.json"
  echo "Copied: c-eyes-cloud.json (API key template)"
else
  echo "Cloud config template not found at $CLOUD_CFG_SRC. Skipping config copy."
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
echo "Link mode: $LINK_MODE"
echo "glibc baseline: $GLIBC_BASELINE"
