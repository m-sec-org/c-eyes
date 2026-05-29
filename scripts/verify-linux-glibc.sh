#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <artifact-path> [glibc-baseline]" >&2
  exit 1
fi

TARGET="$1"
GLIBC_BASELINE="${2:-2.28}"

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

collect_targets() {
  local target="$1"
  if [[ -d "$target" ]]; then
    (
      shopt -s nullglob
      local path
      for path in "$target"/c-eyes "$target"/*.so "$target"/*.so.*; do
        [[ -f "$path" ]] && printf '%s\n' "$path"
      done
    ) | sort -u
    return
  fi
  if [[ -f "$target" ]]; then
    printf '%s\n' "$target"
    return
  fi
  echo "artifact path not found: $target" >&2
  exit 1
}

extract_versions() {
  local file="$1"
  readelf -W --version-info "$file" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/^GLIBC_//' | sort -Vu || true
}

highest_version() {
  local versions="$1"
  if [[ -z "$versions" ]]; then
    echo ""
    return
  fi
  printf '%s\n' "$versions" | tail -n 1
}

failures=0
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  versions="$(extract_versions "$file")"
  highest="$(highest_version "$versions")"
  if [[ -z "$highest" ]]; then
    continue
  fi
  echo "$file -> GLIBC_$highest"
  if version_gt "$highest" "$GLIBC_BASELINE"; then
    echo "error: $file exceeds glibc baseline $GLIBC_BASELINE" >&2
    failures=1
  fi
done < <(collect_targets "$TARGET")

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi

echo "glibc verification passed (baseline=$GLIBC_BASELINE)"
