param(
    [string]$LinuxGlibcBaseline = "2.28",
    [ValidateSet("amd64", "arm64")]
    [string]$TargetArch = "amd64",
    [string]$LinuxBaselineImage = "rockylinux:8"
)

$ErrorActionPreference = "Stop"

function Test-DockerAvailable {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        return $false
    }
    try {
        $info = & $docker.Source info --format "{{.OSType}}" 2>$null
        return $LASTEXITCODE -eq 0 -and ($info -eq "linux")
    } catch {
        return $false
    }
}

function Ensure-Arm64Emulation {
    param(
        [string]$Image
    )

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # Fast path: arm64 container already runnable.
    docker run --rm --platform linux/arm64 $Image uname -m *> $null
    if ($LASTEXITCODE -eq 0) {
        $ErrorActionPreference = $prevEap
        return
    }

    Write-Host "ARM64 emulation is not ready. Installing binfmt for arm64..."
    docker run --privileged --rm tonistiigi/binfmt --install arm64
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $prevEap
        throw "Failed to install arm64 emulation (binfmt)."
    }

    docker run --rm --platform linux/arm64 $Image uname -m *> $null
    $ErrorActionPreference = $prevEap
    if ($LASTEXITCODE -ne 0) {
        throw "ARM64 emulation is still unavailable after binfmt installation."
    }
}

if (-not (Test-DockerAvailable)) {
    throw "Docker Linux containers are required to rebuild baseline Linux YARA-X artifacts."
}

$platform = switch ($TargetArch) {
    "amd64" { "linux/amd64" }
    "arm64" { "linux/arm64" }
    default { throw "unsupported target architecture: $TargetArch" }
}

if ($TargetArch -eq "arm64") {
    Ensure-Arm64Emulation -Image $LinuxBaselineImage
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
$cacheRoot = Join-Path $root "tmp\yarax-linux-cache\$TargetArch"
$cargoCache = Join-Path $cacheRoot "cargo"
$rustupCache = Join-Path $cacheRoot "rustup"
$targetCache = Join-Path $cacheRoot "target"
New-Item -ItemType Directory -Force -Path $cargoCache, $rustupCache, $targetCache | Out-Null

Write-Host "Rebuild Linux YARA-X baseline artifacts (image=$LinuxBaselineImage, glibcBaseline=$LinuxGlibcBaseline, targetArch=$TargetArch, platform=$platform)"
$bashBuildScript = @'
set -euo pipefail
retry() {
  local n=0
  local max="$1"
  shift
  until "$@"; do
    n=$((n+1))
    if [[ "$n" -ge "$max" ]]; then
      return 1
    fi
    sleep 5
  done
}

dnf install -y gcc gcc-c++ pkgconf-pkg-config unzip file binutils curl perl make openssl-devel systemd-libs libcurl-devel
if ! command -v cargo >/dev/null 2>&1; then
  dnf install -y rust cargo || true
fi
if ! command -v cargo >/dev/null 2>&1; then
  retry 5 bash -lc 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
fi
source /root/.cargo/env 2>/dev/null || true
if ! cargo cinstall -h >/dev/null 2>&1; then
  export CURL_SYS_USE_PKG_CONFIG=1
  export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/share/pkgconfig:${PKG_CONFIG_PATH:-}
  retry 5 cargo install cargo-c --version '0.10.21+cargo-0.95.0' --locked
fi
GLIBC_BASELINE=__GLIBC__ TARGET_ARCH=__ARCH__ bash ./scripts/rebuild-yarax-linux-baseline.sh
'@

$bashBuildScript = $bashBuildScript.Replace('__GLIBC__', $LinuxGlibcBaseline).Replace('__ARCH__', $TargetArch)

docker run --rm `
    --platform $platform `
    -e CARGO_HOME=/cache/cargo `
    -e RUSTUP_HOME=/cache/rustup `
    -e CARGO_TARGET_DIR=/cache/target `
    -v "${root}:/workspace" `
    -v "${cargoCache}:/cache/cargo" `
    -v "${rustupCache}:/cache/rustup" `
    -v "${targetCache}:/cache/target" `
    -w /workspace `
    $LinuxBaselineImage `
    bash -lc $bashBuildScript

if ($LASTEXITCODE -ne 0) {
    throw "Baseline Linux YARA-X rebuild failed."
}

Write-Host "Baseline Linux YARA-X artifacts updated."
