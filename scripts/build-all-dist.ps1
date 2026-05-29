param(
    [bool]$Offline = $false,
    [ValidateSet("static", "dynamic")]
    [string]$WindowsLinkMode = "static",
    [string]$LinuxGlibcBaseline = "2.28",
    [string]$LinuxBaselineImage = "rockylinux:8",
    [switch]$IncludeLinuxArm64
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

function Invoke-DockerLinuxBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [Parameter(Mandatory = $true)]
        [string]$OfflineFlag,
        [Parameter(Mandatory = $true)]
        [string]$LinuxGlibcBaseline,
        [Parameter(Mandatory = $true)]
        [string]$LinuxBaselineImage,
        [Parameter(Mandatory = $true)]
        [ValidateSet("amd64", "arm64")]
        [string]$TargetArch
    )

    $dockerImage = $LinuxBaselineImage
    Write-Host "Build Linux dist via Docker: $OutputDir (arch=$TargetArch, image=$dockerImage, glibcBaseline=$LinuxGlibcBaseline)"
    $dockerArgs = @(
        "run",
        "--rm",
        "--platform", "linux/$TargetArch",
        "-v", "${Root}:/workspace",
        "-w", "/workspace"
    )

    $hostGoModCache = Join-Path $env:USERPROFILE "go\pkg\mod"
    if ($OfflineFlag -eq "1" -and (Test-Path $hostGoModCache)) {
        Write-Host "Mount host Go module cache: $hostGoModCache"
        $dockerArgs += @("-v", "${hostGoModCache}:/gomodcache", "-e", "GOMODCACHE=/gomodcache")
    }

    $dockerArgs += @(
        $dockerImage,
        "bash",
        "-lc",
        "set -euo pipefail; dnf install -y gcc gcc-c++ pkgconf-pkg-config unzip file binutils systemd-libs golang git curl tar; BUILD_PROFILE=release TARGET_ARCH=$TargetArch OFFLINE=$OfflineFlag COPY_RULES=0 GLIBC_BASELINE=$LinuxGlibcBaseline ENFORCE_BASELINE_ENV=1 VERIFY_GLIBC_BASELINE=1 bash ./scripts/build-linux.sh $OutputDir"
    )
    & docker @dockerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Linux build failed for $OutputDir"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
$offlineFlag = if ($Offline) { "1" } else { "0" }

Write-Host "Build all dist packages (offline=$Offline, windowsLinkMode=$WindowsLinkMode, linuxGlibcBaseline=$LinuxGlibcBaseline, includeLinuxArm64=$($IncludeLinuxArm64.IsPresent))"

Push-Location $root
try {
    & (Join-Path $root "scripts\build-windows.ps1") -OutputDir "dist-windows-amd64" -Offline:$Offline -LinkMode $WindowsLinkMode -CopyRules:$false
    & (Join-Path $root "scripts\build-windows.ps1") -OutputDir "dist-windows-amd64-public" -Offline:$Offline -LinkMode $WindowsLinkMode -CopyRules:$false

    if (Test-DockerAvailable) {
        Invoke-DockerLinuxBuild -Root $root -OutputDir "dist-linux-amd64" -OfflineFlag $offlineFlag -LinuxGlibcBaseline $LinuxGlibcBaseline -LinuxBaselineImage $LinuxBaselineImage -TargetArch "amd64"
        Invoke-DockerLinuxBuild -Root $root -OutputDir "dist-linux-amd64-public" -OfflineFlag $offlineFlag -LinuxGlibcBaseline $LinuxGlibcBaseline -LinuxBaselineImage $LinuxBaselineImage -TargetArch "amd64"

        if ($IncludeLinuxArm64.IsPresent) {
            Invoke-DockerLinuxBuild -Root $root -OutputDir "dist-linux-arm64" -OfflineFlag $offlineFlag -LinuxGlibcBaseline $LinuxGlibcBaseline -LinuxBaselineImage $LinuxBaselineImage -TargetArch "arm64"
            Invoke-DockerLinuxBuild -Root $root -OutputDir "dist-linux-arm64-public" -OfflineFlag $offlineFlag -LinuxGlibcBaseline $LinuxGlibcBaseline -LinuxBaselineImage $LinuxBaselineImage -TargetArch "arm64"
        }
    } else {
        throw "No pinned Linux baseline build runtime found. Make Docker Linux containers available and ensure the baseline-compatible YARA-X Linux artifacts have been regenerated before packaging."
    }
}
finally {
    Pop-Location
}

Write-Host "All dist directories updated."
