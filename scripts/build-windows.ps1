param(
    [string]$OutputDir = "dist-windows-amd64",
    [switch]$BootstrapToolchain,
    [bool]$Offline = $false,
    [ValidateSet("static", "dynamic")]
    [string]$LinkMode = "static",
    [bool]$CopyRules = $false,
    [switch]$SkipAutoFetchThirdParty
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $root

function New-DefaultCloudConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    @'
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
'@ | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

function Write-SanitizedCloudConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $content = Get-Content -LiteralPath $SourcePath -Raw
    $content = [regex]::Replace($content, '(?<="api_key"\s*:\s*")[^"]*', '')
    Set-Content -LiteralPath $OutputPath -Value $content -Encoding UTF8
}

$yaraBase = Join-Path $root "third_party\yara-x-dist"
$include = Join-Path $yaraBase "include"
$lib = Join-Path $yaraBase "lib"
$bin = Join-Path $yaraBase "bin"

$localToolchainBin = Join-Path $root "third_party\toolchain\mingw64\bin"
$localGcc = Join-Path $localToolchainBin "gcc.exe"
$localGpp = Join-Path $localToolchainBin "g++.exe"
$localPkgconf = Join-Path $localToolchainBin "pkgconf.exe"

if ((-not $SkipAutoFetchThirdParty.IsPresent) -and ((-not (Test-Path $include)) -or (-not (Test-Path $lib)) -or (-not (Test-Path $bin)) -or (-not (Test-Path $localGcc)))) {
    & (Join-Path $root "scripts\ensure-third-party.ps1") -Platform windows -Arch amd64
}

if (-not (Test-Path $include) -or -not (Test-Path $lib) -or -not (Test-Path $bin)) {
    throw "yara-x-dist not found. Expected $yaraBase."
}

if ($BootstrapToolchain -and -not (Test-Path $localGcc)) {
    & (Join-Path $root "scripts\setup-windows-toolchain.ps1")
}

$compiler = $null
$compilerSource = "system"
if (Test-Path $localGcc) {
    $compiler = $localGcc
    $compilerSource = "project"
} else {
    $cmd = Get-Command gcc -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        $compiler = $cmd.Source
    }
}

if (-not $compiler) {
    throw "gcc not found. Run .\scripts\setup-windows-toolchain.ps1 (project-local) or install MinGW."
}

$modeText = if ($Offline) { "offline" } else { "online" }
Write-Host "Build mode: $modeText"

$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS = "-I$include"
if ($LinkMode -eq "static") {
    $staticArchive = Join-Path $lib "libyara_x_capi.a"
    if (-not (Test-Path $staticArchive)) {
        throw "static archive not found: $staticArchive"
    }
    # Link YARA-X C API into c-eyes.exe to avoid distributing yara_x_capi.dll.
    $env:CGO_LDFLAGS = "`"$staticArchive`" -lbcrypt -ladvapi32 -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp"
} else {
    $env:CGO_LDFLAGS = "-L$lib -lyara_x_capi"
}
$env:CC = $compiler
if ($Offline) {
    $env:GOTOOLCHAIN = "local"
    if (-not $env:GOPROXY) {
        $env:GOPROXY = "off"
    }
    if (-not $env:GOSUMDB) {
        $env:GOSUMDB = "off"
    }
}
if (Test-Path $localGpp) {
    $env:CXX = $localGpp
}
if (Test-Path $localPkgconf) {
    $env:PKG_CONFIG = $localPkgconf
}
if ($compilerSource -eq "project") {
    $env:PATH = "$localToolchainBin;$bin;$env:PATH"
} else {
    $env:PATH = "$bin;$env:PATH"
}

$outDir = Join-Path $root $OutputDir
$goBuildCache = Join-Path $root "tmp\\go-build-cache"
New-Item -ItemType Directory -Force $goBuildCache | Out-Null
if (-not $env:GOCACHE) {
    $env:GOCACHE = $goBuildCache
}

New-Item -ItemType Directory -Force $outDir | Out-Null
if (-not $CopyRules) {
    $rulesDir = Join-Path $outDir "rules"
    if (Test-Path $rulesDir) {
        Remove-Item -Recurse -Force $rulesDir
    }
}

$exe = Join-Path $outDir "c-eyes.exe"
@("yara_x_capi.dll", "libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll") | ForEach-Object {
    $stale = Join-Path $outDir $_
    if (Test-Path $stale) {
        Remove-Item -Force $stale
    }
}

Push-Location $root
try {
    go build -tags yarax -o $exe .\cmd\edr
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $exe)) {
    throw "expected build output not found: $exe"
}

if ($LinkMode -eq "dynamic") {
    Copy-Item (Join-Path $bin "yara_x_capi.dll") $outDir -Force

    # Package MinGW runtime DLLs when using project-local toolchain.
    if ($compilerSource -eq "project") {
        @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll") | ForEach-Object {
            $dll = Join-Path $localToolchainBin $_
            if (Test-Path $dll) {
                Copy-Item $dll $outDir -Force
                Write-Host "Copied: $_"
            }
        }
    }
}

if ($CopyRules) {
    $rulesSrc = Join-Path $root "rules\\yaraRules"
    if (Test-Path $rulesSrc) {
        $rulesDest = Join-Path $outDir "rules\\yaraRules"
        New-Item -ItemType Directory -Force $rulesDest | Out-Null
        Copy-Item -Recurse -Force (Join-Path $rulesSrc "*") $rulesDest
        Write-Host "Copied rules: $rulesDest"
    } else {
        Write-Host "Rules not found at $rulesSrc. Skipping rule copy."
    }
} else {
    Write-Host "Rules copy disabled (using embedded rules by default)."
}

$cloudTemplate = Join-Path $root "c-eyes-cloud.json"
 $cloudOutput = Join-Path $outDir "c-eyes-cloud.json"
if (Test-Path $cloudTemplate) {
    Write-SanitizedCloudConfig -SourcePath $cloudTemplate -OutputPath $cloudOutput
    Write-Host "Wrote: c-eyes-cloud.json (sanitized API key template)"
} else {
    New-DefaultCloudConfig -OutputPath $cloudOutput
    Write-Host "Generated: c-eyes-cloud.json (default API key template)"
}

Write-Host "Built: $exe"
if ($LinkMode -eq "dynamic") {
    Write-Host "Copied: yara_x_capi.dll"
} else {
    Write-Host "Linked: libyara_x_capi.a (static)"
}
Write-Host "Compiler: $compiler"
Write-Host "Link mode: $LinkMode"
