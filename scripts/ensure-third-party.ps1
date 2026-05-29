param(
    [ValidateSet("windows", "linux")]
    [string]$Platform = "windows",
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",
    [string]$GlibcBaseline = "2.28",
    [string]$Repo = "",
    [string]$Tag = "",
    [string]$CacheDir = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptRoot
$disableLocalBundle = ($env:DISABLE_LOCAL_BUNDLE -eq "1")
$thirdPartyProxy = $env:THIRD_PARTY_PROXY
if ([string]::IsNullOrWhiteSpace($thirdPartyProxy)) { $thirdPartyProxy = $env:HTTPS_PROXY }
if ([string]::IsNullOrWhiteSpace($thirdPartyProxy)) { $thirdPartyProxy = $env:https_proxy }
if ([string]::IsNullOrWhiteSpace($thirdPartyProxy)) { $thirdPartyProxy = $env:HTTP_PROXY }
if ([string]::IsNullOrWhiteSpace($thirdPartyProxy)) { $thirdPartyProxy = $env:http_proxy }

function Resolve-Repo {
    if (-not [string]::IsNullOrWhiteSpace($Repo)) { return $Repo }
    if ($env:THIRD_PARTY_REPO) { return $env:THIRD_PARTY_REPO }
    $repoFile = Join-Path $root "third_party\repo.txt"
    if (Test-Path $repoFile) {
        $line = Get-Content $repoFile | Where-Object { $_ -and ($_ -notmatch '^\s*#') } | Select-Object -First 1
        if ($line -and $line.Trim() -match '.+/.+') { return $line.Trim() }
    }
    try {
        $remote = git -C $root config --get remote.origin.url 2>$null
        if ($LASTEXITCODE -eq 0 -and $remote) {
            $r = $remote.Trim()
            $r = $r -replace '^git@github.com:', ''
            $r = $r -replace '^https://github.com/', ''
            $r = $r -replace '\.git$', ''
            if ($r -match '.+/.+') { return $r }
        }
    } catch {}
    return ""
}

function Resolve-Tag {
    if (-not [string]::IsNullOrWhiteSpace($Tag)) { return $Tag }
    if ($env:THIRD_PARTY_TAG) { return $env:THIRD_PARTY_TAG }
    $versionFile = Join-Path $root "third_party\version.txt"
    if (Test-Path $versionFile) {
        $line = Get-Content $versionFile | Where-Object { $_ -and ($_ -notmatch '^\s*#') } | Select-Object -First 1
        if ($line) { return $line.Trim() }
    }
    try {
        $exactTag = git -C $root describe --tags --exact-match 2>$null
        if ($LASTEXITCODE -eq 0 -and $exactTag) { return $exactTag.Trim() }
    } catch {}
    return ""
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    if (-not [string]::IsNullOrWhiteSpace($thirdPartyProxy)) {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -Proxy $thirdPartyProxy -TimeoutSec 300
    } else {
        & curl.exe -L --fail --retry 5 --retry-delay 3 --retry-all-errors -o $OutFile $Url
        if ($LASTEXITCODE -ne 0) {
            throw "download failed: $Url"
        }
    }
}

function Restore-FromReleaseBundle {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$CacheRoot,
        [Parameter(Mandatory = $true)][string]$AssetName,
        [Parameter(Mandatory = $true)][string]$SourceLabel
    )

    $bundleName = "c-eyes-third-party.zip"
    $bundlePath = Join-Path $CacheRoot $bundleName
    Download-File -Url "$BaseUrl/$bundleName" -OutFile $bundlePath

    $bundleExtract = Join-Path $CacheRoot "b"
    if (Test-Path $bundleExtract) { Remove-Item -Recurse -Force $bundleExtract }
    New-Item -ItemType Directory -Force $bundleExtract | Out-Null
    $tarCmd = Get-Command tar -ErrorAction SilentlyContinue
    if ($tarCmd) {
        & $tarCmd.Source -xf $bundlePath -C $bundleExtract
        if ($LASTEXITCODE -ne 0) {
            throw "failed to extract $bundlePath with tar"
        }
    } else {
        Expand-Archive -Path $bundlePath -DestinationPath $bundleExtract -Force
    }

    $bundleCandidates = @(
        (Join-Path $bundleExtract "c-eyes-third-party\release-bundles"),
        (Join-Path $bundleExtract "c-eyes-third-party"),
        $bundleExtract
    )
    foreach ($candidate in $bundleCandidates) {
        $archive = Join-Path $candidate $AssetName
        $sums = Join-Path $candidate "SHA256SUMS.txt"
        if (-not (Test-Path $archive) -or -not (Test-Path $sums)) { continue }
        Restore-ThirdPartyFromArchive -ArchivePath $archive -SumsPath $sums -ExtractRoot $candidate -SourceLabel $SourceLabel
        return
    }
    throw "$SourceLabel does not contain $AssetName and SHA256SUMS.txt"
}

function Get-ExpectedHash {
    param(
        [Parameter(Mandatory = $true)][string]$SumsPath,
        [Parameter(Mandatory = $true)][string]$AssetName
    )
    $line = Get-Content $SumsPath | Where-Object { $_ -match ("(^|\s)\*?" + [regex]::Escape($AssetName) + "$") } | Select-Object -First 1
    if (-not $line) { return "" }
    return ($line -split '\s+')[0].Trim().ToLowerInvariant()
}

if ($Platform -eq "windows") {
    $assetName = "third_party-windows-amd64.zip"
    $targetChecks = @(
        (Join-Path $root "third_party\toolchain\mingw64\bin\gcc.exe"),
        (Join-Path $root "third_party\yara-x-dist\lib\libyara_x_capi.a")
    )
} else {
    $assetName = "third_party-linux-glibc-$GlibcBaseline-$Arch.tar.gz"
    $targetChecks = @(
        (Join-Path $root "third_party\yara-x-dist-linux-glibc-$GlibcBaseline-$Arch\lib64\libyara_x_capi.so")
    )
}

$alreadyReady = $true
foreach ($p in $targetChecks) {
    if (-not (Test-Path $p)) { $alreadyReady = $false; break }
}
if ($alreadyReady -and -not $Force) {
    Write-Host "third_party already present for $Platform/$Arch"
    exit 0
}

function Restore-ThirdPartyFromArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$SumsPath,
        [Parameter(Mandatory = $true)][string]$ExtractRoot,
        [Parameter(Mandatory = $true)][string]$SourceLabel
    )

    if (-not (Test-Path $ArchivePath)) { throw "$SourceLabel missing asset: $ArchivePath" }
    if (-not (Test-Path $SumsPath)) { throw "$SourceLabel missing SHA256SUMS.txt: $SumsPath" }

    $expectedHash = Get-ExpectedHash -SumsPath $SumsPath -AssetName $assetName
    if (-not $expectedHash) { throw "$SourceLabel SHA256SUMS.txt has no entry for $assetName" }
    $actualHash = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLowerInvariant()
    if ($expectedHash -ne $actualHash) {
        throw "$SourceLabel checksum mismatch for $assetName (expected=$expectedHash actual=$actualHash)"
    }

    $tmpRoot = [System.IO.Path]::GetTempPath()
    $extractDir = Join-Path $tmpRoot ("ceyes-tp-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
    if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
    New-Item -ItemType Directory -Force $extractDir | Out-Null

    try {
        if ($ArchivePath.ToLowerInvariant().EndsWith(".zip")) {
            $tarCmd = Get-Command tar -ErrorAction SilentlyContinue
            if ($tarCmd) {
                & $tarCmd.Source -xf $ArchivePath -C $extractDir
                if ($LASTEXITCODE -ne 0) { throw "failed to extract $ArchivePath with tar" }
            } else {
                Expand-Archive -Path $ArchivePath -DestinationPath $extractDir -Force
            }
        } else {
            tar -xzf $ArchivePath -C $extractDir
            if ($LASTEXITCODE -ne 0) { throw "failed to extract $ArchivePath" }
        }

        $payloadRoot = if (Test-Path (Join-Path $extractDir "third_party")) { Join-Path $extractDir "third_party" } else { $extractDir }
    $dstThirdParty = Join-Path $root "third_party"
    New-Item -ItemType Directory -Force $dstThirdParty | Out-Null

        if ($Platform -eq "windows") {
            foreach ($name in @("toolchain", "yara-x-dist")) {
                $src = Join-Path $payloadRoot $name
                if (-not (Test-Path $src)) { throw "$SourceLabel archive missing $name" }
                $dst = Join-Path $dstThirdParty $name
                if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
                Copy-Item -Recurse -Force $src $dst
            }
        } else {
            $name = "yara-x-dist-linux-glibc-$GlibcBaseline-$Arch"
            $src = Join-Path $payloadRoot $name
            if (-not (Test-Path $src)) { throw "$SourceLabel archive missing $name" }
            $dst = Join-Path $dstThirdParty $name
            if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
            Copy-Item -Recurse -Force $src $dst
        }

        foreach ($p in $targetChecks) {
            if (-not (Test-Path $p)) {
                throw "$SourceLabel restored third_party is incomplete: missing $p"
            }
        }
    } finally {
        if (Test-Path $extractDir) {
            Remove-Item -Recurse -Force $extractDir -ErrorAction SilentlyContinue
        }
    }
}

$localErrors = @()
$localCandidates = @(
    (Join-Path $root "c-eyes-third-party"),
    (Join-Path (Split-Path -Parent $root) "c-eyes-third-party"),
    (Join-Path (Split-Path -Parent $root) "release-assets\c-eyes-third-party"),
    (Join-Path (Get-Location).Path "c-eyes-third-party")
) | Select-Object -Unique

if (-not $disableLocalBundle) {
    foreach ($candidate in $localCandidates) {
        if (-not (Test-Path $candidate)) { continue }
        $bundleRoot = if (Test-Path (Join-Path $candidate "release-bundles")) { Join-Path $candidate "release-bundles" } else { $candidate }
        $localArchive = Join-Path $bundleRoot $assetName
        $localSums = Join-Path $bundleRoot "SHA256SUMS.txt"
        if (-not (Test-Path $localArchive) -or -not (Test-Path $localSums)) {
            $localErrors += "$candidate found but required files are missing ($assetName and SHA256SUMS.txt)"
            continue
        }
        try {
            Restore-ThirdPartyFromArchive -ArchivePath $localArchive -SumsPath $localSums -ExtractRoot $bundleRoot -SourceLabel "local bundle $candidate"
            Write-Host "third_party prepared from local bundle: $candidate"
            exit 0
        } catch {
            $localErrors += $_.Exception.Message
        }
    }
}

if ($CacheDir) {
    $baseCacheRoot = $CacheDir
} elseif ($env:THIRD_PARTY_CACHE_DIR) {
    $baseCacheRoot = $env:THIRD_PARTY_CACHE_DIR
} else {
    $baseCacheRoot = "D:\tmp\c-eyes-cache"
}

$repoName = Resolve-Repo
$tagName = Resolve-Tag
if (-not $repoName -or -not $tagName) {
    $hint = "unable to resolve release source. Set THIRD_PARTY_REPO and THIRD_PARTY_TAG or put tag in third_party/version.txt"
    if ($localErrors.Count -gt 0) {
        throw ($hint + "`nlocal bundle errors:`n- " + ($localErrors -join "`n- "))
    }
    throw $hint
}

$cacheRoot = Join-Path $baseCacheRoot "third-party\$($repoName.Replace('/','_'))\$tagName"
New-Item -ItemType Directory -Force $cacheRoot | Out-Null

$baseUrl = "https://github.com/$repoName/releases/download/$tagName"
$archivePath = Join-Path $cacheRoot $assetName
$sumsPath = Join-Path $cacheRoot "SHA256SUMS.txt"

if (-not [string]::IsNullOrWhiteSpace($thirdPartyProxy)) {
    Write-Host "Downloading c-eyes-third-party.zip from $repoName@$tagName (proxy=$thirdPartyProxy)"
} else {
    Write-Host "Downloading c-eyes-third-party.zip from $repoName@$tagName"
}

$bundleError = ""
try {
    Restore-FromReleaseBundle -BaseUrl $baseUrl -CacheRoot $cacheRoot -AssetName $assetName -SourceLabel "release bundle $repoName@$tagName"
    Write-Host "third_party prepared for $Platform/$Arch"
    exit 0
} catch {
    $bundleError = $_.Exception.Message
}

Write-Host "release bundle unavailable; trying split asset $assetName"
try {
    Download-File -Url "$baseUrl/$assetName" -OutFile $archivePath
    Download-File -Url "$baseUrl/SHA256SUMS.txt" -OutFile $sumsPath
    Restore-ThirdPartyFromArchive -ArchivePath $archivePath -SumsPath $sumsPath -ExtractRoot $cacheRoot -SourceLabel "release $repoName@$tagName"
    Write-Host "third_party prepared for $Platform/$Arch"
    exit 0
} catch {
    $splitError = $_.Exception.Message
    $msg = "failed to restore third_party from release $repoName@$tagName.`nbundle: $bundleError`nsplit: $splitError"
    if ($localErrors.Count -gt 0) {
        $msg = $msg + "`nlocal bundle errors:`n- " + ($localErrors -join "`n- ")
    }
    throw $msg
}
