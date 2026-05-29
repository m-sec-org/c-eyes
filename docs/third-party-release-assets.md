# Third-Party Release Assets

`c-eyes` source no longer stores heavy `third_party` binaries in Git.  
Build scripts can auto-download required dependencies from GitHub Release.

## Local bundle first (recommended)

Build scripts first look for a local folder named `c-eyes-third-party` before downloading.

Search order:

1. `<repo>/c-eyes-third-party`
2. `<repo>/../c-eyes-third-party`
3. `<repo>/../release-assets/c-eyes-third-party`
4. `<current-working-directory>/c-eyes-third-party`

Supported local layouts:

- `c-eyes-third-party/release-bundles/<asset files>`
- `c-eyes-third-party/<asset files>`

Required files in that local folder:

- platform asset file (`.zip` or `.tar.gz`)
- `SHA256SUMS.txt`

Validation steps:

1. Match expected asset entry in `SHA256SUMS.txt`
2. Verify SHA256 hash of the asset
3. Extract and verify required `third_party` target files

If local verification fails, scripts fall back to GitHub Release download.
If both local and Release paths fail, build exits with an explicit error.

## Release assets

- `third_party-windows-amd64.zip`
- `third_party-linux-glibc-2.28-amd64.tar.gz`
- `third_party-linux-glibc-2.28-arm64.tar.gz`
- `SHA256SUMS.txt`

Alternative release bundle supported by scripts:

- `c-eyes-third-party.zip` (contains `release-bundles/*` and `SHA256SUMS.txt`)

## Archive content rules

- `third_party-windows-amd64.zip` must contain:
  - `third_party/toolchain/...`
  - `third_party/yara-x-dist/...`
- Linux assets must contain:
  - `third_party/yara-x-dist-linux-glibc-2.28-<arch>/...`

## SHA256SUMS format

Each asset file must have one checksum line, for example:

```text
<sha256> *third_party-windows-amd64.zip
<sha256> *third_party-linux-glibc-2.28-amd64.tar.gz
<sha256> *third_party-linux-glibc-2.28-arm64.tar.gz
```

## How build scripts find release source

Priority for repo:

1. `THIRD_PARTY_REPO` environment variable
2. `third_party/repo.txt` (first non-comment line, `owner/repo`)
3. Git `remote.origin.url` parsed as GitHub repo

Priority for tag:

1. `THIRD_PARTY_TAG` environment variable
2. `third_party/version.txt` (first non-comment line, tag value)
3. Exact Git tag of current checkout

If repo or tag cannot be resolved, build fails with a clear message.
