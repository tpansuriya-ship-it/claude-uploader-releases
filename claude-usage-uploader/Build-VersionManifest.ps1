# Generates version.json for the agent auto-update Gist, from a PUBLISHED GitHub release.
#
#   .\Build-VersionManifest.ps1 -Version 2.0.9
#
# Options:
#   -Repo   tpansuriya-ship-it/claude-uploader-releases
#   -OutFile version.json
#   -Verify  also re-download each binary and confirm its hash (slow, ~300 MB)
#
# WHY THIS EXISTS: the checksums in version.json were previously copied by hand from
# SHA256SUMS.txt. A single wrong character makes every agent reject the download it just
# fetched, and the failure looks like "the update server is broken" rather than "the
# manifest is wrong". This reads the published sums directly, so they cannot be mistyped.
#
# ASCII only - PowerShell 5.1 reads .ps1 as ANSI without a BOM.

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Version,
  [string]$Repo = 'tpansuriya-ship-it/claude-uploader-releases',
  [string]$OutFile = '',
  [switch]$Verify
)

$ErrorActionPreference = 'Stop'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'version.json' }

function Step($t) { Write-Host "`n==> $t" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "    OK   $t" -ForegroundColor Green }
function Bad($t)  { Write-Host "    FAIL $t" -ForegroundColor Red }
function Note($t) { Write-Host "    ..   $t" -ForegroundColor Gray }

$tag  = "v$Version"
$base = "https://github.com/$Repo/releases/download/$tag"

Step "Fetching SHA256SUMS.txt from $tag"

$sumsUrl = "$base/SHA256SUMS.txt"
try {
  $sums = (Invoke-WebRequest $sumsUrl -UseBasicParsing).Content
  Ok "downloaded from $sumsUrl"
} catch {
  Bad "Could not fetch $sumsUrl"
  Note 'Has the tag been pushed and has the build finished? Check the Actions tab.'
  Note "  git tag $tag ; git push origin $tag"
  exit 1
}

# Lines are "<sha256>  <filename>", as produced by sha256sum.
$map = @{}
foreach ($line in ($sums -split "`r?`n")) {
  if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
    $map[$matches[2].Trim()] = $matches[1].ToLower()
  }
}
Ok "$($map.Count) checksum(s) parsed"
foreach ($k in ($map.Keys | Sort-Object)) { Note "$k" }

Step 'Mapping binaries to platform keys'

# One binary can serve several keys - the agent looks itself up by process.platform and
# sometimes by platform-arch, so both spellings must be present or an update silently
# finds no entry and never installs.
$binaries = @{
  'win-x64'     = "ClaudeUsageUploader_v$Version-win-x64.exe"
  'macos-arm64' = "ClaudeUsageUploader_v$Version-macos-arm64"
  'macos-x64'   = "ClaudeUsageUploader_v$Version-macos-x64"
  'linux-x64'   = "ClaudeUsageUploader_v$Version-linux-x64"
}
$keysFor = @{
  'win-x64'     = @('win32', 'win32-x64')
  'macos-arm64' = @('darwin', 'darwin-arm64')
  'macos-x64'   = @('darwin-x64')
  'linux-x64'   = @('linux', 'linux-x64')
}

$platforms = [ordered]@{}
$missing = @()

foreach ($b in 'win-x64','macos-arm64','macos-x64','linux-x64') {
  $file = $binaries[$b]
  if (-not $map.ContainsKey($file)) { $missing += $file; continue }
  foreach ($key in $keysFor[$b]) {
    $platforms[$key] = [ordered]@{
      downloadUrl = "$base/$file"
      checksum    = $map[$file]
    }
  }
  Ok "$file -> $($keysFor[$b] -join ', ')"
}

if ($missing.Count -gt 0) {
  Bad "Missing from SHA256SUMS.txt: $($missing -join ', ')"
  Note 'The release is incomplete. Do NOT publish this manifest - agents on those'
  Note 'platforms would have no entry and would silently never update.'
  exit 1
}

if ($Verify) {
  Step 'Re-downloading each binary to confirm its hash'
  foreach ($b in 'win-x64','macos-arm64','macos-x64','linux-x64') {
    $file = $binaries[$b]
    $tmp = Join-Path $env:TEMP $file
    Note "downloading $file"
    Invoke-WebRequest "$base/$file" -OutFile $tmp -UseBasicParsing
    $actual = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $map[$file]) { Ok "$file hash matches" }
    else { Bad "$file hash MISMATCH - published sums do not match the published binary"; exit 1 }
    Remove-Item -LiteralPath $tmp -Force
  }
}

Step 'Writing the manifest'

$manifest = [ordered]@{ latestVersion = $Version; platforms = $platforms }
$json = $manifest | ConvertTo-Json -Depth 5
Set-Content -Path $OutFile -Value $json -Encoding UTF8
Ok "$OutFile"

Write-Host ''
Write-Host $json -ForegroundColor Gray
Write-Host ''
Write-Host '--------------------------------------------------------------' -ForegroundColor Gray
Write-Host 'NEXT: paste the JSON above into the update Gist.' -ForegroundColor White
Write-Host '  https://gist.github.com/tpansuriya-ship-it/efa5db7d25aaa85db78d8bdc402f9903'
Write-Host ''
Write-Host 'NOTHING SELF-UPDATES UNTIL THAT GIST IS SAVED. The release existing on' -ForegroundColor Yellow
Write-Host 'GitHub is not enough - the Gist is what agents actually read.'
Write-Host ''
Write-Host 'Then pilot ONE machine before letting the fleet follow:'
Write-Host '  - dashboard shows it on 2.0.9'
Write-Host '  - a report still lands in Drive'
Write-Host '  - %TEMP%\claude-uploader.log says "Reporting to https://claudeusage..."'
Write-Host '--------------------------------------------------------------' -ForegroundColor Gray
