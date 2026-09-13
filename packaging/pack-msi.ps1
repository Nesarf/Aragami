#Requires -Version 7.0
<#
.SYNOPSIS
  Build per-target MSI installers with WiX.

.DESCRIPTION
  Requires the WiX toolset, installed as a dotnet global tool outside the tool path:
      dotnet tool install wix --version 5.* --tool-path <dir>

  The MSI installs the same bundled payload as the portable zip, plus two things an
  installer is for: the launchers go on the system PATH, and upgrades replace rather than
  stack. Both depend on stable identifiers, which is why the UpgradeCode and the component
  GUID are constants here and not generated per build.

  Default install location is Program Files\Aragami. Pass -InstallFolderOverride at the
  msiexec command line to install elsewhere, which is also how the pack script verifies a
  build on a machine that must not write to the system drive.

.EXAMPLE
  .\pack-msi.ps1
  .\pack-msi.ps1 -Target tor
#>
[CmdletBinding()]
param(
  [ValidateSet('all', 'tor', 'firefox')][string]$Target = 'all',
  [string]$OutDir,
  [string]$TempDir,
  [string]$WixExe,
  [switch]$KeepStaging
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\stage-payload.ps1')

$repo = Split-Path $PSScriptRoot -Parent
$version = Get-AragamiVersion -Repo $repo

# Output and staging resolve to paths inside the checkout and to the OS temp directory, not to
# a layout outside the checkout. They used to default to a hardcoded absolute path, which does
# not exist on a CI runner, so every packaging step would have failed on the first New-Item --
# and even on a machine where that path does exist, the artifacts would have landed outside the
# artifacts/ directory the workflow uploads. Passing -OutDir / -TempDir explicitly still
# overrides both.
if (-not $OutDir)  { $OutDir  = Join-Path $repo 'artifacts' }
if (-not $TempDir) { $TempDir = Join-Path ([IO.Path]::GetTempPath()) 'aragami' }

# WiX is resolved rather than assumed. This parameter used to default to one machine's
# relocated tool path (a private tool directory, chosen to keep the .NET toolchain off the
# system drive), which meant the MSI step failed on any other machine -- including the CI
# runner, which installs the tool globally and would have been told "WiX not found" while WiX
# was sitting on PATH. An explicit -WixExe still wins.
if (-not $WixExe) {
  $cmd = Get-Command wix -ErrorAction SilentlyContinue
  if ($cmd) {
    $WixExe = $cmd.Source
  } else {
    # Where `dotnet tool install --global wix` puts it.
    $global = Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe'
    if (Test-Path $global) { $WixExe = $global }
  }
}

if (-not $WixExe -or -not (Test-Path $WixExe)) {
  Write-Host '  [!!] WiX not found.' -ForegroundColor Red
  Write-Host '       Install it with either of:' -ForegroundColor Yellow
  Write-Host '         dotnet tool install --global wix --version 5.*' -ForegroundColor Yellow
  Write-Host '         dotnet tool install wix --version 5.* --tool-path <dir>   then pass -WixExe <dir>\wix.exe' -ForegroundColor Yellow
  exit 1
}

# Stable identities. Changing an UpgradeCode makes the new version install alongside the old
# one instead of upgrading it, which is a silent, confusing failure -- so these are pinned.
$products = @{
  'all'     = @{ Name = 'Aragami (Tor and Firefox posture audit)'; UpgradeCode = 'ADE40F7B-E814-4EBC-A38E-757A911AE390'; PathGuid = 'D2A50295-051B-4CB2-8AD0-A39971254566'; Dir = 'Aragami' }
  'tor'     = @{ Name = 'Aragami for Tor Browser';                 UpgradeCode = '1A3E952F-4C37-43C0-830C-CAC1DF218825'; PathGuid = '94601A5D-1468-43E8-96CD-80E40D1D13DE'; Dir = 'Aragami' }
  'firefox' = @{ Name = 'Aragami for Firefox';                     UpgradeCode = '78195BBE-5742-48DF-B612-EA32A6007FC8'; PathGuid = 'C4D7ED7E-295C-4BCD-A748-3AC6EF84C5E8'; Dir = 'Aragami' }
}

if (-not (Test-Path $WixExe)) {
  Write-Host "  [!!] WiX not found at $WixExe" -ForegroundColor Red
  Write-Host '       dotnet tool install wix --version 5.* --tool-path <dir>' -ForegroundColor Yellow
  exit 1
}

$template = Get-Content (Join-Path $PSScriptRoot 'wix\Aragami.wxs.in') -Raw

foreach ($t in @($Target)) {
  $p = $products[$t]
  $suffix = if ($t -eq 'all') { '' } else { "-$t" }
  $stage = Join-Path $TempDir "msi-$t"
  $root = Join-Path $stage 'payload'
  $msi = Join-Path $OutDir "aragami$suffix-$version.msi"

  Write-Host "Building aragami$suffix-$version.msi" -ForegroundColor Magenta
  Stage-AragamiPayload -Repo $repo -Root $root -Target $t | Out-Null

  $wxs = $template.
    Replace('@NAME@', $p.Name).
    Replace('@DIRNAME@', $p.Dir).
    Replace('@VERSION@', $version).
    Replace('@UPGRADECODE@', $p.UpgradeCode).
    Replace('@PATHGUID@', $p.PathGuid).
    Replace('@PAYLOAD@', $root)
  $wxsPath = Join-Path $stage 'Aragami.wxs'
  Set-Content -LiteralPath $wxsPath -Value $wxs -Encoding UTF8
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

  # -pdbtype none: the .wixpdb is a build-time debug database, not a release artifact.
  & $WixExe build -pdbtype none -o $msi $wxsPath
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $msi)) { Write-Host '  [!!] wix build failed' -ForegroundColor Red; exit 1 }

  Write-Host "  [ok] $msi  ($([Math]::Round((Get-Item $msi).Length / 1KB, 1)) KB)" -ForegroundColor Green

  if (-not $KeepStaging) { Remove-Item $stage -Recurse -Force }
}

Write-Host "`nArtifacts in $OutDir" -ForegroundColor Magenta
