#Requires -Version 7.0
<#
.SYNOPSIS
  Build the portable, no-install distribution of Aragami.

.DESCRIPTION
  Produces a zip that runs from any directory with Node.js >= 18 on PATH.

  The payload is the bundled CommonJS output, not the source tree plus node_modules. That
  matters: the MCP SDK drags in 95 packages and 16 MB, which made the zip 5 MB and the build
  take over eight minutes. The bundle is one 720 KB file, so the package is a few hundred
  kilobytes and builds in seconds.

  The payload is identical across targets; only the launchers differ. Forking the code per
  target would mean two implementations to keep in step.

.EXAMPLE
  .\pack-portable.ps1
  .\pack-portable.ps1 -Target firefox
#>
[CmdletBinding()]
param(
  [ValidateSet('all', 'tor', 'firefox')][string]$Target = 'all',
  [string]$OutDir,
  [string]$TempDir,
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

$suffix = if ($Target -eq 'all') { '' } else { "-$Target" }
$name = "aragami$suffix-$version"
$stage = Join-Path $TempDir "pack-$name"
$zip = Join-Path $OutDir "$name-portable.zip"

Write-Host "Building $name-portable.zip" -ForegroundColor Magenta
$root = Stage-AragamiPayload -Repo $repo -Root (Join-Path $stage $name) -Target $Target
New-AragamiPortableNote -Root $root -Target $Target -Version $version
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (Test-Path $zip) { Remove-Item $zip -Force }
# bsdtar is far faster than Compress-Archive on many small files and ships with Windows 10+,
# macOS and most Linux distributions.
if (Get-Command tar.exe -ErrorAction SilentlyContinue) {
  & tar.exe -a -c -f $zip -C $stage $name
} else {
  Compress-Archive -Path $root -DestinationPath $zip -CompressionLevel Optimal
}
if (-not (Test-Path $zip) -or (Get-Item $zip).Length -eq 0) { throw 'zip was not produced' }

Write-Host "  [ok] $zip  ($([Math]::Round((Get-Item $zip).Length / 1KB, 1)) KB)" -ForegroundColor Green
if (-not $KeepStaging) { Remove-Item $stage -Recurse -Force } else { Write-Host "  staging kept at $stage" -ForegroundColor Gray }
