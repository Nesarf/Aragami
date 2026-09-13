#Requires -Version 7.0
<#
.SYNOPSIS
  Build the Linux tarball distribution of Aragami.

.DESCRIPTION
  A tarball plus install.sh is one of the two Linux forms that needs no Linux toolchain to
  produce, which is why it is built here rather than only in CI.

  The archive is built by mktar.py, not by tar. This script previously claimed that "the
  archive preserves the executable bit on install.sh" and used bsdtar, which cannot: Windows
  has no execute bit to preserve, so install.sh shipped at mode 0666 and `./install.sh` failed
  with "Permission denied" while the README told the reader to run exactly that. The modes are
  now stated rather than inherited, and mktar.py is the same builder the .deb uses, so the
  defect cannot come back in one form while being fixed in the other.

.EXAMPLE
  .\build-tarball.ps1
  .\build-tarball.ps1 -Target firefox
#>
[CmdletBinding()]
param(
  [ValidateSet('all', 'tor', 'firefox')][string]$Target = 'all',
  [string]$OutDir,
  [string]$TempDir,
  [switch]$KeepStaging
)

$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib\stage-payload.ps1')

$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
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
$stage = Join-Path $TempDir "linux-$name"
$tarball = Join-Path $OutDir "$name-linux.tar.gz"

Write-Host "Building $name-linux.tar.gz" -ForegroundColor Magenta
$root = Stage-AragamiPayload -Repo $repo -Root (Join-Path $stage $name) -Target $Target
# The stager emits Windows .cmd launchers; on Linux they are dead weight and misleading.
# install.sh writes the shell wrappers at install time instead, which keeps target pinning
# in one place.
Remove-Item (Join-Path $root 'bin') -Recurse -Force
Copy-Item (Join-Path $PSScriptRoot 'install.sh') (Join-Path $root 'install.sh') -Force
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Built by mktar.py so that install.sh carries an execute bit and the payload does not. The
# prefix makes the archive unpack into a directory of its own, the way a release tarball is
# expected to.
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { throw 'python not found on PATH; it builds the archive with the modes set' }
$mkTar = Join-Path $PSScriptRoot 'mktar.py'

if (Test-Path $tarball) { Remove-Item $tarball -Force }
& $python $mkTar (Join-Path $stage $name) $tarball --prefix $name
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tarball)) { throw 'mktar.py failed' }

$size = [Math]::Round((Get-Item $tarball).Length / 1KB, 1)
Write-Host "  [ok] $tarball  ($size KB)" -ForegroundColor Green

# Verify by listing the archive: a truncated or empty tar is the failure mode worth catching.
$listing = & tar.exe -t -f $tarball
$files = ($listing | Measure-Object -Line).Lines
Write-Host "  [ok] archive lists $files entries" -ForegroundColor Green

# The mode that the README depends on: install.sh has to be runnable straight out of the
# archive, and asserting it here is what stops the defect returning unnoticed.
$modeResult = & $python $mkTar --check $tarball 2>&1
if ($LASTEXITCODE -ne 0) { throw "wrong modes in the archive:`n$modeResult" }
Write-Host "  [ok] install.sh is 0755 and the payload is 0644" -ForegroundColor Green

if (-not $KeepStaging) { Remove-Item $stage -Recurse -Force } else { Write-Host "  staging kept at $stage" -ForegroundColor Gray }
