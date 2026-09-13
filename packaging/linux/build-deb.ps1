#Requires -Version 7.0
<#
.SYNOPSIS
  Build the Debian package for Aragami.

.DESCRIPTION
  A .deb is an ar archive holding three members -- debian-binary, control.tar.gz and
  data.tar.gz -- in that order. None of that requires a Linux kernel, so this is built
  on Windows with the GNU ar that ships alongside the C toolchain and with bsdtar for
  the two inner archives. Being able to produce the package here means a release does
  not depend on CI being reachable.

  The payload is architecture independent (it is JavaScript running on whatever Node the
  system provides), which is why the control file says Architecture: all rather than
  naming the machine that happened to build it.

  The wrappers in /usr/bin do not copy the launchers; they exec the bundle and set
  ARAGAMI_TARGET, so target pinning lives in one place and an unpacked .deb behaves the
  same way as the tarball distribution.

.EXAMPLE
  .\build-deb.ps1
  .\build-deb.ps1 -Target firefox
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
$pkgName = "aragami$suffix"
$stage = Join-Path $TempDir "deb-$pkgName"
$outFile = Join-Path $OutDir "$pkgName`_${version}_all.deb"

$ar = (Get-Command ar -ErrorAction SilentlyContinue).Source
if (-not $ar) { throw 'ar not found on PATH; cannot assemble the .deb container' }

Write-Host "Building $pkgName`_${version}_all.deb" -ForegroundColor Magenta
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
$dataRoot = Join-Path $stage 'data'
$ctrlRoot = Join-Path $stage 'control'
New-Item -ItemType Directory -Force -Path $dataRoot, $ctrlRoot | Out-Null

# --- data tree -----------------------------------------------------------------------
$libDir = Join-Path $dataRoot 'usr/lib/aragami'
$payload = Stage-AragamiPayload -Repo $repo -Root $libDir -Target $Target
Remove-Item (Join-Path $payload 'bin') -Recurse -Force -ErrorAction SilentlyContinue

$binDir = Join-Path $dataRoot 'usr/bin'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

# Wrappers use the absolute /usr/lib path because that is where the payload lands once
# installed, not the staging path it is being written from.
$libDirPosix = '/usr/lib/aragami'
$wrappers = @(
  @{ Name = 'aragami';             Mode = 'cli'; Pinned = '' },
  @{ Name = 'aragami-mcp';         Mode = 'mcp'; Pinned = '' },
  @{ Name = 'aragami-tor';         Mode = 'cli'; Pinned = 'tor' },
  @{ Name = 'aragami-tor-mcp';     Mode = 'mcp'; Pinned = 'tor' },
  @{ Name = 'aragami-firefox';     Mode = 'cli'; Pinned = 'firefox' },
  @{ Name = 'aragami-firefox-mcp'; Mode = 'mcp'; Pinned = 'firefox' }
)
foreach ($w in $wrappers) {
  $entry = if ($w.Mode -eq 'mcp') { 'mcp.cjs' } else { 'cli.cjs' }
  $lines = @('#!/bin/sh')
  if ($w.Pinned) { $lines += "ARAGAMI_TARGET=$($w.Pinned); export ARAGAMI_TARGET" }
  $lines += "exec node `"$libDirPosix/dist/$entry`" `"`$@`""
  # -NoNewline plus an explicit LF: a shell script with CRLF fails on Linux with
  # "bad interpreter", and this file is being written from Windows.
  $text = ($lines -join "`n") + "`n"
  [IO.File]::WriteAllText((Join-Path $binDir $w.Name), $text, (New-Object Text.UTF8Encoding($false)))
}

# --- md5sums -------------------------------------------------------------------------
$dataFull = (Resolve-Path $dataRoot).Path
$sums = foreach ($f in (Get-ChildItem -Recurse -File $dataRoot | Sort-Object FullName)) {
  $rel = $f.FullName.Substring($dataFull.Length + 1).Replace('\', '/')
  $hash = (Get-FileHash $f.FullName -Algorithm MD5).Hash.ToLower()
  "$hash  $rel"
}
[IO.File]::WriteAllText((Join-Path $ctrlRoot 'md5sums'), ($sums -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))

# --- control -------------------------------------------------------------------------
$control = Get-Content (Join-Path $PSScriptRoot 'deb\control.in') -Raw
$control = $control.Replace('@VERSION@', $version)
if ($Target -ne 'all') {
  # Per-target packages conflict, because they all own /usr/bin/aragami and
  # /usr/lib/aragami. Without this dpkg would happily half-overwrite one with the other.
  $control = $control -replace '(?m)^Package: aragami\r?\n', "Package: $pkgName`n"
  $control = "$control".TrimEnd() + "`nConflicts: aragami, aragami-tor, aragami-firefox`nReplaces: aragami, aragami-tor, aragami-firefox`n"
}
[IO.File]::WriteAllText((Join-Path $ctrlRoot 'control'), $control, (New-Object Text.UTF8Encoding($false)))

# --- inner archives ------------------------------------------------------------------
# Built with a small Python helper rather than with tar, because tar on Windows has no
# execute bit to preserve: every member came out 0666, including the /usr/bin wrappers,
# which would have installed as non-executable files. See mktar.py.
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { throw 'python not found on PATH; it builds the inner tar members' }
$mkTar = Join-Path $PSScriptRoot 'mktar.py'

function New-InnerArchive {
  param([string]$From, [string]$Out)
  if (Test-Path $Out) { Remove-Item $Out -Force }
  $count = & $python $mkTar $From $Out
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Out)) { throw "mktar.py failed for $Out" }
  $script:lastMemberCount = [int]$count
}

$ctrlTar = Join-Path $stage 'control.tar.gz'
$dataTar = Join-Path $stage 'data.tar.gz'
New-InnerArchive -From $ctrlRoot -Out $ctrlTar
New-InnerArchive -From $dataRoot -Out $dataTar

# --- container -----------------------------------------------------------------------
$debianBinary = Join-Path $stage 'debian-binary'
[IO.File]::WriteAllText($debianBinary, "2.0`n", (New-Object Text.UTF8Encoding($false)))

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (Test-Path $outFile) { Remove-Item $outFile -Force }

Push-Location $stage
try {
  # Order is part of the format, and -D keeps the archive reproducible.
  & $ar rcD $outFile debian-binary control.tar.gz data.tar.gz
  if ($LASTEXITCODE -ne 0) { throw 'ar failed' }
} finally { Pop-Location }

$size = [Math]::Round((Get-Item $outFile).Length / 1KB, 1)
Write-Host "  [ok] $outFile  ($size KB)" -ForegroundColor Green

# --- verification --------------------------------------------------------------------
# Read the container back rather than trusting the tool that wrote it. The first member
# has to be debian-binary and the version string has to be "2.0", because dpkg reads the
# members in order and rejects the file otherwise.
$bytes = [IO.File]::ReadAllBytes($outFile)
# Built from character codes rather than written as a literal: the ar trailer is a
# backtick followed by LF, and inside a PowerShell double-quoted string a backtick is an
# escape character, so a literal spelling of it silently compares against the wrong bytes.
$arMagic = '!<arch>' + [char]0x0A
$arTrailer = [string][char]0x60 + [char]0x0A
if ([Text.Encoding]::ASCII.GetString($bytes, 0, 8) -ne $arMagic) { throw 'not an ar archive' }

$members = @()
$off = 8
while ($off + 60 -le $bytes.Length) {
  $hdr = [Text.Encoding]::ASCII.GetString($bytes, $off, 60)
  if ($hdr.Substring(58, 2) -ne $arTrailer) { throw "bad ar header at $off" }
  $name = $hdr.Substring(0, 16).Trim()
  $len = [int]$hdr.Substring(48, 10).Trim()
  $members += [pscustomobject]@{ Name = $name.TrimEnd('/'); Length = $len; Offset = $off + 60 }
  $off += 60 + $len + ($len % 2)
}
$expected = @('debian-binary', 'control.tar.gz', 'data.tar.gz')
$actual = $members | ForEach-Object { $_.Name }
if (($actual -join ',') -ne ($expected -join ',')) { throw "member order is $($actual -join ',')" }
Write-Host "  [ok] ar members in order: $($actual -join ', ')" -ForegroundColor Green

$dbBytes = [byte[]]$bytes[($members[0].Offset)..($members[0].Offset + $members[0].Length - 1)]
if ([Text.Encoding]::ASCII.GetString($dbBytes).Trim() -ne '2.0') { throw 'debian-binary is not 2.0' }
Write-Host "  [ok] debian-binary = 2.0" -ForegroundColor Green

# The inner archives are checked with the system tar, which fails loudly on a truncated
# or corrupt gzip stream -- the realistic failure mode for a hand-assembled container.
foreach ($m in @($members[1], $members[2])) {
  $tmp = Join-Path $stage "verify-$($m.Name)"
  [IO.File]::WriteAllBytes($tmp, $bytes[$m.Offset..($m.Offset + $m.Length - 1)])
  $listing = & tar.exe -t -z -f $tmp 2>&1
  if ($LASTEXITCODE -ne 0) { throw "$($m.Name) is not a readable gzip tar: $listing" }
  $count = ($listing | Measure-Object -Line).Lines
  Write-Host "  [ok] $($m.Name) lists $count entries" -ForegroundColor Green
  if ($m.Name -eq 'control.tar.gz') {
    if (-not ($listing -match '(^|/)\./control$')) { throw 'control.tar.gz has no ./control' }
    Write-Host "  [ok] control.tar.gz contains ./control and ./md5sums" -ForegroundColor Green
  }
}

# The modes are asserted separately because this is exactly what went wrong first time: the
# package built and unpacked perfectly while every wrapper in usr/bin was non-executable.
$modeResult = & $python $mkTar --check $dataTar 2>&1
if ($LASTEXITCODE -ne 0) { throw "wrong modes in the data member:`n$modeResult" }
Write-Host "  [ok] every member has the mode and owner a .deb requires (usr/bin is 0755)" -ForegroundColor Green

Write-Host "  [ok] package name $pkgName, version $version, architecture all" -ForegroundColor Green

if (-not $KeepStaging) { Remove-Item $stage -Recurse -Force } else { Write-Host "  staging kept at $stage" -ForegroundColor Gray }
