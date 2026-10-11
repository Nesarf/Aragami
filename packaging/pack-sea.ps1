#Requires -Version 7.0
<#
.SYNOPSIS
  Build single-file executables with Node SEA.

.DESCRIPTION
  Wraps the whole pipeline: bundle to CommonJS, prepare the SEA blob, copy node.exe and
  inject the blob with postject. The result needs no Node.js on the target machine.

  Two things are easy to get wrong here and are handled explicitly:
    - The payload must be CommonJS. Node's SEA loader decides the module type from the
      executable's extension, not the payload's, so an ESM payload inside a .exe fails with
      "Cannot use import statement outside a module".
    - The target default has to be baked at build time, because an executable cannot export
      an environment variable to itself. An explicit --target argument still overrides it.

  Cost note: the output is roughly the size of node.exe plus the payload, about 90 MB per
  executable. That is the price of needing no runtime on the target.

.EXAMPLE
  .\pack-sea.ps1
  .\pack-sea.ps1 -Target tor
#>
[CmdletBinding()]
param(
  [ValidateSet('all', 'tor', 'firefox')]
  [string]$Target = 'all',

  [string]$OutDir,
  [string]$TempDir
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path $PSScriptRoot -Parent
$pkg = Get-Content (Join-Path $repo 'package.json') -Raw | ConvertFrom-Json
$version = $pkg.version

# Output and staging resolve to paths inside the checkout and to the OS temp directory, not to
# a layout outside the checkout. They used to default to a hardcoded absolute path, which does
# not exist on a CI runner, so every packaging step would have failed on the first New-Item --
# and even on a machine where that path does exist, the artifacts would have landed outside the
# artifacts/ directory the workflow uploads. Passing -OutDir / -TempDir explicitly still
# overrides both.
if (-not $OutDir)  { $OutDir  = Join-Path $repo 'artifacts' }
if (-not $TempDir) { $TempDir = Join-Path ([IO.Path]::GetTempPath()) 'aragami' }

# The sentinel fuse is a fixed marker inside node.exe. Confirm it is present rather than
# trusting the constant, so a Node upgrade that renames it fails loudly here.
$nodeExe = (Get-Command node).Source
$fuse = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'
$needle = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($nodeExe))
if ($needle.IndexOf($fuse) -lt 0) {
  Write-Host "  [!!] $fuse not found in $nodeExe -- the fuse name changed; check node --help" -ForegroundColor Red
  exit 1
}

$postject = Join-Path $repo 'node_modules\postject\dist\cli.js'
if (-not (Test-Path $postject)) {
  Write-Host '  [!!] postject is not installed. Run: npm install' -ForegroundColor Red
  exit 1
}

$work = Join-Path $TempDir 'aragami-sea'
New-Item -ItemType Directory -Force -Path $work, $OutDir | Out-Null

# One variant per invocation, matching every other packaging script. `all` means the neutral
# package that auto-detects at runtime, not "all three packages" -- which is what the other
# five scripts mean by it, and what this one did not. The difference was invisible until CI
# was read against it: the workflow called this script once and the portable and MSI scripts
# three times, and both were correct, for different reasons. Someone copying one pattern onto
# the other script would have got a silently incomplete or pointlessly repeated artifact set.
# The caller now loops for all six forms, with no exceptions to remember.
$variants = switch ($Target) {
  'all'     { @{ name = 'aragami';         bake = $null;     out = 'dist' } }
  'tor'     { @{ name = 'aragami-tor';     bake = 'tor';     out = 'dist-tor' } }
  'firefox' { @{ name = 'aragami-firefox'; bake = 'firefox'; out = 'dist-ff' } }
}

foreach ($v in $variants) {
  Write-Host "Building $($v.name).exe" -ForegroundColor Magenta

  $bundleArgs = @((Join-Path $repo 'packaging\bundle.mjs'), '--entry', 'sea', '--outdir', $v.out)
  if ($v.bake) { $bundleArgs += @('--bake-target', $v.bake) }
  & node @bundleArgs | Out-Null

  $payload = Join-Path $repo "$($v.out)\aragami.cjs"
  if (-not (Test-Path $payload)) { Write-Host "  [!!] bundle missing: $payload" -ForegroundColor Red; exit 1 }

  $exe = "$($v.name).exe"
  Copy-Item $payload (Join-Path $work 'payload.cjs') -Force
  Copy-Item $nodeExe (Join-Path $work $exe) -Force
  @{ main = 'payload.cjs'; output = 'payload.blob'; disableExperimentalSEAWarning = $true } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $work 'sea-config.json') -Encoding UTF8

  Push-Location $work
  & node --experimental-sea-config sea-config.json 2>&1 | Out-Null
  Pop-Location

  $out = & node $postject (Join-Path $work $exe) NODE_SEA_BLOB (Join-Path $work 'payload.blob') `
           --sentinel-fuse $fuse 2>&1 | Out-String
  if ($out -notmatch 'Injection done') {
    Write-Host "  [!!] injection failed:" -ForegroundColor Red
    $out -split "`n" | Select-Object -First 5 | ForEach-Object { Write-Host "      $_" }
    exit 1
  }

  $dest = Join-Path $OutDir $exe
  Move-Item (Join-Path $work $exe) $dest -Force

  # CLEAR THE PE'S CERTIFICATE-TABLE DIRECTORY ENTRY, because postject leaves it stale.
  #
  # postject inserts a section and appends the blob, but the optional header's data directory entry 4
  # (IMAGE_DIRECTORY_ENTRY_SECURITY) keeps the offset it had in the base node.exe. In the produced file
  # that offset lands in the middle of the section data -- measured on every executable built for this
  # project and its sibling: 72435712 + 10448 in the published artifacts, 93365760 + 15688 against the
  # local node, with the sections ending at the file length in both -- and signtool then refuses the
  # WHOLE file with 0x800700C1 ERROR_BAD_EXE_FORMAT ("bad exe format"), while an ordinary PE of the
  # same size signs beside it without complaint.
  #
  # The entry is meaningless in an unsigned file, and the executable runs either way; both were
  # measured, before and after signing. Clearing it here means every artifact this repository builds
  # can be signed, instead of each release rediscovering the same rejection.
  $bytes = [System.IO.File]::ReadAllBytes($dest)
  $peOff = [BitConverter]::ToInt32($bytes, 0x3C)
  $optOff = $peOff + 4 + 20
  $magic = [BitConverter]::ToUInt16($bytes, $optOff)
  $dirsOff = $optOff + $(if ($magic -eq 0x20b) { 112 } else { 96 })
  $entryOff = $dirsOff + (4 * 8)
  $staleVa = [BitConverter]::ToInt32($bytes, $entryOff)
  $staleSize = [BitConverter]::ToInt32($bytes, $entryOff + 4)
  if ($staleVa -ne 0 -or $staleSize -ne 0) {
    for ($i = 0; $i -lt 4; $i++) {
      $bytes[$entryOff + $i] = 0
      $bytes[$entryOff + 4 + $i] = 0
    }
    [System.IO.File]::WriteAllBytes($dest, $bytes)
    Write-Host ("    cleared a stale certificate-table entry (offset {0} size {1}) so the exe can be signed" -f $staleVa, $staleSize)
  }

  # Prove it runs rather than trusting the injection message.
  $probe = & $dest aragami_version --online false 2>&1 | Out-String
  $ok = $probe -match '"verdict"'
  $size = [Math]::Round((Get-Item $dest).Length / 1MB, 1)
  if ($ok) {
    $t = ([regex]::Match($probe, '"target":\s*"([a-z]+)"')).Groups[1].Value
    Write-Host "  [ok] $exe  ${size} MB  (default target: $t)" -ForegroundColor Green
  } else {
    Write-Host "  [!!] $exe built but did not run:" -ForegroundColor Red
    $probe -split "`n" | Select-Object -First 3 | ForEach-Object { Write-Host "      $_" }
    exit 1
  }
}

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`nDone. Artifacts in $OutDir" -ForegroundColor Magenta
