#Requires -Version 7.0
<#
.SYNOPSIS
  Generate winget manifests from the built MSI packages.

.DESCRIPTION
  Manifest identifiers, the installer URL and the SHA256 all have to agree with the actual
  release, and they change every version. Generating them from the MSIs removes the class of
  error where a manifest points at the previous build.

  The three packages are separate identifiers rather than one package with switches, because
  the target is baked into the MSI's product identity (separate UpgradeCodes), so Windows
  sees them as genuinely different products.

  --release-base defaults to the project's GitHub Releases URL. Point it at a local folder to
  validate against files that are not published yet; winget validate only reads the document,
  so the URL does not have to resolve.

.EXAMPLE
  .\generate.ps1
  .\generate.ps1 -ReleaseBase 'https://github.com/Nesarf/Aragami/releases/download/v0.1.0'
#>
[CmdletBinding()]
param(
  [string]$MsiDir,
  [string]$OutDir = (Join-Path $PSScriptRoot 'manifests'),
  [string]$ReleaseBase,
  [string]$Publisher = 'Nesarf',
  [string]$License = 'MIT',
  [string]$PackageUrl = 'https://github.com/Nesarf/Aragami'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$version = (Get-Content (Join-Path $repo 'package.json') -Raw | ConvertFrom-Json).version
if (-not $ReleaseBase) { $ReleaseBase = "$PackageUrl/releases/download/v$version" }

# The MSIs are read from the checkout's artifacts directory by default. This used to point at
# one machine's download folder, which does not exist on a CI runner.
if (-not $MsiDir) { $MsiDir = Join-Path $repo 'artifacts' }

$defs = @(
  @{ Id = 'Nesarf.Aragami';         Moniker = 'aragami';         Name = 'Aragami';                     Desc = 'Static posture audit for Tor Browser and Firefox. Read-only: it reports configuration posture and static residue across build, transport, content/authorization, metadata and endpoint layers.'; Msi = "aragami-$version.msi" }
  @{ Id = 'Nesarf.Aragami.Tor';     Moniker = 'aragami-tor';     Name = 'Aragami for Tor Browser';     Desc = 'Static posture audit for Tor Browser: versions, bridges and pluggable transports, uTLS and domain fronting, onion client authorization, state guard residue, descriptor caches, disk location.'; Msi = "aragami-tor-$version.msi" }
  @{ Id = 'Nesarf.Aragami.Firefox'; Moniker = 'aragami-firefox'; Name = 'Aragami for Firefox';         Desc = 'Static posture audit for a plain Firefox profile: proxy and DoH and content-blocking prefs, saved logins and key material, history and cookies and site data, telemetry ID and account linkage, persistence.'; Msi = "aragami-firefox-$version.msi" }
)

# winget uses ProductCode to correlate an installed MSI with the manifest, so it has to be
# read from the package rather than guessed. The WindowsInstaller COM interface is the only
# way to do that without a WiX dependency at manifest-generation time.
function Get-MsiProductCode {
  param([Parameter(Mandatory)][string]$Msi)
  $wi = New-Object -ComObject WindowsInstaller.Installer
  try {
    $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($Msi, 0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db,
      @("SELECT Value FROM Property WHERE Property='ProductCode'"))
    # [void] is load-bearing: Execute returns null, and a bare method call puts that null on
    # the pipeline, which becomes part of this function's return value. The caller then holds
    # @($null, '<productcode>') and any member call on it fails on the null element.
    [void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    if (-not $rec) { return $null }
    $code = $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @(1))
    if (-not $code) { return $null }
    return [string]$code
  } finally {
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wi)
  }
}

# Manifests are tracked with LF endings (see .gitattributes). A here-string closing on
# its own line terminates with [Environment]::NewLine, which is CRLF on Windows, and
# Set-Content appends one more -- so without this the last line of every manifest would
# land in the repository with a different ending than the rest of the file. Git catches
# it (core.safecrlf), but the fix belongs here rather than in the repository config.
filter ConvertTo-Lf {
  ($_ -replace "`r`n", "`n")
}

$made = 0
foreach ($d in $defs) {
  $msi = Join-Path $MsiDir $d.Msi
  if (-not (Test-Path $msi)) { Write-Host "  [skip] $($d.Msi) not built yet" -ForegroundColor Yellow; continue }
  $sha = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
  $productCode = Get-MsiProductCode -Msi $msi
  if (-not $productCode) { Write-Host "  [!!] cannot read ProductCode from $($d.Msi)" -ForegroundColor Red; exit 1 }

  $dir = Join-Path $OutDir "$($d.Id)\$version"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null

  @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
PackageIdentifier: $($d.Id)
PackageVersion: $version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"@ | ConvertTo-Lf | Set-Content -LiteralPath (Join-Path $dir "$($d.Id).yaml") -Encoding UTF8 -NoNewline

  @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
PackageIdentifier: $($d.Id)
PackageVersion: $version
PackageLocale: en-US
Publisher: $Publisher
PublisherUrl: '$PackageUrl'
PublisherSupportUrl: '$PackageUrl/issues'
PackageName: $($d.Name)
PackageUrl: '$PackageUrl'
License: $License
LicenseUrl: '$PackageUrl/blob/main/LICENSE'
ShortDescription: '$($d.Desc)'
Description: '$($d.Desc) It never launches the browser under audit and never uses the network except for the version lookup, and every response carries a boundary notice stating what the audit does not cover. A clean audit is not proof of safety.'
Moniker: $($d.Moniker)
Tags:
  - security
  - privacy
  - audit
  - tor
  - firefox
  - opsec
  - cli
  - mcp
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"@ | ConvertTo-Lf | Set-Content -LiteralPath (Join-Path $dir "$($d.Id).locale.en-US.yaml") -Encoding UTF8 -NoNewline

  @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json
PackageIdentifier: $($d.Id)
PackageVersion: $version
InstallerType: wix
Scope: machine
InstallModes:
  - interactive
  - silent
  - silentWithProgress
UpgradeBehavior: install
Commands:
  - aragami
  - aragami-mcp
Installers:
  - Architecture: x64
    InstallerUrl: $ReleaseBase/$($d.Msi)
    InstallerSha256: $sha
    ProductCode: '$($productCode.Trim())'
ManifestType: installer
ManifestVersion: 1.6.0
"@ | ConvertTo-Lf | Set-Content -LiteralPath (Join-Path $dir "$($d.Id).installer.yaml") -Encoding UTF8 -NoNewline

  Write-Host "  [ok] $($d.Id) $version  sha256 $($sha.Substring(0,16))..." -ForegroundColor Green
  $made++
}
Write-Host "`n$made manifest set(s) in $OutDir" -ForegroundColor Magenta
