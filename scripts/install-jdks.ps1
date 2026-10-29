# Copyright (c) 2026 AutoMint. License: see LICENSE.
[CmdletBinding()]
param(
    [ValidateSet(8, 21, 25)]
    [int[]] $Major = @(8, 21, 25)
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolsRoot = Join-Path $projectRoot '.tools'
$downloadRoot = Join-Path $toolsRoot 'downloads'
New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null

foreach ($javaMajor in $Major) {
    $manifest = Get-Content -LiteralPath (Join-Path $projectRoot "tooling/jdk$javaMajor-windows-x64.json") -Raw | ConvertFrom-Json
    if ($manifest.javaHome -notmatch '^\.tools/[A-Za-z0-9.+_-]+$' -or
        $manifest.archive -notmatch '^OpenJDK[0-9A-Za-z_.-]+\.zip$' -or
        $manifest.url -notlike 'https://github.com/adoptium/temurin*-binaries/releases/download/*' -or
        $manifest.sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Invalid pinned JDK $javaMajor manifest."
    }
    $javaHomePath = Join-Path $projectRoot $manifest.javaHome
    if (Test-Path -LiteralPath $javaHomePath) {
        try {
            & (Join-Path $PSScriptRoot 'check-toolchains.ps1') -Major $javaMajor
        } catch {
            throw "Existing JDK $javaMajor could not be verified at $javaHomePath. Rename that directory to a backup, then rerun this installer to extract the verified archive again. Details: $_"
        }
        continue
    }
    $archivePath = Join-Path $downloadRoot $manifest.archive
    $cachedHash = if (Test-Path -LiteralPath $archivePath) {
        (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { '' }
    if ($cachedHash -ne $manifest.sha256) {
        $partialPath = "$archivePath.partial"
        Invoke-WebRequest -Uri $manifest.url -OutFile $partialPath -UseBasicParsing
        $actualHash = (Get-FileHash -LiteralPath $partialPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $manifest.sha256) {
            throw "JDK $javaMajor checksum mismatch. The download was not installed: $partialPath"
        }
        Move-Item -LiteralPath $partialPath -Destination $archivePath -Force
    }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $toolsRoot
    & (Join-Path $PSScriptRoot 'check-toolchains.ps1') -Major $javaMajor
}
