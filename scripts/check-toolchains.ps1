# Copyright (c) 2026 AutoMint. License: see LICENSE.
[CmdletBinding()]
param(
    [ValidateSet(8, 21, 25)]
    [int[]] $Major = @(8, 21, 25)
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
foreach ($javaMajor in $Major) {
    $manifest = Get-Content -LiteralPath (Join-Path $projectRoot "tooling/jdk$javaMajor-windows-x64.json") -Raw | ConvertFrom-Json
    if ($manifest.javaHome -notmatch '^\.tools/[A-Za-z0-9.+_-]+$') { throw 'Invalid project-local JDK path.' }
    $javaHomePath = Join-Path $projectRoot $manifest.javaHome
    foreach ($tool in @('java.exe', 'javac.exe', 'jar.exe')) {
        if (!(Test-Path -LiteralPath (Join-Path $javaHomePath "bin/$tool"))) {
            throw "Missing JDK $javaMajor tool: $tool. Run ./scripts/install-jdks.ps1 -Major $javaMajor"
        }
    }
    Write-Output "Checking pinned Temurin $($manifest.version) at $javaHomePath"
    & (Join-Path $javaHomePath 'bin/java.exe') -version
    if ($LASTEXITCODE -ne 0) { throw "JDK $javaMajor java check failed." }
    & (Join-Path $javaHomePath 'bin/javac.exe') -version
    if ($LASTEXITCODE -ne 0) { throw "JDK $javaMajor javac check failed." }
}
Write-Output 'Toolchain checks passed. No compilation or mod build was run.'
