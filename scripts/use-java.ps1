# Copyright (c) 2026 AutoMint. License: see LICENSE.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(8, 21, 25)]
    [int] $Major
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$manifest = Get-Content -LiteralPath (Join-Path $projectRoot "tooling/jdk$Major-windows-x64.json") -Raw | ConvertFrom-Json
if ($manifest.javaHome -notmatch '^\.tools/[A-Za-z0-9.+_-]+$') { throw 'Invalid project-local JDK path.' }
$javaHomePath = Join-Path $projectRoot $manifest.javaHome
$javaBin = Join-Path $javaHomePath 'bin'
if (!(Test-Path -LiteralPath (Join-Path $javaBin 'javac.exe'))) {
    throw "JDK $Major is not installed. Run ./scripts/install-jdks.ps1 -Major $Major"
}
$env:JAVA_HOME = $javaHomePath
$pathEntries = @($env:PATH -split ';' | Where-Object { $_ -and $_ -ne $javaBin })
$env:PATH = (@($javaBin) + $pathEntries) -join ';'
Write-Output "Selected project-local JDK $Major for this terminal: $javaHomePath"
