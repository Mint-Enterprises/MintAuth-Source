# Copyright (c) 2026 AutoMint. License: see LICENSE.
[CmdletBinding()]
param([ValidateSet('9.2.0','9.8.2')][string]$Version='9.2.0')
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$hashes=@{ '9.2.0'='df67a32e86e3276d011735facb1535f64d0d88df84fa87521e90becc2d735444'; '9.8.2'='21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607' }
$archive=Join-Path $projectRoot ".tools/downloads/gradle-$Version-bin.zip"
$destination=Join-Path $projectRoot ".tools/gradle-$Version"
if (!(Test-Path -LiteralPath $archive)) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $archive) | Out-Null
    Invoke-WebRequest -Uri "https://services.gradle.org/distributions/gradle-$Version-bin.zip" -OutFile "$archive.partial" -TimeoutSec 300
    if ((Get-FileHash -LiteralPath "$archive.partial" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$Version]) { throw 'Gradle checksum mismatch' }
    Move-Item -LiteralPath "$archive.partial" -Destination $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$Version]) { throw 'Cached Gradle checksum mismatch' }
if (!(Test-Path -LiteralPath $destination)) { Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $projectRoot '.tools') }
Write-Output "Verified Gradle $Version at $destination"
