# Copyright (c) 2026 AutoMint. License: see LICENSE.
[CmdletBinding()]
param([ValidateSet('all','core','forge-1.8.9','fabric-1.21.11','fabric-26.3')][string]$Target='all', [switch]$VerifyReproducible)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
function Clear-GeneratedReadOnly {
foreach($relativeOutput in @('.tools/builds','forge-1.8.9/build','fabric-1.21.11/build','fabric-26.3/build')) {
$generatedRoot=Join-Path $projectRoot $relativeOutput
if(Test-Path -LiteralPath $generatedRoot) {
    $generated=Get-Item -Force -LiteralPath $generatedRoot
    if($generated.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Generated build root must not be a link'}
    $items=@($generated)+@(Get-ChildItem -LiteralPath $generatedRoot -Recurse -Force)
    foreach($item in $items) {
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
        if($item.Attributes -band [IO.FileAttributes]::ReadOnly) {
            $item.Attributes=$item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
        }
    }
}
}
}
Clear-GeneratedReadOnly
& (Join-Path $PSScriptRoot 'check-toolchains.ps1')
$javaHomes=@{}
foreach($major in @(8,21,25)) {
    $manifest=Get-Content -LiteralPath (Join-Path $projectRoot "tooling/jdk$major-windows-x64.json") -Raw | ConvertFrom-Json
    $javaHomes[$major]=(Resolve-Path -LiteralPath (Join-Path $projectRoot $manifest.javaHome)).Path
}
$oldJava=$env:JAVA_HOME
$oldGradle=$env:GRADLE_USER_HOME
try {
    $env:GRADLE_USER_HOME=Join-Path $projectRoot '.tools/gradle-cache'
    $targets=if($Target -eq 'all'){@('core','forge-1.8.9','fabric-1.21.11','fabric-26.3')}else{@($Target)}
    foreach($item in $targets) {
        $legacy=$item -in @('core','forge-1.8.9')
        $version=if($legacy){'9.2.0'}else{'9.8.2'}
        & (Join-Path $PSScriptRoot 'install-gradle.ps1') -Version $version
        $env:JAVA_HOME=if($legacy){$javaHomes[21]}else{$javaHomes[25]}
        $directory=if($item -eq 'core'){$projectRoot}else{Join-Path $projectRoot $item}
        Push-Location -LiteralPath $directory
        try {
            $task=if($item -eq 'core'){'core:test'}else{'build'}
            & (Join-Path $projectRoot ".tools/gradle-$version/bin/gradle.bat") --no-daemon "-Dorg.gradle.java.installations.paths=$($javaHomes.Values -join ',')" --dependency-verification=strict $task
            if($LASTEXITCODE -ne 0){throw "MintAuth $item failed"}
            if($VerifyReproducible -and $item -ne 'core') {
                $finalJars=@(Get-ChildItem -LiteralPath (Join-Path $directory 'build/libs') -Filter '*.jar' | Where-Object {$_.Name -notmatch '-(bundled|thin|sources|dev)\.jar$'})
                if($finalJars.Count -ne 1){throw "Expected one final $item JAR"}
                $before=(Get-FileHash -LiteralPath $finalJars[0].FullName -Algorithm SHA256).Hash
                Clear-GeneratedReadOnly
                & (Join-Path $projectRoot ".tools/gradle-$version/bin/gradle.bat") --no-daemon "-Dorg.gradle.java.installations.paths=$($javaHomes.Values -join ',')" --dependency-verification=strict --rerun-tasks $task
                if($LASTEXITCODE -ne 0){throw "MintAuth $item reproducibility rebuild failed"}
                if((Get-FileHash -LiteralPath $finalJars[0].FullName -Algorithm SHA256).Hash -ne $before){throw "MintAuth $item is not byte-for-byte reproducible"}
                Write-Output "Byte-for-byte reproducibility verified: $item"
            }
        }finally{Pop-Location}
    }
}finally{$env:JAVA_HOME=$oldJava;$env:GRADLE_USER_HOME=$oldGradle}
