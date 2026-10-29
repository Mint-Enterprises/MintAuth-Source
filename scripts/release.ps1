# Copyright (c) 2026 AutoMint. License: see LICENSE.
[CmdletBinding()]
param([switch]$Pull, [ValidateSet('pilot','stable')][string]$Channel='pilot', [string]$Output)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    git diff --quiet HEAD
    if($LASTEXITCODE -ne 0){throw 'Commit or preserve tracked changes before making a source-bound release'}
    if($Pull) {
        git fetch --no-tags origin
        if($LASTEXITCODE -ne 0){throw 'Fetch failed'}
        git merge --ff-only '@{u}'
        if($LASTEXITCODE -ne 0){throw 'Fast-forward failed; checkout was not reset'}
    }
    $commit=(git rev-parse HEAD).Trim()
    if($commit -notmatch '^[a-f0-9]{40}$'){throw 'Invalid source commit'}
    if(-not $env:MINTAUTH_SIGNING_HOME){$env:MINTAUTH_SIGNING_HOME=Join-Path $env:LOCALAPPDATA 'MintAuthSigning'}
    if(-not $Output){$Output=Join-Path $projectRoot ".tools/signed/$commit-$Channel"}
    node scripts/release.mjs build
    if($LASTEXITCODE -ne 0){throw 'Release build failed'}
    node scripts/release.mjs sign .tools/artifacts $Output $commit $Channel
    if($LASTEXITCODE -ne 0){throw 'Release signing failed'}
    foreach($jar in Get-ChildItem -LiteralPath $Output -Filter '*.jar') {
        node scripts/check-packaged-runtime.mjs $jar.FullName (Join-Path $Output 'release.json') (Join-Path $Output 'release.json.sig')
        if($LASTEXITCODE -ne 0){throw 'Signed packaged runtime verification failed'}
    }
    Write-Output "Transfer the signed bundle (no private keys) to the deploy controller, then use: deploy mintauth $commit --mintauth-bundle <server-bundle-directory>"
}finally{Pop-Location}
