# Copyright (c) 2026 AutoMint. License: see LICENSE.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$output=Join-Path $projectRoot '.tools/artifacts'
New-Item -ItemType Directory -Force -Path $output | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$checksums=@()
foreach($target in @('forge-1.8.9','fabric-1.21.11','fabric-26.3')) {
    $candidates=@(Get-ChildItem -LiteralPath (Join-Path $projectRoot "$target/build/libs") -Filter '*.jar' |
        Where-Object {$_.Name -notmatch '-(bundled|thin|sources|dev)\.jar$'})
    if($candidates.Count -ne 1){throw "Expected one final $target JAR; remove stale versions from the build directory before packaging."}
    $jar=$candidates[0]
    $archive=[IO.Compression.ZipFile]::OpenRead($jar.FullName)
    try {
        $names=@($archive.Entries | ForEach-Object {$_.FullName})
        foreach($required in @('META-INF/mintauth/SCANNER-NOTES.md','META-INF/mintauth/LICENSE.txt','META-INF/mintauth/THIRD_PARTY.md','META-INF/mintauth/licenses/gson/LICENSE','META-INF/mintauth/licenses/bouncycastle/LICENSE','META-INF/mintauth/licenses/jna/LICENSE','META-INF/mintauth/licenses/jna/AL2.0','META-INF/mintauth/licenses/jna/libffi-LICENSE','META-INF/mintauth/licenses/jna-platform/LICENSE','com/sun/jna/darwin-aarch64/libjnidispatch.jnilib','com/sun/jna/darwin-x86-64/libjnidispatch.jnilib')) {
            if($names -notcontains $required){throw "$target is missing $required"}
        }
        $supportedNatives=@('com/sun/jna/win32-x86-64/jnidispatch.dll','com/sun/jna/linux-x86-64/libjnidispatch.so',
            'com/sun/jna/darwin-x86-64/libjnidispatch.jnilib','com/sun/jna/darwin-aarch64/libjnidispatch.jnilib')
        $nativeNames=@($names | Where-Object {$_ -match '\.(so|dll|jnilib|a|dylib)$'})
        if($nativeNames.Count -ne 4 -or @($supportedNatives | Where-Object {$names -notcontains $_}).Count -ne 0){throw "$target native support matrix changed"}
        $unusedCrypto=@($names | Where-Object {$_ -match '\.class$' -and $_ -notmatch '/package-info.class$' -and $_ -match '/bc/(pqc/|jce/provider/|jcajce/provider/|math/ec/tools/|LICENSE.class)'})
        if($names -contains 'META-INF/services/java.security.Provider' -or $unusedCrypto.Count -gt 0){throw "$target contains unused crypto providers/tools"}
        if($names | Where-Object {$_ -match '(^|/)(\.env[^/]*|header\.json|vault-[^/]+\.enc|[^/]+\.(pem|key))$|^net/minecraft/'}){throw "$target contains an unexpected credential or game file"}
        $maximum=if($target -eq 'forge-1.8.9'){52}elseif($target -eq 'fabric-1.21.11'){65}else{69}
        foreach($entry in $archive.Entries | Where-Object {if($target -eq 'forge-1.8.9'){$_.FullName -match '\.class$'}else{$_.FullName -match '^online/automint/mintauth/(core|forge|fabric)/.*\.class$'}}) {
            $stream=$entry.Open()
            try {$header=New-Object byte[] 8;if($stream.Read($header,0,8) -ne 8){throw 'Truncated class'}
                $major=([int]$header[6] -shl 8)+$header[7]
                $allowed=if($entry.FullName -match '/core/'){52}else{$maximum}
                if($major -gt $allowed){throw "$target contains incompatible bytecode: $($entry.FullName)"}
            }finally{$stream.Dispose()}
            if($entry.FullName -match '^online/automint/mintauth/(core|forge|fabric)/') {
                if($entry.Length -gt 4MB){throw 'Unexpected class size'}
                $secretStream=$entry.Open();$buffer=[IO.MemoryStream]::new()
                try {$secretStream.CopyTo($buffer);$text=[Text.Encoding]::ASCII.GetString($buffer.ToArray())
                    if($text -match 'ma_(at|rt)_[A-Za-z0-9_-]{43}|-----BEGIN (EC |RSA |ENCRYPTED )?PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,}') {throw 'Credential-shaped material in MintAuth classes'}
                }finally{$secretStream.Dispose();$buffer.Dispose()}
            }
        }
    }finally{$archive.Dispose()}
    & node (Join-Path $PSScriptRoot 'check-packaged-runtime.mjs') $jar.FullName
    if($LASTEXITCODE -ne 0){throw "$target packaged runtime failed"}
    $destination=Join-Path $output $jar.Name
    Copy-Item -LiteralPath $jar.FullName -Destination $destination -Force
    $checksums+="$((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant())  $($jar.Name)"
}
[IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS'),(($checksums | Sort-Object) -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
Write-Output "Verified three private pilot artifacts at $output. These are not signed official releases."
