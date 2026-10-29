# Copyright (c) 2026 AutoMint. License: see LICENSE.
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

root = Path(__file__).resolve().parent.parent
output = root / '.tools/artifacts'
output.mkdir(parents=True, exist_ok=True)
checksums = []
for target, maximum in [('forge-1.8.9', 52), ('fabric-1.21.11', 65), ('fabric-26.3', 69)]:
    jars = [p for p in (root / target / 'build/libs').glob('*.jar') if not re.search(r'-(thin|bundled|sources|dev)\.jar$', p.name)]
    if len(jars) != 1 or jars[0].is_symlink():
        raise ValueError('Expected exactly one final JAR')
    jar = jars[0]
    with zipfile.ZipFile(jar) as archive:
        names = archive.namelist()
        required = ['SCANNER-NOTES.md', 'LICENSE.txt', 'THIRD_PARTY.md', 'licenses/gson/LICENSE', 'licenses/bouncycastle/LICENSE',
                    'licenses/jna/LICENSE', 'licenses/jna/AL2.0', 'licenses/jna/libffi-LICENSE', 'licenses/jna-platform/LICENSE']
        if any('META-INF/mintauth/' + name not in names for name in required):
            raise ValueError('Missing notices')
        for architecture in ['aarch64', 'x86-64']:
            if 'com/sun/jna/darwin-' + architecture + '/libjnidispatch.jnilib' not in names:
                raise ValueError('Missing bundled macOS native architecture')
        native_names = {name for name in names if re.search(r'\.(so|dll|jnilib|a|dylib)$', name)}
        if native_names != {'com/sun/jna/win32-x86-64/jnidispatch.dll', 'com/sun/jna/linux-x86-64/libjnidispatch.so',
                            'com/sun/jna/darwin-x86-64/libjnidispatch.jnilib', 'com/sun/jna/darwin-aarch64/libjnidispatch.jnilib'}:
            raise ValueError('Native support matrix changed')
        if 'META-INF/services/java.security.Provider' in names or any(name.endswith('.class') and not name.endswith('/package-info.class') and re.search(r'/bc/(pqc/|jce/provider/|jcajce/provider/|math/ec/tools/|LICENSE.class)', name) for name in names):
            raise ValueError('Unused crypto providers/tools bundled')
        if len(names) != len(set(names)):
            raise ValueError('Duplicate archive entries')
        for entry in archive.infolist():
            name = entry.filename
            if name.startswith('net/minecraft/') or re.search(r'(^|/)(\.env[^/]*|header\.json|vault-[^/]+\.enc|[^/]+\.(pem|key))$', name):
                raise ValueError('Unexpected credential or game file')
            own = name.startswith(('online/automint/mintauth/core/', 'online/automint/mintauth/forge/', 'online/automint/mintauth/fabric/'))
            if name.endswith('.class') and (own or target == 'forge-1.8.9'):
                if entry.file_size > 4 * 1024 * 1024:
                    raise ValueError('Oversized class')
                data = archive.read(entry)
                limit = 52 if '/core/' in name else maximum
                if len(data) < 8 or int.from_bytes(data[6:8], 'big') > limit:
                    raise ValueError('Incompatible bytecode')
                if own and re.search(rb'ma_(at|rt)_[A-Za-z0-9_-]{43}|-----BEGIN (EC |RSA |ENCRYPTED )?PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,}', data):
                    raise ValueError('Credential-shaped constant')
    subprocess.run(['node', str(root / 'scripts/check-packaged-runtime.mjs'), str(jar)], check=True)
    destination = output / jar.name
    shutil.copyfile(jar, destination)
    checksums.append(hashlib.sha256(destination.read_bytes()).hexdigest() + '  ' + jar.name + '\n')
with (output / 'SHA256SUMS').open('w', encoding='utf-8', newline='\n') as manifest:
    manifest.write(''.join(sorted(checksums)))
print('Inspected three unsigned artifacts; release signing is a separate step.')
