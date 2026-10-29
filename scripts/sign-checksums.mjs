// Copyright (c) 2026 AutoMint. License: see LICENSE.
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';

function read(path, maximum) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximum) throw new Error('Invalid input file');
  return readFileSync(path);
}
const [mode, manifest, option, keyPath] = process.argv.slice(2);
try {
  if (!manifest || !keyPath || !['--sign', '--verify'].includes(mode)
    || option !== (mode === '--sign' ? '--private-key-file' : '--public-key-file')) throw new Error('Invalid arguments');
  const bytes = read(manifest, 16384);
  if (!/^(?:[a-f0-9]{64}  mintauth-[A-Za-z0-9._-]+\.jar\n){3}$/.test(bytes.toString('utf8'))) throw new Error('Invalid checksum manifest');
  const material = read(keyPath, 16384);
  try {
    const key = mode === '--sign' ? createPrivateKey(material) : createPublicKey(material);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 key required');
    if (mode === '--sign') writeFileSync(manifest + '.sig', sign(null, bytes, key).toString('base64') + '\n', { flag: 'wx', mode: 0o600 });
    else if (!verify(null, bytes, key, Buffer.from(read(manifest + '.sig', 256).toString('utf8').trim(), 'base64'))) throw new Error('Signature mismatch');
  } finally { material.fill(0); }
  process.stdout.write(mode === '--sign' ? 'Checksum signature written.\n' : 'Checksum signature verified.\n');
} catch { process.stderr.write('Checksum signing/verification failed; no key material was printed.\n'); process.exitCode = 1; }
