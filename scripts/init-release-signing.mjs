// Copyright (c) 2026 AutoMint. License: see LICENSE.
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

process.umask(0o077);
const [directory, javaHome] = process.argv.slice(2);
try {
  if (!directory || !javaHome) throw new Error();
  const root = resolve(directory), stat = lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error();
  const names = ['release-private.pem', 'release-public.pub', 'jar-signing.p12', 'jar-password', 'jar-signing.crt'];
  if (names.some(name => existsSync(join(root, name)))) throw new Error('Signing material already exists; refusing replacement');
  const pair = generateKeyPairSync('ed25519');
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  writeFileSync(join(root, names[0]), privatePem, { flag: 'wx', mode: 0o600 });
  writeFileSync(join(root, names[1]), publicPem, { flag: 'wx', mode: 0o600 });
  writeFileSync(join(root, 'jar-password'), randomBytes(48).toString('base64url'), { flag: 'wx', mode: 0o600 });
  const tool = join(javaHome, 'bin', process.platform === 'win32' ? 'keytool.exe' : 'keytool');
  const common = ['-keystore', join(root, 'jar-signing.p12'), '-storepass:file', join(root, 'jar-password'), '-alias', 'mintauth'];
  for (const args of [
    ['-genkeypair', ...common, '-storetype', 'PKCS12', '-keyalg', 'RSA', '-keysize', '3072', '-sigalg', 'SHA256withRSA', '-validity', '3650', '-dname', 'CN=MintAuth Release, O=Mint Enterprises'],
    ['-exportcert', ...common, '-rfc', '-file', join(root, 'jar-signing.crt')],
  ]) {
    const result = spawnSync(tool, args, { stdio: 'pipe', windowsHide: true });
    if (result.status !== 0) throw new Error('Keytool failed; retain partial material for operator recovery');
  }
  const fingerprint = createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  if (!readFileSync(join(root, 'jar-signing.crt')).includes('BEGIN CERTIFICATE')) throw new Error();
  process.stdout.write(`MintAuth signing material created. Public release-key SHA256: ${fingerprint}\n`);
} catch (error) {
  process.stderr.write(`${error.message || 'Signing initialization failed; no private material was printed'}\n`);
  process.exitCode = 1;
}
