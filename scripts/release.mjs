// Copyright (c) 2026 AutoMint. License: see LICENSE.
import { createHash, createPrivateKey, createPublicKey, X509Certificate, sign, verify } from 'node:crypto';
import { constants, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, rmdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const targets = ['forge-1.8.9', 'fabric-1.21.11', 'fabric-26.3'];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function read(path, maximum) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximum) throw new Error('Unsafe or oversized release file');
  return readFileSync(path);
}
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', windowsHide: true, ...options });
  if (result.status !== 0) throw new Error(`Release step failed: ${command}`);
}
function javaHome() {
  if (process.env.MINTAUTH_JAVA_21_HOME) return process.env.MINTAUTH_JAVA_21_HOME;
  if (process.platform === 'win32') {
    return resolve(project, JSON.parse(read(join(project, 'tooling/jdk21-windows-x64.json'), 16384)).javaHome);
  }
  throw new Error('Set MINTAUTH_JAVA_21_HOME');
}
function javaTool(name) { return join(javaHome(), 'bin', name + (process.platform === 'win32' ? '.exe' : '')); }
function signingMaterial() {
  const signingRoot = process.env.MINTAUTH_SIGNING_HOME;
  if (!signingRoot) throw new Error('Set MINTAUTH_SIGNING_HOME to the protected signing directory');
  const directory = lstatSync(signingRoot);
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error('Unsafe signing directory');
  for (const name of ['release-private.pem', 'jar-signing.p12', 'jar-password']) {
    const stat = lstatSync(join(signingRoot, name));
    if (!stat.isFile() || stat.isSymbolicLink() || process.platform !== 'win32'
      && (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0)) throw new Error('Signing files must be private to the signing user');
  }
  if (process.platform !== 'win32' && (directory.uid !== process.getuid() || (directory.mode & 0o077) !== 0)) throw new Error('Signing directory must be private to the signing user');
  const material = read(join(signingRoot, 'release-private.pem'), 16384);
  let key;
  try { key = createPrivateKey(material); } finally { material.fill(0); }
  if (key.asymmetricKeyType !== 'ed25519' || !createPublicKey(key).export({ type: 'spki', format: 'der' }).equals(createPublicKey(read(join(project, 'signing/release-public.pub'), 16384)).export({ type: 'spki', format: 'der' }))) throw new Error('Unexpected signing key');
  const expectedCert = read(join(project, 'signing/jar-signing.crt'), 16384);
  const certificate = new X509Certificate(expectedCert);
  if (!certificate.raw.equals(new X509Certificate(read(join(signingRoot, 'jar-signing.crt'), 16384)).raw)) throw new Error('Unexpected JAR certificate');
  const exported = spawnSync(javaTool('keytool'), ['-exportcert', '-rfc', '-alias', 'mintauth', '-keystore', join(signingRoot, 'jar-signing.p12'),
    '-storetype', 'PKCS12', '-storepass:file', join(signingRoot, 'jar-password')], { encoding: 'utf8', stdio: 'pipe', timeout: 60000, maxBuffer: 32768, windowsHide: true });
  if (exported.status !== 0 || !new X509Certificate(exported.stdout).raw.equals(certificate.raw)) throw new Error('JAR keystore identity or password does not match');
  return { signingRoot, key, expectedCert };
}
function verifyJar(jar, certificate) {
  const temporary = mkdtempSync(join(tmpdir(), 'mintauth-trust-'));
  try {
    const store = join(temporary, 'trust.p12');
    run(javaTool('keytool'), ['-importcert', '-noprompt', '-alias', 'mintauth', '-file', certificate, '-keystore', store, '-storetype', 'PKCS12', '-storepass', 'mintauth-public-trust']);
    run(javaTool('jarsigner'), ['-verify', '-strict', '-keystore', store, '-storepass', 'mintauth-public-trust', jar, 'mintauth']);
  } finally {
    for (const name of readdirSync(temporary)) rmSync(join(temporary, name));
    rmdirSync(temporary);
  }
}
export function verifyBundle(directory, expectedCommit) {
  const publicKey = createPublicKey(read(join(project, 'signing/release-public.pub'), 16384));
  const bytes = read(join(directory, 'release.json'), 16384);
  const signature = read(join(directory, 'release.json.sig'), 256).toString('utf8').trim();
  if (!verify(null, bytes, publicKey, Buffer.from(signature, 'base64'))) throw new Error('Release signature mismatch');
  const manifest = JSON.parse(bytes);
  if (manifest.schema !== 'mintauth-release-v1' || !/^[a-f0-9]{40}$/.test(manifest.commit)
    || expectedCommit && manifest.commit !== expectedCommit || !['pilot', 'stable'].includes(manifest.channel)
    || !Array.isArray(manifest.files) || manifest.files.length !== 3) throw new Error('Invalid release metadata');
  const cert = new X509Certificate(read(join(project, 'signing/jar-signing.crt'), 16384));
  if (manifest.jarSignerSha256 !== hash(cert.raw)) throw new Error('JAR signer mismatch');
  for (const target of targets) {
    const file = manifest.files.find(file => file.target === target);
    if (!file || !new RegExp(`^mintauth-${target.replaceAll('.', '\\.')}-(?:[A-Za-z0-9._-]+)\\.jar$`).test(file.name)
      || !/^[a-f0-9]{64}$/.test(file.sha256) || !Number.isInteger(file.size) || file.size < 1 || file.size > 32 * 1024 * 1024) throw new Error('Invalid release file');
    const jar = read(join(directory, file.name), 32 * 1024 * 1024);
    if (jar.length !== file.size || hash(jar) !== file.sha256) throw new Error('Release file hash mismatch');
    verifyJar(join(directory, file.name), join(project, 'signing/jar-signing.crt'));
  }
  const sums = manifest.files.map(file => `${file.sha256}  ${file.name}\n`).sort().join('');
  if (read(join(directory, 'SHA256SUMS'), 16384).toString('utf8') !== sums
    || !verify(null, Buffer.from(sums), publicKey, Buffer.from(read(join(directory, 'SHA256SUMS.sig'), 256).toString('utf8').trim(), 'base64'))) throw new Error('Checksum manifest mismatch');
  return manifest;
}

async function main() {
  const [mode, input, output, commit, channel = 'pilot'] = process.argv.slice(2);
  if (mode === 'verify') { verifyBundle(resolve(input), output); process.stdout.write('Release, all file hashes and embedded JAR signatures verified.\n'); return; }
  if (mode === 'check-signing') { signingMaterial(); process.stdout.write('Private signing permissions and both pinned release identities verified.\n'); return; }
  if (mode === 'build') {
    if (process.platform === 'win32') {
      run('pwsh.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(project, 'scripts/build.ps1'), '-VerifyReproducible']);
      run('pwsh.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(project, 'scripts/package-artifacts.ps1')]);
    } else run('bash', [join(project, 'scripts/build-release.sh')]);
    return;
  }
  if (mode !== 'sign' || !input || !output || !/^[a-f0-9]{40}$/.test(commit ?? '') || !['pilot', 'stable'].includes(channel)) throw new Error('Usage: release.mjs check-signing | build | sign INPUT OUTPUT COMMIT [pilot|stable] | verify BUNDLE [COMMIT]');
  if (existsSync(output)) throw new Error('Output exists; refusing to overwrite a signed release');
  const { signingRoot, key, expectedCert } = signingMaterial();
  const entries = readdirSync(input).filter(name => name.endsWith('.jar'));
  if (entries.length !== 3) throw new Error('Expected exactly three final JARs');
  const files = [];
  mkdirSync(dirname(resolve(output)), { recursive: true, mode: 0o700 });
  mkdirSync(output, { mode: 0o700 });
  for (const target of targets) {
    const name = entries.find(name => name.startsWith(`mintauth-${target}-`) && /^mintauth-[A-Za-z0-9._-]+\.jar$/.test(name));
    if (!name) throw new Error('Missing target');
    read(join(input, name), 32 * 1024 * 1024);
    const destination = join(output, name);
    copyFileSync(join(input, name), destination, constants.COPYFILE_EXCL);
    run(javaTool('jarsigner'), ['-keystore', join(signingRoot, 'jar-signing.p12'), '-storetype', 'PKCS12', '-storepass:file', join(signingRoot, 'jar-password'), '-sigalg', 'SHA256withRSA', '-digestalg', 'SHA-256', destination, 'mintauth']);
    verifyJar(destination, join(project, 'signing/jar-signing.crt'));
    const bytes = read(destination, 32 * 1024 * 1024);
    files.push({ target, name, size: bytes.length, sha256: hash(bytes) });
  }
  const manifest = { schema: 'mintauth-release-v1', commit, channel, createdAt: new Date().toISOString(), jarSignerSha256: hash(new X509Certificate(expectedCert).raw), files };
  const sums = files.map(file => `${file.sha256}  ${file.name}\n`).sort().join('');
  for (const [name, bytes] of [['release.json', JSON.stringify(manifest) + '\n'], ['SHA256SUMS', sums]]) {
    writeFileSync(join(output, name), bytes, { flag: 'wx', mode: 0o600 });
    writeFileSync(join(output, name + '.sig'), sign(null, Buffer.from(bytes), key).toString('base64') + '\n', { flag: 'wx', mode: 0o600 });
  }
  verifyBundle(output, commit);
  process.stdout.write(`Signed ${channel} bundle created at ${resolve(output)}. Publication and website rollout were not performed.\n`);
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(error.message); process.exitCode = 1; });
