// Copyright (c) 2026 AutoMint. License: see LICENSE.
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve, delimiter } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [artifact, manifest, signature] = process.argv.slice(2);
if (!artifact || Boolean(manifest) !== Boolean(signature)) throw new Error('Usage: check-packaged-runtime.mjs JAR [MANIFEST SIGNATURE]');
const jar = resolve(artifact), work = mkdtempSync(join(tmpdir(), 'mintauth-packaged-probe-'));
const windows = process.platform === 'win32';
const javaHome = major => {
  const override = process.env[`MINTAUTH_JAVA_${major}_HOME`];
  if (override) return override;
  if (windows) return resolve(project, JSON.parse(readFileSync(join(project, `tooling/jdk${major}-windows-x64.json`))).javaHome);
  throw new Error(`Set MINTAUTH_JAVA_${major}_HOME`);
};
const tool = (major, name) => join(javaHome(major), 'bin', name + (windows ? '.exe' : ''));
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit', windowsHide: true, timeout: 120000 });
  if (result.status !== 0) throw new Error('Packaged runtime check failed');
}
try {
  if (!existsSync(jar)) throw new Error('Missing final JAR');
  run(tool(8, 'javac'), ['-encoding', 'UTF-8', '-cp', jar, '-d', work, join(project, 'scripts/PackagedRuntimeProbe.java')]);
  for (const major of [8, 21, 25]) {
    console.log(`Checking packaged runtime on Java ${major}`);
    run(tool(major, 'java'), ['-Xmx256m', '-cp', work + delimiter + jar,
      'online.automint.mintauth.probe.PackagedRuntimeProbe', ...(manifest ? [resolve(manifest), resolve(signature)] : [])]);
  }
} finally {
  function clean(path) {
    for (const item of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, item.name);
      if (item.isDirectory()) { clean(child); rmdirSync(child); }
      else unlinkSync(child);
    }
  }
  if (dirname(resolve(work)) !== resolve(tmpdir()) || !work.split(/[\\/]/).pop().startsWith('mintauth-packaged-probe-'))
    throw new Error('Unsafe probe cleanup');
  clean(work); rmdirSync(work);
}
