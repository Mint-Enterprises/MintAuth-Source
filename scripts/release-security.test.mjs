// Copyright (c) 2026 AutoMint. License: see LICENSE.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root = mkdtempSync(join(tmpdir(), 'mintauth-signing-test-'));
const script = fileURLToPath(new URL('release.mjs', import.meta.url));
function run(directory, args = ['check-signing']) {
  return spawnSync(process.execPath, [script, ...args], { env: { ...process.env, MINTAUTH_SIGNING_HOME: directory }, encoding: 'utf8', windowsHide: true });
}
function fixture(name) {
  const directory = join(root, name); mkdirSync(directory, { mode: 0o700 });
  const key = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
  for (const [file, bytes] of [['release-private.pem', key], ['jar-signing.p12', 'synthetic'], ['jar-password', 'synthetic']]) writeFileSync(join(directory, file), bytes, { mode: 0o600 });
  return directory;
}
after(() => {
  if (dirname(root) !== resolve(tmpdir()) || !basename(root).startsWith('mintauth-signing-test-')) throw new Error('Unsafe test cleanup target');
  rmSync(root, { recursive: true, force: true });
});
test('missing signing material fails without creating an identity', () => {
  const directory = join(root, 'missing'); mkdirSync(directory, { mode: 0o700 });
  assert.notEqual(run(directory).status, 0);
});
test('a different valid Ed25519 key cannot adopt the pinned release identity', () => {
  const result = run(fixture('wrong-identity'));
  assert.notEqual(result.status, 0); assert.match(result.stderr, /Unexpected signing key/);
  assert.doesNotMatch(result.stdout + result.stderr, /BEGIN PRIVATE KEY/);
});
test('existing signed output cannot be overwritten, even before key access', () => {
  const output = join(root, 'already-signed'); mkdirSync(output);
  const result = run(join(root, 'absent-keys'), ['sign', join(root, 'absent-input'), output, 'a'.repeat(40), 'pilot']);
  assert.notEqual(result.status, 0); assert.match(result.stderr, /refusing to overwrite/);
});
test('Unix signing files readable by other users are rejected', { skip: process.platform === 'win32' }, () => {
  const directory = fixture('unsafe-mode'); chmodSync(join(directory, 'release-private.pem'), 0o644);
  const result = run(directory); assert.notEqual(result.status, 0); assert.match(result.stderr, /private to the signing user/);
});
