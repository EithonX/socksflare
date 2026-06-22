/**
 * Package smoke test.
 *
 * Runs `npm pack --json --dry-run`, parses the output, and asserts that the
 * packed file list contains every required path and excludes every forbidden
 * prefix.  Uses Node built-ins only (node:test, node:assert/strict,
 * node:child_process).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

/** Resolve the npm binary so the test works on Windows too. */
const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function packFiles() {
  const stdout = execFileSync(
    npmCmd,
    ['pack', '--json', '--dry-run'],
    { encoding: 'utf8', shell: process.platform === 'win32' },
  );
  /** @type {Array<{ files: Array<{ path: string }> }>} */
  const packages = JSON.parse(stdout);
  const first = packages[0];
  assert.ok(first, 'npm pack returned no package entries');
  return first.files.map((f) => f.path);
}

const REQUIRED = [
  'src/index.js',
  'index.d.ts',
  'rust-tls-wasm/pkg/rust_tls_wasm.js',
  'rust-tls-wasm/pkg/rust_tls_wasm.d.ts',
  'rust-tls-wasm/pkg/rust_tls_wasm_bg.wasm',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'example/worker.js',
];

const FORBIDDEN_PREFIXES = [
  '.agents/',
  '.github/',
  'tests/',
  'node_modules/',
];

test('packed files include all required paths', () => {
  const files = packFiles();
  const missing = REQUIRED.filter((req) => !files.includes(req));
  assert.deepEqual(
    missing,
    [],
    `Missing required files in package:\n  ${missing.join('\n  ')}\n\nActual files:\n  ${files.join('\n  ')}`,
  );
});

test('packed files exclude forbidden prefixes', () => {
  const files = packFiles();
  const violations = files.filter((f) =>
    FORBIDDEN_PREFIXES.some((prefix) => f.startsWith(prefix)),
  );
  assert.deepEqual(
    violations,
    [],
    `Forbidden files found in package:\n  ${violations.join('\n  ')}`,
  );
});
