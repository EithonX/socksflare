import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

test('package exposes TypeScript declarations', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.types, './index.d.ts');

  const dts = readFileSync(new URL('../index.d.ts', import.meta.url), 'utf8');
  assert.match(dts, /export class Socks5Client/);
  assert.match(dts, /export interface SocksflareFetchOptions/);
  assert.match(dts, /export function proxyFetch/);
  assert.match(dts, /export function socks5Connect/);
});
