import { readFileSync } from 'node:fs';

const staleMessage =
  'rust-tls-wasm/pkg is stale. Run npm run build:wasm in CI or locally, then commit the regenerated rust-tls-wasm/pkg files.';

const files = {
  js: 'rust-tls-wasm/pkg/rust_tls_wasm.js',
  dts: 'rust-tls-wasm/pkg/rust_tls_wasm.d.ts',
  bgDts: 'rust-tls-wasm/pkg/rust_tls_wasm_bg.wasm.d.ts',
};

function readUtf8(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function fail(reasons) {
  for (const reason of reasons) {
    console.error(reason);
  }
  console.error(staleMessage);
  process.exitCode = 1;
}

const jsSource = readUtf8(files.js);
const dtsSource = readUtf8(files.dts);
const bgDtsSource = readUtf8(files.bgDts);
const reasons = [];

if (!/constructor\s*\(\s*hostname\s*,\s*alpn_csv\s*,\s*extra_roots\s*\)/.test(jsSource)) {
  reasons.push(`${files.js}: missing constructor third parameter extra_roots.`);
}

const wasmNewCallMatch = jsSource.match(/wasm\.wasmtlsclient_new\(([^)]*)\)/);
if (!wasmNewCallMatch) {
  reasons.push(`${files.js}: missing wasm.wasmtlsclient_new(...) call.`);
} else {
  const argCount = wasmNewCallMatch[1]
    .split(',')
    .map(part => part.trim())
    .filter(Boolean)
    .length;
  if (argCount <= 5) {
    reasons.push(`${files.js}: wasm.wasmtlsclient_new(...) still uses stale two-argument constructor wiring.`);
  }
}

if (!/constructor\s*\(\s*hostname:\s*string\s*,\s*alpn_csv\?:\s*string\s*\|\s*null\s*,\s*extra_roots\?:/m.test(dtsSource)) {
  reasons.push(`${files.dts}: constructor type missing optional extra_roots parameter.`);
}

const bgNewMatch = bgDtsSource.match(/wasmtlsclient_new:\s*\(([^)]*)\)\s*=>\s*void/);
if (!bgNewMatch) {
  reasons.push(`${files.bgDts}: missing wasmtlsclient_new signature.`);
} else {
  const argCount = bgNewMatch[1]
    .split(',')
    .map(part => part.trim())
    .filter(Boolean)
    .length;
  if (argCount <= 5) {
    reasons.push(`${files.bgDts}: wasmtlsclient_new signature still has stale 5-parameter shape.`);
  }
}

if (reasons.length > 0) {
  fail(reasons);
} else {
  console.log('rust-tls-wasm/pkg constructor API matches extra-root WASM bindings.');
}
