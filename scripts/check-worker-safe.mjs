import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const scanTargets = [
  path.join(root, 'src'),
  path.join(root, 'index.d.ts'),
];

const checks = [
  { label: 'node: import', pattern: /from\s+['"]node:[^'"]+['"]/g },
  { label: 'require()', pattern: /\brequire\s*\(/g },
  { label: 'Buffer', pattern: /\bBuffer\b/g },
  { label: 'process.', pattern: /\bprocess\./g },
  { label: 'fs import/reference', pattern: /\bfrom\s+['"]fs['"]|\bimport\s+['"]fs['"]|\brequire\s*\(\s*['"]fs['"]\s*\)/g },
  { label: 'net import/reference', pattern: /\bfrom\s+['"]net['"]|\bimport\s+['"]net['"]|\brequire\s*\(\s*['"]net['"]\s*\)/g },
  { label: 'tls import/reference', pattern: /\bfrom\s+['"]tls['"]|\bimport\s+['"]tls['"]|\brequire\s*\(\s*['"]tls['"]\s*\)/g },
  { label: 'http2 import/reference', pattern: /\bfrom\s+['"]http2['"]|\bimport\s+['"]http2['"]|\brequire\s*\(\s*['"]http2['"]\s*\)/g },
  { label: 'Node crypto import/reference', pattern: /\bfrom\s+['"]crypto['"]|\bimport\s+['"]crypto['"]|\brequire\s*\(\s*['"]crypto['"]\s*\)/g },
];

const findings = [];

for (const target of scanTargets) {
  walk(target);
}

if (findings.length > 0) {
  for (const finding of findings) {
    console.error(`${finding.file}:${finding.line} ${finding.label}`);
    console.error(`  ${finding.text}`);
  }
  process.exit(1);
}

console.log('Worker-safe scan passed: no obvious Node-only APIs found in src/ or index.d.ts');

function walk(target) {
  const stats = statSync(target);
  if (stats.isDirectory()) {
    for (const entry of readdirSync(target)) {
      walk(path.join(target, entry));
    }
    return;
  }

  const rel = path.relative(root, target);
  const source = readFileSync(target, 'utf8');
  const lines = source.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim() || /^\s*\/\//.test(line) || /^\s*\/\*/.test(line) || /^\s*\*/.test(line)) continue;
    for (const check of checks) {
      check.pattern.lastIndex = 0;
      if (check.pattern.test(line)) {
        findings.push({
          file: rel,
          line: index + 1,
          label: check.label,
          text: line.trim(),
        });
      }
    }
  }
}
