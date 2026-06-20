import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const targets = [
  { dir: 'src', ext: '.js' },
  { dir: 'example', ext: '.js' },
  { dir: 'tests', ext: '.mjs' },
];

const files = [];

async function collectFiles(dir, ext) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err && err.code === 'ENOENT') return;
    throw err;
  }

  for (const entry of entries) {
    const path = join(dir, entry.name);

    if (entry.isDirectory()) {
      await collectFiles(path, ext);
      continue;
    }

    if (entry.isFile() && path.endsWith(ext)) {
      files.push(path);
    }
  }
}

for (const target of targets) {
  await collectFiles(target.dir, target.ext);
}

if (files.length === 0) {
  throw new Error('No files matched syntax check targets');
}

for (const file of files.sort()) {
  await execFileAsync(process.execPath, ['--check', file]);
}
