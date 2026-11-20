'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.resolve(
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-2107539-01',
);
const staging = path.join(evidence, 'npm-pack-staging');
const expectedSource = '2107539cb4d1df65e071f01640e8c3406ed14e6f';
const currentSource = execFileSync('git.exe', ['rev-parse', 'HEAD'], {
  cwd: repo,
  encoding: 'utf8',
  timeout: 10_000,
  windowsHide: true,
}).trim();
const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
const rawPacklist = fs.readFileSync(path.join(evidence, 'npm-pack.stdout.txt'), 'utf8');
const records = JSON.parse(rawPacklist);

assert.equal(currentSource, expectedSource, 'source HEAD 不符合本次核准 SHA');
assert.equal(manifest.name, 'agent-system-sshdeck');
assert.equal(manifest.version, '0.1.3');
assert.ok(Array.isArray(records) && records.length === 1, 'npm pack 必須輸出一個 package record');

const record = records[0];
assert.equal(record.name, manifest.name);
assert.equal(record.version, manifest.version);
assert.equal(record.filename, `${manifest.name}-${manifest.version}.tgz`);
assert.ok(Array.isArray(record.files) && record.files.length > 0);
assert.equal(record.entryCount, record.files.length);
assert.ok(fs.statSync(path.join(staging, record.filename)).isFile(), 'npm pack archive 不存在');

const fileList = `${record.files
  .map(({ path: filePath, size, mode }) => `${filePath.replaceAll('\\', '/')} | ${size} bytes | mode ${mode}`)
  .join('\n')}\n`;
const packlistPath = path.join(evidence, 'packlist.json');
const fileListPath = path.join(evidence, 'file-list.txt');
const generationPath = path.join(evidence, 'packlist-generation.json');

fs.writeFileSync(packlistPath, `${JSON.stringify(records, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
fs.writeFileSync(fileListPath, fileList, { encoding: 'utf8', flag: 'wx' });
const generation = {
  runId: 'v4-rebuild-20261120-2107539-01-packlist-generation-01',
  result: 'passed',
  sourceCommit: currentSource,
  packageName: record.name,
  version: record.version,
  filename: record.filename,
  entryCount: record.entryCount,
  unpackedSize: record.unpackedSize,
  input: 'npm-pack.stdout.txt',
  outputs: ['packlist.json', 'file-list.txt'],
  createdAt: new Date().toISOString(),
};
fs.writeFileSync(generationPath, `${JSON.stringify(generation, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
process.stdout.write(`${JSON.stringify(generation, null, 2)}\n`);
