'use strict';

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.resolve(
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-2107539-01',
);
const candidate = process.argv[2] && path.resolve(process.argv[2]);
assert.ok(candidate, '請提供 candidate 目錄');
const expectedSource = '2107539cb4d1df65e071f01640e8c3406ed14e6f';
const sourceCommit = execFileSync('git.exe', ['rev-parse', 'HEAD'], {
  cwd: repo,
  encoding: 'utf8',
  timeout: 10_000,
  windowsHide: true,
}).trim();
assert.equal(sourceCommit, expectedSource, 'source HEAD 不符合本次核准 SHA');

const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'));
const provenance = JSON.parse(fs.readFileSync(path.join(candidate, 'provenance.json'), 'utf8'));
const records = JSON.parse(fs.readFileSync(path.join(candidate, 'packlist.json'), 'utf8'));
const packRecords = JSON.parse(fs.readFileSync(path.join(evidence, 'npm-pack.stdout.txt'), 'utf8'));
assert.ok(Array.isArray(records) && records.length === 1);
assert.deepEqual(records, packRecords, 'candidate packlist 與 npm pack 輸出不同');

const record = records[0];
assert.equal(manifest.name, 'agent-system-sshdeck');
assert.equal(manifest.version, '0.1.3');
assert.equal(lock.name, manifest.name);
assert.equal(lock.version, manifest.version);
assert.equal(record.name, manifest.name);
assert.equal(record.version, manifest.version);
assert.equal(provenance.sourceCommit, sourceCommit);
assert.equal(provenance.packageName, manifest.name);
assert.equal(provenance.version, manifest.version);
assert.equal(provenance.archive, record.filename);
assert.equal(provenance.entryCount, record.entryCount);
assert.equal(provenance.unpackedSize, record.unpackedSize);

const archivePath = path.join(candidate, provenance.archive);
const archive = fs.readFileSync(archivePath);
const archiveSha256 = createHash('sha256').update(archive).digest('hex');
const npmShasum = createHash('sha1').update(archive).digest('hex');
const npmIntegrity = `sha512-${createHash('sha512').update(archive).digest('base64')}`;
const checksum = fs.readFileSync(path.join(candidate, 'SHA256SUMS'), 'utf8').trim();
assert.equal(archive.length, record.size);
assert.equal(archive.length, provenance.archiveSize);
assert.equal(archiveSha256, provenance.archiveSha256);
assert.equal(archiveSha256, `${checksum.split(/\s+/)[0]}`);
assert.equal(checksum, `${archiveSha256}  ${provenance.archive}`);
assert.equal(npmShasum, record.shasum);
assert.equal(npmShasum, provenance.npmShasum);
assert.equal(npmIntegrity, record.integrity);
assert.equal(npmIntegrity, provenance.npmIntegrity);

const normalizedFileList = fs.readFileSync(path.join(candidate, 'file-list.txt'), 'utf8')
  .replaceAll('\r\n', '\n')
  .replaceAll('\r', '\n');
const expectedFileList = `${record.files
  .map(({ path: filePath, size, mode }) => `${filePath.replaceAll('\\', '/')} | ${size} bytes | mode ${mode}`)
  .join('\n')}\n`;
assert.equal(normalizedFileList, expectedFileList, 'candidate file list 與 packlist 不符');

const files = record.files.map(({ path: filePath, size, mode }) => {
  const normalizedPath = filePath.replaceAll('\\', '/').replace(/^\.\//, '');
  const source = fs.readFileSync(path.join(repo, normalizedPath));
  assert.equal(source.length, size, `source 檔案大小不符：${normalizedPath}`);
  const extracted = spawnSync('tar.exe', ['-xOf', archivePath, `package/${normalizedPath}`], {
    cwd: repo,
    encoding: null,
    timeout: 10_000,
    windowsHide: true,
    maxBuffer: 2 * 1024 * 1024,
  });
  assert.equal(extracted.error, undefined, `archive 解壓失敗：${normalizedPath}：${extracted.error?.message}`);
  assert.equal(extracted.status, 0, `archive 解壓退出碼不為 0：${normalizedPath}`);
  assert.deepEqual(extracted.stdout, source, `archive 內容與核准 source 不同：${normalizedPath}`);
  return {
    path: normalizedPath,
    size,
    mode,
    archiveContentMatchesSource: true,
  };
});

process.stdout.write(`${JSON.stringify({
  result: 'passed',
  candidatePath: path.relative(repo, candidate).replaceAll('\\', '/'),
  sourceCommit,
  package: `${manifest.name}@${manifest.version}`,
  archive: provenance.archive,
  archiveSize: archive.length,
  archiveSha256,
  npmShasum,
  npmIntegrity,
  entryCount: record.entryCount,
  unpackedSize: record.unpackedSize,
  packlistMatchesNpmOutput: true,
  fileListMatchesPacklist: true,
  sourceArchiveBytesMatch: true,
  files,
}, null, 2)}\n`);
