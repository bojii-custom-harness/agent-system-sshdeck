'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const repo = process.cwd();
const candidate = path.join(
  repo,
  'docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3',
);
const evidence = path.join(
  repo,
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-265769e-01',
);
const provenance = JSON.parse(fs.readFileSync(path.join(candidate, 'provenance.json'), 'utf8'));
const packlist = JSON.parse(fs.readFileSync(path.join(candidate, 'packlist.json'), 'utf8'))[0];
const recordedPack = JSON.parse(fs.readFileSync(path.join(evidence, 'packlist.json'), 'utf8'))[0];
const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'));
const archivePath = path.join(candidate, provenance.archive);
const archive = fs.readFileSync(archivePath);
const sourceCommit = execFileSync('git.exe', ['rev-parse', 'HEAD'], {
  cwd: repo,
  encoding: 'utf8',
  timeout: 10_000,
  windowsHide: true,
}).trim();
const sha256 = createHash('sha256').update(archive).digest('hex');
const sha1 = createHash('sha1').update(archive).digest('hex');
const sha512Integrity = `sha512-${createHash('sha512').update(archive).digest('base64')}`;
const sums = fs.readFileSync(path.join(candidate, 'SHA256SUMS'), 'utf8').trim();
const expectedFileList = `${packlist.files
  .map(({ path: filePath, size, mode }) => `${filePath} | ${size} bytes | mode ${mode}`)
  .join('\n')}\n`;
const actualFileList = fs.readFileSync(path.join(candidate, 'file-list.txt'), 'utf8');
const normalizedFileList = actualFileList.replaceAll('\r\n', '\n').replaceAll('\r', '\n');

assert.equal(sourceCommit, '265769e815d608d7bfc1ce7cb83fc46b74cbfd0c');
assert.equal(provenance.sourceCommit, sourceCommit);
assert.equal(manifest.name, provenance.packageName);
assert.equal(manifest.version, provenance.version);
assert.equal(lock.name, manifest.name);
assert.equal(lock.version, manifest.version);
assert.deepEqual(packlist, recordedPack);
assert.equal(packlist.name, manifest.name);
assert.equal(packlist.version, manifest.version);
assert.equal(packlist.entryCount, packlist.files.length);
assert.equal(packlist.entryCount, provenance.entryCount);
assert.equal(packlist.unpackedSize, provenance.unpackedSize);
assert.equal(archive.length, provenance.archiveSize);
assert.equal(sha256, provenance.archiveSha256);
assert.equal(sha1, provenance.npmShasum);
assert.equal(sha512Integrity, provenance.npmIntegrity);
assert.equal(sums, `${sha256}  ${provenance.archive}`);
assert.equal(normalizedFileList, expectedFileList);

process.stdout.write(`${JSON.stringify({
  result: 'passed',
  sourceCommit,
  package: `${manifest.name}@${manifest.version}`,
  archive: provenance.archive,
  archiveSize: archive.length,
  archiveSha256: sha256,
  npmShasum: sha1,
  npmIntegrity: sha512Integrity,
  entryCount: packlist.entryCount,
  unpackedSize: packlist.unpackedSize,
  packlistMatchesEvidence: true,
  fileListMatchesPacklist: true,
  packageLockVersion: lock.lockfileVersion,
}, null, 2)}\n`);
