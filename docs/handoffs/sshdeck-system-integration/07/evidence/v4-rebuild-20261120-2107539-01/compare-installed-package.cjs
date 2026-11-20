'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.resolve(
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-2107539-01',
);
const candidateDir = path.resolve('docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3');
const installed = process.argv[2] && path.resolve(process.argv[2]);
assert.ok(installed, '請提供已安裝套件目錄');

const expectedSource = '2107539cb4d1df65e071f01640e8c3406ed14e6f';
const integrity = JSON.parse(fs.readFileSync(path.join(evidence, 'final-candidate-integrity.stdout.txt'), 'utf8'));
assert.equal(integrity.result, 'passed');
assert.equal(integrity.sourceCommit, expectedSource);
assert.ok(integrity.files.every((file) => file.archiveContentMatchesSource), 'candidate archive 未與 source 完整比對');

const record = JSON.parse(fs.readFileSync(path.join(candidateDir, 'packlist.json'), 'utf8'))[0];
const packageManifest = JSON.parse(fs.readFileSync(path.join(installed, 'package.json'), 'utf8'));
assert.equal(packageManifest.name, record.name);
assert.equal(packageManifest.version, record.version);

function expectedInstalledBytes(filePath, source) {
  if (filePath !== 'bin/sshdeck.js') return { bytes: source, normalization: null };
  const firstLineEnd = source.indexOf(0x0a);
  if (firstLineEnd > 0 && source[firstLineEnd - 1] === 0x0d) {
    return {
      bytes: Buffer.concat([source.subarray(0, firstLineEnd - 1), source.subarray(firstLineEnd)]),
      normalization: 'npm on Windows converts the bin shebang CRLF to LF',
    };
  }
  return { bytes: source, normalization: null };
}

const files = record.files.map(({ path: filePath, size }) => {
  const normalizedPath = filePath.replaceAll('\\', '/').replace(/^\.\//, '');
  const source = fs.readFileSync(path.join(repo, normalizedPath));
  const installedBytes = fs.readFileSync(path.join(installed, normalizedPath));
  assert.equal(source.length, size, `source size mismatch: ${normalizedPath}`);
  const expected = expectedInstalledBytes(normalizedPath, source);
  assert.deepEqual(installedBytes, expected.bytes, `installed package differs beyond expected npm normalization: ${normalizedPath}`);
  return {
    path: normalizedPath,
    sourceSize: source.length,
    installedSize: installedBytes.length,
    sourceSha256: createHash('sha256').update(source).digest('hex'),
    installedSha256: createHash('sha256').update(installedBytes).digest('hex'),
    ...(expected.normalization ? { installedNormalization: expected.normalization } : {}),
  };
});

const readme = fs.readFileSync(path.join(installed, 'README.md'), 'utf8');
assert.match(readme, /version=\$\(node -p "require\('\.\/package\.json'\)\.version"\)/);
assert.match(readme, /git push origin "v\$version"/);

process.stdout.write(`${JSON.stringify({
  result: 'passed',
  sourceCommit: expectedSource,
  package: `${packageManifest.name}@${packageManifest.version}`,
  installedRoot: installed,
  entryCount: files.length,
  sourceArchiveContentsMatch: true,
  installedContentsMatch: true,
  readmeUsesPackageVersionForTag: true,
  files,
}, null, 2)}\n`);
