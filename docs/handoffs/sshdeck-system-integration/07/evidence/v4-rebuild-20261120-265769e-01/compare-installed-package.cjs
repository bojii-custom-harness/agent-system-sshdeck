'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.join(
  repo,
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-265769e-01',
);
const installed = path.join(
  process.env.LOCALAPPDATA,
  'Temp/opencode/sshdeck-ticket07-v4-265769e-01/node_modules/agent-system-sshdeck',
);
const archive = path.join(
  repo,
  'docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3/agent-system-sshdeck-0.1.3.tgz',
);

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function expectedInstalledBytes(filePath, source) {
  if (filePath !== 'bin/sshdeck.js') return { bytes: source, normalization: null };
  const firstLineEnd = source.indexOf(0x0a);
  if (firstLineEnd > 0 && source[firstLineEnd - 1] === 0x0d) {
    return {
      bytes: Buffer.concat([source.subarray(0, firstLineEnd - 1), source.subarray(firstLineEnd)]),
      normalization: 'npm Windows bin installation converts the shebang CRLF to LF',
    };
  }
  return { bytes: source, normalization: null };
}

const record = JSON.parse(fs.readFileSync(path.join(evidence, 'packlist.json'), 'utf8'))[0];
assert.equal(record.name, 'agent-system-sshdeck');
assert.equal(record.version, '0.1.3');

const files = record.files.map(({ path: filePath, size }) => {
  const source = fs.readFileSync(path.join(repo, filePath));
  const packageFile = fs.readFileSync(path.join(installed, filePath));
  const extracted = spawnSync('tar.exe', ['-xOf', archive, `package/${filePath}`], {
    cwd: repo,
    encoding: null,
    timeout: 10_000,
    windowsHide: true,
    maxBuffer: 2 * 1024 * 1024,
  });
  assert.equal(extracted.error, undefined, `tar extraction failed: ${filePath}`);
  assert.equal(extracted.status, 0, `tar extraction failed: ${filePath}`);
  assert.deepEqual(extracted.stdout, source, `archive content differs from source: ${filePath}`);
  const expected = expectedInstalledBytes(filePath, source);
  assert.equal(source.length, size, `source size mismatch: ${filePath}`);
  assert.deepEqual(packageFile, expected.bytes, `installed content differs beyond npm bin normalization: ${filePath}`);
  return {
    path: filePath,
    sourceSize: size,
    installedSize: packageFile.length,
    sourceSha256: sha256(source),
    installedSha256: sha256(packageFile),
    ...(expected.normalization ? { installedNormalization: expected.normalization } : {}),
  };
});

const readme = fs.readFileSync(path.join(installed, 'README.md'), 'utf8');
assert.match(readme, /version=\$\(node -p "require\('\.\/package\.json'\)\.version"\)/);
assert.match(readme, /git push origin "v\$version"/);

const report = {
  package: `${record.name}@${record.version}`,
  sourceCommit: '265769e815d608d7bfc1ce7cb83fc46b74cbfd0c',
  installedRoot: installed,
  entryCount: files.length,
  sourceArchiveContentsMatch: true,
  readmeUsesPackageVersionForTag: true,
  files,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
