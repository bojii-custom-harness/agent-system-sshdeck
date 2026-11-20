'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.resolve(
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-2107539-01',
);
const candidate = path.resolve('docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3');
const replacement = path.join(evidence, 'candidate-replacement');
const expectedSource = '2107539cb4d1df65e071f01640e8c3406ed14e6f';
const expectedPreviousSource = '265769e815d608d7bfc1ce7cb83fc46b74cbfd0c';
const expectedPreviousArchiveSha256 = '0db06a8fd40ff82bd27ce9200034a47ecffa1332fc1d59999f1196f520dadbc9';
const sourceCommit = execFileSync('git.exe', ['rev-parse', 'HEAD'], {
  cwd: repo,
  encoding: 'utf8',
  timeout: 10_000,
  windowsHide: true,
}).trim();
assert.equal(sourceCommit, expectedSource, 'source HEAD 不符合本次核准 SHA');

const preservation = JSON.parse(fs.readFileSync(path.join(evidence, 'previous-candidate-preservation.metadata.json'), 'utf8'));
assert.equal(preservation.result, 'passed');
assert.equal(preservation.sourceCommit, expectedPreviousSource);
assert.equal(preservation.archiveSha256, expectedPreviousArchiveSha256);

const oldProvenance = JSON.parse(fs.readFileSync(path.join(candidate, 'provenance.json'), 'utf8'));
assert.equal(oldProvenance.sourceCommit, expectedPreviousSource);
assert.equal(oldProvenance.archiveSha256, expectedPreviousArchiveSha256);
const currentOldArchiveSha256 = createHash('sha256')
  .update(fs.readFileSync(path.join(candidate, oldProvenance.archive)))
  .digest('hex');
assert.equal(currentOldArchiveSha256, expectedPreviousArchiveSha256, '待覆寫的舊 archive 與核准舊 hash 不符');

const stagedVerification = JSON.parse(
  fs.readFileSync(path.join(evidence, 'candidate-stage-integrity.stdout.txt'), 'utf8'),
);
assert.equal(stagedVerification.result, 'passed');
assert.equal(stagedVerification.sourceCommit, expectedSource);

const files = [
  'agent-system-sshdeck-0.1.3.tgz',
  'SHA256SUMS',
  'file-list.txt',
  'packlist.json',
  'provenance.json',
];
const oldHashes = {};
const newHashes = {};
for (const file of files) {
  oldHashes[file] = fs.existsSync(path.join(candidate, file))
    ? createHash('sha256').update(fs.readFileSync(path.join(candidate, file))).digest('hex')
    : null;
  assert.ok(fs.statSync(path.join(replacement, file)).isFile(), `replacement 缺少檔案：${file}`);
}

for (const file of files) fs.copyFileSync(path.join(replacement, file), path.join(candidate, file));
for (const file of files) {
  const actual = fs.readFileSync(path.join(candidate, file));
  const expected = fs.readFileSync(path.join(replacement, file));
  assert.deepEqual(actual, expected, `candidate 安裝後位元組不符：${file}`);
  newHashes[file] = createHash('sha256').update(actual).digest('hex');
}

const record = {
  runId: 'v4-rebuild-20261120-2107539-01-candidate-install-01',
  result: 'passed',
  sourceCommit,
  previousCandidateSourceCommit: expectedPreviousSource,
  previousCandidateArchiveSha256: expectedPreviousArchiveSha256,
  replacedFiles: files,
  oldFileSha256: oldHashes,
  newFileSha256: newHashes,
  finishedAt: new Date().toISOString(),
};
fs.writeFileSync(
  path.join(evidence, 'candidate-install.json'),
  `${JSON.stringify(record, null, 2)}\n`,
  { encoding: 'utf8', flag: 'wx' },
);
process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
