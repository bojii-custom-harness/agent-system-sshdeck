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
const staging = path.join(evidence, 'npm-pack-staging');
const replacement = path.join(evidence, 'candidate-replacement');
const expectedSource = '2107539cb4d1df65e071f01640e8c3406ed14e6f';
const previousSource = '265769e815d608d7bfc1ce7cb83fc46b74cbfd0c';
const previousArchiveSha256 = '0db06a8fd40ff82bd27ce9200034a47ecffa1332fc1d59999f1196f520dadbc9';

const sourceCommit = execFileSync('git.exe', ['rev-parse', 'HEAD'], {
  cwd: repo,
  encoding: 'utf8',
  timeout: 10_000,
  windowsHide: true,
}).trim();
const sourceTree = execFileSync('git.exe', ['rev-parse', 'HEAD^{tree}'], {
  cwd: repo,
  encoding: 'utf8',
  timeout: 10_000,
  windowsHide: true,
}).trim();
assert.equal(sourceCommit, expectedSource, 'source HEAD 不符合本次核准 SHA');
assert.equal(fs.existsSync(replacement), false, 'candidate replacement 目錄已存在');

const oldProvenance = JSON.parse(fs.readFileSync(path.join(candidate, 'provenance.json'), 'utf8'));
assert.equal(oldProvenance.sourceCommit, previousSource, '舊 provenance source 與預期不同');
assert.equal(oldProvenance.archiveSha256, previousArchiveSha256, '舊 provenance archive hash 與預期不同');

const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
const packlist = JSON.parse(fs.readFileSync(path.join(evidence, 'packlist.json'), 'utf8'))[0];
const sourceArchive = path.join(staging, packlist.filename);
const archive = fs.readFileSync(sourceArchive);
const archiveSha256 = createHash('sha256').update(archive).digest('hex');
const npmShasum = createHash('sha1').update(archive).digest('hex');
const npmIntegrity = `sha512-${createHash('sha512').update(archive).digest('base64')}`;
assert.equal(packlist.name, manifest.name);
assert.equal(packlist.version, manifest.version);
assert.equal(packlist.shasum, npmShasum);
assert.equal(packlist.integrity, npmIntegrity);
assert.equal(packlist.size, archive.length);

fs.mkdirSync(replacement, { recursive: false });
const archiveName = packlist.filename;
fs.copyFileSync(sourceArchive, path.join(replacement, archiveName), fs.constants.COPYFILE_EXCL);
fs.copyFileSync(path.join(evidence, 'packlist.json'), path.join(replacement, 'packlist.json'), fs.constants.COPYFILE_EXCL);
fs.copyFileSync(path.join(evidence, 'file-list.txt'), path.join(replacement, 'file-list.txt'), fs.constants.COPYFILE_EXCL);
fs.writeFileSync(
  path.join(replacement, 'SHA256SUMS'),
  `${archiveSha256}  ${archiveName}\n`,
  { encoding: 'utf8', flag: 'wx' },
);

const createdAt = new Date().toISOString();
const provenance = {
  ticket: 'SSHDeck Ticket 07',
  baseCommit: 'c2b96f437bcf1ae1122b113794292996aaca485f',
  sourceCommit,
  sourceTree,
  packageName: manifest.name,
  version: manifest.version,
  archive: archiveName,
  archiveSha256,
  npmShasum,
  npmIntegrity,
  archiveSize: archive.length,
  entryCount: packlist.entryCount,
  unpackedSize: packlist.unpackedSize,
  packlist: 'packlist.json',
  fileList: 'file-list.txt',
  createdAt,
  previousCandidateSourceCommit: oldProvenance.sourceCommit,
  previousCandidateArchiveSha256: oldProvenance.archiveSha256,
};
fs.writeFileSync(
  path.join(replacement, 'provenance.json'),
  `${JSON.stringify(provenance, null, 2)}\n`,
  { encoding: 'utf8', flag: 'wx' },
);

const candidateUpdate = {
  runId: 'v4-rebuild-20261120-2107539-01-candidate-update-01',
  updatedAt: createdAt,
  sourceCommit,
  sourceTree,
  package: `${manifest.name}@${manifest.version}`,
  entryCount: packlist.entryCount,
  unpackedSize: packlist.unpackedSize,
  archive: archiveName,
  archiveSize: archive.length,
  archiveSha256,
  npmShasum,
  npmIntegrity,
  candidatePath: 'docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3',
  replacementPath: path.relative(repo, replacement).replaceAll('\\', '/'),
  previousCandidateSourceCommit: oldProvenance.sourceCommit,
  previousCandidateArchiveSha256: oldProvenance.archiveSha256,
};
fs.writeFileSync(
  path.join(evidence, 'candidate-update.json'),
  `${JSON.stringify(candidateUpdate, null, 2)}\n`,
  { encoding: 'utf8', flag: 'wx' },
);
fs.writeFileSync(
  path.join(evidence, 'candidate-preparation.metadata.json'),
  `${JSON.stringify({
    runId: 'v4-rebuild-20261120-2107539-01-candidate-preparation-01',
    result: 'passed',
    sourceCommit,
    sourceTree,
    replacementFiles: ['agent-system-sshdeck-0.1.3.tgz', 'SHA256SUMS', 'file-list.txt', 'packlist.json', 'provenance.json'],
    archiveSize: archive.length,
    archiveSha256,
    preparedAt: createdAt,
  }, null, 2)}\n`,
  { encoding: 'utf8', flag: 'wx' },
);
process.stdout.write(`${JSON.stringify(candidateUpdate, null, 2)}\n`);
