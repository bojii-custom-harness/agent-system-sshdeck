'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const packageManifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) return undefined;
  return process.argv[index + 1];
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function runGit(args) {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `git ${args[0]} failed`);
  return result.stdout.trim();
}

function runNpmPack(destination) {
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli && path.isAbsolute(npmCli), '請透過 npm run candidate:source 執行');
  const result = spawnSync(process.execPath, [
    npmCli,
    'pack',
    '--json',
    '--pack-destination',
    destination,
  ], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `npm pack failed with exit ${result.status}`);
  const records = JSON.parse(result.stdout);
  assert.ok(Array.isArray(records) && records.length === 1, 'npm pack 必須產生單一 package archive');
  const record = records[0];
  assert.equal(record.name, packageManifest.name);
  assert.equal(record.version, packageManifest.version);
  const archivePath = path.join(destination, record.filename);
  assert.ok(fs.statSync(archivePath).isFile(), 'npm pack archive 必須存在');
  return {
    archivePath,
    filename: record.filename,
    bytes: fs.statSync(archivePath).size,
    sha256: sha256(archivePath),
      files: record.files
        .map((item) => item.path.replaceAll('\\', '/').replace(/^\.\//, ''))
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)),
  };
}

function main() {
  const outputArgument = argument('--output-dir');
  assert.ok(outputArgument, '用法：npm run candidate:source -- --output-dir <external-directory> [--manifest <repo-relative-path>]');
  const outputDir = path.resolve(root, outputArgument);
  const relativeOutput = path.relative(root, outputDir);
  assert.ok(
    relativeOutput === '..'
      || relativeOutput.startsWith(`..${path.sep}`)
      || path.isAbsolute(relativeOutput),
    'candidate archive 與證據必須保存在 source repo 之外');

  const manifestArgument = argument('--manifest');
  const manifestPath = manifestArgument ? path.resolve(root, manifestArgument) : undefined;
  if (manifestPath) {
    const relativeManifest = path.relative(root, manifestPath);
    assert.ok(!relativeManifest.startsWith('..') && !path.isAbsolute(relativeManifest),
      'candidate manifest 必須位於 source repo 內');
    assert.ok(!fs.existsSync(manifestPath), 'candidate manifest 已存在；拒絕覆寫');
  }

  const status = runGit(['status', '--porcelain']);
  assert.equal(status, '', 'candidate 必須從乾淨且已提交的 source snapshot 建立');
  const sourceCommit = runGit(['rev-parse', 'HEAD']);
  assert.match(sourceCommit, /^[0-9a-f]{40}$/);

  fs.mkdirSync(outputDir, { recursive: false });
  const firstDirectory = path.join(outputDir, 'pack-run-1');
  const secondDirectory = path.join(outputDir, 'pack-run-2');
  fs.mkdirSync(firstDirectory);
  fs.mkdirSync(secondDirectory);
  const first = runNpmPack(firstDirectory);
  const second = runNpmPack(secondDirectory);
  assert.equal(first.sha256, second.sha256, '相同 source commit 的兩次 npm pack archive SHA-256 必須一致');
  assert.deepEqual(first.files, second.files, '相同 source commit 的兩次 npm pack 檔案清單必須一致');
  assert.equal(first.bytes, second.bytes, '相同 source commit 的兩次 npm pack archive 大小必須一致');

  const candidateArchive = path.join(outputDir, first.filename);
  fs.copyFileSync(first.archivePath, candidateArchive, fs.constants.COPYFILE_EXCL);
  const candidateSha256 = sha256(candidateArchive);
  assert.equal(candidateSha256, first.sha256, 'candidate archive 複製後 hash 必須一致');
  const repository = packageManifest.repository?.url;
  assert.ok(typeof repository === 'string' && repository.length > 0, 'package.json 必須指定 repository URL');
  const manifest = {
    schemaVersion: 1,
    candidateType: 'local-source-package',
    repository,
    sourceCommit,
    package: {
      name: packageManifest.name,
      version: packageManifest.version,
    },
    archive: {
      filename: first.filename,
      bytes: first.bytes,
      sha256: candidateSha256,
    },
    reproducibility: {
      packRuns: 2,
      archiveSha256Matches: true,
      fileListsMatch: true,
      archiveSizesMatch: true,
    },
    files: first.files,
    publication: {
      officialRelease: 'not performed',
      gitTag: 'not created',
      registryPublish: 'not performed',
      deployment: 'not performed',
      agentSystemDeploymentPin: 'unchanged',
    },
  };

  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  fs.writeFileSync(path.join(outputDir, 'candidate-manifest.json'), manifestText, {
    encoding: 'utf8',
    flag: 'wx',
  });
  if (manifestPath) {
    fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
    fs.writeFileSync(manifestPath, manifestText, { encoding: 'utf8', flag: 'wx' });
  }
  process.stdout.write(`${JSON.stringify({
    sourceCommit,
    package: manifest.package,
    archive: manifest.archive,
    fileCount: manifest.files.length,
    reproducible: true,
    manifestPath: manifestPath ? path.relative(root, manifestPath).replaceAll('\\', '/') : undefined,
  }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`source candidate 建立失敗：${error.name} ${error.message}\n`);
  process.exitCode = 1;
}
