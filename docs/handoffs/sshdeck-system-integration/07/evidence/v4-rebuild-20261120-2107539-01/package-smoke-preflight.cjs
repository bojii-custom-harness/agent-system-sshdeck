'use strict';

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.resolve(
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-2107539-01',
);
const candidateDir = path.resolve('docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3');
const expectedSource = '2107539cb4d1df65e071f01640e8c3406ed14e6f';
const ports = [18792, 18793];
const localAppData = process.env.LOCALAPPDATA;
assert.ok(localAppData, 'LOCALAPPDATA 未設定，不能建立批准的隔離安裝前置');
const installPrefix = path.join(localAppData, 'Temp', 'opencode', 'sshdeck-ticket07-v4-2107539-01');
assert.equal(fs.existsSync(installPrefix), false, '唯一隔離 npm prefix 已存在；不覆寫');

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
assert.equal(sourceCommit, expectedSource);

const sourceDiff = spawnSync('git.exe', [
  'diff',
  '--quiet',
  'HEAD',
  '--',
  'README.md',
  'package.json',
  'package-lock.json',
  'bin',
  'lib',
  'public',
  'docs/service-api.md',
  '.opencode/skills/agent-system-sshdeck',
], {
  cwd: repo,
  encoding: 'utf8',
  timeout: 10_000,
  windowsHide: true,
});
assert.equal(sourceDiff.error, undefined, `source 差異檢查失敗：${sourceDiff.error?.message}`);
assert.equal(sourceDiff.status, 0, 'package source 有未提交差異');

const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
const provenance = JSON.parse(fs.readFileSync(path.join(candidateDir, 'provenance.json'), 'utf8'));
const packlist = JSON.parse(fs.readFileSync(path.join(candidateDir, 'packlist.json'), 'utf8'))[0];
const archive = fs.readFileSync(path.join(candidateDir, provenance.archive));
const archiveSha256 = createHash('sha256').update(archive).digest('hex');
assert.equal(provenance.sourceCommit, sourceCommit);
assert.equal(manifest.name, provenance.packageName);
assert.equal(manifest.version, provenance.version);
assert.equal(packlist.name, manifest.name);
assert.equal(packlist.version, manifest.version);
assert.equal(archiveSha256, provenance.archiveSha256);

function portAvailable(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', (error) => {
      if (error.code === 'EADDRINUSE') resolve(false);
      else reject(error);
    });
    server.listen(port, '127.0.0.1', () => {
      server.close((error) => error ? reject(error) : resolve(true));
    });
  });
}

async function main() {
  const listeners = [];
  for (const port of ports) {
    if (!await portAvailable(port)) listeners.push(port);
  }
  assert.deepEqual(listeners, [], `package smoke port 已占用：${listeners.join(', ')}`);
  process.stdout.write(`${JSON.stringify({
    result: 'clear',
    cwd: repo,
    sourceCommit,
    sourceTree,
    nodeVersion: process.version,
    npmVersion: execFileSync('cmd.exe', ['/d', '/s', '/c', 'npm.cmd --version'], {
      cwd: repo,
      encoding: 'utf8',
      timeout: 10_000,
      windowsHide: true,
    }).trim(),
    packageName: manifest.name,
    packageVersion: manifest.version,
    packageLockVersion: JSON.parse(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8')).lockfileVersion,
    archiveSha256,
    installPrefix,
    installPrefixAbsent: true,
    smokePorts: ports,
    listeners,
    evidencePath: path.relative(repo, evidence).replaceAll('\\', '/'),
    tempRoot: os.tmpdir(),
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exitCode = 1;
});
