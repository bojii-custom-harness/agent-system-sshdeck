'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const expectedSource = '265769e815d608d7bfc1ce7cb83fc46b74cbfd0c';
const ports = [18792, 18793];
const candidate = path.join(
  process.cwd(),
  'docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3',
);

function command(file, args) {
  const result = spawnSync(file, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  assert.equal(result.error, undefined, `${file} 執行失敗：${result.error?.message}`);
  assert.equal(result.status, 0, `${file} 退出碼：${result.status}；${result.stderr}`);
  return result.stdout.trim();
}

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
  const manifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const lock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
  const provenance = JSON.parse(fs.readFileSync(path.join(candidate, 'provenance.json'), 'utf8'));
  const archivePath = path.join(candidate, provenance.archive);
  const archiveSha256 = createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');
  const head = command('git.exe', ['rev-parse', 'HEAD']);
  const packagePaths = [
    'README.md',
    'package.json',
    'package-lock.json',
    'bin',
    'lib',
    'public',
    'docs/service-api.md',
    '.opencode/skills/agent-system-sshdeck',
  ];
  const diff = spawnSync('git.exe', ['diff', '--quiet', 'HEAD', '--', ...packagePaths], {
    cwd: process.cwd(),
    timeout: 10_000,
    windowsHide: true,
  });
  assert.equal(diff.error, undefined, `git diff 執行失敗：${diff.error?.message}`);
  assert.equal(diff.status, 0, 'package 所含來源有未提交差異');
  assert.equal(head, expectedSource, 'source HEAD 不符合本次核准 SHA');
  assert.equal(manifest.name, lock.name);
  assert.equal(manifest.version, lock.version);
  assert.equal(manifest.name, provenance.packageName);
  assert.equal(manifest.version, provenance.version);
  assert.equal(provenance.sourceCommit, head);
  assert.equal(archiveSha256, provenance.archiveSha256);
  const listeners = [];
  for (const port of ports) {
    if (!await portAvailable(port)) listeners.push(port);
  }
  assert.deepEqual(listeners, [], `package smoke ports 已占用：${listeners.join(', ')}`);
  const npmVersion = command('cmd.exe', ['/d', '/s', '/c', 'npm.cmd --version']);
  process.stdout.write(`${JSON.stringify({
    result: 'clear',
    cwd: process.cwd(),
    sourceCommit: head,
    nodeVersion: process.version,
    npmVersion,
    packageName: manifest.name,
    packageVersion: manifest.version,
    packageLockVersion: lock.lockfileVersion,
    smokePorts: ports,
    listeners,
    archivePath: path.relative(process.cwd(), archivePath).replaceAll('\\', '/'),
    archiveSha256,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exitCode = 1;
});
