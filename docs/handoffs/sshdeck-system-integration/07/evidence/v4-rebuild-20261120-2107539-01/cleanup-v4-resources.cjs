'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.resolve(
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-2107539-01',
);
const candidate = path.resolve('docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3');
const localAppData = process.env.LOCALAPPDATA;
assert.ok(localAppData);
const installPrefix = path.resolve(
  path.join(localAppData, 'Temp', 'opencode', 'sshdeck-ticket07-v4-2107539-01'),
);
const allowedTempRoot = path.resolve(path.join(localAppData, 'Temp', 'opencode'));
const staging = path.resolve(path.join(evidence, 'npm-pack-staging'));
const replacement = path.resolve(path.join(evidence, 'candidate-replacement'));
const expectedArchiveSha256 = '69dea1146a326c59574a2bc2a068dce68b2c1fd55b584d610c2e027c0355a0ed';

assert.ok(installPrefix.startsWith(`${allowedTempRoot}${path.sep}`), 'isolated install path escaped approved Temp root');
assert.ok(staging.startsWith(`${evidence}${path.sep}`), 'npm staging path escaped this evidence run');
assert.ok(replacement.startsWith(`${evidence}${path.sep}`), 'candidate replacement path escaped this evidence run');

const smoke = JSON.parse(fs.readFileSync(path.join(evidence, 'package-smoke.json'), 'utf8'));
const install = JSON.parse(fs.readFileSync(path.join(evidence, 'isolated-install.metadata.json'), 'utf8'));
const candidateProvenance = JSON.parse(fs.readFileSync(path.join(candidate, 'provenance.json'), 'utf8'));
const savedOldCandidate = path.join(evidence, 'previous-candidate', 'agent-system-sshdeck-0.1.3.tgz');
assert.equal(smoke.status, 'passed');
assert.equal(smoke.cleanupPassed, true);
assert.equal(install.exitCode, 0);
assert.equal(candidateProvenance.archiveSha256, expectedArchiveSha256);
assert.equal(createHash('sha256').update(fs.readFileSync(path.join(candidate, candidateProvenance.archive))).digest('hex'), expectedArchiveSha256);
assert.equal(
  createHash('sha256').update(fs.readFileSync(savedOldCandidate)).digest('hex'),
  '0db06a8fd40ff82bd27ce9200034a47ecffa1332fc1d59999f1196f520dadbc9',
);

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
  const portResults = {};
  for (const port of [smoke.uiPort, smoke.servicePort]) portResults[port] = await portAvailable(port);
  assert.ok(Object.values(portResults).every(Boolean), 'package smoke port 仍被占用，保留資源並停止清理');

  const serviceProcessAlive = (() => {
    try {
      process.kill(smoke.servicePid, 0);
      return true;
    } catch (error) {
      if (error.code === 'ESRCH') return false;
      throw error;
    }
  })();
  assert.equal(serviceProcessAlive, false, 'package smoke service process 仍存活，保留資源並停止清理');

  const paths = [installPrefix, staging, replacement];
  const removed = [];
  for (const target of paths) {
    const existed = fs.existsSync(target);
    if (existed) fs.rmSync(target, { recursive: true, force: false });
    removed.push({ path: path.relative(repo, target).replaceAll('\\', '/'), existed, absentAfter: !fs.existsSync(target) });
    assert.equal(fs.existsSync(target), false, `精確清理後路徑仍存在：${target}`);
  }

  const smokeStartedAt = Date.parse(smoke.startedAt);
  const smokeFinishedAt = Date.parse(smoke.finishedAt);
  const remainingRunScopedSmokeDirs = fs.readdirSync(os.tmpdir(), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith('sshdeck-release-package-smoke-'))
    .map((entry) => {
      const fullPath = path.join(os.tmpdir(), entry.name);
      return { name: entry.name, birthtimeMs: fs.statSync(fullPath).birthtimeMs };
    })
    .filter(({ birthtimeMs }) => birthtimeMs >= smokeStartedAt - 1000 && birthtimeMs <= smokeFinishedAt + 60_000);
  assert.deepEqual(remainingRunScopedSmokeDirs, [], 'package smoke run 的 temp dir 尚未清理');
  assert.equal(fs.existsSync(savedOldCandidate), true, '舊 candidate evidence 被移除');

  const report = {
    runId: 'v4-rebuild-20261120-2107539-01-resource-cleanup-01',
    result: 'passed',
    removed,
    smokePorts: portResults,
    serviceProcessAlive,
    remainingRunScopedSmokeDirs,
    oldCandidateSnapshotPreserved: true,
    candidateArchiveRetained: true,
    finishedAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(evidence, 'cleanup.json'), `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exitCode = 1;
});
