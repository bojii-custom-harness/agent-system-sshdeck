'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const evidence = path.resolve(
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-2107539-01',
);
const smoke = JSON.parse(fs.readFileSync(path.join(evidence, 'package-smoke.json'), 'utf8'));
const ports = [smoke.uiPort, smoke.servicePort];

assert.equal(smoke.package, 'agent-system-sshdeck@0.1.3');
assert.equal(smoke.status, 'passed');
assert.equal(smoke.cleanupPassed, true);
assert.equal(smoke.standaloneUiStopped, true);
assert.equal(smoke.serviceCliStopped, true);
assert.equal(smoke.port18792Free, true);
assert.equal(smoke.port18793Free, true);

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
  for (const port of ports) portResults[port] = await portAvailable(port);
  assert.ok(Object.values(portResults).every(Boolean), 'package smoke port 仍被占用');

  let serviceProcessAlive = false;
  try {
    process.kill(smoke.servicePid, 0);
    serviceProcessAlive = true;
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
  assert.equal(serviceProcessAlive, false, 'package smoke service process 仍存活');

  const smokeStartedAt = Date.parse(smoke.startedAt);
  const smokeFinishedAt = Date.parse(smoke.finishedAt);
  const newSmokeTempDirs = fs.readdirSync(os.tmpdir(), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith('sshdeck-release-package-smoke-'))
    .map((entry) => {
      const fullPath = path.join(os.tmpdir(), entry.name);
      const birthtimeMs = fs.statSync(fullPath).birthtimeMs;
      return { name: entry.name, birthtimeMs };
    })
    .filter(({ birthtimeMs }) => birthtimeMs >= smokeStartedAt - 1000 && birthtimeMs <= smokeFinishedAt + 60_000);
  assert.deepEqual(newSmokeTempDirs, [], 'package smoke run interval has a remaining temporary directory');

  process.stdout.write(`${JSON.stringify({
    result: 'passed',
    runId: 'v4-rebuild-20261120-2107539-01-package-smoke-cleanup-01',
    smokeEvidence: 'package-smoke.json',
    serviceCliStopped: smoke.serviceCliStopped,
    serviceProcessAlive,
    ports: portResults,
    runScopedSmokeTempDirs: newSmokeTempDirs,
    verifiedAt: new Date().toISOString(),
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exitCode = 1;
});
