'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { Client, utils } = require('ssh2');
const ssh = require('../lib/ssh');
const { startService } = require('../lib/service-server');
const { runCli } = require('../lib/service-client');
const { createOpenSshServiceFixture } = require('./helpers/openssh-service-fixture');
const {
  api,
  createServiceEnv,
  makeTaskTemp,
  spawnCli,
  waitForOutput,
  forceKillCli,
} = require('./helpers/service-test-utils');

const enabled = process.env.SSHDECK_TEST_SERVICE_SSH === '1';

function fixtureEnabled() {
  return enabled ? false : 'Set SSHDECK_TEST_SERVICE_SSH=1 to start the task-owned WSL OpenSSH fixture.';
}

function directSshExec({ host, port, privateKey, passphrase, expectedFingerprint, command }) {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => finish(new Error('direct SSH fixture probe timeout')), 10_000);
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.end();
      if (error) reject(error);
      else resolve(result);
    };
    client.on('error', (error) => finish(error));
    client.on('ready', () => {
      client.exec(command, (error, stream) => {
        if (error) return finish(error);
        stream.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
        stream.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
        stream.on('close', (code) => finish(null, { code, stdout, stderr }));
      });
    });
    client.connect({
      host,
      port,
      username: 'root',
      privateKey,
      passphrase,
      readyTimeout: 5000,
      hostVerifier: (key) => ssh.fingerprint(key) === expectedFingerprint,
    });
  });
}

test('真實 SSHDeck service／雙 OpenSSH targets：信任、持久憑證、串流、並行、取消與斷線不重送', {
  skip: fixtureEnabled(),
  timeout: 100_000,
}, async () => {
  const temp = makeTaskTemp();
  const serviceHome = path.join(temp, 'service-home');
  const standaloneHome = path.join(temp, 'standalone-home');
  const env = createServiceEnv(serviceHome);
  const passphrase = randomBytes(24).toString('base64url');
  const keyPair = utils.generateKeyPairSync('ed25519', {
    passphrase,
    cipher: 'aes256-cbc',
    comment: 'sshdeck-ticket01-real-ssh',
  });
  let fixture;
  let server;

  const ui = (route, options = {}) => api(server, route, { ...options, token: env.SSHDECK_UI_TOKEN });
  const cliApi = (route, options = {}) => api(server, route, { ...options, token: env.SSHDECK_SERVICE_TOKEN });
  const cliEnv = () => ({
    SSHDECK_MODE: 'service',
    SSHDECK_SERVICE_URL: server.url,
    SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
    SSHDECK_HOME: standaloneHome,
  });
  const execCli = async (alias, fixtureCommand, options = {}) => {
    const result = spawnCli(['exec', alias, '--', fixture.command(fixtureCommand)], { env: cliEnv(), ...options });
    return { result, completed: await result.closed };
  };

  try {
    fs.mkdirSync(standaloneHome, { recursive: true });
    fs.writeFileSync(path.join(standaloneHome, 'hosts.json'), JSON.stringify([
      { alias: 'standalone-only', hostname: '127.0.0.1', port: 1, username: 'not-used' },
    ]));
    fixture = await createOpenSshServiceFixture({
      authorizedPublicKey: keyPair.public,
      evidenceFile: process.env.SSHDECK_TEST_SERVICE_FIXTURE_EVIDENCE,
    });
    assert.notEqual(fixture.fingerprints.a, fixture.fingerprints.b);
    const directProbe = await directSshExec({
      host: '127.0.0.1',
      port: fixture.ports[0],
      privateKey: keyPair.private,
      passphrase,
      expectedFingerprint: fixture.fingerprints.a,
      command: fixture.command('target-a'),
    });
    assert.equal(directProbe.code, 0, `直接 SSH fixture probe：${directProbe.stderr}`);
    assert.equal(directProbe.stdout, 'target-a\n');

    server = await startService({ env, port: 0 });
    for (const [alias, port] of [['target-a', fixture.ports[0]], ['target-b', fixture.ports[1]]]) {
      const createdHost = await ui('/v1/hosts', {
        method: 'POST',
        body: { alias, hostname: '127.0.0.1', port, username: 'root' },
      });
      assert.equal(createdHost.status, 201, `建立 ${alias} 主機設定`);
      const imported = await ui(`/v1/hosts/${alias}/key/import`, {
        method: 'POST',
        body: { privateKey: keyPair.private, passphrase },
      });
      assert.equal(imported.status, 201, `經 API 匯入 ${alias} 測試金鑰`);
      assert.equal(imported.text.includes(keyPair.private), false, 'API 不回傳私鑰');
      assert.equal(imported.text.includes(passphrase), false, 'API 不回傳密語');
    }
    const generatedHost = await ui('/v1/hosts', {
      method: 'POST',
      body: { alias: 'generated-only', hostname: '127.0.0.1', port: fixture.ports[0], username: 'root' },
    });
    assert.equal(generatedHost.status, 201);
    const generated = await ui('/v1/hosts/generated-only/key/create', { method: 'POST', body: {} });
    assert.equal(generated.status, 201, '經公開 API 產生服務金鑰');
    assert.equal(generated.text.includes(env.SSHDECK_ENCRYPTION_KEY), false);

    const keys = await ui('/v1/keys');
    assert.equal(keys.status, 200);
    const targetAKey = keys.payload.find((item) => item.associatedAliases.includes('target-a'));
    const targetBKey = keys.payload.find((item) => item.associatedAliases.includes('target-b'));
    const generatedKey = keys.payload.find((item) => item.associatedAliases.includes('generated-only'));
    assert.ok(targetAKey?.id && targetBKey?.id && generatedKey?.id);

    const unknownA = await cliApi('/v1/hosts/target-a/check', { method: 'POST', body: {} });
    assert.equal(unknownA.status, 409);
    assert.equal(unknownA.payload.code, 'HOST_TRUST_REQUIRED');
    assert.equal(unknownA.payload.fingerprint, fixture.fingerprints.a);
    assert.equal((await ui('/v1/hosts/target-a')).payload.trustedFingerprint, null,
      '未經信任的觀測指紋不能當作初始化身分');
    const blockedBeforeTrust = await execCli('target-a', 'count-a');
    assert.equal(blockedBeforeTrust.completed.code, 1);
    assert.equal(blockedBeforeTrust.completed.stdout, '');
    assert.match(blockedBeforeTrust.completed.stderr, /SHA256:/);
    assert.equal(blockedBeforeTrust.completed.stderr.includes('登入金鑰密語'), false);

    const acceptedA = spawnCli(['host', 'trust', 'target-a', '--fingerprint', fixture.fingerprints.a], { env: cliEnv() });
    const acceptedAResult = await acceptedA.closed;
    assert.equal(acceptedAResult.code, 0, acceptedAResult.stderr);
    assert.match(acceptedAResult.stdout, /已核對並信任 target-a/);
    const trustedA = await cliApi('/v1/hosts/target-a/check', { method: 'POST', body: {} });
    assert.equal(trustedA.status, 200);
    assert.equal(trustedA.payload.fingerprint, fixture.fingerprints.a);
    assert.equal((await ui('/v1/hosts/target-a')).payload.trustedFingerprint, fixture.fingerprints.a,
      '公開主機資料提供目前信任的穩定指紋，供 consumer 判定初始化失效');
    const wrongFingerprintExec = await cliApi('/v1/hosts/target-a/exec', {
      method: 'POST',
      body: {
        command: fixture.command('count-a'),
        expectedFingerprint: fixture.fingerprints.b,
      },
    });
    assert.equal(wrongFingerprintExec.status, 409, '已知 host key 不得繞過不相符的人工核對值');
    assert.equal(wrongFingerprintExec.payload.code, 'HOST_KEY_CHANGED');
    assert.equal(wrongFingerprintExec.payload.fingerprint, fixture.fingerprints.a);
    const blockedCount = await execCli('target-a', 'count-a');
    assert.equal(blockedCount.completed.code, 0, `fixture count command failed safely: ${blockedCount.completed.stderr}`);
    assert.equal(blockedCount.completed.stdout, '0\n', '未知指紋遭拒時遠端命令尚未執行');

    const unknownB = await cliApi('/v1/hosts/target-b/check', { method: 'POST', body: {} });
    assert.equal(unknownB.status, 409);
    assert.equal(unknownB.payload.code, 'HOST_TRUST_REQUIRED');
    assert.equal(unknownB.payload.fingerprint, fixture.fingerprints.b);
    const acceptedB = spawnCli(['host', 'trust', 'target-b', '--fingerprint', fixture.fingerprints.b], { env: cliEnv() });
    const acceptedBResult = await acceptedB.closed;
    assert.equal(acceptedBResult.code, 0, acceptedBResult.stderr);

    const beforeRestartKeys = await ui('/v1/keys');
    assert.equal(beforeRestartKeys.payload.length, 3);
    await server.closeAsync();
    server = await startService({ env, port: 0 });
    const afterRestartKeys = await ui('/v1/keys');
    assert.equal(afterRestartKeys.status, 200);
    assert.equal(afterRestartKeys.payload.length, 3);
    assert.equal(fixture.isWslSessionActive(), true, '本任務 WSL session 必須在 service restart 期間維持 fixture 存活');
    assert.equal(fixture.isListening(fixture.ports[0]), true, 'service restart 後 OpenSSH listener 應持續監聽');
    const restartedLoopback = await directSshExec({
      host: '127.0.0.1',
      port: fixture.ports[0],
      privateKey: keyPair.private,
      passphrase,
      expectedFingerprint: fixture.fingerprints.a,
      command: fixture.command('target-a'),
    });
    assert.equal(restartedLoopback.code, 0, restartedLoopback.stderr);
    assert.equal(restartedLoopback.stdout, 'target-a\n');
    const restartedPrivate = await directSshExec({
      host: fixture.sshHost,
      port: fixture.ports[0],
      privateKey: keyPair.private,
      passphrase,
      expectedFingerprint: fixture.fingerprints.a,
      command: fixture.command('target-a'),
    });
    assert.equal(restartedPrivate.code, 0, restartedPrivate.stderr);
    assert.equal(restartedPrivate.stdout, 'target-a\n');
    const autoUnlocked = await execCli('target-a', 'target-a');
    assert.equal(autoUnlocked.completed.code, 0, autoUnlocked.completed.stderr);
    assert.equal(autoUnlocked.completed.stdout, 'target-a\n');

    const parallelA = spawnCli(['exec', 'target-a', '--', fixture.command('combined-a')], { env: cliEnv() });
    const parallelB = spawnCli(['exec', 'target-b', '--', fixture.command('combined-b')], { env: cliEnv() });
    const [parallelAResult, parallelBResult] = await Promise.all([parallelA.closed, parallelB.closed]);
    assert.equal(parallelAResult.code, 7);
    assert.equal(parallelAResult.stdout, 'A-stdout\n');
    assert.equal(parallelAResult.stderr, 'A-stderr\n');
    assert.equal(parallelBResult.code, 9);
    assert.equal(parallelBResult.stdout, 'B-stdout\n');
    assert.equal(parallelBResult.stderr, 'B-stderr\n');

    let cancelledStdout = '';
    let cancelledStderr = '';
    let resolveCancelledStart;
    const cancelledStarted = new Promise((resolve) => { resolveCancelledStart = resolve; });
    const cancelProcess = new EventEmitter();
    cancelProcess.exitCode = 0;
    const cancelCli = runCli(['exec', 'target-a', '--', fixture.command('counted-a')], {
      env: cliEnv(),
      processObject: cancelProcess,
      stdout: {
        write(chunk) {
          cancelledStdout += chunk;
          if (cancelledStdout.includes('started-a')) resolveCancelledStart();
        },
      },
      stderr: { write(chunk) { cancelledStderr += chunk; } },
    });
    await cancelledStarted;
    const unaffectedB = spawnCli(['exec', 'target-b', '--', fixture.command('slow-b')], {
      env: cliEnv(),
      deadlineMs: 15_000,
    });
    await waitForOutput(unaffectedB, 'stdout', 'started-b', 10_000, '取消 A 時 B 的命令應開始');
    cancelProcess.emit('SIGINT');
    const unaffectedResult = await unaffectedB.closed;
    await cancelCli;
    assert.equal(cancelProcess.exitCode, 130);
    assert.equal(cancelledStdout, 'started-a\n');
    assert.equal(cancelledStderr, '');
    assert.equal(unaffectedResult.code, 0, unaffectedResult.stderr);
    assert.equal(unaffectedResult.stdout, 'started-b\nfinished-b\n');
    const countA = fixture.readCounter('a');
    assert.equal(countA.trim().split('\n').filter(Boolean).length, 1);

    const disconnectedB = spawnCli(['exec', 'target-b', '--', fixture.command('counted-b')], {
      env: cliEnv(),
      deadlineMs: 30_000,
    });
    await waitForOutput(disconnectedB, 'stdout', 'started-b', 10_000, '斷線測試的 B 命令應開始');
    const killResult = forceKillCli(disconnectedB.child);
    assert.ok(killResult.status === 0 || killResult.status === 128 || killResult.status === 255,
      '只終止本次 CLI client process tree');
    await disconnectedB.closed;
    const countB = fixture.readCounter('b');
    assert.equal(countB.trim().split('\n').filter(Boolean).length, 1,
      'client 斷線後 service 不自動重送命令');

    const checkedHosts = await ui('/v1/hosts');
    assert.equal(checkedHosts.payload.find((item) => item.alias === 'target-a').check.state, 'success');
    const updated = await ui('/v1/hosts/target-a', {
      method: 'PUT',
      body: { hostname: '127.0.0.1', port: fixture.ports[0], username: 'root' },
    });
    assert.equal(updated.status, 200);
    const invalidated = await ui('/v1/hosts');
    assert.equal(invalidated.payload.find((item) => item.alias === 'target-a').check.state, 'unchecked',
      '主機設定更新後檢查快取失效');

    const sharedHost = await ui('/v1/hosts', {
      method: 'POST',
      body: { alias: 'shared-target', hostname: '127.0.0.1', port: fixture.ports[0], username: 'root' },
    });
    assert.equal(sharedHost.status, 201);
    const linked = await ui('/v1/hosts/shared-target/key/link', {
      method: 'POST',
      body: { keyId: targetAKey.id },
    });
    assert.equal(linked.status, 200);
    const sharedDelete = await ui(`/v1/keys/${targetAKey.id}`, { method: 'DELETE' });
    assert.equal(sharedDelete.status, 409);
    assert.equal(sharedDelete.payload.code, 'KEY_IN_USE');

    const unlinkedA = await ui('/v1/hosts/target-a/key/unlink', { method: 'POST', body: {} });
    assert.equal(unlinkedA.status, 204);
    const staleA = await execCli('target-a', 'target-a');
    assert.equal(staleA.completed.code, 1);
    assert.match(staleA.completed.stderr, /尚未關聯登入金鑰/);
    const sharedStillWorks = await execCli('shared-target', 'target-a');
    assert.equal(sharedStillWorks.completed.code, 0, sharedStillWorks.completed.stderr);
    assert.equal(sharedStillWorks.completed.stdout, 'target-a\n');
    const stillSharedDelete = await ui(`/v1/keys/${targetAKey.id}`, { method: 'DELETE' });
    assert.equal(stillSharedDelete.status, 409);
    const unlinkedShared = await ui('/v1/hosts/shared-target/key/unlink', { method: 'POST', body: {} });
    assert.equal(unlinkedShared.status, 204);
    const deletedKey = await ui(`/v1/keys/${targetAKey.id}`, { method: 'DELETE' });
    assert.equal(deletedKey.status, 200);
    const staleLink = await ui('/v1/hosts/target-a/key/link', {
      method: 'POST',
      body: { keyId: targetAKey.id },
    });
    assert.equal(staleLink.status, 404);

    const generatedUnlink = await ui('/v1/hosts/generated-only/key/unlink', { method: 'POST', body: {} });
    assert.equal(generatedUnlink.status, 204);
    const generatedDelete = await ui(`/v1/keys/${generatedKey.id}`, { method: 'DELETE' });
    assert.equal(generatedDelete.status, 200);
    const deleteHost = await ui('/v1/hosts/generated-only', { method: 'DELETE' });
    assert.equal(deleteHost.status, 204);
    const deletedHost = await ui('/v1/hosts/generated-only');
    assert.equal(deletedHost.status, 404);

    const rotatedFingerprint = await fixture.rotateB();
    assert.notEqual(rotatedFingerprint, fixture.fingerprints.b);
    const changedB = await cliApi('/v1/hosts/target-b/check', { method: 'POST', body: {} });
    assert.equal(changedB.status, 409);
    assert.equal(changedB.payload.code, 'HOST_KEY_CHANGED');
    assert.equal(changedB.payload.previousFingerprint, fixture.fingerprints.b);
    assert.equal(changedB.payload.fingerprint, rotatedFingerprint);
    const changedExec = await execCli('target-b', 'combined-b');
    assert.equal(changedExec.completed.code, 1);
    assert.match(changedExec.completed.stderr, /主機指紋已改變/);
    const reacceptedB = spawnCli(['host', 'trust', 'target-b', '--fingerprint', rotatedFingerprint], { env: cliEnv() });
    const reacceptedBResult = await reacceptedB.closed;
    assert.equal(reacceptedBResult.code, 0, reacceptedBResult.stderr);
    const changedTargetWorks = await execCli('target-b', 'target-b');
    assert.equal(changedTargetWorks.completed.code, 0, changedTargetWorks.completed.stderr);
    assert.equal(changedTargetWorks.completed.stdout, 'target-b\n');

    const lock = await ui('/v1/lock', { method: 'POST', body: {} });
    assert.equal(lock.status, 204);
    await server.closeAsync();
    server = await startService({ env, port: 0 });
    const remainsLocked = await execCli('target-b', 'target-b');
    assert.equal(remainsLocked.completed.code, 1);
    assert.match(remainsLocked.completed.stderr, /手動鎖定/);
    assert.equal(remainsLocked.completed.stderr.includes('登入金鑰密語'), false);
    const unlock = await ui('/v1/unlock', { method: 'POST', body: {} });
    assert.equal(unlock.status, 204);
    const afterUiUnlock = await execCli('target-b', 'target-b');
    assert.equal(afterUiUnlock.completed.code, 0, afterUiUnlock.completed.stderr);
    assert.equal(afterUiUnlock.completed.stdout, 'target-b\n');

    const shutdownExecution = spawnCli(['exec', 'target-b', '--', fixture.command('counted-b')], {
      env: cliEnv(),
      deadlineMs: 30_000,
    });
    await waitForOutput(shutdownExecution, 'stdout', 'started-b', 10_000, 'service shutdown 前的 B 命令應開始');
    const shutdownStartedAt = Date.now();
    await server.closeAsync();
    assert.ok(Date.now() - shutdownStartedAt < 5_000, 'service 關閉應先取消作用中 SSH channel，不等待遠端命令自然結束');
    server = undefined;
    const shutdownResult = await shutdownExecution.closed;
    assert.equal(shutdownResult.timedOut, false);
    assert.notEqual(shutdownResult.code, 0, 'service 結束時中止作用中的命令');
  } finally {
    if (server) await server.closeAsync();
    if (fixture) await fixture.cleanup();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
