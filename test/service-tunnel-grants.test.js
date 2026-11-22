'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { Server: SshServer, utils } = require('ssh2');
const { startService } = require('../lib/service-server');
const ssh = require('../lib/ssh');
const { api, createServiceEnv, makeTaskTemp } = require('./helpers/service-test-utils');

const fingerprint = 'SHA256:ticket01-synthetic-trust';

async function createHost(server, env, {
  alias,
  hostname = '192.0.2.10',
  port = 2227,
  key = true,
  trust = true,
} = {}) {
  const host = { alias, hostname, port, username: 'ticket01-user' };
  const created = await api(server, '/v1/hosts', {
    method: 'POST',
    token: env.SSHDECK_UI_TOKEN,
    body: host,
  });
  assert.equal(created.status, 201, 'fixture 主機必須透過 service API 建立');
  if (key) {
    const managed = await api(server, `/v1/hosts/${alias}/key/create`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: {},
    });
    assert.equal(managed.status, 201, 'fixture 必須建立 service-managed key');
    if (trust) ssh.trust(path.join(env.SSHDECK_SERVICE_HOME, 'hosts.json'), host, fingerprint);
  }
  return host;
}

async function createGrant(server, env, alias, {
  targetHost = '192.0.2.80',
  targetPort = 3001,
} = {}) {
  const created = await api(server, `/v1/hosts/${alias}/tcp-tunnel-targets`, {
    method: 'POST',
    token: env.SSHDECK_UI_TOKEN,
    body: { targetHost, targetPort },
  });
  assert.equal(created.status, 201, 'fixture target grant 必須透過 service API 建立');
  return created.payload.targetId;
}

function snapshotFiles(directory) {
  const files = new Map();
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const target = path.join(current, entry.name);
      if (entry.isDirectory()) visit(target);
      else files.set(path.relative(directory, target), createHash('sha256').update(fs.readFileSync(target)).digest('hex'));
    }
  };
  visit(directory);
  return files;
}

function createSshHostKey() {
  const pair = utils.generateKeyPairSync('ed25519');
  const parsed = utils.parseKey(Buffer.from(pair.private));
  return {
    privateKey: Buffer.from(pair.private),
    fingerprint: ssh.fingerprint(parsed.getPublicSSH()),
  };
}

function startSshFingerprintPeer(privateKey, port = 0) {
  const server = new SshServer({ hostKeys: [privateKey] }, (client) => {
    client.on('authentication', (context) => context.accept());
  });
  return new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once('error', onError);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', onError);
      resolve(server);
    });
  });
}

function closeSshFingerprintPeer(server) {
  if (!server) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

test('UI token 建立並撤銷綁定已信任 managed host 的精確 TCP target grant', {
  timeout: 60_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-grant-');
  const serviceHome = path.join(temp, 'service-home');
  const env = createServiceEnv(serviceHome);
  let service;
  try {
    service = await startService({ env, port: 0 });
    const host = await createHost(service, env, { alias: 'grant-one' });
    const secondHost = await createHost(service, env, { alias: 'grant-two', port: 2228 });
    const noKeyHost = await createHost(service, env, { alias: 'grant-no-key', key: false });
    await createHost(service, env, {
      alias: 'grant-untrusted',
      hostname: '192.0.2.11',
      trust: false,
    });

    const route = `/v1/hosts/${host.alias}/tcp-tunnel-targets`;
    const body = { targetHost: '192.0.2.80', targetPort: 3001 };

    assert.equal((await api(service, route, { method: 'POST', body })).status, 401,
      '未認證要求不得建立 target grant');
    assert.equal((await api(service, route, { method: 'POST', token: env.SSHDECK_SERVICE_TOKEN, body })).status, 403,
      'CLI token 不得管理 target grant');
    assert.equal((await api(service, route, { method: 'POST', token: env.SSHDECK_TUNNEL_TOKEN, body })).status, 403,
      'tunnel token 不得管理 target grant');
    assert.equal((await api(service, `/v1/hosts/unknown/tcp-tunnel-targets`, {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body,
    })).status, 404, '未知 alias 不得建立 target grant');
    const noKey = await api(service, `/v1/hosts/${noKeyHost.alias}/tcp-tunnel-targets`, {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body,
    });
    assert.equal(noKey.status, 428, '未關聯受管 key 的 host 不得建立 target grant');
    assert.equal(noKey.payload.code, 'KEY_REQUIRED');
    const untrusted = await api(service, '/v1/hosts/grant-untrusted/tcp-tunnel-targets', {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body,
    });
    assert.equal(untrusted.status, 409, '未完成 fingerprint trust 的 host 不得建立 target grant');
    assert.equal(untrusted.payload.code, 'HOST_TRUST_REQUIRED');

    const invalidTargets = [
      { targetHost: 'localhost', targetPort: 80 },
      { targetHost: '*', targetPort: 80 },
      { targetHost: '0.0.0.0', targetPort: 80 },
      { targetHost: '::', targetPort: 80 },
      { targetHost: '0:0:0:0:0:0:0:0', targetPort: 80 },
      { targetHost: '192.0.2.0/24', targetPort: 80 },
      { targetHost: '192.0.2.80' },
      { targetHost: '192.0.2.80', targetPort: null },
      { targetHost: '192.0.2.80', targetPort: 0 },
      { targetHost: '192.0.2.80', targetPort: 65536 },
      { targetHost: '192.0.2.80', targetPort: '3001' },
      { targetHost: '192.0.2.80', targetPort: 1.5 },
      { targetHost: '192.0.2.80', targetPort: 3001, wildcard: true },
    ];
    for (const invalid of invalidTargets) {
      const response = await api(service, route, {
        method: 'POST',
        token: env.SSHDECK_UI_TOKEN,
        body: invalid,
      });
      assert.equal(response.status, 400, 'target 必須是單一 IP literal 與 1–65535 整數 port');
      assert.equal(response.payload.code, 'INVALID_TARGET');
    }

    const locked = await api(service, '/v1/lock', {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    });
    assert.equal(locked.status, 204);
    const lockedGrant = await api(service, route, { method: 'POST', token: env.SSHDECK_UI_TOKEN, body });
    assert.equal(lockedGrant.status, 423, 'locked host 不得建立 target grant');
    assert.equal(lockedGrant.payload.code, 'SERVICE_LOCKED');
    assert.equal((await api(service, '/v1/unlock', {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);

    const baseFiles = snapshotFiles(serviceHome);
    const grants = [];
    for (const target of [
      body,
      { targetHost: '2001:db8::80', targetPort: 65535 },
    ]) {
      const created = await api(service, route, {
        method: 'POST',
        token: env.SSHDECK_UI_TOKEN,
        body: target,
      });
      assert.equal(created.status, 201, '合法 target 必須建立 grant');
      for (const secret of [
        env.SSHDECK_SERVICE_TOKEN,
        env.SSHDECK_UI_TOKEN,
        env.SSHDECK_TUNNEL_TOKEN,
        env.SSHDECK_ENCRYPTION_KEY,
      ]) {
        assert.equal(created.text.includes(secret), false, 'target grant response 不得包含 server-side 憑證');
      }
      assert.equal(/^[A-Za-z0-9_-]{22,}$/.test(created.payload.targetId), true,
        'targetId 必須是 opaque 且至少包含 128-bit 隨機資料');
      assert.equal(Buffer.from(created.payload.targetId, 'base64url').length >= 16, true);
      grants.push(created.payload.targetId);
    }
    assert.equal(grants[0] !== grants[1], true, 'target grant 必須有獨立 opaque ID');
    const firstGrant = service.getTunnelTargetGrant(host.alias, grants[0]);
    assert.equal(Boolean(firstGrant), true, 'service 應提供 Ticket 02 可消費的精確 grant');
    assert.equal(firstGrant?.targetId === grants[0], true, 'grant lookup 必須保留 opaque ID 關聯');
    assert.equal(firstGrant?.alias, host.alias);
    assert.equal(firstGrant?.targetHost, body.targetHost);
    assert.equal(firstGrant?.targetPort, body.targetPort);
    assert.equal(service.getTunnelTargetGrant(secondHost.alias, grants[0]) === undefined, true,
      'target grant 不得跨 alias 重新綁定');
    assert.equal(service.getTunnelTargetGrant(host.alias, 'unknown-target-id') === undefined, true);

    assert.equal((await api(service, `/v1/hosts/${secondHost.alias}/tcp-tunnel-targets/${grants[0]}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    })).status, 204, '不同 alias 撤銷不存在的 target ID 仍應冪等成功');
    assert.equal(Boolean(service.getTunnelTargetGrant(host.alias, grants[0])), true,
      '以其他 alias 撤銷不得移除原 alias 的 grant');

    const revokeRoute = `/v1/hosts/${host.alias}/tcp-tunnel-targets/${grants[0]}`;
    assert.equal((await api(service, revokeRoute, { method: 'DELETE' })).status, 401);
    assert.equal((await api(service, revokeRoute, {
      method: 'DELETE', token: env.SSHDECK_SERVICE_TOKEN,
    })).status, 403);
    assert.equal((await api(service, revokeRoute, {
      method: 'DELETE', token: env.SSHDECK_TUNNEL_TOKEN,
    })).status, 403);
    assert.equal((await api(service, revokeRoute, {
      method: 'DELETE', token: env.SSHDECK_UI_TOKEN,
    })).status, 204, 'UI token 應可撤銷 target grant');
    assert.equal((await api(service, revokeRoute, {
      method: 'DELETE', token: env.SSHDECK_UI_TOKEN,
    })).status, 204, '同一 alias 下重複撤銷應保持冪等');
    assert.equal(service.getTunnelTargetGrant(host.alias, grants[0]) === undefined, true,
      '撤銷後 target grant 不得再授權');
    assert.deepEqual(snapshotFiles(serviceHome), baseFiles,
      'target grant 建立與撤銷只改記憶體，不得寫入服務資料');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('grant invalidation subscription 收到 alias-scoped 撤銷事件且撤銷先於通知', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-invalidation-event-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  try {
    service = await startService({ env, port: 0 });
    await createHost(service, env, { alias: 'event-one' });
    await createHost(service, env, { alias: 'event-two', hostname: '192.0.2.12', port: 2228 });
    const targetId = await createGrant(service, env, 'event-one');
    const unrelatedTargetId = await createGrant(service, env, 'event-two');
    const events = [];
    const unsubscribe = service.subscribeTunnelTargetGrantInvalidation((event) => {
      events.push(event);
      assert.equal(service.getTunnelTargetGrant(event.alias, event.targetId), undefined,
        'subscriber 執行前 grant 必須已不可授權');
      assert.equal(Boolean(service.getTunnelTargetGrant('event-two', unrelatedTargetId)), true,
        '單一 alias 撤銷不得影響其他 alias grant');
    });
    const revoke = await api(service, `/v1/hosts/event-one/tcp-tunnel-targets/${targetId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    });
    assert.equal(revoke.status, 204);
    assert.deepEqual(events, [{
      alias: 'event-one',
      targetId,
      reason: 'revoked',
    }]);

    unsubscribe();
    unsubscribe();
    assert.equal((await api(service, `/v1/hosts/event-two/tcp-tunnel-targets/${unrelatedTargetId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    })).status, 204);
    assert.equal(events.length, 1, '解除訂閱後不得再收到 lifecycle event');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('DELETE 等待 async invalidation subscribers，拒絕時 grant 失效且回報失敗', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-invalidation-await-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let releaseNotification = () => {};
  try {
    service = await startService({ env, port: 0 });
    await createHost(service, env, { alias: 'await-revoke' });
    const targetId = await createGrant(service, env, 'await-revoke');
    let markNotified;
    const notified = new Promise((resolve) => { markNotified = resolve; });
    const notificationGate = new Promise((resolve) => { releaseNotification = resolve; });
    const events = [];
    service.subscribeTunnelTargetGrantInvalidation((event) => {
      events.push(event);
      assert.equal(service.getTunnelTargetGrant(event.alias, event.targetId), undefined,
        '通知開始時 grant 必須已撤銷');
      markNotified();
      return notificationGate;
    });

    let responseReceived = false;
    const pendingResponse = api(service, `/v1/hosts/await-revoke/tcp-tunnel-targets/${targetId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    }).then((response) => {
      responseReceived = true;
      return response;
    });
    await notified;
    assert.equal(responseReceived, false, 'subscriber 尚未完成時 DELETE 不得提早回應 204');
    let duplicateResponseReceived = false;
    const duplicateResponse = api(service, `/v1/hosts/await-revoke/tcp-tunnel-targets/${targetId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    }).then((response) => {
      duplicateResponseReceived = true;
      return response;
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.equal(duplicateResponseReceived, false,
      '同一 target 的並行冪等 DELETE 也必須等待先行的失效通知完成');
    releaseNotification();
    assert.equal((await pendingResponse).status, 204);
    assert.equal((await duplicateResponse).status, 204);
    assert.deepEqual(events, [{ alias: 'await-revoke', targetId, reason: 'revoked' }]);

    await createHost(service, env, { alias: 'reject-revoke', hostname: '192.0.2.13', port: 2229 });
    const rejectedTargetId = await createGrant(service, env, 'reject-revoke');
    let rejectedCalls = 0;
    service.subscribeTunnelTargetGrantInvalidation(() => {
      rejectedCalls += 1;
      throw new Error('subscriber failure must not reach the response');
    });
    const rejected = await api(service, `/v1/hosts/reject-revoke/tcp-tunnel-targets/${rejectedTargetId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    });
    assert.equal(rejected.status, 502, 'subscriber rejection 不得回報撤銷操作成功');
    assert.equal(rejected.payload.code, 'TUNNEL_INVALIDATION_FAILED');
    assert.equal(rejected.text.includes('subscriber failure'), false, 'subscriber error details 不得洩漏');
    assert.equal(service.getTunnelTargetGrant('reject-revoke', rejectedTargetId), undefined,
      'subscriber rejection 不得恢復已撤銷 grant');

    await createHost(service, env, { alias: 'after-reject', hostname: '192.0.2.14', port: 2230 });
    const afterRejectId = await createGrant(service, env, 'after-reject');
    assert.equal((await api(service, `/v1/hosts/after-reject/tcp-tunnel-targets/${afterRejectId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    })).status, 204, '拒絕的 subscriber 應移除，避免污染後續失效操作');
    assert.equal(rejectedCalls, 1);
  } finally {
    releaseNotification();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('host、key、lock 與 shutdown lifecycle 以原因欄位通知並清除對應 grants', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-invalidation-lifecycle-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  const events = [];
  let markShutdownNotified;
  const shutdownNotified = new Promise((resolve) => { markShutdownNotified = resolve; });
  let releaseShutdown;
  const shutdownGate = new Promise((resolve) => { releaseShutdown = resolve; });
  try {
    service = await startService({ env, port: 0 });
    service.subscribeTunnelTargetGrantInvalidation((event) => {
      events.push(event);
      if (event.reason === 'service-shutdown') {
        markShutdownNotified();
        return shutdownGate;
      }
    });
    const lockedHost = await createHost(service, env, { alias: 'lifecycle-lock' });
    const otherLockedHost = await createHost(service, env, {
      alias: 'lifecycle-lock-other', hostname: '192.0.2.15', port: 2231,
    });
    const lockedId = await createGrant(service, env, lockedHost.alias);
    const otherLockedId = await createGrant(service, env, otherLockedHost.alias);
    assert.equal((await api(service, '/v1/lock', {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);
    assert.deepEqual(events.splice(0), [
      { alias: lockedHost.alias, targetId: lockedId, reason: 'service-locked' },
      { alias: otherLockedHost.alias, targetId: otherLockedId, reason: 'service-locked' },
    ]);
    assert.equal((await api(service, '/v1/unlock', {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);

    const updatedHost = await createHost(service, env, { alias: 'lifecycle-update', hostname: '192.0.2.16', port: 2232 });
    const updatedId = await createGrant(service, env, updatedHost.alias);
    assert.equal((await api(service, `/v1/hosts/${updatedHost.alias}`, {
      method: 'PUT', token: env.SSHDECK_UI_TOKEN, body: { username: 'updated-user' },
    })).status, 200);
    assert.deepEqual(events.splice(0), [{
      alias: updatedHost.alias, targetId: updatedId, reason: 'host-updated',
    }], 'host 與 managed-key profile 更新都須通知並失效舊 grant');

    const removedHost = await createHost(service, env, { alias: 'lifecycle-remove', hostname: '192.0.2.17', port: 2233 });
    const removedId = await createGrant(service, env, removedHost.alias);
    assert.equal((await api(service, `/v1/hosts/${removedHost.alias}`, {
      method: 'DELETE', token: env.SSHDECK_UI_TOKEN,
    })).status, 204);
    assert.deepEqual(events.splice(0), [{
      alias: removedHost.alias, targetId: removedId, reason: 'host-removed',
    }]);

    const unlinkedHost = await createHost(service, env, { alias: 'lifecycle-unlink', hostname: '192.0.2.18', port: 2234 });
    const unlinkedId = await createGrant(service, env, unlinkedHost.alias);
    assert.equal((await api(service, `/v1/hosts/${unlinkedHost.alias}/key/unlink`, {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);
    assert.deepEqual(events.splice(0), [{
      alias: unlinkedHost.alias, targetId: unlinkedId, reason: 'host-key-unlinked',
    }]);

    const shutdownHost = await createHost(service, env, { alias: 'lifecycle-shutdown', hostname: '192.0.2.19', port: 2235 });
    const shutdownId = await createGrant(service, env, shutdownHost.alias);
    let closeCompleted = false;
    const closeRequest = service.closeAsync().then(() => { closeCompleted = true; });
    await shutdownNotified;
    assert.equal(closeCompleted, false, 'service shutdown 必須等待 async invalidation subscriber');
    releaseShutdown();
    await closeRequest;
    service = undefined;
    assert.deepEqual(events, [{
      alias: shutdownHost.alias, targetId: shutdownId, reason: 'service-shutdown',
    }]);
  } finally {
    releaseShutdown();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('lock 後解鎖也不得恢復既有 target grant', { timeout: 30_000 }, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-lock-grant-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  try {
    service = await startService({ env, port: 0 });
    await createHost(service, env, { alias: 'lock-target' });
    const targetId = await createGrant(service, env, 'lock-target');

    assert.equal((await api(service, '/v1/lock', {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);
    assert.equal((await api(service, '/v1/unlock', {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);
    assert.equal(service.getTunnelTargetGrant('lock-target', targetId) === undefined, true,
      '解除 service lock 不得復活 lock 前建立的 grant');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('service restart 不恢復記憶體中的 target grant', { timeout: 30_000 }, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-restart-grant-');
  const serviceHome = path.join(temp, 'service-home');
  const env = createServiceEnv(serviceHome);
  let service;
  try {
    service = await startService({ env, port: 0 });
    await createHost(service, env, { alias: 'restart-target' });
    const targetId = await createGrant(service, env, 'restart-target');
    await service.closeAsync();
    service = await startService({ env, port: 0 });

    assert.equal(service.getTunnelTargetGrant('restart-target', targetId) === undefined, true,
      '新 service process 不得載入前一 process 的 target grant');
    assert.equal((await api(service, `/v1/hosts/restart-target/tcp-tunnel-targets/${targetId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    })).status, 204, 'restart 後撤銷已不存在的 grant 仍應回 204');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('host 設定更新後即使還原也不得恢復舊 target grant', { timeout: 30_000 }, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-host-update-grant-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  try {
    service = await startService({ env, port: 0 });
    const host = await createHost(service, env, { alias: 'update-target' });
    const targetId = await createGrant(service, env, host.alias);

    assert.equal((await api(service, `/v1/hosts/${host.alias}`, {
      method: 'PUT',
      token: env.SSHDECK_UI_TOKEN,
      body: { username: 'changed-user' },
    })).status, 200);
    assert.equal((await api(service, `/v1/hosts/${host.alias}`, {
      method: 'PUT',
      token: env.SSHDECK_UI_TOKEN,
      body: { username: host.username },
    })).status, 200);
    assert.equal(service.getTunnelTargetGrant(host.alias, targetId) === undefined, true,
      'host update 必須立即清除 grant，不因設定值還原而復活');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('host 移除後以相同 alias 重新新增與 trust 不得恢復舊 target grant', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-host-remove-grant-');
  const serviceHome = path.join(temp, 'service-home');
  const env = createServiceEnv(serviceHome);
  let service;
  try {
    service = await startService({ env, port: 0 });
    const host = await createHost(service, env, { alias: 'remove-target' });
    const managedKey = ssh.listManagedKeys(path.join(serviceHome, 'hosts.json'))
      .find((record) => record.alias === host.alias);
    const keyId = managedKey.id;
    const targetId = await createGrant(service, env, host.alias);

    assert.equal((await api(service, `/v1/hosts/${host.alias}`, {
      method: 'DELETE', token: env.SSHDECK_UI_TOKEN,
    })).status, 204);
    assert.equal((await api(service, '/v1/hosts', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: host,
    })).status, 201);
    assert.equal((await api(service, `/v1/hosts/${host.alias}/key/link`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { keyId },
    })).status, 200);
    ssh.trust(path.join(serviceHome, 'hosts.json'), host, fingerprint);

    const readdedHost = JSON.parse(fs.readFileSync(path.join(serviceHome, 'hosts.json'), 'utf8'))
      .find((item) => item.alias === host.alias);
    assert.equal(readdedHost.hostname === host.hostname && readdedHost.port === host.port
      && readdedHost.username === host.username, true, 're-added host profile must match its original');
    assert.equal(path.resolve(readdedHost.keyPath) === path.resolve(managedKey.keyPath), true,
      're-added host must use the same managed key path');
    assert.equal(ssh.trustedFingerprintForHost(path.join(serviceHome, 'hosts.json'), readdedHost) === fingerprint, true,
      're-added host must have the same explicitly seeded fingerprint trust');
    assert.equal(service.getTunnelTargetGrant(host.alias, targetId) === undefined, true,
      'host 移除、重新新增、關聯金鑰與重新 trust 後舊 targetId 仍須失效');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('host key unlink 後重新關聯同一把 key 不得恢復舊 target grant', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-key-unlink-grant-');
  const serviceHome = path.join(temp, 'service-home');
  const env = createServiceEnv(serviceHome);
  let service;
  try {
    service = await startService({ env, port: 0 });
    const host = await createHost(service, env, { alias: 'unlink-target' });
    const keyId = ssh.listManagedKeys(path.join(serviceHome, 'hosts.json'))
      .find((record) => record.alias === host.alias).id;
    const targetId = await createGrant(service, env, host.alias);

    assert.equal((await api(service, `/v1/hosts/${host.alias}/key/unlink`, {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);
    assert.equal((await api(service, `/v1/hosts/${host.alias}/key/link`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { keyId },
    })).status, 200);

    assert.equal(service.getTunnelTargetGrant(host.alias, targetId) === undefined, true,
      'key unlink 後重新關聯同一把 key 仍不得恢復舊 targetId');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('managed key 移除後建立並 trust 新 key 不得恢復舊 target grant', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-key-remove-grant-');
  const serviceHome = path.join(temp, 'service-home');
  const env = createServiceEnv(serviceHome);
  let service;
  try {
    service = await startService({ env, port: 0 });
    const host = await createHost(service, env, { alias: 'remove-key-target' });
    const oldKeyId = ssh.listManagedKeys(path.join(serviceHome, 'hosts.json'))
      .find((record) => record.alias === host.alias).id;
    const targetId = await createGrant(service, env, host.alias);

    assert.equal((await api(service, `/v1/hosts/${host.alias}/key/unlink`, {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);
    assert.equal((await api(service, `/v1/keys/${oldKeyId}`, {
      method: 'DELETE', token: env.SSHDECK_UI_TOKEN,
    })).status, 200);
    assert.equal((await api(service, `/v1/hosts/${host.alias}/key/create`, {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 201);
    ssh.trust(path.join(serviceHome, 'hosts.json'), host, fingerprint);

    assert.equal(service.getTunnelTargetGrant(host.alias, targetId) === undefined, true,
      '移除舊 managed key、建立新 key 並重新 trust 後，舊 targetId 仍須失效');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('解除共享 key 的單一 host 關聯只撤銷該 alias 的 target grants', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-shared-key-grant-');
  const serviceHome = path.join(temp, 'service-home');
  const env = createServiceEnv(serviceHome);
  let service;
  try {
    service = await startService({ env, port: 0 });
    const firstHost = await createHost(service, env, { alias: 'shared-one' });
    const managedKey = ssh.listManagedKeys(path.join(serviceHome, 'hosts.json'))
      .find((record) => record.alias === firstHost.alias);
    const secondHost = await createHost(service, env, {
      alias: 'shared-two',
      hostname: '192.0.2.12',
      port: 2228,
      key: false,
    });
    assert.equal((await api(service, `/v1/hosts/${secondHost.alias}/key/link`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { keyId: managedKey.id },
    })).status, 200);
    ssh.trust(path.join(serviceHome, 'hosts.json'), secondHost, 'SHA256:ticket01-second-host');

    const firstTargetId = await createGrant(service, env, firstHost.alias);
    const secondTargetId = await createGrant(service, env, secondHost.alias);
    assert.equal((await api(service, `/v1/hosts/${firstHost.alias}/key/unlink`, {
      method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {},
    })).status, 204);

    assert.equal(service.getTunnelTargetGrant(firstHost.alias, firstTargetId) === undefined, true,
      '解除關聯的 alias grant 必須失效');
    assert.equal(Boolean(service.getTunnelTargetGrant(secondHost.alias, secondTargetId)), true,
      '仍關聯同一 managed key 的其他 alias grant 必須維持有效');
  } finally {
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('fingerprint trust A→B→A 在中途未 lookup 時也永久撤銷舊 target grant', {
  timeout: 60_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket01-trust-rotation-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  const keyA = createSshHostKey();
  const keyB = createSshHostKey();
  let peer;
  let service;
  try {
    peer = await startSshFingerprintPeer(keyA.privateKey);
    const port = peer.address().port;
    service = await startService({ env, port: 0 });
    const host = await createHost(service, env, {
      alias: 'trust-rotation',
      hostname: '127.0.0.1',
      port,
      trust: false,
    });
    const check = (expectedFingerprint) => api(service, `/v1/hosts/${host.alias}/check`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { expectedFingerprint },
    });

    assert.equal((await check(keyA.fingerprint)).status, 200, '第一個已核對的 fingerprint 應完成 trust');
    const targetId = await createGrant(service, env, host.alias);
    const events = [];
    service.subscribeTunnelTargetGrantInvalidation((event) => {
      events.push(event);
      assert.equal(service.getTunnelTargetGrant(event.alias, event.targetId), undefined,
        'fingerprint trust 變更通知前 grant 必須已撤銷');
    });

    await closeSshFingerprintPeer(peer);
    peer = await startSshFingerprintPeer(keyB.privateKey, port);
    assert.equal((await check(keyB.fingerprint)).status, 200, '輪替後核對的新 fingerprint 應完成 trust');
    assert.deepEqual(events, [{
      alias: host.alias, targetId, reason: 'fingerprint-trust-changed',
    }]);

    await closeSshFingerprintPeer(peer);
    peer = await startSshFingerprintPeer(keyA.privateKey, port);
    assert.equal((await check(keyA.fingerprint)).status, 200, '再次核對舊 fingerprint 應完成 trust');

    assert.equal(service.getTunnelTargetGrant(host.alias, targetId) === undefined, true,
      'A→B→A 輪替不得讓中途未 lookup 的舊 target ID 復活');
    assert.equal(events.length, 1, '已撤銷 target ID 不得在 trust 回到 A 時重新產生失效事件或復活');
  } finally {
    if (peer) await closeSshFingerprintPeer(peer);
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
