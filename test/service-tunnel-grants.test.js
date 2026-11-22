'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
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
