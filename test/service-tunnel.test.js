'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { Duplex } = require('node:stream');
const { utils } = require('ssh2');
const WebSocket = require('ws');
const ssh = require('../lib/ssh');
const { startService } = require('../lib/service-server');
const { createOpenSshServiceFixture } = require('./helpers/openssh-service-fixture');
const { api, createServiceEnv, makeTaskTemp } = require('./helpers/service-test-utils');

const trustedFingerprint = 'SHA256:ticket02-test-trust';

function createTargetGrant(service, env, alias, { targetHost = '127.0.0.1', targetPort = 1 } = {}) {
  return api(service, `/v1/hosts/${alias}/tcp-tunnel-targets`, {
    method: 'POST',
    token: env.SSHDECK_UI_TOKEN,
    body: { targetHost, targetPort },
  });
}

function installMockDirectTcpip({ holdFirstWrite = false, holdOpen = false } = {}) {
  const originalOpenDirectTcpip = ssh.openDirectTcpip;
  const sessions = [];
  let resolveOpenStarted;
  let releasePendingOpen;
  let openAbortObserved = false;
  const openStarted = new Promise((resolve) => { resolveOpenStarted = resolve; });
  ssh.openDirectTcpip = async (_dataFile, host, _passphrase, { signal } = {}) => {
    resolveOpenStarted();
    if (holdOpen) {
      await new Promise((_resolve, reject) => {
        const onAbort = () => { openAbortObserved = true; };
        signal?.addEventListener('abort', onAbort, { once: true });
        releasePendingOpen = () => {
          signal?.removeEventListener('abort', onAbort);
          reject(Object.assign(new Error('mock direct-tcpip open cancelled'), { code: 'ABORT_ERR' }));
        };
      });
    }
    let firstWriteReleased = !holdFirstWrite;
    let releaseFirstWrite;
    let resolveFirstWrite;
    let failure;
    const record = {
      alias: host.alias,
      received: [],
      firstWrite: new Promise((resolve) => { resolveFirstWrite = resolve; }),
      releaseFirstWrite() {
        firstWriteReleased = true;
        releaseFirstWrite?.();
        releaseFirstWrite = undefined;
      },
      fail(error = Object.assign(new Error('mock direct-tcpip channel failed'), { code: 'MOCK_CHANNEL_FAILED' })) {
        failure = error;
        channel.destroy(error);
      },
    };
    const channel = new Duplex({
      read() {},
      write(chunk, _encoding, callback) {
        const copy = Buffer.from(chunk);
        record.received.push(copy);
        resolveFirstWrite();
        const finish = () => {
          if (!channel.destroyed) channel.push(copy);
          callback();
        };
        if (!firstWriteReleased && record.received.length === 1) releaseFirstWrite = finish;
        else finish();
      },
    });
    channel.on('error', (error) => { failure = error; });
    const closed = new Promise((resolve) => {
      channel.once('close', () => resolve(failure ? { error: failure } : {}));
    });
    const close = () => {
      if (!channel.destroyed) channel.destroy();
      return closed;
    };
    const abort = () => { void close(); };
    signal?.addEventListener('abort', abort, { once: true });
    closed.then(() => signal?.removeEventListener('abort', abort));
    const session = { alias: host.alias, channel, closed, close, ...record };
    sessions.push(session);
    return session;
  };
  return {
    sessions,
    openStarted,
    get openAbortObserved() { return openAbortObserved; },
    releaseOpen() { releasePendingOpen?.(); },
    restore() { ssh.openDirectTcpip = originalOpenDirectTcpip; },
  };
}

async function connectGrantedTunnel(service, env, alias, targetId) {
  const url = `${service.url.replace(/^http/, 'ws')}/v1/hosts/${alias}/tcp-tunnel`;
  const opened = await openSocket(url, env.SSHDECK_TUNNEL_TOKEN);
  assert.equal(opened.status, 101);
  const started = waitForControl(opened.socket, (message) => ['started', 'error'].includes(message.type));
  opened.socket.send(JSON.stringify({ type: 'open', targetId }));
  const result = await started;
  assert.equal(result.type, 'started', `SSH direct-tcpip 必須建立：${result.code || ''} ${result.error || ''}`);
  return opened.socket;
}

function openSocket(url, token) {
  return new Promise((resolve) => {
    const socket = new WebSocket(url, {
      ...(token ? { headers: { authorization: `Bearer ${token}` } } : {}),
      handshakeTimeout: 5000,
      perMessageDeflate: false,
    });
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, socket });
    };
    socket.once('open', () => finish({ status: 101 }));
    socket.once('unexpected-response', (_request, response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      response.once('end', () => finish({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    socket.once('error', () => finish({ status: 0 }));
  });
}

function closeSocket(socket) {
  if (!socket || socket.readyState === WebSocket.CLOSED) return Promise.resolve();
  return new Promise((resolve) => {
    socket.once('close', resolve);
    if (socket.readyState === WebSocket.OPEN) socket.close();
    else socket.terminate();
  });
}

function waitForControl(socket, predicate, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off('message', onMessage);
      reject(new Error('等待 tunnel WebSocket control frame 逾時'));
    }, timeoutMs);
    const onMessage = (data, isBinary) => {
      if (isBinary) return;
      let message;
      try { message = JSON.parse(data.toString()); } catch { return; }
      if (!predicate(message)) return;
      clearTimeout(timer);
      socket.off('message', onMessage);
      resolve(message);
    };
    socket.on('message', onMessage);
  });
}

function waitForSocketClose(socket, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off('close', onClose);
      reject(new Error('等待 tunnel WebSocket close 逾時'));
    }, timeoutMs);
    const onClose = (code, reason) => {
      clearTimeout(timer);
      resolve({ code, reason: reason.toString() });
    };
    socket.once('close', onClose);
  });
}

async function createGrantedHost(service, env, alias) {
  const host = { alias, hostname: '127.0.0.1', port: 2227, username: 'ticket02-user' };
  const created = await api(service, '/v1/hosts', {
    method: 'POST',
    token: env.SSHDECK_UI_TOKEN,
    body: host,
  });
  assert.equal(created.status, 201);
  const key = await api(service, `/v1/hosts/${alias}/key/create`, {
    method: 'POST',
    token: env.SSHDECK_UI_TOKEN,
    body: {},
  });
  assert.equal(key.status, 201, `key/create failed: ${key.payload?.code || 'unknown'}`);
  ssh.trust(path.join(env.SSHDECK_SERVICE_HOME, 'hosts.json'), host, trustedFingerprint);
  const grant = await api(service, `/v1/hosts/${alias}/tcp-tunnel-targets`, {
    method: 'POST',
    token: env.SSHDECK_UI_TOKEN,
    body: { targetHost: '127.0.0.1', targetPort: 1 },
  });
  assert.equal(grant.status, 201);
  return { host, targetId: grant.payload.targetId };
}

async function sendAndExpectError(socket, frame, expectedCode) {
  const control = waitForControl(socket, (message) => message.type === 'error');
  const closed = waitForSocketClose(socket);
  if (Buffer.isBuffer(frame)) socket.send(frame, { binary: true });
  else socket.send(frame);
  const [message, close] = await Promise.all([control, closed]);
  assert.equal(message.code, expectedCode);
  assert.equal(typeof message.error, 'string');
  assert.notEqual(close.code, 1000, '無效 tunnel frame 必須以協定錯誤關閉');
}

function waitForBinaryBytes(socket, length, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    const timer = setTimeout(() => finish(new Error('等待 tunnel binary echo 逾時')), timeoutMs);
    const onMessage = (data, isBinary) => {
      if (!isBinary) return;
      chunks.push(Buffer.from(data));
      bytes += data.length;
      if (bytes >= length) finish();
    };
    const finish = (error) => {
      clearTimeout(timer);
      socket.off('message', onMessage);
      if (error) reject(error);
      else resolve(Buffer.concat(chunks, bytes));
    };
    socket.on('message', onMessage);
  });
}

test('tcp tunnel WebSocket 僅接受 tunnel token，並拒絕 query token／destination', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-auth-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  const sockets = [];
  try {
    service = await startService({ env, port: 0 });
    const route = `/v1/hosts/unconfigured/tcp-tunnel`;
    const url = `${service.url.replace(/^http/, 'ws')}${route}`;
    const cases = [
      { name: '缺少 token', token: undefined, status: 401 },
      { name: '錯誤 token', token: 'invalid-tunnel-token', status: 401 },
      { name: 'CLI token', token: env.SSHDECK_SERVICE_TOKEN, status: 403 },
      { name: 'UI token', token: env.SSHDECK_UI_TOKEN, status: 403 },
      { name: 'tunnel token', token: env.SSHDECK_TUNNEL_TOKEN, status: 101 },
    ];
    for (const item of cases) {
      const opened = await openSocket(url, item.token);
      sockets.push(opened.socket);
      assert.equal(opened.status, item.status, `${item.name} 的 WebSocket upgrade 狀態錯誤：${opened.body || ''}`);
    }
    const tunnelTokenHttp = await api(service, '/v1/hosts', { token: env.SSHDECK_TUNNEL_TOKEN });
    assert.equal(tunnelTokenHttp.status, 403, 'tunnel token 不得呼叫既有 HTTP 管理 API');

    for (const query of ['?token=sentinel', '?targetHost=127.0.0.1&targetPort=22']) {
      const opened = await openSocket(`${url}${query}`, env.SSHDECK_TUNNEL_TOKEN);
      sockets.push(opened.socket);
      assert.equal(opened.status, 400, `tunnel endpoint 必須拒絕 query ${query}`);
    }
  } finally {
    await Promise.all(sockets.map(closeSocket));
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('真實 Ubuntu OpenSSH direct-tcpip tunnel 傳送 binary bytes 並拒絕 PermitOpen 範圍外目的地', {
  skip: process.platform === 'win32' ? false : '需要受控 Ubuntu WSL OpenSSH fixture',
  timeout: 150_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-ssh-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  const keyPair = utils.generateKeyPairSync('ed25519', { comment: 'sshdeck-ticket02-real-tunnel' });
  let fixture;
  let service;
  const sockets = [];
  try {
    fixture = await createOpenSshServiceFixture({
      authorizedPublicKey: keyPair.public,
      evidenceFile: process.env.SSHDECK_TEST_TUNNEL_FIXTURE_EVIDENCE,
      allowDirectTcpip: true,
    });
    service = await startService({ env, port: 0 });
    const alias = 'ticket02-real-tunnel';
    const host = { alias, hostname: '127.0.0.1', port: fixture.ports[0], username: 'root' };
    assert.equal((await api(service, '/v1/hosts', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: host,
    })).status, 201);
    assert.equal((await api(service, `/v1/hosts/${alias}/key/import`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { privateKey: keyPair.private, passphrase: '' },
    })).status, 201);
    const trusted = await api(service, `/v1/hosts/${alias}/check`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { expectedFingerprint: fixture.fingerprints.a },
    });
    assert.equal(trusted.status, 200, 'service-managed SSH identity 必須核對並信任真實 OpenSSH fingerprint');
    assert.ok(Number.isInteger(fixture.targetPort) && fixture.targetPort > 0);
    assert.equal(fixture.isTargetListening(), true, '受控 Ubuntu TCP echo target 必須在 SSHD PermitOpen 中啟用');
    const targetPort = fixture.targetPort;
    const grant = await api(service, `/v1/hosts/${alias}/tcp-tunnel-targets`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { targetHost: '127.0.0.1', targetPort },
    });
    assert.equal(grant.status, 201);

    const url = `${service.url.replace(/^http/, 'ws')}/v1/hosts/${alias}/tcp-tunnel`;
    const opened = await openSocket(url, env.SSHDECK_TUNNEL_TOKEN);
    let socket = opened.socket;
    sockets.push(socket);
    assert.equal(opened.status, 101);
    const started = waitForControl(socket, (message) => ['started', 'error'].includes(message.type), 20_000);
    socket.send(JSON.stringify({ type: 'open', targetId: grant.payload.targetId }));
    const openResult = await started;
    assert.equal(openResult.type, 'started', `真實 direct-tcpip channel 必須建立：${openResult.code || ''}`);

    const payload = randomBytes(8 * 1024 * 1024);
    const echoed = waitForBinaryBytes(socket, payload.length, 60_000);
    const frameSize = 64 * 1024;
    const clientTransport = socket._socket;
    clientTransport.pause();
    try {
      for (let offset = 0; offset < payload.length; offset += frameSize) {
        socket.send(payload.subarray(offset, Math.min(offset + frameSize, payload.length)), { binary: true });
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    } finally {
      clientTransport.resume();
    }
    assert.deepEqual(await echoed, payload, '多個 binary frame 必須保序、逐 byte 完整傳回');

    const revokeGrant = await createTargetGrant(service, env, alias, { targetPort });
    assert.equal(revokeGrant.status, 201);
    const active = await openSocket(url, env.SSHDECK_TUNNEL_TOKEN);
    const activeSocket = active.socket;
    sockets.push(activeSocket);
    assert.equal(active.status, 101);
    const activeStarted = waitForControl(activeSocket, (message) => ['started', 'error'].includes(message.type), 20_000);
    activeSocket.send(JSON.stringify({ type: 'open', targetId: revokeGrant.payload.targetId }));
    assert.equal((await activeStarted).type, 'started');
    const revokeControl = waitForControl(activeSocket, (message) => message.type === 'error');
    const revokeClose = waitForSocketClose(activeSocket);
    const revoked = await api(
      service,
      `/v1/hosts/${alias}/tcp-tunnel-targets/${revokeGrant.payload.targetId}`,
      { method: 'DELETE', token: env.SSHDECK_UI_TOKEN },
    );
    assert.equal(revoked.status, 204);
    assert.equal((await revokeControl).code, 'TARGET_GRANT_INVALIDATED');
    await revokeClose;
    assert.equal(activeSocket.readyState, WebSocket.CLOSED,
      'grant revoke 回應前必須關閉真實 SSH direct-tcpip channel');

    await closeSocket(socket);
    const deniedGrant = await api(service, `/v1/hosts/${alias}/tcp-tunnel-targets`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { targetHost: '127.0.0.1', targetPort: 22 },
    });
    assert.equal(deniedGrant.status, 201);
    const denied = await openSocket(url, env.SSHDECK_TUNNEL_TOKEN);
    socket = denied.socket;
    sockets.push(socket);
    assert.equal(denied.status, 101);
    await sendAndExpectError(
      socket,
      JSON.stringify({ type: 'open', targetId: deniedGrant.payload.targetId }),
      'DIRECT_TCPIP_DENIED',
    );
  } finally {
    await Promise.all(sockets.map(closeSocket));
    if (service) await service.closeAsync();
    if (fixture) await fixture.cleanup();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('tcp tunnel 只接受首個有效 open text frame 並 fail closed 拒絕無效輸入', {
  timeout: 60_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-open-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  const sockets = [];
  try {
    service = await startService({ env, port: 0 });
    const alias = 'tunnel-open';
    const { targetId } = await createGrantedHost(service, env, alias);
    const otherGrant = await createGrantedHost(service, env, 'tunnel-open-other');
    const url = `${service.url.replace(/^http/, 'ws')}/v1/hosts/${alias}/tcp-tunnel`;
    const invalidFrames = [
      { frame: Buffer.from([0, 1, 255]), code: 'INVALID_TUNNEL_FRAME' },
      { frame: '{invalid json', code: 'INVALID_TUNNEL_FRAME' },
      { frame: JSON.stringify({ type: 'exec', command: 'id' }), code: 'INVALID_TUNNEL_OPEN' },
      {
        frame: JSON.stringify({ type: 'open', targetId, targetHost: '127.0.0.1', targetPort: 22 }),
        code: 'INVALID_TUNNEL_OPEN',
      },
      { frame: JSON.stringify({ type: 'open' }), code: 'INVALID_TUNNEL_OPEN' },
      {
        frame: JSON.stringify({ type: 'open', targetId: 'not-a-grant' }),
        code: 'TARGET_NOT_AUTHORIZED',
      },
      {
        frame: JSON.stringify({ type: 'open', targetId: otherGrant.targetId }),
        code: 'TARGET_NOT_AUTHORIZED',
      },
    ];
    for (const item of invalidFrames) {
      const opened = await openSocket(url, env.SSHDECK_TUNNEL_TOKEN);
      sockets.push(opened.socket);
      assert.equal(opened.status, 101);
      await sendAndExpectError(opened.socket, item.frame, item.code);
    }
  } finally {
    await Promise.all(sockets.map(closeSocket));
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('tcp tunnel 在單一 stream 啟動後拒絕第二個 open', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-single-open-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let mock;
  let socket;
  try {
    service = await startService({ env, port: 0 });
    const alias = 'tunnel-single-open';
    const { targetId } = await createGrantedHost(service, env, alias);
    mock = installMockDirectTcpip();
    socket = await connectGrantedTunnel(service, env, alias, targetId);

    await sendAndExpectError(
      socket,
      JSON.stringify({ type: 'open', targetId }),
      'TUNNEL_ALREADY_OPEN',
    );
    assert.equal(mock.sessions.length, 1, '重複 open 不得另建第二個 SSH channel');
  } finally {
    await closeSocket(socket);
    mock?.restore();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('並行 tunnel streams 保持 binary 隔離且單一 stream 的第二次 open 不影響其他 stream', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-isolation-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let mock;
  const sockets = [];
  try {
    service = await startService({ env, port: 0 });
    const first = await createGrantedHost(service, env, 'tunnel-isolation-a');
    const second = await createGrantedHost(service, env, 'tunnel-isolation-b');
    mock = installMockDirectTcpip();
    const firstSocket = await connectGrantedTunnel(service, env, 'tunnel-isolation-a', first.targetId);
    const secondSocket = await connectGrantedTunnel(service, env, 'tunnel-isolation-b', second.targetId);
    sockets.push(firstSocket, secondSocket);

    const firstPayload = randomBytes(128 * 1024);
    const secondPayload = randomBytes(96 * 1024);
    const firstEcho = waitForBinaryBytes(firstSocket, firstPayload.length);
    const secondEcho = waitForBinaryBytes(secondSocket, secondPayload.length);
    firstSocket.send(firstPayload, { binary: true });
    secondSocket.send(secondPayload, { binary: true });
    const [firstResult, secondResult] = await Promise.all([firstEcho, secondEcho]);
    assert.deepEqual(firstResult, firstPayload);
    assert.deepEqual(secondResult, secondPayload);
    assert.deepEqual(mock.sessions.map((session) => session.alias).sort(), [
      'tunnel-isolation-a',
      'tunnel-isolation-b',
    ]);

    await sendAndExpectError(
      firstSocket,
      JSON.stringify({ type: 'open', targetId: first.targetId }),
      'TUNNEL_ALREADY_OPEN',
    );
    const unaffectedPayload = randomBytes(4096);
    const unaffectedEcho = waitForBinaryBytes(secondSocket, unaffectedPayload.length);
    secondSocket.send(unaffectedPayload, { binary: true });
    assert.deepEqual(await unaffectedEcho, unaffectedPayload);
  } finally {
    await Promise.all(sockets.map(closeSocket));
    mock?.restore();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('TCP tunnel 的 binary backpressure 暫停並恢復讀取且不遺失 bytes', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-backpressure-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let mock;
  let socket;
  try {
    service = await startService({ env, port: 0 });
    const alias = 'tunnel-backpressure';
    const { targetId } = await createGrantedHost(service, env, alias);
    mock = installMockDirectTcpip({ holdFirstWrite: true });
    socket = await connectGrantedTunnel(service, env, alias, targetId);

    const payload = randomBytes(512 * 1024);
    const echoed = waitForBinaryBytes(socket, payload.length);
    const frameSize = 16 * 1024;
    for (let offset = 0; offset < payload.length; offset += frameSize) {
      socket.send(payload.subarray(offset, Math.min(offset + frameSize, payload.length)), { binary: true });
    }
    await mock.sessions[0].firstWrite;
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(mock.sessions[0].received.length, 1,
      'SSH channel 尚未 drain 時不得持續向目的端寫入 buffered bytes');
    mock.sessions[0].releaseFirstWrite();
    assert.deepEqual(await echoed, payload, '目的端恢復 drain 後須依序傳送全部 binary bytes');
    assert.deepEqual(Buffer.concat(mock.sessions[0].received), payload);
  } finally {
    mock?.sessions.forEach((session) => session.releaseFirstWrite());
    await closeSocket(socket);
    mock?.restore();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('SSH direct-tcpip 正常 close 會通知 client 並只關閉自己的 stream', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-close-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let mock;
  const sockets = [];
  try {
    service = await startService({ env, port: 0 });
    const alias = 'tunnel-normal-close';
    const otherAlias = 'tunnel-normal-close-peer';
    const host = await createGrantedHost(service, env, alias);
    const otherHost = await createGrantedHost(service, env, otherAlias);
    mock = installMockDirectTcpip();
    const socket = await connectGrantedTunnel(service, env, alias, host.targetId);
    const otherSocket = await connectGrantedTunnel(service, env, otherAlias, otherHost.targetId);
    sockets.push(socket, otherSocket);

    const closedControl = waitForControl(socket, (message) => message.type === 'closed');
    const socketClosed = waitForSocketClose(socket);
    mock.sessions[0].close();
    const [control, close] = await Promise.all([closedControl, socketClosed]);
    assert.equal(control.type, 'closed');
    assert.equal(close.code, 1000);
    assert.equal(otherSocket.readyState, WebSocket.OPEN);
  } finally {
    await Promise.all(sockets.map(closeSocket));
    mock?.restore();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('grant revoke 與 host update/removal 先關閉相符 streams 且不影響其他 grant', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-invalidation-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let mock;
  const sockets = [];
  try {
    service = await startService({ env, port: 0 });
    const firstAlias = 'tunnel-invalidation-a';
    const secondAlias = 'tunnel-invalidation-b';
    const firstHost = await createGrantedHost(service, env, firstAlias);
    const firstTarget = await createTargetGrant(service, env, firstAlias, { targetPort: 2 });
    const secondHost = await createGrantedHost(service, env, secondAlias);
    assert.equal(firstTarget.status, 201);
    mock = installMockDirectTcpip();

    const firstSocket = await connectGrantedTunnel(service, env, firstAlias, firstHost.targetId);
    const secondSocket = await connectGrantedTunnel(service, env, firstAlias, firstTarget.payload.targetId);
    const otherHostSocket = await connectGrantedTunnel(service, env, secondAlias, secondHost.targetId);
    sockets.push(firstSocket, secondSocket, otherHostSocket);

    const revokedControl = waitForControl(firstSocket, (message) => message.type === 'error');
    const revokedClose = waitForSocketClose(firstSocket);
    const revoked = await api(
      service,
      `/v1/hosts/${firstAlias}/tcp-tunnel-targets/${firstHost.targetId}`,
      { method: 'DELETE', token: env.SSHDECK_UI_TOKEN },
    );
    assert.equal(revoked.status, 204);
    const [revokedMessage] = await Promise.all([revokedControl, revokedClose]);
    assert.equal(revokedMessage.code, 'TARGET_GRANT_INVALIDATED');
    assert.equal(firstSocket.readyState, WebSocket.CLOSED,
      'revoke response 完成前必須已關閉該 target 的 WebSocket');
    assert.equal(secondSocket.readyState, WebSocket.OPEN);
    assert.equal(otherHostSocket.readyState, WebSocket.OPEN);

    const updatedControl = waitForControl(secondSocket, (message) => message.type === 'error');
    const updatedClose = waitForSocketClose(secondSocket);
    const updated = await api(service, `/v1/hosts/${firstAlias}`, {
      method: 'PUT',
      token: env.SSHDECK_UI_TOKEN,
      body: { hostname: '127.0.0.1', port: 2228, username: 'ticket02-user' },
    });
    assert.equal(updated.status, 200);
    const [updatedMessage] = await Promise.all([updatedControl, updatedClose]);
    assert.equal(updatedMessage.code, 'TARGET_GRANT_INVALIDATED');
    assert.equal(secondSocket.readyState, WebSocket.CLOSED,
      'host update response 完成前必須關閉該 alias 的 streams');
    assert.equal(otherHostSocket.readyState, WebSocket.OPEN);

    const removedControl = waitForControl(otherHostSocket, (message) => message.type === 'error');
    const removedClose = waitForSocketClose(otherHostSocket);
    const targetIdBeforeRemoval = secondHost.targetId;
    const removed = await api(service, `/v1/hosts/${secondAlias}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    });
    assert.equal(removed.status, 204);
    const [removedMessage] = await Promise.all([removedControl, removedClose]);
    assert.equal(removedMessage.code, 'TARGET_GRANT_INVALIDATED');
    assert.equal(otherHostSocket.readyState, WebSocket.CLOSED,
      'host removal response 完成前必須關閉該 alias 的 streams');

    await createGrantedHost(service, env, secondAlias);
    const staleAfterRecreation = await openSocket(
      `${service.url.replace(/^http/, 'ws')}/v1/hosts/${secondAlias}/tcp-tunnel`,
      env.SSHDECK_TUNNEL_TOKEN,
    );
    sockets.push(staleAfterRecreation.socket);
    assert.equal(staleAfterRecreation.status, 101);
    await sendAndExpectError(
      staleAfterRecreation.socket,
      JSON.stringify({ type: 'open', targetId: targetIdBeforeRemoval }),
      'TARGET_NOT_AUTHORIZED',
    );
  } finally {
    await Promise.all(sockets.map(closeSocket));
    mock?.restore();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('grant revoke 等待尚在建立中的 direct-tcpip 開啟取消完成', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-open-cancel-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let mock;
  let socket;
  let deletion;
  try {
    service = await startService({ env, port: 0 });
    const alias = 'tunnel-open-cancel';
    const { targetId } = await createGrantedHost(service, env, alias);
    mock = installMockDirectTcpip({ holdOpen: true });
    const opened = await openSocket(
      `${service.url.replace(/^http/, 'ws')}/v1/hosts/${alias}/tcp-tunnel`,
      env.SSHDECK_TUNNEL_TOKEN,
    );
    socket = opened.socket;
    assert.equal(opened.status, 101);
    const invalidation = waitForControl(socket, (message) => message.type === 'error');
    const socketClosed = waitForSocketClose(socket);
    socket.send(JSON.stringify({ type: 'open', targetId }));
    await mock.openStarted;

    let deletionCompleted = false;
    deletion = api(service, `/v1/hosts/${alias}/tcp-tunnel-targets/${targetId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    }).then((result) => {
      deletionCompleted = true;
      return result;
    });
    const [invalidationMessage] = await Promise.all([invalidation, socketClosed]);
    assert.equal(invalidationMessage.code, 'TARGET_GRANT_INVALIDATED');
    assert.equal(mock.openAbortObserved, true, '撤銷必須取消正在進行的 SSH direct-tcpip 開啟');
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.equal(deletionCompleted, false, 'DELETE 必須等待 pending SSH channel 開啟取消完成');

    mock.releaseOpen();
    const revoked = await deletion;
    assert.equal(revoked.status, 204);
  } finally {
    mock?.releaseOpen();
    if (deletion) await deletion;
    await closeSocket(socket);
    mock?.restore();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('key unlink、lock、client disconnect、SSH channel error 與 shutdown 都取消對應 tunnel', {
  timeout: 30_000,
}, async () => {
  const temp = makeTaskTemp('sshdeck-ticket02-tunnel-lifecycle-');
  const env = createServiceEnv(path.join(temp, 'service-home'));
  let service;
  let mock;
  const sockets = [];
  try {
    service = await startService({ env, port: 0 });
    const alias = 'tunnel-lifecycle';
    const otherAlias = 'tunnel-lifecycle-peer';
    await createGrantedHost(service, env, alias);
    await createGrantedHost(service, env, otherAlias);
    const keys = await api(service, '/v1/keys', { token: env.SSHDECK_UI_TOKEN });
    assert.equal(keys.status, 200);
    const keyId = keys.payload.find((item) => item.associatedAliases.includes(alias))?.id;
    assert.ok(keyId);
    mock = installMockDirectTcpip();

    let grant = await createTargetGrant(service, env, alias);
    const targetIdBeforeUnlink = grant.payload.targetId;
    let socket = await connectGrantedTunnel(service, env, alias, grant.payload.targetId);
    sockets.push(socket);
    const unlinkControl = waitForControl(socket, (message) => message.type === 'error');
    const unlinkClose = waitForSocketClose(socket);
    const unlinked = await api(service, `/v1/hosts/${alias}/key/unlink`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: {},
    });
    assert.equal(unlinked.status, 204);
    const [unlinkMessage] = await Promise.all([unlinkControl, unlinkClose]);
    assert.equal(unlinkMessage.code, 'TARGET_GRANT_INVALIDATED');
    assert.equal(socket.readyState, WebSocket.CLOSED,
      'key unlink response 完成前必須關閉相符 streams');

    const linked = await api(service, `/v1/hosts/${alias}/key/link`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { keyId },
    });
    assert.equal(linked.status, 200);
    const staleAfterRelink = await openSocket(
      `${service.url.replace(/^http/, 'ws')}/v1/hosts/${alias}/tcp-tunnel`,
      env.SSHDECK_TUNNEL_TOKEN,
    );
    sockets.push(staleAfterRelink.socket);
    assert.equal(staleAfterRelink.status, 101);
    await sendAndExpectError(
      staleAfterRelink.socket,
      JSON.stringify({ type: 'open', targetId: targetIdBeforeUnlink }),
      'TARGET_NOT_AUTHORIZED',
    );
    const unlinkedForRemoval = await api(service, `/v1/hosts/${alias}/key/unlink`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: {},
    });
    assert.equal(unlinkedForRemoval.status, 204);
    const removedKey = await api(service, `/v1/keys/${keyId}`, {
      method: 'DELETE',
      token: env.SSHDECK_UI_TOKEN,
    });
    assert.equal(removedKey.status, 200);
    const replacementKey = await api(service, `/v1/hosts/${alias}/key/create`, {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: {},
    });
    assert.equal(replacementKey.status, 201);
    const peerGrant = await createTargetGrant(service, env, otherAlias);
    let peerSocket = await connectGrantedTunnel(service, env, otherAlias, peerGrant.payload.targetId);
    sockets.push(peerSocket);
    grant = await createTargetGrant(service, env, alias);
    socket = await connectGrantedTunnel(service, env, alias, grant.payload.targetId);
    sockets.push(socket);
    const lockControl = waitForControl(socket, (message) => message.type === 'error');
    const lockClose = waitForSocketClose(socket);
    const peerLockControl = waitForControl(peerSocket, (message) => message.type === 'error');
    const peerLockClose = waitForSocketClose(peerSocket);
    const locked = await api(service, '/v1/lock', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: {},
    });
    assert.equal(locked.status, 204);
    const [lockMessage, , peerLockMessage] = await Promise.all([
      lockControl,
      lockClose,
      peerLockControl,
      peerLockClose,
    ]);
    assert.equal(lockMessage.code, 'TARGET_GRANT_INVALIDATED');
    assert.equal(peerLockMessage.code, 'TARGET_GRANT_INVALIDATED');
    assert.equal(socket.readyState, WebSocket.CLOSED,
      'lock response 完成前必須關閉所有 grant streams');
    assert.equal(peerSocket.readyState, WebSocket.CLOSED,
      'lock 必須同時關閉其他 alias 的 active streams');
    const lockedUpgrade = await openSocket(
      `${service.url.replace(/^http/, 'ws')}/v1/hosts/${alias}/tcp-tunnel`,
      env.SSHDECK_TUNNEL_TOKEN,
    );
    assert.equal(lockedUpgrade.status, 423, 'locked service 必須在 upgrade 前拒絕新 tunnel');

    const unlocked = await api(service, '/v1/unlock', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: {},
    });
    assert.equal(unlocked.status, 204);
    const disconnectedPeerGrant = await createTargetGrant(service, env, otherAlias);
    peerSocket = await connectGrantedTunnel(service, env, otherAlias, disconnectedPeerGrant.payload.targetId);
    sockets.push(peerSocket);
    grant = await createTargetGrant(service, env, alias);
    socket = await connectGrantedTunnel(service, env, alias, grant.payload.targetId);
    sockets.push(socket);
    const disconnected = waitForSocketClose(socket);
    const disconnectedSession = mock.sessions.at(-1);
    const disconnectPayload = randomBytes(4096);
    const disconnectEcho = waitForBinaryBytes(socket, disconnectPayload.length);
    socket.send(disconnectPayload, { binary: true });
    assert.deepEqual(await disconnectEcho, disconnectPayload);
    const sessionsBeforeDisconnect = mock.sessions.length;
    socket.terminate();
    await Promise.all([disconnected, disconnectedSession.closed]);
    assert.equal(disconnectedSession.channel.destroyed, true);
    assert.equal(mock.sessions.length, sessionsBeforeDisconnect,
      'client disconnect 後不得自動建立 SSH channel 或重送資料');
    assert.equal(peerSocket.readyState, WebSocket.OPEN,
      'client disconnect 不得影響其他 alias 的 stream');
    const peerPayload = randomBytes(4096);
    const peerEcho = waitForBinaryBytes(peerSocket, peerPayload.length);
    peerSocket.send(peerPayload, { binary: true });
    assert.deepEqual(await peerEcho, peerPayload);
    grant = await createTargetGrant(service, env, alias);
    socket = await connectGrantedTunnel(service, env, alias, grant.payload.targetId);
    sockets.push(socket);
    const channelErrorControl = waitForControl(socket, (message) => message.type === 'error');
    const channelErrorClose = waitForSocketClose(socket);
    mock.sessions.at(-1).fail();
    const [channelErrorMessage] = await Promise.all([channelErrorControl, channelErrorClose]);
    assert.equal(channelErrorMessage.code, 'SSH_CHANNEL_FAILED');
    assert.equal(peerSocket.readyState, WebSocket.OPEN);

    grant = await createTargetGrant(service, env, alias);
    socket = await connectGrantedTunnel(service, env, alias, grant.payload.targetId);
    sockets.push(socket);
    const shutdownSession = mock.sessions.at(-1);
    const shutdownPeerSession = mock.sessions.filter((session) => session.alias === otherAlias).at(-1);
    await service.closeAsync();
    service = undefined;
    assert.equal(socket.readyState, WebSocket.CLOSED);
    assert.equal(shutdownSession.channel.destroyed, true);
    assert.equal(peerSocket.readyState, WebSocket.CLOSED);
    assert.equal(shutdownPeerSession.channel.destroyed, true);
  } finally {
    await Promise.all(sockets.map(closeSocket));
    mock?.restore();
    if (service) await service.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
