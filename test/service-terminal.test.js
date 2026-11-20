'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const tls = require('node:tls');
const { randomBytes, randomUUID } = require('node:crypto');
const { chromium } = require('playwright');
const { utils } = require('ssh2');
const WebSocket = require('ws');
const { startUi } = require('../bin/sshdeck.js');
const { startService } = require('../lib/service-server');
const { createOpenSshServiceFixture } = require('./helpers/openssh-service-fixture');
const { createHttpsTestCertificate } = require('./helpers/https-test-certificate');
const { startServiceProcess } = require('./helpers/service-process');
const { createServiceEnv } = require('./helpers/service-test-utils');

const enabled = process.env.SSHDECK_TEST_SERVICE_SSH === '1';
const uiPort = Number(process.env.SSHDECK_TEST_UI_PORT || 18792);
const servicePort = Number(process.env.SSHDECK_TEST_API_PORT || 18793);
const terminalPath = (alias) => `/v1/hosts/${encodeURIComponent(alias)}/terminal`;

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

function socketUrl(base, route) {
  const url = new URL(route, base);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.href;
}

function openSocket(url, { origin, headers = {} } = {}) {
  return new Promise((resolve) => {
    const socket = new WebSocket(url, {
      ...(origin === undefined ? {} : { origin }),
      headers,
      handshakeTimeout: 5000,
      perMessageDeflate: false,
    });
    socket.controlMessages = [];
    socket.controlWaiters = [];
    socket.on('message', (data, isBinary) => {
      if (isBinary) return;
      let value;
      try { value = JSON.parse(data.toString()); } catch { return; }
      const waiterIndex = socket.controlWaiters.findIndex((waiter) => waiter.predicate(value));
      if (waiterIndex >= 0) {
        const [waiter] = socket.controlWaiters.splice(waiterIndex, 1);
        clearTimeout(waiter.timer);
        waiter.resolve(value);
      } else {
        socket.controlMessages.push(value);
      }
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
      let bytes = 0;
      response.on('data', (chunk) => {
        if (bytes >= 8192) return;
        const part = Buffer.from(chunk).subarray(0, 8192 - bytes);
        chunks.push(part);
        bytes += part.length;
      });
      response.once('end', () => finish({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    socket.once('error', () => finish({ status: 0 }));
  });
}

function nextControl(socket, predicate, timeoutMs = 5000) {
  const messageIndex = socket.controlMessages.findIndex(predicate);
  if (messageIndex >= 0) return Promise.resolve(socket.controlMessages.splice(messageIndex, 1)[0]);
  return new Promise((resolve, reject) => {
    const waiter = {
      predicate,
      resolve,
      timer: setTimeout(() => {
        const index = socket.controlWaiters.indexOf(waiter);
        if (index >= 0) socket.controlWaiters.splice(index, 1);
        reject(new Error('等待終端控制訊息逾時'));
      }, timeoutMs),
    };
    socket.controlWaiters.push(waiter);
  });
}

async function addManagedTerminalHost(service, env, alias, port, privateKey) {
  const headers = { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` };
  const added = await requestJson(service.url, '/v1/hosts', {
    method: 'POST',
    headers,
    body: { alias, hostname: '127.0.0.1', port, username: 'root' },
  });
  assert.equal(added.response.status, 201, 'service 受管主機建立失敗');
  const imported = await requestJson(service.url, `/v1/hosts/${encodeURIComponent(alias)}/key/import`, {
    method: 'POST',
    headers,
    body: { privateKey, passphrase: '' },
  });
  assert.equal(imported.response.status, 201, 'service 管理金鑰匯入失敗');
}

async function openTrustedTerminal(service, env, alias, fingerprint) {
  const opened = await openSocket(socketUrl(service.url, terminalPath(alias)), {
    origin: new URL(service.url).origin,
    headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
  });
  assert.equal(opened.status, 101, `合法 service terminal WS 必須 upgrade：${opened.body || ''}`);
  const first = await nextControl(
    opened.socket,
    (message) => ['trust-required', 'host-key-changed', 'started', 'error'].includes(message.type),
  );
  assert.notEqual(first.type, 'error', `真實 SSH PTY 啟動失敗：${first.code}`);
  if (first.type === 'trust-required' || first.type === 'host-key-changed') {
    assert.equal(first.fingerprint, fingerprint, 'trust challenge 必須提供 fixture 的實際指紋');
    const started = nextControl(opened.socket, (message) => message.type === 'started');
    opened.socket.send(JSON.stringify({ type: 'trust', fingerprint }));
    const result = await started;
    assert.equal(result.alias, alias);
  } else {
    assert.equal(first.type, 'started');
    assert.equal(first.alias, alias);
  }
  return opened.socket;
}

async function createTerminalRegressionContext({
  servicePort = 0,
  fixtureEvidenceFile,
} = {}) {
  const runId = randomUUID();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `sshdeck-ticket07-review-${runId}-`));
  const keyPair = utils.generateKeyPairSync('ed25519', { comment: `sshdeck-ticket07-review-${runId}` });
  const env = createServiceEnv(path.join(directory, 'service-home'));
  const context = {
    runId,
    directory,
    keyPair,
    env,
    fixture: null,
    service: null,
    aliasA: `ticket07-review-a-${runId.slice(0, 8)}`,
    aliasB: `ticket07-review-b-${runId.slice(0, 8)}`,
  };
  context.cleanup = async () => {
    const result = {
      service: context.service ? 'pending' : 'not-started',
      fixture: context.fixture ? 'pending' : 'not-started',
      activeTerminals: null,
      directory: 'pending',
    };
    if (context.service) {
      try {
        const shutdown = await context.service.closeAsync();
        result.activeTerminals = shutdown.activeTerminalCount;
        result.serviceExitCode = shutdown.exitCode;
        result.serviceError = shutdown.stderr?.match(/TypeError: [^\r\n]+/)?.[0];
        result.service = shutdown.exitCode === 0 && result.activeTerminals === 0 ? 'passed' : 'failed';
      } catch {
        result.service = 'failed';
      }
    }
    if (context.fixture) {
      try {
        await context.fixture.cleanup();
        result.fixture = 'passed';
      } catch {
        result.fixture = 'failed';
      }
    }
    try {
      fs.rmSync(context.directory, { recursive: true, force: true });
      result.directory = fs.existsSync(context.directory) ? 'failed' : 'passed';
    } catch {
      result.directory = 'failed';
    }
    return result;
  };

  try {
    context.fixture = await createOpenSshServiceFixture({
      authorizedPublicKey: keyPair.public,
      ...(fixtureEvidenceFile ? { evidenceFile: fixtureEvidenceFile } : {}),
      enablePty: true,
    });
    context.service = await startServiceProcess({ env, host: '127.0.0.1', port: servicePort });
    await addManagedTerminalHost(
      context.service,
      env,
      context.aliasA,
      context.fixture.ports[0],
      keyPair.private,
    );
    await addManagedTerminalHost(
      context.service,
      env,
      context.aliasB,
      context.fixture.ports[1],
      keyPair.private,
    );
    return context;
  } catch (error) {
    await context.cleanup();
    throw error;
  }
}

async function waitForActiveTerminalCount(service, expected, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  let count = await service.getActiveTerminalCount();
  while (count !== expected && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    count = await service.getActiveTerminalCount();
  }
  assert.equal(count, expected, `service active terminal count 應為 ${expected}`);
}

function waitForTerminalSocketClose(socket, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off('close', onClose);
      reject(new Error('等待 terminal WebSocket close 逾時'));
    }, timeoutMs);
    const onClose = (code, reason) => {
      clearTimeout(timer);
      resolve({ code, reason: reason.toString() });
    };
    socket.once('close', onClose);
  });
}

function waitForTerminalBinaryText(socket, marker, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let output = '';
    const onMessage = (data, isBinary) => {
      if (!isBinary) return;
      output += data.toString();
      if (!output.includes(marker)) return;
      clearTimeout(timer);
      socket.off('message', onMessage);
      resolve(output);
    };
    const timer = setTimeout(() => {
      socket.off('message', onMessage);
      reject(new Error(`等待 survivor PTY 輸出逾時：${marker}`));
    }, timeoutMs);
    socket.on('message', onMessage);
  });
}

function writeOptionalEvidence(file, evidence, { overwrite = false } = {}) {
  if (!file) return;
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`, {
    flag: overwrite ? 'w' : 'wx',
    encoding: 'utf8',
  });
}

async function requestJson(base, route, { method = 'GET', body, headers = {} } = {}) {
  const response = await fetch(new URL(route, base), {
    method,
    headers: {
      ...headers,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : {
      body: JSON.stringify(body),
    }),
  });
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = text; }
  }
  return { response, text, payload };
}

async function waitForTerminalText(page, marker) {
  await page.waitForFunction((text) => {
    const rows = document.querySelector('#shell-sessions .xterm-rows');
    return rows && [...rows.children].some((row) => row.textContent.includes(text));
  }, marker, { timeout: 10_000 });
}

async function readTerminalRows(page) {
  return page.locator('#shell-sessions .xterm-rows').evaluate((rows) => (
    [...rows.children].map((row) => row.textContent)
  ));
}

function terminalPtySize(rows, marker) {
  return rows.map((row) => row.trim().match(new RegExp(`^${marker}:(\\d{1,3})\\s+(\\d{1,3})$`)))
    .filter(Boolean)
    .map((match) => ({ rows: Number(match[1]), columns: Number(match[2]) }))
    .at(-1);
}

async function runTerminalCommand(page, command, marker) {
  await page.locator('#shell-sessions .xterm-helper-textarea').click();
  await page.keyboard.type(command);
  await page.keyboard.press('Enter');
  await waitForTerminalText(page, marker);
  return readTerminalRows(page);
}

function installDialogHandler(page, { trustedFingerprints = [] } = {}) {
  const messages = [];
  const failures = [];
  let rejectNextTrust = false;
  page.on('dialog', async (dialog) => {
    const message = dialog.message();
    messages.push(message);
    if (message.startsWith('SSH 主機指紋：')) {
      if (!trustedFingerprints.some((fingerprint) => message.includes(fingerprint))) {
        failures.push('指紋確認對話框未顯示預期指紋');
        await dialog.dismiss();
        return;
      }
      if (rejectNextTrust) {
        rejectNextTrust = false;
        await dialog.dismiss();
        return;
      }
    } else if (!message.includes('SSHDeck service 目前已手動鎖定')) {
      failures.push('出現非預期的瀏覽器確認對話框');
      await dialog.dismiss();
      return;
    }
    await dialog.accept();
  });
  return {
    messages,
    failures,
    rejectNextFingerprint() { rejectNextTrust = true; },
  };
}

test('service terminal WebSocket 僅接受 UI token 並拒絕非法來源、未知主機與鎖定狀態', {
  timeout: 30_000,
}, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-ticket07-terminal-auth-'));
  const env = createServiceEnv(path.join(directory, 'service-home'));
  let service;
  let ui;
  const observations = [];
  const logs = [];
  try {
    service = await startService({ env, host: '127.0.0.1', port: 0 });
    const serviceOrigin = new URL(service.url).origin;
    const serviceSocket = (alias) => socketUrl(service.url, terminalPath(alias));
    const validOrigin = serviceOrigin;
    const deniedResponses = [];

    const missing = await openSocket(serviceSocket('unknown'), { origin: validOrigin });
    assert.equal(missing.status, 401, '缺少 token 必須遭拒絕');
    deniedResponses.push(missing.body);
    const wrongToken = randomBytes(36).toString('base64url');
    const wrong = await openSocket(serviceSocket('unknown'), {
      origin: validOrigin,
      headers: { authorization: `Bearer ${wrongToken}` },
    });
    assert.equal(wrong.status, 401, '錯誤 token 必須遭拒絕');
    deniedResponses.push(wrong.body);
    const cli = await openSocket(serviceSocket('unknown'), {
      origin: validOrigin,
      headers: { authorization: `Bearer ${env.SSHDECK_SERVICE_TOKEN}` },
    });
    assert.equal(cli.status, 403, 'CLI token 不得建立終端');
    deniedResponses.push(cli.body);
    const badOrigin = await openSocket(serviceSocket('unknown'), {
      origin: 'http://attacker.invalid',
      headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
    });
    assert.equal(badOrigin.status, 403, '不允許的 Origin 必須遭拒絕');
    deniedResponses.push(badOrigin.body);
    const badHost = await openSocket(serviceSocket('unknown'), {
      origin: 'http://attacker.invalid:18793',
      headers: {
        host: 'attacker.invalid:18793',
        authorization: `Bearer ${env.SSHDECK_UI_TOKEN}`,
      },
    });
    assert.equal(badHost.status, 403, '不允許的 Host 必須遭拒絕');
    deniedResponses.push(badHost.body);
    const noOrigin = await openSocket(serviceSocket('unknown'), {
      headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
    });
    assert.equal(noOrigin.status, 403, '缺少 Origin 必須遭拒絕');
    deniedResponses.push(noOrigin.body);
    const unknown = await openSocket(serviceSocket('unknown'), {
      origin: validOrigin,
      headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
    });
    assert.equal(unknown.status, 404, 'UI token 不得繞過受管 alias 限制');
    deniedResponses.push(unknown.body);

    const host = await requestJson(service.url, '/v1/hosts', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
      body: { alias: 'locked-target', hostname: '127.0.0.1', port: 2227, username: 'root' },
    });
    assert.equal(host.response.status, 201);
    const lock = await fetch(`${service.url}/v1/lock`, {
      method: 'POST',
      headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
    });
    assert.equal(lock.status, 204);
    const locked = await openSocket(serviceSocket('locked-target'), {
      origin: validOrigin,
      headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
    });
    assert.equal(locked.status, 423, '手動鎖定時必須在 WebSocket upgrade 前拒絕 PTY');
    deniedResponses.push(locked.body);

    ui = await startUi({
      mode: 'service',
      env: {
        SSHDECK_MODE: 'service',
        SSHDECK_BASE_PATH: '/sshdeck',
        SSHDECK_SERVICE_URL: service.url,
        SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
        SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
      },
      host: '127.0.0.1',
      port: 0,
      openBrowser: async () => {},
      log: (line) => logs.push(String(line)),
    });
    service.on('upgrade', (request) => {
      if (!request.url?.endsWith('/terminal')) return;
      const authorization = request.headers.authorization || '';
      observations.push({
        usesUiToken: authorization === `Bearer ${env.SSHDECK_UI_TOKEN}`,
        forwardsBasic: /^Basic\s/i.test(authorization),
        hasQuery: request.url.includes('?'),
      });
    });

    const adapterOrigin = new URL(ui.url).origin;
    const untrustedOrigin = await openSocket(socketUrl(ui.url, 'api/shell?alias=unknown'), {
      origin: 'http://attacker.invalid',
    });
    assert.equal(untrustedOrigin.status, 403, 'UI adapter 必須保留精確 Origin gate');
    const adapterPort = new URL(ui.url).port;
    const untrustedHost = await openSocket(socketUrl(ui.url, 'api/shell?alias=unknown'), {
      origin: `http://attacker.invalid:${adapterPort}`,
      headers: { host: `attacker.invalid:${adapterPort}` },
    });
    assert.equal(untrustedHost.status, 403, 'UI adapter 必須保留精確 Host gate');
    assert.equal(observations.length, 0, '非法 UI 來源不得連到 service');

    const browserBasic = `Basic ${randomBytes(24).toString('base64')}`;
    const bridged = await openSocket(socketUrl(ui.url, 'api/shell?alias=unknown'), {
      origin: adapterOrigin,
      headers: { authorization: browserBasic },
    });
    assert.equal(bridged.status, 101, '合法 adapter-origin 請求應由 server-side bridge 處理');
    const bridgeFailure = nextControl(bridged.socket, (message) => message.type === 'error');
    const message = await bridgeFailure;
    assert.equal(message.code, 'SERVICE_LOCKED');
    assert.equal(observations.length, 1);
    assert.equal(observations[0].usesUiToken, true, 'adapter-to-service WS 必須使用獨立 UI token');
    assert.equal(observations[0].forwardsBasic, false, 'browser Basic Authorization 不得轉送');
    assert.equal(observations[0].hasQuery, false, 'service token 不得放入 WS query');
    const serviceHealth = await fetch(`${service.url}/v1/health`);
    const serviceVersion = await fetch(`${service.url}/v1/version`);
    const serviceHosts = await requestJson(service.url, '/v1/hosts', {
      headers: { authorization: `Bearer ${env.SSHDECK_UI_TOKEN}` },
    });
    const adapterHosts = await requestJson(ui.url, 'api/hosts');
    assert.equal(serviceHealth.status, 200);
    assert.equal(serviceVersion.status, 200);
    assert.equal(serviceHosts.response.status, 200);
    assert.equal(adapterHosts.response.status, 200);
    const publicResponses = [
      ...deniedResponses,
      await serviceHealth.text(),
      await serviceVersion.text(),
      serviceHosts.text,
      adapterHosts.text,
      JSON.stringify(message),
    ].join('\n');
    if (bridged.socket.readyState !== WebSocket.CLOSED) {
      await new Promise((resolve) => bridged.socket.once('close', resolve));
    }

    const page = await fetch(ui.url);
    const html = await page.text();
    const assets = await Promise.all(['workspace.js', 'terminal.js'].map(async (asset) => (
      (await fetch(new URL(`assets/${asset}`, ui.url))).text()
    )));
    const browserMaterial = [html, ...await Promise.all(assets)].join('\n');
    for (const secret of [env.SSHDECK_UI_TOKEN, env.SSHDECK_SERVICE_TOKEN, env.SSHDECK_ENCRYPTION_KEY]) {
      assert.equal(browserMaterial.includes(secret), false, 'token 與加密 key 不得進入瀏覽器資產');
      assert.equal(logs.join('\n').includes(secret), false, 'token 與加密 key 不得進入 UI log');
      assert.equal(publicResponses.includes(secret), false, 'token 與加密 key 不得進入一般或拒絕回應');
    }
    assert.equal(publicResponses.includes(wrongToken), false, '錯誤 token 不得被 service 回應');
  } finally {
    if (ui) await new Promise((resolve) => ui.close(resolve));
    if (service) await service.closeAsync();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('ticket07-review-control-frame-structure-closes-only-its-own-pty', {
  skip: enabled ? false : '設定 SSHDECK_TEST_SERVICE_SSH=1 才會啟動本任務隔離 OpenSSH fixtures。',
  timeout: 90_000,
}, async () => {
  const runId = randomUUID();
  const evidenceFile = process.env.SSHDECK_TEST_SERVICE_TERMINAL_REVIEW_STRUCTURE_EVIDENCE;
  const evidence = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    status: 'running',
    stage: 'create-isolated-service-and-open-ssh-fixture',
    frames: ['null', 'true', '[]', '{}'],
  };
  let context;
  let survivor;
  const sockets = [];
  let failure;
  let cleanup = {
    service: 'not-started',
    fixture: 'not-started',
    activeTerminals: null,
    directory: 'not-created',
  };
  writeOptionalEvidence(evidenceFile, evidence);
  try {
    context = await createTerminalRegressionContext({
      fixtureEvidenceFile: process.env.SSHDECK_TEST_SERVICE_TERMINAL_REVIEW_STRUCTURE_FIXTURE_EVIDENCE,
    });
    evidence.servicePort = context.service.address().port;
    evidence.fixturePorts = context.fixture.ports;

    evidence.stage = 'open-survivor-pty';
    survivor = await openTrustedTerminal(
      context.service,
      context.env,
      context.aliasB,
      context.fixture.fingerprints.b,
    );
    sockets.push(survivor);
    await waitForActiveTerminalCount(context.service, 1);

    for (const frame of evidence.frames) {
      evidence.stage = `reject-control-frame-${frame}`;
      const target = await openTrustedTerminal(
        context.service,
        context.env,
        context.aliasA,
        context.fixture.fingerprints.a,
      );
      sockets.push(target);
      await waitForActiveTerminalCount(context.service, 2);

      const errorPromise = nextControl(
        target,
        (message) => message.type === 'error',
        2000,
      ).then((message) => ({ kind: 'error', message }), (error) => ({ kind: 'timeout', error }));
      const closedPromise = waitForTerminalSocketClose(target, 5000)
        .then((closed) => ({ kind: 'closed', closed }), (error) => ({ kind: 'timeout', error }));
      target.send(frame);
      const outcome = await errorPromise;
      const closed = await closedPromise;
      evidence.lastFrameOutcome = {
        kind: outcome.kind,
        ...(outcome.message ? { code: outcome.message.code } : {}),
        ...(outcome.error ? { errorName: outcome.error.name } : {}),
      };
      evidence.lastFrameClose = {
        kind: closed.kind,
        ...(closed.closed ? { code: closed.closed.code } : {}),
      };
      writeOptionalEvidence(evidenceFile, evidence, { overwrite: true });
      assert.equal(outcome.kind, 'error', `${frame} 必須安全拒絕並回報 INVALID_TERMINAL_FRAME`);
      assert.equal(outcome.message.code, 'INVALID_TERMINAL_FRAME');
      assert.equal(closed.kind, 'closed', `${frame} 必須關閉該 terminal session`);
      assert.equal(closed.closed.code, 1008);
      await waitForActiveTerminalCount(context.service, 1);
      assert.equal(survivor.readyState, WebSocket.OPEN, '拒絕單一 frame 不得關閉其他 PTY');
    }

    const marker = `T07_SURVIVOR_AFTER_BAD_FRAME_${runId.slice(0, 8)}`;
    const output = waitForTerminalBinaryText(survivor, marker);
    survivor.send(Buffer.from(`printf '${marker}\\n'\\n`), { binary: true });
    assert.ok((await output).includes(marker), '其他真實 PTY 必須仍可收發資料');
    assert.equal((await fetch(`${context.service.url}/v1/health`)).status, 200, 'service 不得因非法 frame 崩潰');
    evidence.status = 'passed';
    evidence.stage = 'verified-session-isolation-and-service-health';
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
    evidence.failure = { name: error.name, message: error.message };
  } finally {
    for (const socket of sockets) {
      if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    }
    if (context) cleanup = await context.cleanup();
    evidence.cleanup = cleanup;
    writeOptionalEvidence(evidenceFile, evidence, { overwrite: true });
  }
  if (failure) throw failure;
  assert.equal(cleanup.service, 'passed');
  assert.equal(cleanup.activeTerminals, 0);
  assert.equal(cleanup.fixture, 'passed');
  assert.equal(cleanup.directory, 'passed');
});

test('ticket07-review-resize-fields-are-bounded-and-session-isolated', {
  skip: enabled ? false : '設定 SSHDECK_TEST_SERVICE_SSH=1 才會啟動本任務隔離 OpenSSH fixtures。',
  timeout: 90_000,
}, async () => {
  const runId = randomUUID();
  const evidenceFile = process.env.SSHDECK_TEST_SERVICE_TERMINAL_REVIEW_RESIZE_EVIDENCE;
  const invalidFrames = [
    { name: 'cols-below-minimum', message: { type: 'resize', cols: 0, rows: 24 } },
    { name: 'cols-above-maximum', message: { type: 'resize', cols: 1001, rows: 24 } },
    { name: 'rows-below-minimum', message: { type: 'resize', cols: 80, rows: 0 } },
    { name: 'rows-above-maximum', message: { type: 'resize', cols: 80, rows: 1001 } },
    { name: 'fractional-cols', message: { type: 'resize', cols: 80.5, rows: 24 } },
    { name: 'string-rows', message: { type: 'resize', cols: 80, rows: '24' } },
  ];
  const evidence = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    status: 'running',
    stage: 'create-isolated-service-and-open-ssh-fixture',
    invalidFrames,
  };
  let context;
  let survivor;
  const sockets = [];
  let failure;
  let cleanup = {
    service: 'not-started',
    fixture: 'not-started',
    activeTerminals: null,
    directory: 'not-created',
  };
  writeOptionalEvidence(evidenceFile, evidence);
  try {
    context = await createTerminalRegressionContext({
      fixtureEvidenceFile: process.env.SSHDECK_TEST_SERVICE_TERMINAL_REVIEW_RESIZE_FIXTURE_EVIDENCE,
    });
    evidence.servicePort = context.service.address().port;
    evidence.fixturePorts = context.fixture.ports;

    evidence.stage = 'open-survivor-pty';
    survivor = await openTrustedTerminal(
      context.service,
      context.env,
      context.aliasB,
      context.fixture.fingerprints.b,
    );
    sockets.push(survivor);
    await waitForActiveTerminalCount(context.service, 1);
    survivor.send(JSON.stringify({ type: 'resize', cols: 80, rows: 24 }));

    for (const { name, message } of invalidFrames) {
      evidence.stage = `reject-${name}`;
      const target = await openTrustedTerminal(
        context.service,
        context.env,
        context.aliasA,
        context.fixture.fingerprints.a,
      );
      sockets.push(target);
      await waitForActiveTerminalCount(context.service, 2);

      const errorPromise = nextControl(
        target,
        (frame) => frame.type === 'error',
        1500,
      ).then((frame) => ({ kind: 'error', frame }), (error) => ({ kind: 'timeout', error }));
      const closedPromise = waitForTerminalSocketClose(target, 5000)
        .then((closed) => ({ kind: 'closed', closed }), (error) => ({ kind: 'timeout', error }));
      target.send(JSON.stringify(message));
      const outcome = await errorPromise;
      const closed = await closedPromise;
      assert.equal(outcome.kind, 'error', `${name} 必須安全拒絕並回報 INVALID_TERMINAL_FRAME`);
      assert.equal(outcome.frame.code, 'INVALID_TERMINAL_FRAME');
      assert.equal(closed.kind, 'closed', `${name} 必須關閉該 terminal session`);
      assert.equal(closed.closed.code, 1008);
      await waitForActiveTerminalCount(context.service, 1);
      assert.equal(survivor.readyState, WebSocket.OPEN, `${name} 不得關閉其他 PTY`);
      evidence.completedInvalidFrames = [...(evidence.completedInvalidFrames || []), name];
    }

    const marker = `T07_SURVIVOR_AFTER_BAD_RESIZE_${runId.slice(0, 8)}`;
    const output = waitForTerminalBinaryText(survivor, marker);
    survivor.send(Buffer.from(`printf '${marker}\\n'\\n`), { binary: true });
    assert.ok((await output).includes(marker), '其他真實 PTY 必須仍可收發資料');
    assert.equal((await fetch(`${context.service.url}/v1/health`)).status, 200, 'service 不得因非法 resize 崩潰');
    evidence.status = 'passed';
    evidence.stage = 'verified-resize-bounds-session-isolation-and-health';
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
    evidence.failure = { name: error.name, message: error.message };
  } finally {
    for (const socket of sockets) {
      if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    }
    if (context) cleanup = await context.cleanup();
    evidence.cleanup = cleanup;
    writeOptionalEvidence(evidenceFile, evidence, { overwrite: true });
  }
  if (failure) throw failure;
  assert.equal(cleanup.service, 'passed');
  assert.equal(cleanup.activeTerminals, 0);
  assert.equal(cleanup.fixture, 'passed');
  assert.equal(cleanup.directory, 'passed');
});

test('ticket07-review-default-http-port-allows-valid-terminal-origin', {
  skip: !enabled
    ? '設定 SSHDECK_TEST_SERVICE_SSH=1 才會啟動本任務隔離 OpenSSH fixtures。'
    : process.env.SSHDECK_TEST_HTTP_DEFAULT_PORT === '1'
      ? false
      : '設定 SSHDECK_TEST_HTTP_DEFAULT_PORT=1 並確認 loopback port 80 空閒後執行。',
  timeout: 90_000,
}, async () => {
  const runId = randomUUID();
  const evidenceFile = process.env.SSHDECK_TEST_SERVICE_TERMINAL_REVIEW_HTTP80_EVIDENCE;
  const evidence = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    status: 'running',
    stage: 'preflight-loopback-port-80',
    port: 80,
  };
  let context;
  let socket;
  let failure;
  let cleanup = {
    service: 'not-started',
    fixture: 'not-started',
    activeTerminals: null,
    directory: 'not-created',
  };
  writeOptionalEvidence(evidenceFile, evidence);
  try {
    assert.equal(await portAvailable(80), true, 'loopback port 80 已被占用；不會停止既有程序');
    context = await createTerminalRegressionContext({
      servicePort: 80,
      fixtureEvidenceFile: process.env.SSHDECK_TEST_SERVICE_TERMINAL_REVIEW_HTTP80_FIXTURE_EVIDENCE,
    });
    evidence.actualPort = context.service.address().port;
    evidence.origin = new URL(context.service.url).origin;
    evidence.fixturePorts = context.fixture.ports;
    assert.equal(context.service.address().port, 80);
    assert.equal(evidence.origin, 'http://127.0.0.1');

    const route = socketUrl(context.service.url, terminalPath(context.aliasA));
    const authorization = { authorization: `Bearer ${context.env.SSHDECK_UI_TOKEN}` };
    const wrongOrigin = await openSocket(route, {
      origin: 'http://127.0.0.1:81',
      headers: authorization,
    });
    assert.equal(wrongOrigin.status, 403, 'Origin 的非預設 port 必須維持拒絕');
    const wrongHost = await openSocket(route, {
      origin: 'http://127.0.0.1:81',
      headers: { ...authorization, host: '127.0.0.1:81' },
    });
    assert.equal(wrongHost.status, 403, 'Host 的錯誤 port 必須維持拒絕');
    const httpsDefaultOrigin = await openSocket(route, {
      origin: 'https://127.0.0.1',
      headers: authorization,
    });
    assert.equal(httpsDefaultOrigin.status, 403, 'HTTPS default port 不得與 HTTP port 80 混同');

    evidence.stage = 'open-real-pty-with-default-http-authority';
    socket = await openTrustedTerminal(
      context.service,
      context.env,
      context.aliasA,
      context.fixture.fingerprints.a,
    );
    await waitForActiveTerminalCount(context.service, 1);
    const closedPromise = waitForTerminalSocketClose(socket);
    socket.send(JSON.stringify({ type: 'close' }));
    const closed = await closedPromise;
    assert.equal(closed.code, 1000);
    await waitForActiveTerminalCount(context.service, 0);
    assert.equal((await fetch(`${context.service.url}/v1/health`)).status, 200);
    evidence.status = 'passed';
    evidence.stage = 'verified-default-port-pty-and-rejected-mismatches';
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
    evidence.failure = { name: error.name, message: error.message };
  } finally {
    if (socket && socket.readyState !== WebSocket.CLOSED) socket.terminate();
    if (context) cleanup = await context.cleanup();
    evidence.cleanup = cleanup;
    writeOptionalEvidence(evidenceFile, evidence, { overwrite: true });
  }
  if (failure) throw failure;
  assert.equal(cleanup.service, 'passed');
  assert.equal(cleanup.activeTerminals, 0);
  assert.equal(cleanup.fixture, 'passed');
  assert.equal(cleanup.directory, 'passed');
});

test('ticket07-review-https-ingress-service-origin-allows-proxied-port', {
  timeout: 20_000,
}, async () => {
  const runId = randomUUID();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `sshdeck-ticket07-https-origin-${runId}-`));
  const env = createServiceEnv(path.join(directory, 'service-home'));
  const evidenceFile = process.env.SSHDECK_TEST_SERVICE_TERMINAL_HTTPS_ORIGIN_EVIDENCE;
  const trustedOrigin = 'https://sshdeck-service.example';
  env.SSHDECK_SERVICE_TERMINAL_ORIGIN = trustedOrigin;
  const evidence = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    trustedOrigin,
    invalidConfiguredOrigins: [],
    status: 'running',
    stage: 'start-service-on-private-http-listener',
  };
  let service;
  let failure;
  const sockets = [];
  let cleanup = 'not-started';
  writeOptionalEvidence(evidenceFile, evidence);
  try {
    for (const [name, value] of [
      ['credentials', 'https://user@sshdeck-service.example'],
      ['path', 'https://sshdeck-service.example/path'],
      ['query', 'https://sshdeck-service.example?enabled=1'],
      ['non-http-scheme', 'ftp://sshdeck-service.example'],
      ['non-canonical-origin', 'https://sshdeck-service.example/'],
    ]) {
      env.SSHDECK_SERVICE_TERMINAL_ORIGIN = value;
      await assert.rejects(
        startService({ env, host: '127.0.0.1', port: 0 }),
        (error) => error.code === 'SERVICE_TERMINAL_ORIGIN_INVALID',
        `${name} must not be accepted as a service terminal origin`,
      );
      evidence.invalidConfiguredOrigins.push(name);
    }
    env.SSHDECK_SERVICE_TERMINAL_ORIGIN = trustedOrigin;
    evidence.stage = 'invalid-service-terminal-origins-rejected';
    writeOptionalEvidence(evidenceFile, evidence, { overwrite: true });

    evidence.stage = 'start-service-on-private-http-listener';
    service = await startService({ env, host: '127.0.0.1', port: 0 });
    evidence.listenerPort = service.address().port;
    assert.notEqual(service.address().port, 443, '測試 service listener 必須與 HTTPS ingress default port 不同');

    evidence.stage = 'allow-trusted-https-origin-through-service-terminal-gate';
    const trusted = await openSocket(
      socketUrl(service.url, terminalPath('not-configured')),
      {
        origin: trustedOrigin,
        headers: {
          authorization: `Bearer ${env.SSHDECK_UI_TOKEN}`,
          host: 'sshdeck-service.example',
        },
      },
    );
    sockets.push(trusted.socket);
    evidence.trustedStatus = trusted.status;
    assert.equal(trusted.status, 404, `允許的外部 service origin 應通過來源 gate，再回報未知 alias：${trusted.body || ''}`);
    assert.equal(JSON.parse(trusted.body).code, 'HOST_NOT_FOUND');

    const mismatches = [
      {
        name: 'untrusted origin',
        origin: 'https://attacker.example',
        host: 'sshdeck-service.example',
      },
      {
        name: 'untrusted host',
        origin: trustedOrigin,
        host: 'attacker.example',
      },
      {
        name: 'untrusted scheme',
        origin: 'http://sshdeck-service.example',
        host: 'sshdeck-service.example',
      },
      {
        name: 'untrusted port',
        origin: 'https://sshdeck-service.example:444',
        host: 'sshdeck-service.example:444',
      },
    ];
    evidence.stage = 'reject-untrusted-service-authorities';
    evidence.rejected = [];
    for (const mismatch of mismatches) {
      const rejected = await openSocket(
        socketUrl(service.url, terminalPath('not-configured')),
        {
          origin: mismatch.origin,
          headers: {
            authorization: `Bearer ${env.SSHDECK_UI_TOKEN}`,
            host: mismatch.host,
          },
        },
      );
      sockets.push(rejected.socket);
      evidence.rejected.push({ name: mismatch.name, status: rejected.status });
      assert.equal(rejected.status, 403, `${mismatch.name} 必須維持拒絕`);
    }
    evidence.status = 'passed';
    evidence.stage = 'trusted-origin-allowed-and-authority-mismatches-rejected';
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
    evidence.failure = { name: error.name, message: error.message };
  } finally {
    for (const socket of sockets) {
      if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    }
    if (service) {
      try {
        await service.closeAsync();
        evidence.activeTerminalsAfterCleanup = service.activeTerminalCount;
        cleanup = service.activeTerminalCount === 0 ? 'passed' : 'failed';
      } catch {
        cleanup = 'failed';
      }
    }
    fs.rmSync(directory, { recursive: true, force: true });
    evidence.cleanup = {
      service: cleanup,
      directory: fs.existsSync(directory) ? 'failed' : 'passed',
    };
    writeOptionalEvidence(evidenceFile, evidence, { overwrite: true });
  }
  if (failure) throw failure;
  assert.equal(cleanup, 'passed');
  assert.equal(evidence.cleanup.directory, 'passed');
});

test('ticket07-review-https-ingress-proxies-adapter-terminal-websocket-to-private-service-port', {
  timeout: 30_000,
}, async () => {
  const runId = randomUUID();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `sshdeck-ticket07-https-bridge-${runId}-`));
  const env = createServiceEnv(path.join(directory, 'service-home'));
  const evidenceFile = process.env.SSHDECK_TEST_SERVICE_TERMINAL_HTTPS_BRIDGE_EVIDENCE;
  const keyPair = utils.generateKeyPairSync('ed25519', { comment: `sshdeck-ticket07-https-${runId}` });
  const alias = `ticket07-https-${runId.slice(0, 8)}`;
  const certificate = createHttpsTestCertificate();
  const originalTlsConnect = tls.connect;
  let patchedTlsConnect = false;
  const observations = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    status: 'running',
    stage: 'start-https-ingress',
  };
  const proxyConnections = new Set();
  const ingressSockets = new Set();
  const sshTargetSockets = new Set();
  let ingress;
  let service;
  let sshTarget;
  let ui;
  let adapterSocket;
  let failure;
  let cleanup = {
    ui: 'not-started',
    ingress: 'not-started',
    service: 'not-started',
    sshTarget: 'not-started',
    directory: 'not-started',
  };
  writeOptionalEvidence(evidenceFile, observations);
  try {
    ingress = https.createServer({
      key: certificate.privateKeyPem,
      cert: certificate.certificatePem,
    }, (_request, response) => {
      response.writeHead(404);
      response.end();
    });
    ingress.on('connection', (socket) => {
      ingressSockets.add(socket);
      socket.once('close', () => ingressSockets.delete(socket));
    });
    let upstreamServicePort;
    ingress.on('upgrade', (request, clientSocket, head) => {
      const upstream = net.connect({ host: '127.0.0.1', port: upstreamServicePort });
      proxyConnections.add(upstream);
      const proxyObservation = {
        host: request.headers.host,
        origin: request.headers.origin,
        path: request.url,
        tlsTerminated: Boolean(clientSocket.encrypted),
        authorizationPresent: typeof request.headers.authorization === 'string',
        authorizationIsBasic: /^Basic\s/i.test(request.headers.authorization || ''),
      };
      observations.ingressRequest = proxyObservation;
      writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
      let responseStatus;
      upstream.on('data', (chunk) => {
        if (responseStatus) return;
        const headerEnd = chunk.indexOf('\r\n');
        if (headerEnd >= 0) responseStatus = chunk.subarray(0, headerEnd).toString('ascii');
        if (responseStatus) {
          observations.serviceHandshake = responseStatus;
          writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
        }
      });
      upstream.once('connect', () => {
        const headers = [];
        for (let index = 0; index < request.rawHeaders.length; index += 2) {
          headers.push(`${request.rawHeaders[index]}: ${request.rawHeaders[index + 1]}`);
        }
        upstream.write(`${request.method} ${request.url} HTTP/${request.httpVersion}\r\n${headers.join('\r\n')}\r\n\r\n`);
        if (head.length) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.once('error', () => clientSocket.destroy());
      upstream.once('close', () => proxyConnections.delete(upstream));
      clientSocket.once('close', () => {
        if (!upstream.destroyed) upstream.destroy();
      });
    });
    await new Promise((resolve, reject) => {
      ingress.once('error', reject);
      ingress.listen(0, '127.0.0.1', resolve);
    });
    const ingressPort = ingress.address().port;
    tls.connect = (options, ...args) => {
      if (Number(options.port) === ingressPort && options.host === '127.0.0.1') {
        observations.tlsConnectionAttempt = { host: options.host, port: Number(options.port) };
        const socket = originalTlsConnect({
          ...options,
          ca: [...tls.rootCertificates, certificate.certificatePem],
        }, ...args);
        socket.once('secureConnect', () => {
          observations.tlsConnected = true;
          writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
        });
        socket.once('error', (error) => {
          observations.tlsClientError = { code: error.code, message: error.message };
          writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
        });
        return socket;
      }
      return originalTlsConnect(options, ...args);
    };
    patchedTlsConnect = true;
    const ingressOrigin = `https://127.0.0.1:${ingressPort}`;
    observations.ingressOrigin = ingressOrigin;
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    env.SSHDECK_SERVICE_TERMINAL_ORIGIN = ingressOrigin;
    observations.stage = 'start-private-service-and-ssh-target';
    service = await startService({ env, host: '127.0.0.1', port: 0 });
    upstreamServicePort = service.address().port;
    observations.serviceListenerPort = upstreamServicePort;
    assert.notEqual(upstreamServicePort, ingress.address().port, 'service listener 必須與 HTTPS ingress 使用不同 port');
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    sshTarget = net.createServer((socket) => {
      sshTargetSockets.add(socket);
      socket.once('close', () => sshTargetSockets.delete(socket));
      socket.end('not an SSH server\r\n');
    });
    await new Promise((resolve, reject) => {
      sshTarget.once('error', reject);
      sshTarget.listen(0, '127.0.0.1', resolve);
    });
    await addManagedTerminalHost(service, env, alias, sshTarget.address().port, keyPair.private);

    observations.stage = 'start-service-ui-adapter';
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    ui = await startUi({
      mode: 'service',
      env: {
        SSHDECK_MODE: 'service',
        SSHDECK_SERVICE_URL: ingressOrigin,
        SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
        SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
      },
      port: 0,
      openBrowser: async () => {},
      log: () => {},
    });
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    adapterSocket = await openSocket(socketUrl(ui.url, `api/shell?alias=${encodeURIComponent(alias)}`), {
      origin: new URL(ui.url).origin,
    });
    observations.adapterStatus = adapterSocket.status;
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    assert.equal(adapterSocket.status, 101, 'UI adapter 必須接受合法本機瀏覽器來源');
    const terminalFailure = nextControl(adapterSocket.socket, (message) => message.type === 'error');
    const failureMessage = await terminalFailure;
    observations.terminalResult = {
      type: failureMessage.type,
      code: failureMessage.code,
    };
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    assert.equal(failureMessage.type, 'error', '真實 service terminal WebSocket 應在 SSH target 回報連線錯誤');
    assert.ok(observations.ingressRequest, `adapter WS 必須抵達 TLS ingress：${JSON.stringify(observations.tlsClientError || {})}`);
    assert.equal(observations.ingressRequest.tlsTerminated, true);
    assert.equal(observations.ingressRequest.origin, ingressOrigin);
    assert.equal(observations.ingressRequest.host, new URL(ingressOrigin).host);
    assert.equal(observations.ingressRequest.authorizationPresent, true);
    assert.equal(observations.ingressRequest.authorizationIsBasic, false);
    assert.equal(observations.serviceHandshake, 'HTTP/1.1 101 Switching Protocols');
    observations.status = 'passed';
    observations.stage = 'adapter-service-terminal-websocket-upgraded-through-https-ingress';
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    if (adapterSocket.socket.readyState !== WebSocket.CLOSED) adapterSocket.socket.terminate();
  } catch (error) {
    failure = error;
    observations.status = 'failed';
    observations.failure = { name: error.name, message: error.message };
  } finally {
    if (adapterSocket?.socket && adapterSocket.socket.readyState !== WebSocket.CLOSED) {
      adapterSocket.socket.terminate();
    }
    for (const socket of ingressSockets) socket.destroy();
    for (const socket of proxyConnections) socket.destroy();
    observations.cleanupStage = 'close-ui-adapter';
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    if (ui) {
      try {
        await new Promise((resolve) => ui.close(resolve));
        cleanup.ui = 'passed';
      } catch { cleanup.ui = 'failed'; }
    }
    observations.cleanupStage = 'close-https-ingress';
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    if (ingress) {
      try {
        await new Promise((resolve, reject) => ingress.close((error) => error ? reject(error) : resolve()));
        cleanup.ingress = proxyConnections.size === 0 ? 'passed' : 'failed';
      } catch { cleanup.ingress = 'failed'; }
    }
    observations.cleanupStage = 'close-service';
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    if (service) {
      try {
        await service.closeAsync();
        observations.activeTerminalsAfterCleanup = service.activeTerminalCount;
        cleanup.service = service.activeTerminalCount === 0 ? 'passed' : 'failed';
      } catch { cleanup.service = 'failed'; }
    }
    observations.cleanupStage = 'close-ssh-target';
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
    for (const socket of sshTargetSockets) socket.destroy();
    if (sshTarget) {
      try {
        await new Promise((resolve, reject) => sshTarget.close((error) => error ? reject(error) : resolve()));
        cleanup.sshTarget = 'passed';
      } catch { cleanup.sshTarget = 'failed'; }
    }
    if (patchedTlsConnect) tls.connect = originalTlsConnect;
    fs.rmSync(directory, { recursive: true, force: true });
    cleanup.directory = fs.existsSync(directory) ? 'failed' : 'passed';
    observations.cleanup = cleanup;
    delete observations.cleanupStage;
    writeOptionalEvidence(evidenceFile, observations, { overwrite: true });
  }
  if (failure) throw failure;
  assert.deepEqual(cleanup, {
    ui: 'passed',
    ingress: 'passed',
    service: 'passed',
    sshTarget: 'passed',
    directory: 'passed',
  });
});

test('真實 Chromium 經 UI adapter/service WebSocket 操作隔離 OpenSSH PTY，並驗證取消、lock、shutdown 與 resize', {
  skip: enabled ? false : '設定 SSHDECK_TEST_SERVICE_SSH=1 才會啟動本任務隔離 OpenSSH fixtures。',
  timeout: 120_000,
}, async () => {
  const runId = randomUUID();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `sshdeck-ticket07-terminal-${runId}-`));
  const serviceHome = path.join(directory, 'service-home');
  const keyPair = utils.generateKeyPairSync('ed25519', { comment: `sshdeck-ticket07-${runId}` });
  const env = createServiceEnv(serviceHome);
  const evidence = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    browserVersion: null,
    uiPort,
    servicePort,
    fixturePorts: [2227, 2228],
    status: 'running',
    stage: 'port-preflight',
  };
  let fixture;
  let service;
  let ui;
  let browser;
  let pageA;
  let pageB;
  let failure;
  let uiCleanup = 'not-started';
  let serviceCleanup = 'not-started';
  let fixtureCleanup = 'not-started';
  const observations = [];
  const serviceUpstreamSockets = [];
  const logLines = [];
  const pageOutput = [];
  const aliasA = `ticket07-a-${runId.slice(0, 8)}`;
  const aliasB = `ticket07-b-${runId.slice(0, 8)}`;

  try {
    assert.ok(Number.isInteger(uiPort) && uiPort > 0 && uiPort <= 65535);
    assert.ok(Number.isInteger(servicePort) && servicePort > 0 && servicePort <= 65535);
    assert.notEqual(uiPort, servicePort);
    assert.equal(await portAvailable(uiPort), true, `UI port ${uiPort} 已被占用；不會停止既有程序`);
    assert.equal(await portAvailable(servicePort), true, `service port ${servicePort} 已被占用；不會停止既有程序`);

    evidence.stage = 'create-isolated-pty-enabled-openssh-fixture';
    fixture = await createOpenSshServiceFixture({
      authorizedPublicKey: keyPair.public,
      evidenceFile: process.env.SSHDECK_TEST_SERVICE_TERMINAL_FIXTURE_EVIDENCE,
      enablePty: true,
    });
    evidence.hostFingerprints = {
      a: fixture.fingerprints.a,
      b: fixture.fingerprints.b,
    };
    assert.notEqual(fixture.fingerprints.a, fixture.fingerprints.b);

    evidence.stage = 'start-real-service-and-ui-adapter';
    service = await startService({ env, host: '127.0.0.1', port: servicePort });
    service.on('upgrade', (request, socket) => {
      if (!request.url?.endsWith('/terminal')) return;
      serviceUpstreamSockets.push(socket);
      const authorization = request.headers.authorization || '';
      observations.push({
        usesUiToken: authorization === `Bearer ${env.SSHDECK_UI_TOKEN}`,
        forwardsBasic: /^Basic\s/i.test(authorization),
        hasQuery: request.url.includes('?'),
      });
    });
    ui = await startUi({
      mode: 'service',
      env: {
        SSHDECK_MODE: 'service',
        SSHDECK_BASE_PATH: '/sshdeck',
        SSHDECK_SERVICE_URL: service.url,
        SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
        SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
      },
      host: '127.0.0.1',
      port: uiPort,
      openBrowser: async () => {},
      log: (line) => logLines.push(String(line)),
    });
    assert.equal((await fetch(`${service.url}/v1/health`)).status, 200);

    evidence.stage = 'prepare-service-managed-hosts-and-encrypted-key';
    for (const [alias, port] of [[aliasA, fixture.ports[0]], [aliasB, fixture.ports[1]]]) {
      const created = await requestJson(ui.url, 'api/hosts', {
        method: 'POST',
        body: { alias, hostname: '127.0.0.1', port, username: 'root' },
      });
      assert.equal(created.response.status, 201, '受管主機建立失敗');
      const imported = await requestJson(ui.url, `api/hosts/${encodeURIComponent(alias)}/key/import`, {
        method: 'POST',
        body: { privateKey: keyPair.private, passphrase: '' },
      });
      assert.equal(imported.response.status, 201, '隔離測試登入金鑰匯入失敗');
    }

    evidence.stage = 'launch-real-chromium';
    browser = await chromium.launch({ headless: true, timeout: 10_000 });
    evidence.browserVersion = browser.version();
    const context = await browser.newContext();
    pageA = await context.newPage();
    pageB = await context.newPage();
    for (const page of [pageA, pageB]) {
      page.setDefaultTimeout(10_000);
      page.on('console', (message) => pageOutput.push(message.text()));
      page.on('pageerror', (error) => pageOutput.push(error.message));
      page.on('request', (request) => pageOutput.push(request.url()));
    }
    const trustedFingerprintsB = [fixture.fingerprints.b];
    const dialogsA = installDialogHandler(pageA, { trustedFingerprints: [fixture.fingerprints.a] });
    const dialogsB = installDialogHandler(pageB, { trustedFingerprints: trustedFingerprintsB });

    evidence.stage = 'open-first-service-terminal-and-confirm-fingerprint';
    await pageA.goto(ui.url);
    await pageA.locator('#hosts-loading').waitFor({ state: 'hidden' });
    assert.equal(await pageA.locator('#service-mode-note').isVisible(), true);
    assert.equal(await pageA.locator('#connect-host').count(), 1);
    assert.ok(pageOutput.some((item) => item.includes('/sshdeck/assets/terminal.js')));
    await pageA.locator(`#hosts li[data-alias="${aliasA}"] button`).click();
    assert.equal(await pageA.locator('#connect-host').isVisible(), true);
    assert.equal(await pageA.locator('#terminal-workspace').isVisible(), true);
    await pageA.locator('#connect-host').click();
    await pageA.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasA);
    assert.ok(dialogsA.messages.some((message) => message.includes(fixture.fingerprints.a)));

    evidence.stage = 'exercise-terminal-input-output-and-resize';
    await runTerminalCommand(
      pageA,
      "printf 'PTY_READY_%s\\n' A; read -r value; printf 'PTY_INPUT_A:%s\\n' \"$value\"",
      'PTY_READY_A',
    );
    await pageA.locator('#shell-sessions .xterm-helper-textarea').click();
    await pageA.keyboard.type('browser-input-a');
    await pageA.keyboard.press('Enter');
    await waitForTerminalText(pageA, 'PTY_INPUT_A:browser-input-a');

    const terminalElement = pageA.locator('#shell-sessions .sshdeck-terminal');
    await terminalElement.evaluate((element) => { element.style.width = '840px'; });
    await pageA.waitForFunction(() => {
      const element = document.querySelector('#shell-sessions .sshdeck-terminal');
      return element && element.clientWidth > 700;
    });
    const wideRows = await runTerminalCommand(
      pageA,
      "printf 'PTY_SIZE_%s:%s\\n' 'WIDE' \"$(stty size)\"; printf 'PTY_SIZE_%s_READY\\n' 'WIDE'",
      'PTY_SIZE_WIDE_READY',
    );
    const wideSize = terminalPtySize(wideRows, 'PTY_SIZE_WIDE');
    assert.ok(wideSize, `真實 PTY 必須回報 wide terminal 尺寸：${JSON.stringify(wideRows)}`);
    await terminalElement.evaluate((element) => { element.style.width = '420px'; });
    await pageA.waitForFunction(() => {
      const element = document.querySelector('#shell-sessions .sshdeck-terminal');
      return element && element.clientWidth < 500;
    });
    const narrowRows = await runTerminalCommand(
      pageA,
      "printf 'PTY_SIZE_%s:%s\\n' 'NARROW' \"$(stty size)\"; printf 'PTY_SIZE_%s_READY\\n' 'NARROW'",
      'PTY_SIZE_NARROW_READY',
    );
    const narrowSize = terminalPtySize(narrowRows, 'PTY_SIZE_NARROW');
    assert.ok(narrowSize, `縮小後的真實 PTY 必須回報 terminal 尺寸：${JSON.stringify(narrowRows)}`);
    assert.notEqual(narrowSize.columns, wideSize.columns, 'UI resize 必須更新遠端 PTY 欄數');

    evidence.stage = 'open-parallel-terminal-confirm-host-b-fingerprint';
    await pageB.goto(ui.url);
    await pageB.locator('#hosts-loading').waitFor({ state: 'hidden' });
    await pageB.locator(`#hosts li[data-alias="${aliasB}"] button`).click();
    dialogsB.rejectNextFingerprint();
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction(() => document.querySelector('#error').textContent.includes('已拒絕主機指紋'));
    const oneUntrustedDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 1 && Date.now() < oneUntrustedDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 1, '未確認指紋不得留下 B 的 WebSocket／PTY；A 必須維持原狀');

    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasB);
    assert.ok(dialogsB.messages.some((message) => message.includes(fixture.fingerprints.b)));
    await runTerminalCommand(pageB, "printf 'PTY_READY_%s\\n' B", 'PTY_READY_B');
    assert.equal(service.activeTerminalCount, 2, '兩個真實 service PTY 應同時存在');

    evidence.stage = 'reject-unconfirmed-changed-host-fingerprint';
    await pageB.locator('#connect-host').click();
    const oneAfterBStopDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 1 && Date.now() < oneAfterBStopDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 1, '停止 B 後應只剩 A 的真實 PTY');
    const rotatedFingerprint = await fixture.rotateB();
    trustedFingerprintsB.push(rotatedFingerprint);
    await pageB.evaluate(() => { document.querySelector('#error').textContent = ''; });
    dialogsB.rejectNextFingerprint();
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction(() => document.querySelector('#error').textContent.includes('已拒絕主機指紋'));
    const oneAfterChangedKeyDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 1 && Date.now() < oneAfterChangedKeyDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 1, '未確認變更後的 host key 不得留下終端 session');
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasB);
    assert.ok(dialogsB.messages.some((message) => message.includes(rotatedFingerprint)));

    evidence.stage = 'cancel-one-session-without-affecting-the-other';
    await pageA.locator('#connect-host').click();
    await pageA.waitForFunction(() => document.querySelector('#terminal-status').textContent.includes('中斷'));
    await pageB.locator('#connect-host').waitFor({ state: 'visible' });
    await runTerminalCommand(pageB, "printf 'PTY_B_SURVIVED_%s\\n' 'A_CANCEL'", 'PTY_B_SURVIVED_A_CANCEL');
    await pageA.waitForFunction(() => document.querySelector('#terminal-status').textContent.includes('中斷'));
    const oneActiveDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 1 && Date.now() < oneActiveDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 1, '取消 A 必須保留 B 並清理 A 的 service PTY');

    evidence.stage = 'browser-client-disconnect-cleans-only-its-own-terminal';
    await pageA.locator('#connect-host').click();
    await pageA.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasA);
    assert.equal(service.activeTerminalCount, 2);
    await pageA.close();
    const oneAfterBrowserDisconnectDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 1 && Date.now() < oneAfterBrowserDisconnectDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 1, '瀏覽器 client disconnect 必須只清理 A 的 session');
    await runTerminalCommand(
      pageB,
      "printf 'PTY_B_SURVIVED_%s\\n' 'BROWSER_DISCONNECT'",
      'PTY_B_SURVIVED_BROWSER_DISCONNECT',
    );

    evidence.stage = 'lock-closes-existing-pty-and-rejects-new-one';
    await pageB.locator('#open-legacy-management').click();
    await pageB.locator('#lock-keys').click();
    const noActiveDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 0 && Date.now() < noActiveDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 0, '手動 lock 必須關閉既有 service PTY');
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction(() => document.querySelector('#error').textContent.includes('手動鎖定'));
    assert.equal(service.activeTerminalCount, 0, '手動 lock 必須拒絕新的 service PTY');

    evidence.stage = 'explicit-ui-unlock-and-reopen-terminal';
    await pageB.locator('#check-selected-host').click();
    await pageB.waitForFunction(() => document.querySelector('#hosts li.selected .host-status').textContent.includes('SSH 連線檢查成功'));
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasB);

    evidence.stage = 'ui-adapter-shutdown-closes-open-pty';
    await new Promise((resolve, reject) => ui.close((error) => error ? reject(error) : resolve()));
    ui = null;
    uiCleanup = 'passed';
    const noAdapterTerminalDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 0 && Date.now() < noAdapterTerminalDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 0, 'UI adapter shutdown 必須清除既有 service PTY');

    evidence.stage = 'restart-ui-adapter-and-open-terminal-for-service-shutdown';
    ui = await startUi({
      mode: 'service',
      env: {
        SSHDECK_MODE: 'service',
        SSHDECK_BASE_PATH: '/sshdeck',
        SSHDECK_SERVICE_URL: service.url,
        SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
        SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
      },
      host: '127.0.0.1',
      port: uiPort,
      openBrowser: async () => {},
      log: (line) => logLines.push(String(line)),
    });
    await pageB.goto(ui.url);
    await pageB.locator('#hosts-loading').waitFor({ state: 'hidden' });
    await pageB.locator(`#hosts li[data-alias="${aliasB}"] button`).click();
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasB);
    assert.equal(service.activeTerminalCount, 1);

    evidence.stage = 'verify-normal-remote-shell-exit-and-reopen';
    await pageB.locator('#shell-sessions .xterm-helper-textarea').click();
    await pageB.keyboard.type('exit 7');
    await pageB.keyboard.press('Enter');
    const noExitedTerminalDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 0 && Date.now() < noExitedTerminalDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 0, '遠端 shell 正常結束後應清理對應 service PTY');
    await pageB.waitForFunction(() => (
      !document.querySelector('#terminal-status').textContent.includes('已連線至')
    ));
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasB);
    assert.equal(service.activeTerminalCount, 1, '遠端結束後應可明確重新開啟新的 PTY');

    evidence.stage = 'recover-from-abnormal-upstream-websocket-close';
    const upstreamSocket = serviceUpstreamSockets.at(-1);
    assert.ok(upstreamSocket && !upstreamSocket.destroyed, '需找到目前 PTY 對應的真實 service socket');
    upstreamSocket.destroy();
    await pageB.waitForFunction(() => (
      !document.querySelector('#terminal-status').textContent.includes('已連線至')
    ));
    const noAbnormallyClosedTerminalDeadline = Date.now() + 5000;
    while (service.activeTerminalCount !== 0 && Date.now() < noAbnormallyClosedTerminalDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(service.activeTerminalCount, 0, 'upstream abnormal close 必須清理本機 SSH PTY');
    await pageB.locator('#connect-host').click();
    await pageB.waitForFunction((alias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${alias}`)
    ), aliasB);
    assert.equal(service.activeTerminalCount, 1, 'upstream abnormal close 後應可建立新 PTY');

    evidence.stage = 'service-shutdown-closes-open-pty';
    await service.closeAsync();
    serviceCleanup = 'passed';
    await pageB.waitForFunction(() => !document.querySelector('#terminal-status').textContent.includes('已連線至'));
    assert.equal(service.activeTerminalCount, 0, 'service shutdown 必須清除既有 service PTY');

    evidence.stage = 'security-and-browser-material-checks';
    assert.ok(observations.length >= 4, '每個 adapter terminal upgrade 都須到達真實 service');
    assert.equal(observations.every((item) => item.usesUiToken && !item.forwardsBasic && !item.hasQuery), true);
    const html = await pageB.content();
    const browserAssets = await Promise.all(['workspace.js', 'terminal.js'].map(async (asset) => (
      (await fetch(new URL(`assets/${asset}`, ui.url))).text()
    )));
    const browserMaterial = [html, ...browserAssets, ...pageOutput, ...logLines].join('\n');
    for (const secret of [env.SSHDECK_UI_TOKEN, env.SSHDECK_SERVICE_TOKEN, env.SSHDECK_ENCRYPTION_KEY]) {
      assert.equal(browserMaterial.includes(secret), false, '瀏覽器資產、URL、console 與 UI log 不得含服務秘密');
    }
    assert.deepEqual(dialogsA.failures, []);
    assert.deepEqual(dialogsB.failures, []);
    evidence.status = 'passed';
    evidence.stage = 'all-real-terminal-assertions-passed';
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
    evidence.failure = error.message;
  } finally {
    if (browser) {
      try { await browser.close(); } catch { evidence.browserCleanup = 'failed'; }
    }
    if (ui) {
      try {
        await new Promise((resolve, reject) => ui.close((error) => error ? reject(error) : resolve()));
        uiCleanup = 'passed';
      } catch { uiCleanup = 'failed'; }
    }
    if (service && serviceCleanup !== 'passed') {
      try { await service.closeAsync(); serviceCleanup = 'passed'; } catch { serviceCleanup = 'failed'; }
    }
    if (fixture) {
      try { await fixture.cleanup(); fixtureCleanup = 'passed'; } catch { fixtureCleanup = 'failed'; }
    }
    evidence.uiCleanup = uiCleanup;
    evidence.serviceCleanup = serviceCleanup;
    evidence.fixtureCleanup = fixtureCleanup;
    evidence.serviceUpgradeCount = observations.length;
    evidence.upstreamAuthorization = observations.map(({ usesUiToken, forwardsBasic, hasQuery }) => ({
      usesUiToken,
      forwardsBasic,
      hasQuery,
    }));
    if (process.env.SSHDECK_TEST_SERVICE_TERMINAL_EVIDENCE) {
      fs.writeFileSync(process.env.SSHDECK_TEST_SERVICE_TERMINAL_EVIDENCE, `${JSON.stringify(evidence, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
      });
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }

  if (failure) throw failure;
  assert.equal(uiCleanup, 'passed');
  assert.equal(serviceCleanup, 'passed');
  assert.equal(fixtureCleanup, 'passed');
  assert.equal(evidence.browserCleanup, undefined);
});

test('standalone Chromium terminal remains compatible with real OpenSSH PTY', {
  skip: enabled ? false : '設定 SSHDECK_TEST_SERVICE_SSH=1 才會啟動本任務隔離 OpenSSH fixtures。',
  timeout: 90_000,
}, async () => {
  const runId = randomUUID();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `sshdeck-ticket07-standalone-${runId}-`));
  const uiPort = Number(process.env.SSHDECK_TEST_UI_PORT || 18792);
  const keyPair = utils.generateKeyPairSync('ed25519', { comment: `sshdeck-ticket07-standalone-${runId}` });
  const evidence = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    browserVersion: null,
    uiPort,
    fixturePorts: [2227, 2228],
    status: 'running',
    stage: 'port-preflight',
  };
  let fixture;
  let ui;
  let browser;
  let dialogs;
  let failure;
  let uiCleanup = 'not-started';
  let fixtureCleanup = 'not-started';
  const shellUpgrades = [];

  try {
    assert.ok(Number.isInteger(uiPort) && uiPort > 0 && uiPort <= 65535);
    assert.equal(await portAvailable(uiPort), true, `UI port ${uiPort} 已被占用；不會停止既有程序`);
    evidence.stage = 'create-pty-enabled-isolated-openssh-fixture';
    fixture = await createOpenSshServiceFixture({
      authorizedPublicKey: keyPair.public,
      enablePty: true,
    });
    evidence.hostFingerprints = { a: fixture.fingerprints.a, b: fixture.fingerprints.b };

    evidence.stage = 'prepare-standalone-host-and-private-key';
    const dataFile = path.join(directory, 'hosts.json');
    const privateKeyPath = path.join(directory, 'standalone-ed25519');
    const alias = `ticket07-standalone-${runId.slice(0, 8)}`;
    fs.writeFileSync(privateKeyPath, keyPair.private, { encoding: 'utf8', mode: 0o600 });
    fs.writeFileSync(dataFile, JSON.stringify([{
      alias,
      hostname: '127.0.0.1',
      port: fixture.ports[0],
      username: 'root',
      keyPath: privateKeyPath,
    }]), 'utf8');

    evidence.stage = 'start-standalone-ui-and-real-chromium';
    ui = await startUi({
      mode: 'standalone',
      dataFile,
      host: '127.0.0.1',
      port: uiPort,
      openBrowser: async () => {},
      log: () => {},
    });
    ui.on('upgrade', (request) => shellUpgrades.push(request.url || ''));
    browser = await chromium.launch({ headless: true, timeout: 10_000 });
    evidence.browserVersion = browser.version();
    const page = await browser.newPage();
    page.setDefaultTimeout(10_000);
    dialogs = installDialogHandler(page, { trustedFingerprints: [fixture.fingerprints.a] });

    evidence.stage = 'open-standalone-terminal-and-confirm-host-key';
    await page.goto(ui.url);
    await page.locator('#hosts-loading').waitFor({ state: 'hidden' });
    assert.equal(await page.locator('#service-mode-note').isVisible(), false);
    await page.locator(`#hosts li[data-alias="${alias}"] button`).click();
    assert.equal(await page.locator('#connect-host').textContent(), '連線');
    await page.locator('#connect-host').click();
    await page.locator('#unlock-dialog').waitFor({ state: 'visible' });
    await page.locator('#unlock-form button[type="submit"]').click();
    await page.waitForFunction((selectedAlias) => (
      document.querySelector('#terminal-status').textContent.includes(`已連線至 ${selectedAlias}`)
    ), alias);
    assert.ok(dialogs.messages.some((message) => message.includes(fixture.fingerprints.a)));

    evidence.stage = 'verify-standalone-input-output-and-resize';
    await runTerminalCommand(
      page,
      "printf 'STANDALONE_%s\\n' 'READY'; read -r value; printf 'STANDALONE_INPUT:%s\\n' \"$value\"",
      'STANDALONE_READY',
    );
    await page.locator('#shell-sessions .xterm-helper-textarea').click();
    await page.keyboard.type('standalone-browser-input');
    await page.keyboard.press('Enter');
    await waitForTerminalText(page, 'STANDALONE_INPUT:standalone-browser-input');

    const terminalElement = page.locator('#shell-sessions .sshdeck-terminal');
    await terminalElement.evaluate((element) => { element.style.width = '840px'; });
    await page.waitForFunction(() => {
      const element = document.querySelector('#shell-sessions .sshdeck-terminal');
      return element && element.clientWidth > 700;
    });
    const wideRows = await runTerminalCommand(
      page,
      "printf 'STANDALONE_SIZE_%s:%s\\n' 'WIDE' \"$(stty size)\"; printf 'STANDALONE_SIZE_%s_READY\\n' 'WIDE'",
      'STANDALONE_SIZE_WIDE_READY',
    );
    const wideSize = terminalPtySize(wideRows, 'STANDALONE_SIZE_WIDE');
    assert.ok(wideSize, `standalone 真實 PTY 必須回報 wide terminal 尺寸：${JSON.stringify(wideRows)}`);
    await terminalElement.evaluate((element) => { element.style.width = '420px'; });
    await page.waitForFunction(() => {
      const element = document.querySelector('#shell-sessions .sshdeck-terminal');
      return element && element.clientWidth < 500;
    });
    const narrowRows = await runTerminalCommand(
      page,
      "printf 'STANDALONE_SIZE_%s:%s\\n' 'NARROW' \"$(stty size)\"; printf 'STANDALONE_SIZE_%s_READY\\n' 'NARROW'",
      'STANDALONE_SIZE_NARROW_READY',
    );
    const narrowSize = terminalPtySize(narrowRows, 'STANDALONE_SIZE_NARROW');
    assert.ok(narrowSize, `standalone 真實 PTY 必須回報 resized terminal 尺寸：${JSON.stringify(narrowRows)}`);
    assert.notEqual(narrowSize.columns, wideSize.columns, 'standalone terminal resize 必須更新遠端 PTY');

    evidence.stage = 'cancel-standalone-terminal-and-assert-legacy-route';
    await page.locator('#connect-host').click();
    await page.waitForFunction(() => document.querySelector('#terminal-status').textContent.includes('中斷'));
    assert.ok(shellUpgrades.some((url) => url.startsWith(`/api/shell?alias=${encodeURIComponent(alias)}`)));
    assert.deepEqual(dialogs.failures, []);
    evidence.status = 'passed';
    evidence.stage = 'standalone-real-terminal-passed';
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
    evidence.failure = error.message;
  } finally {
    if (browser) {
      try { await browser.close(); } catch { evidence.browserCleanup = 'failed'; }
    }
    if (ui) {
      try {
        await new Promise((resolve, reject) => ui.close((error) => error ? reject(error) : resolve()));
        uiCleanup = 'passed';
      } catch { uiCleanup = 'failed'; }
    }
    if (fixture) {
      try { await fixture.cleanup(); fixtureCleanup = 'passed'; } catch { fixtureCleanup = 'failed'; }
    }
    evidence.uiCleanup = uiCleanup;
    evidence.fixtureCleanup = fixtureCleanup;
    evidence.shellUpgradeCount = shellUpgrades.length;
    if (process.env.SSHDECK_TEST_STANDALONE_TERMINAL_EVIDENCE) {
      fs.writeFileSync(process.env.SSHDECK_TEST_STANDALONE_TERMINAL_EVIDENCE, `${JSON.stringify(evidence, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
      });
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }

  if (failure) throw failure;
  assert.equal(uiCleanup, 'passed');
  assert.equal(fixtureCleanup, 'passed');
  assert.equal(evidence.browserCleanup, undefined);
});
