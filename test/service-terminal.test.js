'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { randomBytes, randomUUID } = require('node:crypto');
const { chromium } = require('playwright');
const { utils } = require('ssh2');
const WebSocket = require('ws');
const { startUi } = require('../bin/sshdeck.js');
const { startService } = require('../lib/service-server');
const { createOpenSshServiceFixture } = require('./helpers/openssh-service-fixture');
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
    service.on('upgrade', (request) => {
      if (!request.url?.endsWith('/terminal')) return;
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
