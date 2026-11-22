'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { utils } = require('ssh2');
const { main, startUi } = require('../bin/sshdeck.js');
const { startService } = require('../lib/service-server');
const { applyTicket03TokenSentinels, createServiceEnv } = require('./helpers/service-test-utils');

const browserModule = process.env.SSHDECK_PLAYWRIGHT_MODULE;

async function request(server, route, { method = 'GET', body } = {}) {
  const response = await fetch(`${new URL(server.url).origin}${route}`, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = text; }
  }
  return { response, payload, text };
}

test('service 模式的 ui CLI 可啟動掛載管理 UI', { timeout: 30_000 }, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-ui-cli-'));
  const serviceEnv = createServiceEnv(path.join(directory, 'service-home'));
  const overrides = {
    SSHDECK_MODE: 'service',
    SSHDECK_BASE_PATH: '/sshdeck',
    SSHDECK_SERVICE_URL: '',
    SSHDECK_SERVICE_TOKEN: serviceEnv.SSHDECK_SERVICE_TOKEN,
    SSHDECK_UI_TOKEN: serviceEnv.SSHDECK_UI_TOKEN,
    SSHDECK_HOME: path.join(directory, 'standalone-home'),
  };
  const previousEnv = new Map(Object.keys(overrides).map((key) => [key, process.env[key]]));
  let service;
  let ui;
  try {
    service = await startService({ env: serviceEnv, port: 0 });
    overrides.SSHDECK_SERVICE_URL = service.url;
    for (const [key, value] of Object.entries(overrides)) process.env[key] = value;

    ui = await main(['ui', '--host', '127.0.0.1', '--port', '0'], {
      openBrowser: async () => {},
    });

    assert.equal(ui.uiMode, 'service');
    assert.equal(ui.basePath, '/sshdeck');
    assert.equal((await fetch(ui.url)).status, 200);
    assert.equal((await fetch(new URL('/', ui.url))).status, 404);
  } finally {
    if (ui) await new Promise((resolve) => ui.close(resolve));
    if (service) await service.closeAsync();
    for (const [key, value] of previousEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('service UI adapter 以 server-side token 消費 API 並安全處理 CRUD、金鑰與秘密', {
  timeout: 60_000,
}, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-ui-service-'));
  const serviceHome = path.join(directory, 'service-home');
  const env = createServiceEnv(serviceHome);
  const tokenSentinels = applyTicket03TokenSentinels(env);
  let service;
  let ui;
  const serviceRequests = [];
  const uiLogs = [];
  try {
    service = await startService({ env, port: 0 });
    service.on('request', (request) => serviceRequests.push(request.url));
    const uiEnv = {
      SSHDECK_MODE: 'service',
      SSHDECK_BASE_PATH: '/sshdeck',
      SSHDECK_SERVICE_URL: service.url,
      SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
      SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
    };
    ui = await startUi({
      mode: 'service',
      env: uiEnv,
      port: 0,
      openBrowser: async () => {},
      log: (line) => uiLogs.push(String(line)),
    });
    const origin = new URL(ui.url).origin;
    const html = await (await fetch(ui.url)).text();
    const visibleResponses = [];
    const uiRequest = async (...args) => {
      const result = await request(ui, ...args);
      visibleResponses.push(result.text);
      return result;
    };
    assert.match(html, /"mode":"service"/);
    assert.match(html, /"basePath":"\/sshdeck"/);
    const secrets = [...tokenSentinels, env.SSHDECK_ENCRYPTION_KEY];
    assert.equal(new Set(secrets.slice(0, 3)).size, 3, '三種 token sentinel 必須彼此不同');
    const browserAssets = await Promise.all(['workspace.js', 'terminal.js', 'connection-guide.js'].map(async (asset) => (
      await (await fetch(`${origin}/sshdeck/assets/${asset}`)).text()
    )));
    for (const value of [html, ...browserAssets]) {
      for (const secret of secrets) {
        assert.equal(value.includes(secret), false, 'browser-visible 資料不得包含 server-side 憑證');
      }
    }
    for (const secret of secrets) {
      assert.equal(ui.url.includes(secret), false, 'UI URL 不得包含 server-side 憑證');
      assert.equal(service.url.includes(secret), false, 'service URL 不得包含 server-side 憑證');
      assert.equal(process.argv.some((argument) => argument.includes(secret)), false, '程序 argv 不得包含 server-side 憑證');
    }
    assert.equal((await fetch(`${origin}/api/hosts`)).status, 404);

    const serviceRequestCount = serviceRequests.length;
    const unexposedGrantRoutes = [
      { route: '/sshdeck/api/hosts/import-target/tcp-tunnel-targets', method: 'POST', body: { targetHost: '127.0.0.1', targetPort: 80 } },
      { route: '/sshdeck/api/hosts/import-target/tcp-tunnel-targets/opaque-id', method: 'DELETE' },
    ];
    for (const { route, method, body } of unexposedGrantRoutes) {
      assert.equal((await uiRequest(route, { method, body })).response.status, 404,
        'UI adapter 不得代理或公開 target grant 管理路徑');
    }
    assert.equal(serviceRequests.length, serviceRequestCount, 'grant 管理路徑不得轉送到 SSHDeck service');

    const host = await uiRequest('/sshdeck/api/hosts', {
      method: 'POST',
      body: { alias: 'import-target', hostname: '127.0.0.1', port: 1, username: 'tester' },
    });
    assert.equal(host.response.status, 201, 'UI adapter 應安全建立 managed host');
    assert.equal(host.payload.keyPath, undefined);

    const invalidPrivateKey = 'ticket02-invalid-private-key-marker';
    const invalidPassphrase = 'ticket02-invalid-passphrase-marker';
    const invalid = await uiRequest('/sshdeck/api/hosts/import-target/key/import', {
      method: 'POST',
      body: { privateKey: invalidPrivateKey, passphrase: invalidPassphrase },
    });
    assert.equal(invalid.response.status, 400);
    assert.equal(invalid.text.includes(invalidPrivateKey), false);
    assert.equal(invalid.text.includes(invalidPassphrase), false);
    assert.equal((await uiRequest('/sshdeck/api/keys')).payload.length, 0);

    const passphrase = randomBytes(24).toString('base64url');
    const wrongPassphrase = randomBytes(24).toString('base64url');
    const pair = utils.generateKeyPairSync('ed25519', {
      passphrase,
      cipher: 'aes256-cbc',
      comment: 'sshdeck-ticket02-service-ui',
    });
    const wrong = await uiRequest('/sshdeck/api/hosts/import-target/key/import', {
      method: 'POST',
      body: { privateKey: pair.private, passphrase: wrongPassphrase },
    });
    assert.equal(wrong.response.status, 400);
    assert.equal(wrong.text.includes(pair.private), false);
    assert.equal(wrong.text.includes(wrongPassphrase), false);
    assert.equal((await uiRequest('/sshdeck/api/keys')).payload.length, 0);

    const imported = await uiRequest('/sshdeck/api/hosts/import-target/key/import', {
      method: 'POST',
      body: { privateKey: pair.private, passphrase },
    });
    assert.equal(imported.response.status, 201, 'service-managed key 匯入應成功');
    assert.match(imported.payload.publicKey, /^ssh-ed25519 /);
    assert.match(imported.payload.guide, /遠端撤銷/);
    for (const secret of [pair.private, passphrase, wrongPassphrase, ...secrets]) {
      assert.equal(imported.text.includes(secret), false, '一般 API 回應不得包含私鑰、密語或 token');
    }

    const listed = await uiRequest('/sshdeck/api/keys');
    assert.equal(listed.response.status, 200);
    assert.equal(listed.payload.length, 1);
    const record = listed.payload[0];
    assert.equal(record.keyPath, `service-key:${record.id}`);
    assert.equal(listed.text.includes(serviceHome), false);
    assert.equal(listed.text.includes(pair.private), false);
    assert.equal(listed.text.includes(passphrase), false);
    const hosts = await uiRequest('/sshdeck/api/hosts');
    assert.equal(hosts.payload[0].keyPath, `service-key:${record.id}`);
    assert.equal(hosts.text.includes(serviceHome), false);

    const secondHost = await uiRequest('/sshdeck/api/hosts', {
      method: 'POST',
      body: { alias: 'shared-target', hostname: '127.0.0.1', port: 1, username: 'tester' },
    });
    assert.equal(secondHost.response.status, 201);
    const linked = await uiRequest('/sshdeck/api/hosts/shared-target/key/link', {
      method: 'POST',
      body: { keyId: record.id },
    });
    assert.equal(linked.response.status, 200);
    const blockedDelete = await uiRequest('/sshdeck/api/hosts/import-target/key/delete', { method: 'POST', body: {} });
    assert.equal(blockedDelete.response.status, 409);
    assert.equal(blockedDelete.payload.code, 'KEY_IN_USE');
    assert.equal((await uiRequest('/sshdeck/api/hosts')).payload.find((item) => item.alias === 'import-target').keyPath, `service-key:${record.id}`);

    assert.equal((await uiRequest('/sshdeck/api/hosts/shared-target/key/unlink', { method: 'POST', body: {} })).response.status, 204);
    const deletedKey = await uiRequest('/sshdeck/api/hosts/import-target/key/delete', { method: 'POST', body: {} });
    assert.equal(deletedKey.response.status, 200, '未再關聯的 service-managed key 應可刪除');
    assert.match(deletedKey.payload.guide, /authorized_keys/);
    assert.equal((await uiRequest('/sshdeck/api/keys')).payload.length, 0);
    const generatedHost = await uiRequest('/sshdeck/api/hosts', {
      method: 'POST',
      body: { alias: 'generated-target', hostname: '127.0.0.1', port: 1, username: 'tester' },
    });
    assert.equal(generatedHost.response.status, 201);
    const generatedPassphrase = randomBytes(24).toString('base64url');
    const generated = await uiRequest('/sshdeck/api/hosts/generated-target/key', {
      method: 'POST',
      body: { passphrase: generatedPassphrase },
    });
    assert.equal(generated.response.status, 201, 'service-managed key 產生應成功');
    assert.equal(generated.text.includes(generatedPassphrase), false, 'service API 回應不得包含產生金鑰時的密語');

    const updated = await uiRequest('/sshdeck/api/hosts/generated-target', {
      method: 'PUT',
      body: { hostname: '127.0.0.1', port: 2, username: 'updated' },
    });
    assert.equal(updated.response.status, 200);
    const invalidPath = await uiRequest('/sshdeck/api/hosts/generated-target', {
      method: 'PUT',
      body: { keyPath: 'C:\\private\\id_ed25519' },
    });
    assert.equal(invalidPath.response.status, 400);
    assert.equal((await uiRequest('/sshdeck/api/hosts/generated-target', { method: 'DELETE' })).response.status, 204);

    assert.equal((await uiRequest('/sshdeck/api/lock', { method: 'POST', body: {} })).response.status, 204);
    assert.equal((await uiRequest('/sshdeck/api/unlock', { method: 'POST', body: {} })).response.status, 204);
    for (const secret of secrets) {
      assert.equal(uiLogs.join('\n').includes(secret), false, '一般 UI adapter log 不得包含 server-side 憑證');
      assert.equal(serviceRequests.some((route) => route.includes(secret)), false, 'service URL/query 不得包含 server-side 憑證');
      assert.equal(visibleResponses.join('\n').includes(secret), false, '瀏覽器可讀 API response 不得包含 server-side 憑證');
    }
    for (const secret of [
      pair.private,
      passphrase,
      wrongPassphrase,
      generatedPassphrase,
      invalidPrivateKey,
      invalidPassphrase,
    ]) {
      assert.equal(uiLogs.join('\n').includes(secret), false, '一般 UI adapter log 不得包含私鑰或密語');
      assert.equal(serviceRequests.some((route) => route.includes(secret)), false, 'service URL/query 不得包含私鑰或密語');
      assert.equal(visibleResponses.join('\n').includes(secret), false, '瀏覽器可讀 API response 不得包含私鑰或密語');
    }
    assert.equal(serviceRequests.some((route) => route.includes('?')), false, 'UI adapter 不得把 credential 放入 service query');
  } finally {
    if (ui) await new Promise((resolve) => ui.close(resolve));
    if (service) await service.closeAsync();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('真實 Chromium 不接觸 server-side token，也無法經 UI adapter 呼叫 tunnel 管理路徑', {
  skip: browserModule ? false : '需設定 SSHDECK_PLAYWRIGHT_MODULE 為 Playwright 模組絕對路徑。',
  timeout: 60_000,
}, async () => {
  const { chromium } = require(browserModule);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-ticket03-browser-security-'));
  const env = createServiceEnv(path.join(directory, 'service-home'));
  const tokenSentinels = applyTicket03TokenSentinels(env);
  const serviceRequests = [];
  const serviceUpgrades = [];
  const uiLogs = [];
  const browserRequests = [];
  const browserResponses = [];
  const browserLogs = [];
  const browserSocketRequests = [];
  const browserSocketResponses = [];
  const browserSocketFrames = [];
  const browserSocketHeaders = [];
  const uiWebSocketResponses = [];
  const uiUpgrades = [];
  let service;
  let ui;
  let browser;
  let context;
  let cdp;

  function assertNoSentinels(value, surface) {
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    for (const sentinel of tokenSentinels) {
      assert.equal(text.includes(sentinel), false, `${surface} 不得包含 server-side token sentinel`);
    }
  }

  function isTunnelManagementRoute(route) {
    const pathname = new URL(route, 'http://127.0.0.1').pathname;
    return /^\/v1\/hosts\/[^/]+\/(?:tcp-tunnel|tcp-tunnel-targets(?:\/[^/]+)?)$/.test(pathname);
  }

  try {
    service = await startService({ env, port: 0 });
    service.on('request', (request) => {
      serviceRequests.push({ method: request.method, url: request.url });
    });
    service.on('upgrade', (request) => {
      serviceUpgrades.push({ method: request.method, url: request.url });
    });

    const uiEnv = {
      SSHDECK_MODE: 'service',
      SSHDECK_BASE_PATH: '/sshdeck',
      SSHDECK_SERVICE_URL: service.url,
      SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
      SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
    };
    ui = await startUi({
      mode: 'service',
      env: uiEnv,
      port: 0,
      openBrowser: async () => {},
      log: (line) => uiLogs.push(String(line)),
    });
    ui.on('upgrade', (request) => {
      uiUpgrades.push({ method: request.method, url: request.url });
    });
    ui.prependListener('upgrade', (_request, socket) => {
      const originalEnd = socket.end;
      socket.end = function captureWebSocketRejection(response, ...args) {
        if (Buffer.isBuffer(response) || typeof response === 'string') {
          uiWebSocketResponses.push(Buffer.from(response).toString('utf8'));
        }
        return originalEnd.call(this, response, ...args);
      };
    });

    browser = await chromium.launch({ headless: true, timeout: 10_000 });
    context = await browser.newContext();
    const page = await context.newPage();
    page.setDefaultTimeout(10_000);
    page.on('request', (request) => {
      browserRequests.push({
        method: request.method(),
        url: request.url(),
        postData: request.postData(),
        headers: request.headers(),
      });
    });
    page.on('response', (response) => {
      const record = {
        url: response.url(),
        status: response.status(),
        headers: response.headers(),
        body: '',
      };
      browserResponses.push(record);
      record.bodyPromise = response.text()
        .then((body) => { record.body = body; })
        .catch(() => {});
    });
    page.on('console', (message) => {
      browserLogs.push(`${message.type()}:${message.text()}`);
    });
    page.on('pageerror', (error) => browserLogs.push(error.message));
    page.on('requestfailed', (request) => {
      browserLogs.push(`${request.method()}:${request.url()}:${request.failure()?.errorText || 'request-failed'}`);
    });
    page.on('websocket', (webSocket) => {
      browserSocketRequests.push(webSocket.url());
      webSocket.on('framesent', (frame) => browserSocketFrames.push(frame.payload));
      webSocket.on('framereceived', (frame) => browserSocketFrames.push(frame.payload));
      webSocket.on('socketerror', (message) => browserLogs.push(String(message)));
    });
    cdp = await context.newCDPSession(page);
    await cdp.send('Network.enable');
    cdp.on('Network.requestWillBeSent', (event) => {
      if (event.type === 'WebSocket') browserSocketRequests.push(event.request.url);
    });
    cdp.on('Network.webSocketWillSendHandshakeRequest', (event) => {
      browserSocketHeaders.push(JSON.stringify(event.request.headers || {}));
    });
    cdp.on('Network.webSocketHandshakeResponseReceived', (event) => {
      browserSocketResponses.push({
        status: event.response.status,
        statusText: event.response.statusText,
        headers: event.response.headers,
      });
    });
    cdp.on('Network.webSocketFrameSent', (event) => browserSocketFrames.push(event.response.payloadData));
    cdp.on('Network.webSocketFrameReceived', (event) => browserSocketFrames.push(event.response.payloadData));

    await page.goto(ui.url);
    await page.locator('#hosts-loading').waitFor({ state: 'hidden' });
    assert.equal(new URL(page.url()).pathname, '/sshdeck/');

    const forbiddenRoutes = [
      {
        method: 'POST',
        path: '/sshdeck/api/hosts/browser-target/tcp-tunnel-targets',
        body: { targetHost: '192.0.2.10', targetPort: 3001 },
      },
      {
        method: 'DELETE',
        path: '/sshdeck/api/hosts/browser-target/tcp-tunnel-targets/opaque-id',
      },
      {
        method: 'POST',
        path: '/sshdeck/api/hosts/browser-target/tcp-tunnel',
        body: { targetId: 'opaque-id' },
      },
    ];
    const routeResults = await page.evaluate(async (routes) => {
      const results = [];
      for (const route of routes) {
        const response = await fetch(route.path, {
          method: route.method,
          headers: route.body ? { 'content-type': 'application/json' } : {},
          ...(route.body ? { body: JSON.stringify(route.body) } : {}),
        });
        results.push({
          method: route.method,
          url: response.url,
          status: response.status,
          body: await response.text(),
        });
      }
      return results;
    }, forbiddenRoutes);
    assert.deepEqual(routeResults.map((result) => result.status), [404, 404, 404],
      'Chromium 發出的 grant/tunnel 管理要求必須由 UI adapter 拒絕');

    const webSocketOutcome = await page.evaluate(() => new Promise((resolve) => {
      const socketUrl = new URL('/sshdeck/v1/hosts/browser-target/tcp-tunnel', location.href);
      socketUrl.protocol = socketUrl.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = new WebSocket(socketUrl.href);
      let settled = false;
      const finish = (outcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(outcome);
      };
      const timer = setTimeout(() => {
        try { socket.close(); } catch {}
        finish('timeout');
      }, 5000);
      socket.addEventListener('open', () => {
        try { socket.close(); } catch {}
        finish('opened');
      }, { once: true });
      socket.addEventListener('error', () => finish('rejected'), { once: true });
    }));
    assert.equal(webSocketOutcome, 'rejected',
      'Chromium 對 UI adapter tunnel WebSocket 路徑必須收到拒絕');
    assert.ok(browserSocketRequests.some((request) =>
      request.includes('/sshdeck/v1/hosts/browser-target/tcp-tunnel')),
    'Chromium 必須實際送出 tunnel WebSocket 要求至 UI adapter');
    assert.ok(uiUpgrades.some((request) =>
      request.url === '/sshdeck/v1/hosts/browser-target/tcp-tunnel'),
    'UI adapter 必須實際收到 Chromium 的 tunnel WebSocket upgrade');
    assert.ok(uiWebSocketResponses.some((response) =>
      response.startsWith('HTTP/1.1 403 Forbidden\r\n')),
    'UI adapter 必須將非 shell WebSocket upgrade 以拒絕回應送回 Chromium');

    await page.waitForTimeout(50);
    await Promise.all(browserResponses.map((response) => response.bodyPromise));
    const browserState = await page.evaluate(() => JSON.stringify({
      href: location.href,
      search: location.search,
      hash: location.hash,
      html: document.documentElement.outerHTML,
      text: document.documentElement.innerText,
      cookie: document.cookie,
      localStorage: Object.keys(localStorage).map((key) => [key, localStorage.getItem(key)]),
      sessionStorage: Object.keys(sessionStorage).map((key) => [key, sessionStorage.getItem(key)]),
    }));
    const browserSurface = {
      uiUrl: ui.url,
      serviceUrl: service.url,
      browserState,
      requests: browserRequests,
      responses: browserResponses.map(({ bodyPromise, ...response }) => response),
      responseBodies: browserResponses.map((response) => response.body),
      logs: browserLogs,
      uiLogs,
      socketRequests: browserSocketRequests,
      socketHeaders: browserSocketHeaders,
      socketResponses: browserSocketResponses,
      webSocketResponses: uiWebSocketResponses,
      socketFrames: browserSocketFrames,
      uiUpgrades,
    };
    assertNoSentinels(browserSurface, 'Chromium URL、query、DOM/storage、HTTP/WebSocket、bundle 與 logs');
    assertNoSentinels(serviceRequests, 'service request URL/query');
    assertNoSentinels(serviceUpgrades, 'service WebSocket URL/query');
    assert.equal(browserRequests.some((request) => request.url.includes('?')
      && tokenSentinels.some((sentinel) => request.url.includes(sentinel))), false);
    assert.equal(browserRequests.some((request) => Object.values(request.headers)
      .some((value) => tokenSentinels.some((sentinel) => value.includes(sentinel)))), false,
    'Node test 的 server-side token 不得進入 Chromium request headers');
    assert.equal(serviceRequests.some((request) => isTunnelManagementRoute(request.url)), false,
      'UI adapter 不得將 grant/tunnel 管理要求送至 service HTTP API');
    assert.equal(serviceUpgrades.some((request) => isTunnelManagementRoute(request.url)), false,
      'UI adapter 不得將 tunnel WebSocket upgrade 送至 service');
    assert.equal(Object.hasOwn(uiEnv, 'SSHDECK_TUNNEL_TOKEN'), false,
      'UI adapter 設定不應包含 tunnel token');
  } finally {
    if (cdp) await cdp.detach().catch(() => {});
    if (browser) await browser.close();
    if (ui) await new Promise((resolve) => ui.close(resolve));
    if (service) await service.closeAsync();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
