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
const { startUi } = require('../bin/sshdeck.js');
const { startService } = require('../lib/service-server');
const { createOpenSshServiceFixture } = require('./helpers/openssh-service-fixture');
const { createServiceEnv } = require('./helpers/service-test-utils');

const enabled = process.env.SSHDECK_TEST_SERVICE_SSH === '1';

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

async function addHostThroughGuide(page, { alias, port, keyId }) {
  await page.locator('#guide-tab').click();
  let restart = page.getByRole('button', { name: '開始新的建立指南' });
  if (!await restart.count()) {
    const back = page.getByRole('button', { name: '上一步' });
    if (await back.count()) await back.click();
    restart = page.getByRole('button', { name: '開始新的建立指南' });
  }
  if (await restart.count()) await restart.click();
  await page.locator('[name="alias"]').fill(alias);
  await page.locator('[name="hostname"]').fill('127.0.0.1');
  await page.locator('[name="port"]').fill(String(port));
  await page.locator('[name="username"]').fill(port === 1 ? 'tester' : 'root');
  await page.getByRole('button', { name: '下一步' }).click();
  await page.locator('#guide-step-title').filter({ hasText: '登入金鑰' }).waitFor();
  if (keyId) {
    await page.getByRole('radio', { name: new RegExp(keyId) }).check();
    await page.getByRole('button', { name: '下一步' }).click();
    await page.locator('#guide-step-title').filter({ hasText: '遠端授權' }).waitFor();
  }
}

async function selectHost(page, alias) {
  await page.locator('#hosts').getByRole('button').filter({ hasText: alias }).click();
  await page.locator('#host-workspace').waitFor({ state: 'visible' });
  const advanced = page.locator('#advanced-management');
  if (await advanced.getAttribute('open') === null) await advanced.locator(':scope > summary').click();
  await page.locator('#selected-host-actions').waitFor({ state: 'visible' });
}

async function importPrivateKey(page, privateKey, passphrase) {
  await page.locator('#selected-host-actions').getByRole('button', { name: '匯入登入金鑰' }).click();
  await page.locator('#private-key-file').setInputFiles({
    name: 'sshdeck-ticket02-test-key',
    mimeType: 'text/plain',
    buffer: Buffer.from(privateKey, 'utf8'),
  });
  await page.locator('#import-key-passphrase').fill(passphrase);
  await page.locator('#key-import-form button[type="submit"]').click();
}

async function checkSelectedHostWithTrust(page, expectedFingerprints) {
  const isManualCheck = (request) => {
    if (request.method() !== 'POST') return false;
    try {
      return /^\/sshdeck\/api\/hosts\/[^/]+\/check$/.test(new URL(request.url()).pathname);
    } catch {
      return false;
    }
  };
  const readExpectedFingerprint = (request) => {
    try {
      return JSON.parse(request.postData() || '{}').expectedFingerprint;
    } catch {
      return undefined;
    }
  };
  const challengeRequest = page.waitForRequest((request) => isManualCheck(request) && !readExpectedFingerprint(request));
  const confirmedResponse = page.waitForResponse((response) => isManualCheck(response.request())
    && Boolean(readExpectedFingerprint(response.request())) && response.status() === 200);
  const dialogPromise = page.waitForEvent('dialog').then(async (dialog) => {
    const message = dialog.message();
    await dialog.accept();
    return message;
  });
  await page.locator('#selected-host-actions').getByRole('button', { name: '檢查 SSH 與 Docker' }).click();
  await challengeRequest;
  const message = await dialogPromise;
  await confirmedResponse;
  await page.waitForFunction(() => {
    const item = document.querySelector('#hosts li.selected .host-status');
    return item?.textContent.includes('SSH 連線檢查成功');
  });
  const shownFingerprints = [...message.matchAll(/SHA256:[A-Za-z0-9+/=]+/g)].map(([value]) => value);
  for (const fingerprint of expectedFingerprints) {
    assert.ok(shownFingerprints.includes(fingerprint), `確認對話框須顯示待核對的實際主機指紋；實際顯示：${shownFingerprints.join(', ') || '無'}`);
  }
  return message;
}

test('真實 Chromium：service UI 在 /sshdeck/ 匯入金鑰、核對指紋並管理主機', {
  skip: enabled ? false : '設定 SSHDECK_TEST_SERVICE_SSH=1 才會啟動本任務隔離 OpenSSH fixtures。',
  timeout: 100_000,
}, async () => {
  const runId = randomUUID();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `sshdeck-ticket02-browser-${runId}-`));
  const serviceHome = path.join(directory, 'service-home');
  const uiPort = Number(process.env.SSHDECK_TEST_UI_PORT || 18787);
  const apiPort = Number(process.env.SSHDECK_TEST_API_PORT || 18788);
  assert.ok(Number.isInteger(uiPort) && uiPort > 0 && uiPort <= 65535);
  assert.ok(Number.isInteger(apiPort) && apiPort > 0 && apiPort <= 65535);
  assert.notEqual(uiPort, apiPort);

  const passphrase = randomBytes(24).toString('base64url');
  const wrongPassphrase = randomBytes(24).toString('base64url');
  const pair = utils.generateKeyPairSync('ed25519', {
    passphrase,
    cipher: 'aes256-cbc',
    comment: `sshdeck-ticket02-${runId}`,
  });
  const env = createServiceEnv(serviceHome);
  const evidence = {
    runId,
    processId: process.pid,
    nodeVersion: process.version,
    browserVersion: null,
    uiPort,
    apiPort,
    fixturePorts: [2227, 2228],
    status: 'running',
    stage: 'port-preflight',
  };

  let fixture;
  let service;
  let ui;
  let browser;
  let failure;
  try {
    assert.equal(await portAvailable(uiPort), true, `UI port ${uiPort} 已被占用；不會停止既有程序`);
    assert.equal(await portAvailable(apiPort), true, `API port ${apiPort} 已被占用；不會停止既有程序`);

    evidence.stage = 'create-isolated-openssh-fixture';
    fixture = await createOpenSshServiceFixture({
      authorizedPublicKey: pair.public,
      evidenceFile: process.env.SSHDECK_TEST_SERVICE_FIXTURE_EVIDENCE,
    });
    evidence.hostFingerprints = fixture.fingerprints;
    assert.notEqual(fixture.fingerprints.a, fixture.fingerprints.b);

    evidence.stage = 'start-service-and-ui';
    service = await startService({ env, host: '127.0.0.1', port: apiPort });
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
      log: () => {},
    });
    const health = await fetch(`${service.url}/v1/health`, { signal: AbortSignal.timeout(5000) });
    assert.equal(health.status, 200);
    evidence.serviceHealth = await health.json();

    evidence.stage = 'launch-chromium';
    browser = await chromium.launch({ headless: true, timeout: 10_000 });
    evidence.browserVersion = browser.version();
    const context = await browser.newContext({ ignoreHTTPSErrors: false });
    const page = await context.newPage();
    page.setDefaultTimeout(10_000);
    const pageErrors = [];
    const requestPaths = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('request', (request) => {
      try { requestPaths.push(new URL(request.url()).pathname); } catch { /* 忽略非 HTTP 請求 */ }
    });

    evidence.stage = 'load-mounted-management-ui';
    await page.goto(ui.url);
    await page.locator('#hosts-loading').waitFor({ state: 'hidden' });
    assert.equal(new URL(page.url()).pathname, '/sshdeck/');
    assert.equal(await page.locator('#service-mode-note').isVisible(), true);
    assert.equal(await page.locator('#connect-host').isVisible(), false);
    assert.equal(await page.locator('#terminal-workspace').isVisible(), false);
    assert.ok(requestPaths.includes('/sshdeck/assets/workspace.js'));
    assert.ok(requestPaths.includes('/sshdeck/assets/connection-guide.js'));
    assert.ok(requestPaths.includes('/sshdeck/api/hosts'));
    assert.equal(requestPaths.some((pathname) => /^\/(?:api|assets)\//.test(pathname)), false);
    const html = await page.locator('html').innerText();
    assert.equal(html.includes(env.SSHDECK_UI_TOKEN), false);
    assert.equal(html.includes(env.SSHDECK_SERVICE_TOKEN), false);
    assert.equal(html.includes(env.SSHDECK_ENCRYPTION_KEY), false);

    evidence.stage = 'create-real-ssh-host-in-ui';
    const aliasA = `ticket02-a-${runId.slice(0, 8)}`;
    await page.getByRole('button', { name: '開始建立指南' }).click();
    await page.locator('[name="alias"]').fill(aliasA);
    await page.locator('[name="hostname"]').fill('127.0.0.1');
    await page.locator('[name="port"]').fill(String(fixture.ports[0]));
    await page.locator('[name="username"]').fill('root');
    await page.getByRole('button', { name: '下一步' }).click();
    await page.locator('#guide-step-title').filter({ hasText: '登入金鑰' }).waitFor();
    await page.locator('#hosts-tab').click();
    await selectHost(page, aliasA);

    evidence.stage = 'reject-wrong-private-key-passphrase';
    await importPrivateKey(page, pair.private, wrongPassphrase);
    await page.waitForFunction(() => Boolean(document.querySelector('#error').textContent));
    const failedImportMessage = await page.locator('#error').textContent();
    assert.equal(failedImportMessage.includes(passphrase), false);
    assert.equal(failedImportMessage.includes(wrongPassphrase), false);
    assert.equal(failedImportMessage.includes(pair.private), false);
    assert.equal(await page.locator('#key-info').isVisible(), false);

    evidence.stage = 'import-key-and-verify-no-browser-persistence';
    await importPrivateKey(page, pair.private, passphrase);
    await page.locator('#key-info').waitFor({ state: 'visible' });
    const keyInfo = await page.locator('#key-output').textContent();
    assert.match(keyInfo, /ssh-ed25519 /);
    assert.match(keyInfo, /authorized_keys/);
    const savedGuide = await page.evaluate(() => localStorage.getItem('sshdeck.connection-guide.v1') || '');
    for (const secret of [pair.private, passphrase, wrongPassphrase, env.SSHDECK_UI_TOKEN, env.SSHDECK_SERVICE_TOKEN, env.SSHDECK_ENCRYPTION_KEY]) {
      assert.equal(savedGuide.includes(secret), false, 'localStorage 不得保存私鑰、密語、token 或加密 key');
    }

    evidence.stage = 'confirm-first-host-fingerprint';
    await checkSelectedHostWithTrust(page, [fixture.fingerprints.a]);
    evidence.stage = 'verify-mounted-service-exec-stream';
    const mountedStream = await page.evaluate(async ({ alias, command }) => {
      const response = await fetch('api/exec', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ alias, command }),
      });
      return {
        status: response.status,
        contentType: response.headers.get('content-type'),
        body: await response.text(),
      };
    }, { alias: aliasA, command: fixture.command('target-a') });
    assert.equal(mountedStream.status, 200);
    assert.match(mountedStream.contentType, /application\/x-ndjson/);
    const mountedEvents = mountedStream.body.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(mountedEvents.find((event) => event.type === 'stdout')?.data, 'target-a\n');
    assert.deepEqual(mountedEvents.find((event) => event.type === 'exit'), { type: 'exit', code: 0 });
    evidence.stage = 'add-second-host-and-link-managed-key';
    const keys = await (await fetch(`${ui.url}api/keys`)).json();
    const sharedKey = keys.find((record) => record.associatedAliases.includes(aliasA));
    assert.ok(sharedKey?.id);
    const aliasB = `ticket02-b-${runId.slice(0, 8)}`;
    await addHostThroughGuide(page, { alias: aliasB, port: fixture.ports[1], keyId: sharedKey.id });
    await page.locator('#hosts-tab').click();
    await selectHost(page, aliasB);
    await checkSelectedHostWithTrust(page, [fixture.fingerprints.b]);

    evidence.stage = 'confirm-changed-host-fingerprint';
    const changedFingerprint = await fixture.rotateB();
    await checkSelectedHostWithTrust(page, [fixture.fingerprints.b, changedFingerprint]);

    evidence.stage = 'enforce-shared-key-delete-constraint';
    await page.evaluate(() => { window.confirm = () => true; });
    await page.locator('#selected-host-actions').getByRole('button', { name: '刪除本機金鑰' }).click();
    await page.waitForFunction(() => document.querySelector('#error').textContent.includes('共用'));
    const deleteConflict = await page.locator('#error').textContent();
    assert.match(deleteConflict, /共用|關聯/);
    await page.locator('#selected-host-actions').getByRole('button', { name: '解除此主機關聯' }).click();

    evidence.stage = 'exercise-host-edit-and-delete';
    const aliasCrud = `ticket02-crud-${runId.slice(0, 8)}`;
    await addHostThroughGuide(page, { alias: aliasCrud, port: 1 });
    await page.locator('#hosts-tab').click();
    await selectHost(page, aliasCrud);
    await page.evaluate(() => {
      window.prompt = (label) => ({
        '主機名稱': '127.0.0.1',
        '連接埠': '2',
        '登入帳號': 'tester-edited',
      })[label] ?? null;
      window.confirm = () => true;
    });
    await page.locator('#selected-host-actions').getByRole('button', { name: '編輯' }).click();
    await page.waitForFunction((alias) => {
      const item = document.querySelector(`#hosts li[data-alias="${alias}"] button`);
      return item?.textContent.includes('tester-edited@127.0.0.1:2');
    }, aliasCrud);
    await page.locator('#selected-host-actions').getByRole('button', { name: '刪除' }).click();
    await page.locator(`#hosts li[data-alias="${aliasCrud}"]`).waitFor({ state: 'detached' });

    evidence.stage = 'generate-service-managed-key';
    await selectHost(page, aliasA);
    await page.locator('#selected-host-actions').getByRole('button', { name: '刪除本機金鑰' }).click();
    await page.waitForFunction(() => document.querySelector('#selected-host-actions').textContent.includes('建立登入金鑰'));
    await page.locator('#selected-host-actions').getByRole('button', { name: '建立登入金鑰' }).click();
    await page.locator('#key-info').waitFor({ state: 'visible' });
    assert.match(await page.locator('#key-output').textContent(), /ssh-ed25519 /);
    assert.deepEqual(pageErrors, []);

    evidence.status = 'passed';
    evidence.stage = 'all-browser-assertions-passed';
    evidence.requestPaths = requestPaths.filter((pathname) => pathname.startsWith('/sshdeck/'));
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
  } finally {
    if (browser) {
      try { await browser.close(); } catch { evidence.browserCleanup = 'failed'; }
    }
    if (ui) {
      try { await new Promise((resolve, reject) => ui.close((error) => error ? reject(error) : resolve())); }
      catch { evidence.uiCleanup = 'failed'; }
    }
    if (service) {
      try { await service.closeAsync(); } catch { evidence.serviceCleanup = 'failed'; }
    }
    if (fixture) {
      try { await fixture.cleanup(); evidence.fixtureCleanup = 'passed'; }
      catch { evidence.fixtureCleanup = 'failed'; }
    }
    fs.rmSync(directory, { recursive: true, force: true });
    if (process.env.SSHDECK_TEST_UI_EVIDENCE) {
      fs.writeFileSync(process.env.SSHDECK_TEST_UI_EVIDENCE, `${JSON.stringify(evidence, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
      });
    }
  }

  if (failure) throw failure;
  assert.equal(evidence.browserCleanup, undefined);
  assert.equal(evidence.uiCleanup, undefined);
  assert.equal(evidence.serviceCleanup, undefined);
  assert.equal(evidence.fixtureCleanup, 'passed');
});
