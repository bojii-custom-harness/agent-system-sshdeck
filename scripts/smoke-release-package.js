'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

function readInstalledPath() {
  const index = process.argv.indexOf('--installed');
  if (index < 0 || !process.argv[index + 1]) throw new Error('用法：node scripts/smoke-release-package.js --installed <套件目錄>');
  return path.resolve(process.argv[index + 1]);
}

function portAvailable(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', (error) => error.code === 'EADDRINUSE' ? resolve(false) : reject(error));
    server.listen(port, '127.0.0.1', () => server.close((error) => error ? reject(error) : resolve(true)));
  });
}

function fetchWithoutKeepAlive(url, options = {}) {
  const headers = new Headers(options.headers);
  headers.set('connection', 'close');
  return fetch(url, { ...options, headers });
}

function createServiceEnv(home, secrets) {
  const env = {
    SSHDECK_SERVICE_HOME: home,
    SSHDECK_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'),
    SSHDECK_SERVICE_TOKEN: crypto.randomBytes(36).toString('base64url'),
    SSHDECK_UI_TOKEN: crypto.randomBytes(36).toString('base64url'),
  };
  secrets.push(env.SSHDECK_ENCRYPTION_KEY, env.SSHDECK_SERVICE_TOKEN, env.SSHDECK_UI_TOKEN);
  return env;
}

function redact(text, secrets) {
  let output = String(text || '');
  for (const secret of secrets) output = output.replaceAll(secret, '<REDACTED>');
  return output;
}

async function closeServer(server) {
  if (!server) return;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function startServiceCli(packageRoot, env, port) {
  const child = spawn(process.execPath, [
    path.join(packageRoot, 'bin', 'sshdeck.js'),
    'service',
    'start',
    '--host',
    '127.0.0.1',
    '--port',
    String(port),
  ], {
    cwd: packageRoot,
    env: { ...process.env, ...env, SSHDECK_MODE: 'standalone' },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.resume();
  const ready = new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, url) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off('error', onError);
      child.off('close', onClose);
      if (error) reject(error);
      else resolve(url);
    };
    const onError = (error) => finish(error);
    const onClose = (code) => finish(new Error(`安裝後 service CLI 提前退出，退出碼 ${code}`));
    const timer = setTimeout(() => finish(new Error('等待安裝後 service CLI 啟動逾時')), 10_000);
    child.once('error', onError);
    child.once('close', onClose);
    child.stdout.on('data', () => {
      const url = stdout.match(/sshdeck service：(http:\/\/127\.0\.0\.1:\d+)/)?.[1];
      if (url) finish(null, url);
    });
  });
  return { child, ready };
}

function waitForChildClose(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.off('close', onClose);
      resolve(false);
    }, timeoutMs);
    const onClose = () => {
      clearTimeout(timer);
      resolve(true);
    };
    child.once('close', onClose);
  });
}

async function stopServiceCli(serviceCli) {
  if (!serviceCli) return;
  const { child } = serviceCli;
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM');
    if (!await waitForChildClose(child, 5000)) {
      if (process.platform === 'win32') {
        spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
          encoding: 'utf8',
          timeout: 5000,
          windowsHide: true,
        });
      } else child.kill('SIGKILL');
      if (!await waitForChildClose(child, 5000)) throw new Error('無法停止本次安裝後 service CLI');
    }
  }
}

async function main() {
  const packageRoot = readInstalledPath();
  const manifest = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  assert.equal(manifest.name, 'agent-system-sshdeck');
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);

  const uiPort = Number(process.env.SSHDECK_TEST_UI_PORT || 18787);
  const servicePort = Number(process.env.SSHDECK_TEST_API_PORT || 18788);
  assert.ok(Number.isInteger(uiPort) && uiPort > 0 && uiPort <= 65535);
  assert.ok(Number.isInteger(servicePort) && servicePort > 0 && servicePort <= 65535);
  assert.notEqual(uiPort, servicePort);
  assert.equal(await portAvailable(uiPort), true, `UI port ${uiPort} 已被占用；不會停止既有程序`);
  assert.equal(await portAvailable(servicePort), true, `service port ${servicePort} 已被占用；不會停止既有程序`);

  const { main: runCli } = require(path.join(packageRoot, 'bin', 'sshdeck.js'));
  const moduleAssets = [
    '@xterm/xterm/lib/xterm.js',
    '@xterm/xterm/css/xterm.css',
    '@xterm/addon-fit/lib/addon-fit.js',
  ].map((specifier) => require.resolve(specifier, { paths: [path.join(packageRoot, 'bin')] }));
  assert.equal(moduleAssets.every((file) => fs.statSync(file).isFile()), true);

  const secrets = [];
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-release-package-smoke-'));
  const env = createServiceEnv(path.join(tempDir, 'service-home'), secrets);
  const uiEnv = {
    SSHDECK_MODE: 'service',
    SSHDECK_BASE_PATH: '/sshdeck',
    SSHDECK_SERVICE_URL: '',
    SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
    SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
    SSHDECK_HOME: path.join(tempDir, 'standalone-home'),
  };
  const previousUiEnv = new Map(Object.keys(uiEnv).map((key) => [key, process.env[key]]));
  let serviceCli;
  let standaloneUi;
  let ui;
  let failure;
  const evidence = {
    package: `${manifest.name}@${manifest.version}`,
    nodeVersion: process.version,
    uiPort,
    servicePort,
    startedAt: new Date().toISOString(),
    status: 'running',
    stage: 'port-preflight',
  };

  try {
    evidence.stage = 'start-service-cli';
    serviceCli = startServiceCli(packageRoot, env, servicePort);
    evidence.servicePid = serviceCli.child.pid;
    const serviceUrl = await serviceCli.ready;
    const healthResponse = await fetch(`${serviceUrl}/v1/health`, { signal: AbortSignal.timeout(5000) });
    assert.equal(healthResponse.status, 200);
    const health = await healthResponse.json();
    assert.equal(health.status, 'ok');

    evidence.stage = 'start-standalone-ui';
    uiEnv.SSHDECK_MODE = 'standalone';
    uiEnv.SSHDECK_BASE_PATH = '';
    for (const [key, value] of Object.entries(uiEnv)) process.env[key] = value;
    standaloneUi = await runCli(['ui', '--host', '127.0.0.1', '--port', String(uiPort)], {
      openBrowser: async () => {},
    });
    assert.equal(standaloneUi.uiMode, 'standalone');
    assert.equal(standaloneUi.basePath, '');

    evidence.stage = 'standalone-page';
    const standalonePage = await fetchWithoutKeepAlive(standaloneUi.url, { signal: AbortSignal.timeout(5000) });
    assert.equal(standalonePage.status, 200);
    const standaloneHtml = await standalonePage.text();
    assert.match(standaloneHtml, /href="\/assets\/workspace\.css/);
    assert.match(standaloneHtml, /src="\/assets\/workspace\.js/);
    assert.doesNotMatch(standaloneHtml, /\/sshdeck\/assets\//);
    for (const secret of secrets) assert.equal(standaloneHtml.includes(secret), false, 'standalone UI HTML 不得包含 service secret');

    const standaloneAssets = [
      'workspace.js',
      'workspace.css',
      'connection-guide.js',
      'terminal.js',
      'xterm.js',
      'xterm.css',
      'addon-fit.js',
    ];
    evidence.stage = 'standalone-assets';
    for (const asset of standaloneAssets) {
      const response = await fetchWithoutKeepAlive(new URL(`assets/${asset}`, standaloneUi.url), { signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200, `standalone root 資產 ${asset} 必須可取得`);
      assert.ok((await response.arrayBuffer()).byteLength > 0, `standalone root 資產 ${asset} 不可為空`);
    }

    evidence.stage = 'standalone-api-list';
    const standaloneHosts = await fetchWithoutKeepAlive(new URL('api/hosts', standaloneUi.url), { signal: AbortSignal.timeout(5000) });
    assert.equal(standaloneHosts.status, 200);
    assert.deepEqual(await standaloneHosts.json(), []);
    const standaloneCreate = await fetchWithoutKeepAlive(new URL('api/hosts', standaloneUi.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ alias: 'release-smoke-standalone', hostname: '127.0.0.1', port: 22, username: 'candidate' }),
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(standaloneCreate.status, 201);
    assert.equal((await standaloneCreate.json()).alias, 'release-smoke-standalone');
    assert.equal((await fetchWithoutKeepAlive(new URL('/sshdeck/assets/workspace.js', standaloneUi.url), { signal: AbortSignal.timeout(5000) })).status, 404);
    assert.equal((await fetchWithoutKeepAlive(new URL('/sshdeck/api/hosts', standaloneUi.url), { signal: AbortSignal.timeout(5000) })).status, 404);
    evidence.standaloneUi = {
      path: new URL(standaloneUi.url).pathname,
      assets: standaloneAssets,
      apiCrud: 'passed',
      mountedPathLeakage: 'none',
    };
    await closeServer(standaloneUi);
    standaloneUi = null;
    evidence.standaloneUiStopped = true;

    evidence.stage = 'start-mounted-service-ui';
    uiEnv.SSHDECK_MODE = 'service';
    uiEnv.SSHDECK_BASE_PATH = '/sshdeck';
    uiEnv.SSHDECK_SERVICE_URL = serviceUrl;
    for (const [key, value] of Object.entries(uiEnv)) process.env[key] = value;
    ui = await runCli(['ui', '--host', '127.0.0.1', '--port', String(uiPort)], {
      openBrowser: async () => {},
    });

    evidence.stage = 'mounted-page';
    const pageResponse = await fetch(ui.url, { signal: AbortSignal.timeout(5000) });
    assert.equal(pageResponse.status, 200);
    const html = await pageResponse.text();
    assert.match(html, /\/sshdeck\/assets\/workspace\.js/);
    assert.match(html, /\/sshdeck\/assets\/xterm\.css/);
    for (const secret of secrets) assert.equal(html.includes(secret), false, 'UI HTML 不得包含 service secret');

    const assets = [
      ['workspace.js', /const services = \{\}/],
      ['workspace.css', /./],
      ['connection-guide.js', /function/],
      ['terminal.js', /function/],
      ['xterm.js', /./],
      ['xterm.css', /./],
      ['addon-fit.js', /./],
    ];
    evidence.stage = 'mounted-assets';
    for (const [asset, contentPattern] of assets) {
      const response = await fetch(new URL(`assets/${asset}`, ui.url), { signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200, `掛載資產 ${asset} 必須可取得`);
      const content = await response.text();
      assert.match(content, contentPattern, `掛載資產 ${asset} 不可為空`);
    }

    evidence.stage = 'mounted-api-list';
    const listResponse = await fetch(new URL('api/hosts', ui.url), { signal: AbortSignal.timeout(5000) });
    assert.equal(listResponse.status, 200);
    assert.deepEqual(await listResponse.json(), []);
    const createResponse = await fetch(new URL('api/hosts', ui.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ alias: 'release-smoke', hostname: '127.0.0.1', port: 22, username: 'candidate' }),
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(createResponse.status, 201);
    const created = await createResponse.json();
    assert.equal(created.alias, 'release-smoke');
    assert.equal(created.keyPath, undefined);

    const rootAsset = await fetch(new URL('/assets/workspace.js', ui.url), { signal: AbortSignal.timeout(5000) });
    const rootApi = await fetch(new URL('/api/hosts', ui.url), { signal: AbortSignal.timeout(5000) });
    assert.equal(rootAsset.status, 404);
    assert.equal(rootApi.status, 404);
    evidence.stage = 'all-assertions-passed';
    evidence.serviceHealth = { ...health, cliStarted: true };
    evidence.mountedUi = {
      path: new URL(ui.url).pathname,
      assets: assets.map(([name]) => name),
      apiCrud: 'passed',
      cliDispatch: 'passed',
      rootLeakage: 'none',
    };
    evidence.status = 'passed';
  } catch (error) {
    failure = error;
    evidence.status = 'failed';
    evidence.failureStage = evidence.stage;
    evidence.errorName = error.name;
    evidence.failure = redact(error.message, secrets);
    if (error.cause) {
      evidence.failureCauseName = error.cause.name;
      if (error.cause.code) evidence.failureCauseCode = error.cause.code;
      evidence.failureCause = redact(error.cause.message, secrets);
    }
  } finally {
    try { await closeServer(standaloneUi); } catch (error) { evidence.standaloneUiCleanup = redact(error.message, secrets); }
    try { await closeServer(ui); } catch (error) { evidence.uiCleanup = redact(error.message, secrets); }
    try { await stopServiceCli(serviceCli); evidence.serviceCliStopped = true; }
    catch (error) { evidence.serviceCleanup = redact(error.message, secrets); }
    for (const [key, value] of previousUiEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(tempDir, { recursive: true, force: true });
    for (const port of [uiPort, servicePort]) evidence[`port${port}Free`] = await portAvailable(port).catch(() => false);
  }

  const cleanupPassed = !evidence.standaloneUiCleanup && !evidence.uiCleanup && !evidence.serviceCleanup
    && evidence[`port${uiPort}Free`] !== false && evidence[`port${servicePort}Free`] !== false;
  evidence.cleanupPassed = cleanupPassed;
  evidence.finishedAt = new Date().toISOString();
  if (failure || !cleanupPassed) evidence.status = 'failed';
  const evidenceFile = process.env.SSHDECK_TEST_RELEASE_EVIDENCE;
  if (evidenceFile) {
    fs.writeFileSync(path.resolve(evidenceFile), `${JSON.stringify(evidence, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
    });
  }
  if (failure || !cleanupPassed) {
    process.stderr.write(`已安裝套件 smoke 失敗：${evidence.failure || 'cleanup 未通過'}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`已安裝套件 smoke 通過：${manifest.name}@${manifest.version}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`已安裝套件 smoke 無法執行：${error.name}：${error.message}\n`);
  process.exitCode = 1;
});
