'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes, createHash } = require('node:crypto');
const { utils } = require('ssh2');
const { ServiceClient } = require('../lib/service-client');
const { startService } = require('../lib/service-server');
const { ENVELOPE_FORMAT } = require('../lib/service-store');
const {
  api,
  applyTicket03TokenSentinels,
  createServiceEnv,
  forceKillCli,
  makeTaskTemp,
  spawnCli,
  waitForOutput,
} = require('./helpers/service-test-utils');

function digest(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function snapshotFiles(dataFile, keyPaths) {
  const files = [dataFile, `${dataFile}.keys.json`, `${dataFile}.service-state.json`, ...keyPaths, ...keyPaths.map((file) => `${file}.pub`)];
  return new Map(files.filter((file) => fs.existsSync(file)).map((file) => [file, digest(file)]));
}

function cliEnvironment(server, env, standaloneHome) {
  return {
    SSHDECK_MODE: 'service',
    SSHDECK_SERVICE_URL: server.url,
    SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
    SSHDECK_HOME: standaloneHome,
  };
}

const directoryAliasTypes = process.platform === 'win32'
  ? [
    { name: 'junction', type: 'junction' },
    { name: 'directory symlink', type: 'dir', mayLackPrivilege: true },
  ]
  : [{ name: 'directory symlink', type: 'dir' }];

for (const aliasType of directoryAliasTypes) {
  test(`service 透過目錄 ${aliasType.name} 指向 standalone 資料時拒絕啟動且保留來源`,
    { timeout: 20_000 }, async (t) => {
      const temp = makeTaskTemp();
      const standaloneHome = path.join(temp, 'standalone-data');
      const serviceAlias = path.join(temp, 'service-data-alias');
      const standaloneData = path.join(standaloneHome, 'hosts.json');
      const originalBytes = Buffer.from(`${JSON.stringify([
        { alias: 'standalone-only', hostname: '127.0.0.1', port: 2227, username: 'fixture-user' },
      ])}\n`);
      const originalHash = createHash('sha256').update(originalBytes).digest('hex');
      let aliasCreated = false;
      let server;
      let serviceStarted = false;

      try {
        fs.mkdirSync(standaloneHome, { recursive: true });
        fs.writeFileSync(standaloneData, originalBytes);
        const originalFiles = fs.readdirSync(standaloneHome).sort();
        try {
          fs.symlinkSync(standaloneHome, serviceAlias, aliasType.type);
          aliasCreated = true;
        } catch (error) {
          if (aliasType.mayLackPrivilege && ['EACCES', 'EPERM', 'UNKNOWN'].includes(error.code)) {
            t.skip(`目前 Windows 環境無建立目錄 symlink 的權限（${error.code}）；junction 別名另有實測`);
            return;
          }
          throw error;
        }

        assert.equal(fs.lstatSync(serviceAlias).isSymbolicLink(), true, '測試必須建立真實目錄別名');
        assert.equal(fs.realpathSync.native(serviceAlias), fs.realpathSync.native(standaloneHome),
          'service 與 standalone 路徑必須實際解析至同一目錄');

        const env = {
          ...createServiceEnv(serviceAlias),
          SSHDECK_HOME: standaloneHome,
        };
        let startupError;
        try {
          server = await startService({ env, port: 0 });
          serviceStarted = true;
        } catch (error) {
          startupError = error;
        }
        if (server) {
          await server.closeAsync();
          server = undefined;
        }

        assert.deepEqual(fs.readFileSync(standaloneData), originalBytes, '碰撞檢查不得覆寫 standalone 原始 bytes');
        assert.equal(digest(standaloneData), originalHash, '碰撞檢查不得改變 standalone 原始 hash');
        assert.deepEqual(fs.readdirSync(standaloneHome).sort(), originalFiles,
          '碰撞檢查不得在 standalone 目錄生成或刪除資料');
        assert.equal(startupError?.code || (serviceStarted ? 'SERVICE_STARTED' : 'REJECTED_WITHOUT_CODE'),
          'SERVICE_HOME_CONFLICT', 'service 必須在讀取或寫入共用資料前以碰撞錯誤拒絕啟動');
      } finally {
        if (server) await server.closeAsync();
        if (aliasCreated) fs.rmSync(serviceAlias, { recursive: true, force: true });
        assert.equal(fs.existsSync(serviceAlias), false, '測試結束後必須移除本次目錄別名');
        assert.equal(fs.existsSync(standaloneData), true, '移除目錄別名不得刪除其 standalone 目標');
        fs.rmSync(temp, { recursive: true, force: true });
        assert.equal(fs.existsSync(temp), false, '測試結束後必須移除本次隔離目錄');
      }
    });
}

test('service API 加密憑證、雙重認證、鎖定／重啟與損壞資料 fail-closed', { timeout: 60_000 }, async () => {
  const temp = makeTaskTemp();
  const serviceHome = path.join(temp, 'service-data');
  const standaloneHome = path.join(temp, 'standalone-data');
  const env = createServiceEnv(serviceHome);
  const tokenSentinels = applyTicket03TokenSentinels(env);
  let server;
  try {
    const conflictingHome = path.join(temp, 'shared-data');
    await assert.rejects(startService({
      env: {
        ...env,
        SSHDECK_HOME: conflictingHome,
        SSHDECK_SERVICE_HOME: conflictingHome,
      },
      port: 0,
    }), (error) => error.code === 'SERVICE_HOME_CONFLICT');
    assert.equal(fs.existsSync(conflictingHome), false, '服務資料根目錄不得覆用 standalone 根目錄');

    const missingKeyEnv = { ...env, SSHDECK_ENCRYPTION_KEY: '' };
    await assert.rejects(startService({ env: missingKeyEnv, port: 0 }), (error) => error.code === 'ENCRYPTION_KEY_REQUIRED');
    assert.equal(fs.existsSync(serviceHome), false, '缺少解密金鑰時不得建立或改寫服務資料');

    server = await startService({ env, port: 0 });
    assert.equal(new URL(server.url).search, '', 'service URL 不得包含 token query');
    assert.equal(tokenSentinels.some((sentinel) => server.url.includes(sentinel)), false,
      'service URL 不得包含 token sentinel');
    const health = await api(server, '/v1/health');
    const version = await api(server, '/v1/version');
    assert.equal(health.payload.protocolVersion, 1);
    assert.equal(version.payload.protocolVersion, 1);
    for (const response of [health.text, version.text]) {
      for (const sentinel of tokenSentinels) {
        assert.equal(response.includes(sentinel), false, 'service API response 不得包含 token sentinel');
      }
    }
    assert.equal((await api(server, '/v1/hosts')).status, 401);
    assert.equal((await api(server, '/v1/hosts', { token: env.SSHDECK_SERVICE_TOKEN })).status, 200);
    assert.equal((await api(server, '/v1/keys', { token: env.SSHDECK_SERVICE_TOKEN })).status, 403);

    const added = await api(server, '/v1/hosts', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { alias: 'import-target', hostname: '127.0.0.1', port: 2227, username: 'root' },
    });
    assert.equal(added.status, 201);
    assert.equal(added.payload.keyPath, undefined);
    const createHost = await api(server, '/v1/hosts', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { alias: 'generated-target', hostname: '127.0.0.1', port: 2228, username: 'root' },
    });
    assert.equal(createHost.status, 201);

    const beforeInvalidImport = snapshotFiles(path.join(serviceHome, 'hosts.json'), []);
    const invalidImport = await api(server, '/v1/hosts/import-target/key/import', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { privateKey: 'invalid-private-key-marker', passphrase: 'invalid-passphrase-marker' },
    });
    assert.equal(invalidImport.status, 400);
    assert.equal(invalidImport.text.includes('invalid-private-key-marker'), false, '錯誤回應不得包含匯入私鑰');
    assert.equal(invalidImport.text.includes('invalid-passphrase-marker'), false, '錯誤回應不得包含匯入密語');
    for (const [file, hash] of beforeInvalidImport) assert.equal(digest(file), hash, '匯入失敗不得改寫既有資料');

    const passphrase = randomBytes(24).toString('base64url');
    const pair = utils.generateKeyPairSync('ed25519', {
      passphrase,
      cipher: 'aes256-cbc',
      comment: 'sshdeck-ticket01-api-test',
    });
    const imported = await api(server, '/v1/hosts/import-target/key/import', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: { privateKey: pair.private, passphrase },
    });
    assert.equal(imported.status, 201, `${imported.payload?.code}: ${imported.payload?.error}`);
    const created = await api(server, '/v1/hosts/generated-target/key/create', {
      method: 'POST',
      token: env.SSHDECK_UI_TOKEN,
      body: {},
    });
    assert.equal(created.status, 201);
    const responses = `${imported.text}\n${created.text}`;
    assert.equal(responses.includes(pair.private), false, 'API 不得回傳匯入私鑰');
    assert.equal(responses.includes(passphrase), false, 'API 不得回傳匯入密語');
    assert.equal(responses.includes(env.SSHDECK_ENCRYPTION_KEY), false, 'API 不得回傳加密金鑰');
    assert.equal(responses.includes(env.SSHDECK_SERVICE_TOKEN), false, 'API 不得回傳 CLI token');
    assert.equal(responses.includes(env.SSHDECK_UI_TOKEN), false, 'API 不得回傳 UI token');
    assert.equal(responses.includes(env.SSHDECK_TUNNEL_TOKEN), false, 'API 不得回傳 tunnel token');
    for (const sentinel of tokenSentinels) {
      assert.equal(responses.includes(sentinel), false, 'service API response 不得包含 token sentinel');
    }

    const listed = await api(server, '/v1/keys', { token: env.SSHDECK_UI_TOKEN });
    assert.equal(listed.status, 200);
    assert.equal(listed.payload.length, 2);
    const importedRecord = listed.payload.find((item) => item.alias === 'import-target');
    assert.ok(importedRecord.id);
    const indexFile = path.join(serviceHome, 'hosts.json.keys.json');
    const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
    const importedFile = index[importedRecord.id].keyPath;
    const storedBytes = fs.readFileSync(importedFile);
    const envelope = JSON.parse(storedBytes.toString('utf8'));
    assert.equal(envelope.format, ENVELOPE_FORMAT);
    assert.equal(storedBytes.includes(Buffer.from(pair.private)), false, '磁碟上的金鑰檔不得包含明文私鑰');
    assert.equal(storedBytes.includes(Buffer.from(passphrase)), false, '磁碟上的金鑰檔不得包含明文密語');
    assert.equal(listed.text.includes(importedFile), false, 'API 不得回傳私鑰檔案路徑');

    const manualLock = await api(server, '/v1/lock', { method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {} });
    assert.equal(manualLock.status, 204);
    const lockedCheck = await api(server, '/v1/hosts/import-target/check', {
      method: 'POST',
      token: env.SSHDECK_SERVICE_TOKEN,
      body: {},
    });
    assert.equal(lockedCheck.status, 423);
    assert.equal(lockedCheck.payload.code, 'SERVICE_LOCKED');
    await server.closeAsync();
    server = await startService({ env, port: 0 });

    const standaloneHosts = path.join(standaloneHome, 'hosts.json');
    fs.mkdirSync(standaloneHome, { recursive: true });
    fs.writeFileSync(standaloneHosts, JSON.stringify([
      { alias: 'standalone-only', hostname: '127.0.0.1', port: 1, username: 'not-a-real-user' },
    ]));
    const serviceList = spawnCli(['host', 'list'], { env: cliEnvironment(server, env, standaloneHome) });
    const listedFromCli = await serviceList.closed;
    assert.equal(listedFromCli.timedOut, false);
    assert.equal(listedFromCli.code, 0);
    assert.match(listedFromCli.stdout, /import-target/);
    assert.equal(listedFromCli.stdout.includes('standalone-only'), false, 'service mode 不得讀取 standalone 資料');
    for (const sentinel of tokenSentinels) {
      assert.equal(`${listedFromCli.stdout}\n${listedFromCli.stderr}`.includes(sentinel), false,
        'headless CLI 可讀輸出不得包含 token sentinel');
    }

    const lockedCli = spawnCli(['exec', 'import-target', '--', 'printf should-not-run'], {
      env: cliEnvironment(server, env, standaloneHome),
    });
    const lockedResult = await lockedCli.closed;
    assert.equal(lockedResult.code, 1);
    assert.match(lockedResult.stderr, /手動鎖定/);
    assert.equal(lockedResult.stderr.includes('登入金鑰密語'), false, 'service mode 錯誤不得提示密語');
    assert.equal(lockedResult.stderr.includes('standalone-only'), false);

    const unlock = await api(server, '/v1/unlock', { method: 'POST', token: env.SSHDECK_UI_TOKEN, body: {} });
    assert.equal(unlock.status, 204);
    const cliCannotUnlock = await api(server, '/v1/unlock', { method: 'POST', token: env.SSHDECK_SERVICE_TOKEN, body: {} });
    assert.equal(cliCannotUnlock.status, 403);
    const afterUnlock = await api(server, '/v1/hosts/import-target/check', {
      method: 'POST',
      token: env.SSHDECK_SERVICE_TOKEN,
      body: {},
    });
    assert.notEqual(afterUnlock.status, 423, 'UI 解鎖後，服務已恢復讀取持久憑證');

    const unavailableCli = spawnCli(['exec', 'standalone-only', '--', 'printf must-not-run'], {
      env: {
        ...cliEnvironment(server, env, standaloneHome),
        SSHDECK_SERVICE_URL: 'http://127.0.0.1:1',
      },
    });
    const unavailable = await unavailableCli.closed;
    assert.equal(unavailable.code, 1);
    assert.match(unavailable.stderr, /無法連線/);
    assert.equal(unavailable.stderr.includes('登入金鑰密語'), false);

    await server.closeAsync();
    server = undefined;
    const managedPaths = Object.values(JSON.parse(fs.readFileSync(indexFile, 'utf8'))).map((record) => record.keyPath);
    const beforeMissingKey = snapshotFiles(path.join(serviceHome, 'hosts.json'), managedPaths);
    await assert.rejects(startService({
      env: { ...env, SSHDECK_ENCRYPTION_KEY: '' },
      port: 0,
    }), (error) => error.code === 'ENCRYPTION_KEY_REQUIRED');
    for (const [file, hash] of beforeMissingKey) assert.equal(digest(file), hash, '缺少解密金鑰不得覆寫主機或憑證資料');

    const originalStored = fs.readFileSync(importedFile);
    const corrupted = JSON.parse(originalStored.toString('utf8'));
    const damaged = corrupted.ciphertext[0] === 'A' ? 'B' : 'A';
    corrupted.ciphertext = `${damaged}${corrupted.ciphertext.slice(1)}`;
    fs.writeFileSync(importedFile, `${JSON.stringify(corrupted)}\n`);
    const corruptSnapshot = fs.readFileSync(importedFile);
    await assert.rejects(startService({ env, port: 0 }), (error) => error.code === 'DATA_CORRUPT');
    assert.deepEqual(fs.readFileSync(importedFile), corruptSnapshot, '損壞資料啟動失敗不得覆寫原始位元組');
  } finally {
    if (server) await server.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('service 要求與既有憑證及加密金鑰分離的 tunnel token', { timeout: 20_000 }, async () => {
  const temp = makeTaskTemp();
  const home = path.join(temp, 'service-data');
  const base = createServiceEnv(home);
  const validTunnelToken = randomBytes(36).toString('base64url');
  assert.equal(new Set([
    base.SSHDECK_SERVICE_TOKEN,
    base.SSHDECK_UI_TOKEN,
    validTunnelToken,
  ]).size, 3, 'CLI、UI、tunnel token sentinel 必須彼此獨立');
  const assertRejected = async (env, code) => {
    let server;
    let startupError;
    try {
      server = await startService({ env, port: 0 });
    } catch (error) {
      startupError = error;
    } finally {
      if (server) await server.closeAsync();
    }
    assert.equal(startupError?.code, code, 'service 必須在啟動前拒絕不合法的 tunnel token 設定');
  };

  let server;
  try {
    const withoutTunnelToken = { ...base };
    delete withoutTunnelToken.SSHDECK_TUNNEL_TOKEN;
    await assertRejected(withoutTunnelToken, 'TUNNEL_TOKEN_REQUIRED');
    await assertRejected({ ...base, SSHDECK_TUNNEL_TOKEN: 'short' }, 'TUNNEL_TOKEN_REQUIRED');
    await assertRejected({ ...base, SSHDECK_TUNNEL_TOKEN: base.SSHDECK_SERVICE_TOKEN }, 'TUNNEL_TOKEN_INVALID');
    await assertRejected({ ...base, SSHDECK_TUNNEL_TOKEN: base.SSHDECK_UI_TOKEN }, 'TUNNEL_TOKEN_INVALID');
    await assertRejected({ ...base, SSHDECK_TUNNEL_TOKEN: base.SSHDECK_ENCRYPTION_KEY }, 'TUNNEL_TOKEN_INVALID');

    server = await startService({
      env: { ...base, SSHDECK_TUNNEL_TOKEN: validTunnelToken },
      port: 0,
    });
    const requestWithToken = (token) => ({ headers: { authorization: `Bearer ${token}` } });
    assert.equal(server.isTunnelAuthorizedRequest(requestWithToken(validTunnelToken)), true,
      'service 應提供 Ticket 02 可消費的 tunnel-only auth role');
    assert.equal(server.isTunnelAuthorizedRequest(requestWithToken(base.SSHDECK_SERVICE_TOKEN)), false,
      'CLI role 不得被視為 tunnel role');
    assert.equal(server.isTunnelAuthorizedRequest(requestWithToken(base.SSHDECK_UI_TOKEN)), false,
      'UI role 不得被視為 tunnel role');
    const tunnelCannotReadHosts = await api(server, '/v1/hosts', { token: validTunnelToken });
    assert.equal(tunnelCannotReadHosts.status, 403, 'tunnel token 必須被辨識，但不得讀取管理 API');
    assert.equal(tunnelCannotReadHosts.payload.code, 'FORBIDDEN');
    for (const secret of [base.SSHDECK_SERVICE_TOKEN, base.SSHDECK_UI_TOKEN, validTunnelToken]) {
      assert.equal(tunnelCannotReadHosts.text.includes(secret), false, 'API response 不得包含 token sentinel');
      assert.equal(server.url.includes(secret), false, 'service URL 不得包含 token sentinel');
    }
    assert.equal((await api(server, '/v1/hosts', { token: base.SSHDECK_SERVICE_TOKEN })).status, 200);
    assert.equal((await api(server, '/v1/hosts', { token: base.SSHDECK_UI_TOKEN })).status, 200);
    const forbiddenRoutes = [
      { route: '/v1/keys' },
      { route: '/v1/hosts/unknown/exec', method: 'POST', body: { command: 'must-not-run' } },
      { route: '/v1/hosts/unknown/key', method: 'GET' },
      { route: '/v1/lock', method: 'POST', body: {} },
      { route: '/v1/unlock', method: 'POST', body: {} },
    ];
    for (const { route, method, body } of forbiddenRoutes) {
      const response = await api(server, route, { token: validTunnelToken, method, body });
      assert.equal(response.status, 403, 'tunnel token 不得呼叫主機／金鑰管理、exec 或 lock 路徑');
    }
  } finally {
    if (server) await server.closeAsync();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('service start CLI 啟動健康端點，終止後不留背景程序', { timeout: 20_000 }, async () => {
  const temp = makeTaskTemp();
  const env = {
    ...createServiceEnv(path.join(temp, 'service-data')),
    SSHDECK_HOME: path.join(temp, 'standalone-data'),
    SSHDECK_MODE: 'standalone',
  };
  const tokenSentinels = applyTicket03TokenSentinels(env);
  let serviceCli;
  let stopped = false;
  try {
    serviceCli = spawnCli(['service', 'start', '--host', '127.0.0.1', '--port', '0'], {
      env,
      deadlineMs: 30_000,
    });
    await waitForOutput(serviceCli, 'stdout', 'sshdeck service：http://127.0.0.1:', 10_000, 'service start CLI 啟動');
    const secrets = [...tokenSentinels, env.SSHDECK_ENCRYPTION_KEY];
    for (const secret of secrets) {
      assert.equal(serviceCli.child.spawnargs.some((argument) => argument.includes(secret)), false,
        'service process argv 不得包含 server-side 憑證');
      assert.equal(`${serviceCli.output.stdout}\n${serviceCli.output.stderr}`.includes(secret), false,
        'service CLI 輸出不得包含 server-side 憑證');
    }
    const url = serviceCli.output.stdout.match(/sshdeck service：(http:\/\/127\.0\.0\.1:\d+)/)?.[1];
    assert.ok(url, 'service CLI 必須回報本次動態監聽 URL');
    assert.equal(new URL(url).search, '', 'service URL 不得包含憑證 query');
    const health = await fetch(`${url}/v1/health`, { signal: AbortSignal.timeout(3000) });
    assert.equal(health.status, 200);
    const healthText = await health.text();
    assert.equal(JSON.parse(healthText).status, 'ok');
    for (const sentinel of tokenSentinels) {
      assert.equal(healthText.includes(sentinel), false, 'service API response 不得包含 token sentinel');
    }

    const killed = forceKillCli(serviceCli.child);
    assert.ok(killed.status === 0 || killed.status === 128 || killed.status === 255,
      '只終止本次 service CLI process tree');
    await serviceCli.closed;
    stopped = true;
    await assert.rejects(fetch(`${url}/v1/health`, { signal: AbortSignal.timeout(1000) }),
      'service CLI 結束後健康端點應停止監聽');
  } finally {
    if (serviceCli && !stopped) {
      if (serviceCli.child.exitCode === null) forceKillCli(serviceCli.child);
      await serviceCli.closed;
    }
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('service mode 版本不相容或設定錯誤時不回退 standalone', { timeout: 20_000 }, async () => {
  let versionUrl;
  const versionClient = new ServiceClient({
    env: {
      SSHDECK_SERVICE_URL: 'http://127.0.0.1:8788',
      SSHDECK_SERVICE_TOKEN: 'v'.repeat(36),
    },
    fetchImpl: async (url, options) => {
      versionUrl = url;
      assert.equal(options.headers.authorization, undefined, '公開版本端點不需要傳送服務 token');
      return new Response(JSON.stringify({ protocolVersion: 999 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  await assert.rejects(versionClient.verifyVersion(), (error) => error.code === 'SERVICE_VERSION_MISMATCH');
  assert.equal(versionUrl, 'http://127.0.0.1:8788/v1/version');

  const temp = makeTaskTemp();
  const standaloneHome = path.join(temp, 'standalone');
  fs.mkdirSync(standaloneHome, { recursive: true });
  fs.writeFileSync(path.join(standaloneHome, 'hosts.json'), JSON.stringify([
    { alias: 'standalone-only', hostname: '127.0.0.1', port: 1, username: 'no-user' },
  ]));
  try {
    const result = spawnCli(['exec', 'standalone-only', '--', 'printf should-not-run'], {
      env: {
        SSHDECK_MODE: 'service',
        SSHDECK_HOME: standaloneHome,
      },
    });
    const completed = await result.closed;
    assert.equal(completed.code, 1);
    assert.match(completed.stderr, /SSHDECK_SERVICE_URL/);
    assert.equal(completed.stderr.includes('登入金鑰密語'), false);
    assert.equal(completed.stderr.includes('standalone-only'), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
