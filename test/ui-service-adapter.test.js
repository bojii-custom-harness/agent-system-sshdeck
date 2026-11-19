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
const { createServiceEnv } = require('./helpers/service-test-utils');

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
  let service;
  let ui;
  try {
    service = await startService({ env, port: 0 });
    const uiEnv = {
      SSHDECK_MODE: 'service',
      SSHDECK_BASE_PATH: '/sshdeck',
      SSHDECK_SERVICE_URL: service.url,
      SSHDECK_SERVICE_TOKEN: env.SSHDECK_SERVICE_TOKEN,
      SSHDECK_UI_TOKEN: env.SSHDECK_UI_TOKEN,
    };
    ui = await startUi({ mode: 'service', env: uiEnv, port: 0, openBrowser: async () => {}, log: () => {} });
    const origin = new URL(ui.url).origin;
    const html = await (await fetch(ui.url)).text();
    assert.match(html, /"mode":"service"/);
    assert.match(html, /"basePath":"\/sshdeck"/);
    assert.doesNotMatch(html, new RegExp(env.SSHDECK_UI_TOKEN));
    assert.doesNotMatch(html, new RegExp(env.SSHDECK_SERVICE_TOKEN));
    assert.doesNotMatch(html, new RegExp(env.SSHDECK_ENCRYPTION_KEY));
    assert.equal((await fetch(`${origin}/api/hosts`)).status, 404);

    const host = await request(ui, '/sshdeck/api/hosts', {
      method: 'POST',
      body: { alias: 'import-target', hostname: '127.0.0.1', port: 1, username: 'tester' },
    });
    assert.equal(host.response.status, 201, JSON.stringify(host.payload));
    assert.equal(host.payload.keyPath, undefined);

    const invalidPrivateKey = 'ticket02-invalid-private-key-marker';
    const invalidPassphrase = 'ticket02-invalid-passphrase-marker';
    const invalid = await request(ui, '/sshdeck/api/hosts/import-target/key/import', {
      method: 'POST',
      body: { privateKey: invalidPrivateKey, passphrase: invalidPassphrase },
    });
    assert.equal(invalid.response.status, 400);
    assert.equal(invalid.text.includes(invalidPrivateKey), false);
    assert.equal(invalid.text.includes(invalidPassphrase), false);
    assert.equal((await request(ui, '/sshdeck/api/keys')).payload.length, 0);

    const passphrase = randomBytes(24).toString('base64url');
    const wrongPassphrase = randomBytes(24).toString('base64url');
    const pair = utils.generateKeyPairSync('ed25519', {
      passphrase,
      cipher: 'aes256-cbc',
      comment: 'sshdeck-ticket02-service-ui',
    });
    const wrong = await request(ui, '/sshdeck/api/hosts/import-target/key/import', {
      method: 'POST',
      body: { privateKey: pair.private, passphrase: wrongPassphrase },
    });
    assert.equal(wrong.response.status, 400);
    assert.equal(wrong.text.includes(pair.private), false);
    assert.equal(wrong.text.includes(wrongPassphrase), false);
    assert.equal((await request(ui, '/sshdeck/api/keys')).payload.length, 0);

    const imported = await request(ui, '/sshdeck/api/hosts/import-target/key/import', {
      method: 'POST',
      body: { privateKey: pair.private, passphrase },
    });
    assert.equal(imported.response.status, 201, JSON.stringify(imported.payload));
    assert.match(imported.payload.publicKey, /^ssh-ed25519 /);
    assert.match(imported.payload.guide, /遠端撤銷/);
    for (const secret of [pair.private, passphrase, wrongPassphrase, env.SSHDECK_UI_TOKEN, env.SSHDECK_SERVICE_TOKEN, env.SSHDECK_ENCRYPTION_KEY]) {
      assert.equal(imported.text.includes(secret), false, '一般 API 回應不得包含私鑰、密語或 token');
    }

    const listed = await request(ui, '/sshdeck/api/keys');
    assert.equal(listed.response.status, 200);
    assert.equal(listed.payload.length, 1);
    const record = listed.payload[0];
    assert.equal(record.keyPath, `service-key:${record.id}`);
    assert.equal(listed.text.includes(serviceHome), false);
    assert.equal(listed.text.includes(pair.private), false);
    assert.equal(listed.text.includes(passphrase), false);
    const hosts = await request(ui, '/sshdeck/api/hosts');
    assert.equal(hosts.payload[0].keyPath, `service-key:${record.id}`);
    assert.equal(hosts.text.includes(serviceHome), false);

    const secondHost = await request(ui, '/sshdeck/api/hosts', {
      method: 'POST',
      body: { alias: 'shared-target', hostname: '127.0.0.1', port: 1, username: 'tester' },
    });
    assert.equal(secondHost.response.status, 201);
    const linked = await request(ui, '/sshdeck/api/hosts/shared-target/key/link', {
      method: 'POST',
      body: { keyId: record.id },
    });
    assert.equal(linked.response.status, 200);
    const blockedDelete = await request(ui, '/sshdeck/api/hosts/import-target/key/delete', { method: 'POST', body: {} });
    assert.equal(blockedDelete.response.status, 409);
    assert.equal(blockedDelete.payload.code, 'KEY_IN_USE');
    assert.equal((await request(ui, '/sshdeck/api/hosts')).payload.find((item) => item.alias === 'import-target').keyPath, `service-key:${record.id}`);

    assert.equal((await request(ui, '/sshdeck/api/hosts/shared-target/key/unlink', { method: 'POST', body: {} })).response.status, 204);
    const deletedKey = await request(ui, '/sshdeck/api/hosts/import-target/key/delete', { method: 'POST', body: {} });
    assert.equal(deletedKey.response.status, 200, JSON.stringify(deletedKey.payload));
    assert.match(deletedKey.payload.guide, /authorized_keys/);
    assert.equal((await request(ui, '/sshdeck/api/keys')).payload.length, 0);
    const generatedHost = await request(ui, '/sshdeck/api/hosts', {
      method: 'POST',
      body: { alias: 'generated-target', hostname: '127.0.0.1', port: 1, username: 'tester' },
    });
    assert.equal(generatedHost.response.status, 201);
    const generated = await request(ui, '/sshdeck/api/hosts/generated-target/key', {
      method: 'POST',
      body: { passphrase: 'must-not-be-used-in-service-mode' },
    });
    assert.equal(generated.response.status, 201, JSON.stringify(generated.payload));
    assert.doesNotMatch(generated.text, /must-not-be-used-in-service-mode/);

    const updated = await request(ui, '/sshdeck/api/hosts/generated-target', {
      method: 'PUT',
      body: { hostname: '127.0.0.1', port: 2, username: 'updated' },
    });
    assert.equal(updated.response.status, 200);
    const invalidPath = await request(ui, '/sshdeck/api/hosts/generated-target', {
      method: 'PUT',
      body: { keyPath: 'C:\\private\\id_ed25519' },
    });
    assert.equal(invalidPath.response.status, 400);
    assert.equal((await request(ui, '/sshdeck/api/hosts/generated-target', { method: 'DELETE' })).response.status, 204);

    assert.equal((await request(ui, '/sshdeck/api/lock', { method: 'POST', body: {} })).response.status, 204);
    assert.equal((await request(ui, '/sshdeck/api/unlock', { method: 'POST', body: {} })).response.status, 204);
  } finally {
    if (ui) await new Promise((resolve) => ui.close(resolve));
    if (service) await service.closeAsync();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
