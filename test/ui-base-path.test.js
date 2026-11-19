'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');
const { startUi } = require('../bin/sshdeck.js');

async function fetchAndDrain(url, options) {
  const response = await fetch(url, options);
  await response.arrayBuffer();
  return response;
}

function responseSocket(url, origin) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { origin });
    const timer = setTimeout(() => {
      socket.terminate();
      reject(new Error('等待 WebSocket 控制訊息逾時'));
    }, 5_000);
    socket.once('message', (message) => {
      clearTimeout(timer);
      const value = message.toString();
      socket.close();
      socket.once('close', () => resolve(value));
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      socket.once('close', () => reject(error));
      socket.terminate();
    });
  });
}

test('掛載 basePath 隔離頁面、資產、API、WebSocket 與安全返回值', { timeout: 20_000 }, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-base-path-'));
  const server = await startUi({
    port: 0,
    basePath: '/sshdeck',
    dataFile: path.join(directory, 'hosts.json'),
    openBrowser: async () => {},
    log: () => {},
  });
  const origin = new URL(server.url).origin;
  try {
    assert.equal(server.url, `${origin}/sshdeck/`);
    const pageResponse = await fetch(server.url);
    assert.equal(pageResponse.status, 200);
    const page = await pageResponse.text();
    assert.match(page, /href="\/sshdeck\/assets\/workspace\.css\?v=2"/);
    assert.match(page, /src="\/sshdeck\/assets\/connection-guide\.js\?v=2"/);
    assert.match(page, /"basePath":"\/sshdeck"/);
    assert.doesNotMatch(page, /(?:src|href)="\/(?:assets|api)\//);
    assert.match(page, /href="\/workspace"/);

    const invalidReturn = await (await fetch(`${origin}/sshdeck/?returnTo=${encodeURIComponent('https://outside.invalid/path')}`)).text();
    assert.match(invalidReturn, /href="\/workspace"/);
    const traversalReturn = await (await fetch(`${origin}/sshdeck/?returnTo=${encodeURIComponent('/workspace/%2e%2e/admin')}`)).text();
    assert.match(traversalReturn, /href="\/workspace"/);
    const encodedSeparatorReturn = await (await fetch(`${origin}/sshdeck/?returnTo=${encodeURIComponent('/workspace/demo/session/%252f..%252fadmin')}`)).text();
    assert.match(encodedSeparatorReturn, /href="\/workspace"/);
    const validReturn = await (await fetch(`${origin}/sshdeck/?returnTo=${encodeURIComponent('/workspace/demo/session/ses_test')}`)).text();
    assert.match(validReturn, /href="\/workspace\/demo\/session\/ses_test"/);

    const redirect = await fetchAndDrain(`${origin}/sshdeck`, { redirect: 'manual' });
    assert.equal(redirect.status, 308);
    assert.equal(redirect.headers.get('location'), '/sshdeck/');
    assert.equal((await fetchAndDrain(`${origin}/`)).status, 404);
    assert.equal((await fetchAndDrain(`${origin}/assets/workspace.js`)).status, 404);
    assert.equal((await fetchAndDrain(`${origin}/api/hosts`)).status, 404);
    assert.equal((await fetchAndDrain(`${origin}/sshdeck/api/hosts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://attacker.invalid' },
      body: JSON.stringify({ alias: 'cross-origin', hostname: '127.0.0.1', port: 22, username: 'tester' }),
    })).status, 403);
    for (const asset of ['workspace.js', 'workspace.css?v=2', 'connection-guide.js?v=2', 'terminal.js', 'xterm.js', 'xterm.css', 'addon-fit.js']) {
      const response = await fetch(`${origin}/sshdeck/assets/${asset}`);
      assert.equal(response.status, 200, asset);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      await response.arrayBuffer();
    }

    const created = await fetch(`${origin}/sshdeck/api/hosts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ alias: 'mounted-ws', hostname: '127.0.0.1', port: 22, username: 'tester' }),
    });
    assert.equal(created.status, 201);
    assert.equal((await created.json()).alias, 'mounted-ws');
    assert.equal((await (await fetch(`${origin}/sshdeck/api/hosts`)).json()).length, 1);

    const mountedSocket = await responseSocket(
      `${origin.replace(/^http/, 'ws')}/sshdeck/api/shell?alias=mounted-ws`,
      origin,
    );
    assert.match(mountedSocket, /登入金鑰|錯誤/);
    await assert.rejects(
      responseSocket(`${origin.replace(/^http/, 'ws')}/api/shell?alias=mounted-ws`, origin),
      /Unexpected server response: 404/,
    );
    const streamError = await fetch(`${origin}/sshdeck/api/exec`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ alias: 'mounted-ws', command: 'true' }),
    });
    assert.equal(streamError.status, 400);
    assert.equal((await streamError.json()).error.includes('金鑰'), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('basePath 設定拒絕相對路徑、traversal 與編碼分隔符', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-base-path-invalid-'));
  try {
    for (const basePath of ['sshdeck', '/sshdeck/../admin', '/sshdeck/%2fadmin', '/sshdeck\\admin', '//sshdeck']) {
      await assert.rejects(startUi({
        port: 0,
        basePath,
        dataFile: path.join(directory, 'hosts.json'),
        openBrowser: async () => {},
        log: () => {},
      }), /SSHDECK_BASE_PATH/);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
