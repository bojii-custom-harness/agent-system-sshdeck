'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');

const productRoot = path.resolve(__dirname, '..', '..');
const cliPath = path.join(productRoot, 'bin', 'sshdeck.js');

function createServiceEnv(home) {
  return {
    SSHDECK_SERVICE_HOME: home,
    SSHDECK_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    SSHDECK_SERVICE_TOKEN: randomBytes(36).toString('base64url'),
    SSHDECK_UI_TOKEN: randomBytes(36).toString('base64url'),
    SSHDECK_TUNNEL_TOKEN: randomBytes(36).toString('base64url'),
  };
}

async function api(server, route, {
  method = 'GET',
  body,
  token,
} = {}) {
  const selectedToken = token || process.env.SSHDECK_TEST_API_TOKEN;
  const response = await fetch(`${server.url}${route}`, {
    method,
    headers: {
      ...(selectedToken ? { authorization: `Bearer ${selectedToken}` } : {}),
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = text; }
  }
  return { status: response.status, headers: response.headers, payload, text };
}

function spawnCli(args, {
  env = {},
  deadlineMs = 15_000,
  stdin = 'ignore',
} = {}) {
  const child = spawn(process.execPath, [cliPath, ...args], {
    cwd: productRoot,
    env: { ...process.env, ...env },
    stdio: [stdin, 'pipe', 'pipe'],
    windowsHide: true,
  });
  const output = { stdout: '', stderr: '' };
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { output.stdout += chunk; });
  child.stderr.on('data', (chunk) => { output.stderr += chunk; });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    if (process.platform === 'win32' && child.pid) {
      spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
        encoding: 'utf8', windowsHide: true, timeout: 5000,
      });
    } else child.kill('SIGKILL');
  }, deadlineMs);
  const closed = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, timedOut, ...output });
    });
  });
  return { child, output, closed };
}

function waitForOutput(running, stream, marker, timeoutMs = 10_000, description = marker) {
  const target = running.output[stream];
  if (target.includes(marker)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const source = stream === 'stdout' ? running.child.stdout : running.child.stderr;
    const onData = () => {
      if (running.output[stream].includes(marker)) finish();
    };
    const onClose = () => finish(new Error(`CLI 在預期輸出前結束：${description} (${stream})`));
    const timer = setTimeout(() => finish(new Error(
      `等待 CLI 輸出逾時：${description} (${stream})；既有輸出：${running.output[stream]}`,
    )), timeoutMs);
    const finish = (error) => {
      clearTimeout(timer);
      source.off('data', onData);
      running.child.off('close', onClose);
      if (error) reject(error);
      else resolve();
    };
    source.on('data', onData);
    running.child.once('close', onClose);
    if (running.output[stream].includes(marker)) finish();
  });
}

function forceKillCli(child) {
  if (process.platform === 'win32') {
    return spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
      encoding: 'utf8', windowsHide: true, timeout: 5000,
    });
  }
  child.kill('SIGKILL');
  return { status: 0 };
}

function makeTaskTemp(prefix = 'sshdeck-ticket01-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

module.exports = {
  productRoot,
  cliPath,
  createServiceEnv,
  api,
  spawnCli,
  waitForOutput,
  forceKillCli,
  makeTaskTemp,
};
