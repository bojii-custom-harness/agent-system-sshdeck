'use strict';

const { fork, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const path = require('node:path');

const workerPath = path.join(__dirname, '../../scripts/service-process-worker.js');

function terminate(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === 'win32') {
    spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 5000,
    });
  } else {
    child.kill('SIGKILL');
  }
}

function startServiceProcess({
  env,
  host = '127.0.0.1',
  port = 0,
  startupTimeoutMs = 10_000,
  requestTimeoutMs = 5_000,
} = {}) {
  const child = fork(workerPath, [], {
    cwd: path.resolve(__dirname, '../..'),
    env: {
      ...process.env,
      ...env,
      SSHDECK_TEST_SERVICE_CHILD_HOST: host,
      SSHDECK_TEST_SERVICE_CHILD_PORT: String(port),
    },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    windowsHide: true,
  });
  child.stderr.setEncoding('utf8');
  let stderr = '';
  child.stderr.on('data', (chunk) => {
    if (stderr.length < 8192) stderr += chunk.slice(0, 8192 - stderr.length);
  });

  let exitState;
  let readyResolve;
  let readyReject;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const pending = new Map();
  const exited = new Promise((resolve) => {
    child.once('close', (code, signal) => {
      exitState = { code, signal };
      readyReject(new Error(`service 子程序在就緒前結束，exit=${code ?? 'null'}`));
      for (const request of pending.values()) {
        clearTimeout(request.timer);
        request.reject(new Error(`service 子程序已結束，exit=${code ?? 'null'}`));
      }
      pending.clear();
      resolve(exitState);
    });
  });

  child.on('error', (error) => readyReject(error));
  child.on('message', (message) => {
    if (message?.type === 'ready') {
      readyResolve(message);
      return;
    }
    if (message?.type === 'startup-error') {
      readyReject(new Error(`service 子程序啟動失敗：${message.code}`));
      return;
    }
    const request = pending.get(message?.requestId);
    if (request) {
      clearTimeout(request.timer);
      pending.delete(message.requestId);
      request.resolve(message);
    }
  });

  const request = (type, timeoutMs = requestTimeoutMs) => {
    if (exitState || !child.connected) {
      return Promise.reject(new Error('service 子程序已停止'));
    }
    const requestId = randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(requestId);
        reject(new Error(`service 子程序 ${type} 要求逾時`));
      }, timeoutMs);
      pending.set(requestId, { resolve, reject, timer });
      child.send({ requestId, type }, (error) => {
        if (!error) return;
        clearTimeout(timer);
        pending.delete(requestId);
        reject(error);
      });
    });
  };

  const waitForExit = async (timeoutMs) => {
    if (exitState) return exitState;
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      exited.then((result) => {
        clearTimeout(timer);
        resolve(result);
      });
    });
  };

  const start = async () => {
    let timer;
    try {
      const startup = await Promise.race([
        ready,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('service 子程序啟動逾時')), startupTimeoutMs);
        }),
      ]);
      clearTimeout(timer);
      return startup;
    } catch (error) {
      clearTimeout(timer);
      terminate(child);
      await waitForExit(5000);
      throw error;
    }
  };

  return start().then(({ port: actualPort }) => ({
    url: `http://${host.includes(':') ? `[${host}]` : host}:${actualPort}`,
    address: () => ({ port: actualPort }),
    getActiveTerminalCount: async () => {
      const response = await request('stats');
      return response.activeTerminalCount;
    },
    closeAsync: async () => {
      if (exitState) {
        return {
          exitCode: exitState.code,
          signal: exitState.signal,
          activeTerminalCount: null,
          stderr,
        };
      }
      try {
        const response = await request('close', 10_000);
        const result = await waitForExit(10_000);
        if (!result) {
          terminate(child);
          await waitForExit(5000);
        }
        return {
          exitCode: exitState?.code ?? null,
          signal: exitState?.signal ?? null,
          activeTerminalCount: response.activeTerminalCount,
          forced: !result,
          stderr,
        };
      } catch {
        if (!exitState) {
          terminate(child);
          await waitForExit(5000);
        }
        return {
          exitCode: exitState?.code ?? null,
          signal: exitState?.signal ?? null,
          activeTerminalCount: null,
          forced: true,
          stderr,
        };
      }
    },
  }));
}

module.exports = { startServiceProcess };
