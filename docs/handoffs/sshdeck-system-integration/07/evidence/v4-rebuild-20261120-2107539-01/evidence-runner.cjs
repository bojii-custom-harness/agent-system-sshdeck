'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

function write(fd, chunk) {
  let offset = 0;
  while (offset < chunk.length) {
    offset += fs.writeSync(fd, chunk, offset, chunk.length - offset);
  }
}

function main() {
  const configPath = process.argv[2];
  if (!configPath) throw new Error('用法：node evidence-runner.cjs <config.json>');

  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  for (const key of ['runId', 'command', 'args', 'cwd', 'timeoutMs', 'stdoutPath', 'stderrPath', 'metadataPath']) {
    if (config[key] === undefined) throw new Error(`缺少必要設定：${key}`);
  }
  if (!Array.isArray(config.args) || !Number.isInteger(config.timeoutMs) || config.timeoutMs < 5000) {
    throw new Error('args 或 timeoutMs 設定無效');
  }

  const stdoutPath = path.resolve(config.stdoutPath);
  const stderrPath = path.resolve(config.stderrPath);
  const metadataPath = path.resolve(config.metadataPath);
  const stdoutFd = fs.openSync(stdoutPath, 'wx');
  let stderrFd;
  try {
    stderrFd = fs.openSync(stderrPath, 'wx');
  } catch (error) {
    fs.closeSync(stdoutFd);
    throw error;
  }

  const cleanupReserveMs = Math.min(config.cleanupReserveMs ?? 10_000, Math.floor(config.timeoutMs / 2));
  const commandDeadlineMs = config.timeoutMs - cleanupReserveMs;
  const startedAt = new Date();
  let timedOut = false;
  let treeKill = null;
  let spawnError = null;
  let finalized = false;
  const child = spawn(config.command, config.args, {
    cwd: config.cwd,
    env: { ...process.env, ...(config.env || {}) },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: config.shell === true,
  });

  child.stdout.on('data', (chunk) => write(stdoutFd, chunk));
  child.stderr.on('data', (chunk) => write(stderrFd, chunk));
  child.on('error', (error) => {
    spawnError = { name: error.name, code: error.code, message: error.message };
  });

  const timer = setTimeout(() => {
    timedOut = true;
    if (process.platform === 'win32' && child.pid) {
      const result = spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
        encoding: null,
        timeout: cleanupReserveMs,
        windowsHide: true,
      });
      treeKill = {
        command: 'taskkill.exe',
        pid: child.pid,
        status: result.status,
        signal: result.signal,
        error: result.error ? { code: result.error.code, message: result.error.message } : null,
        stdoutBase64: result.stdout ? result.stdout.toString('base64') : '',
        stderrBase64: result.stderr ? result.stderr.toString('base64') : '',
      };
    } else if (child.pid) {
      try {
        process.kill(-child.pid, 'SIGTERM');
        treeKill = { signal: 'SIGTERM', pid: child.pid };
      } catch (error) {
        treeKill = { pid: child.pid, error: { code: error.code, message: error.message } };
      }
      child.kill('SIGTERM');
    }
  }, commandDeadlineMs);

  child.once('close', (exitCode, signal) => {
    if (finalized) return;
    finalized = true;
    clearTimeout(timer);
    fs.closeSync(stdoutFd);
    fs.closeSync(stderrFd);
    const finishedAt = new Date();
    const metadata = {
      runId: config.runId,
      command: config.command,
      args: config.args,
      cwd: config.cwd,
      nodeVersion: process.version,
      timeoutMs: config.timeoutMs,
      commandDeadlineMs,
      cleanupReserveMs,
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      elapsedMs: finishedAt.getTime() - startedAt.getTime(),
      timedOut,
      exitCode,
      signal,
      spawnError,
      processId: child.pid ?? null,
      treeKill,
      stdout: path.basename(stdoutPath),
      stderr: path.basename(stderrPath),
    };
    fs.writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
    process.stdout.write(`${JSON.stringify(metadata)}\n`);
    if (timedOut) process.exitCode = 124;
    else if (spawnError) process.exitCode = 1;
    else process.exitCode = exitCode ?? 1;
  });
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exitCode = 1;
}
