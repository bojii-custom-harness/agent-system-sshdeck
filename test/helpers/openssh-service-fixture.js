'use strict';

const fs = require('node:fs');
const net = require('node:net');
const { randomUUID } = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

const ports = [2227, 2228];

// Windows host 直連 WSL 私有 eth0，避免 localhost relay 在大量雙向 SSH 資料時停滯。
function getPrivateWslHostAddress() {
  const addresses = runWsl(['ip', '-4', '-o', 'addr', 'show', 'dev', 'eth0', 'scope', 'global']);
  const host = addresses.match(/\binet\s+([0-9.]+)\/\d+\b/)?.[1];
  if (!host || !net.isIPv4(host)) {
    throw new Error('WSL fixture 無法取得 eth0 私有 IPv4 位址');
  }
  const [first, second] = host.split('.').map(Number);
  const isPrivate = first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
  if (!isPrivate) throw new Error('WSL fixture eth0 位址不在 RFC1918 私有範圍');
  return host;
}

function runWsl(args, { input, timeoutMs = 20_000 } = {}) {
  const result = runWslResult(args, { input, timeoutMs });
  if (result.error || result.status !== 0) {
    const reason = result.error?.message || (result.stderr || '').trim().slice(0, 400) || `exit ${result.status}`;
    throw new Error(`WSL fixture 操作失敗：${reason}`);
  }
  return (result.stdout || '').trim();
}

function runWslResult(args, { input, timeoutMs = 20_000 } = {}) {
  return spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', ...args], {
    input,
    encoding: 'utf8',
    windowsHide: true,
    timeout: timeoutMs,
  });
}

async function startWslSession({
  spawnProcess = spawn,
  startupTimeoutMs = 5000,
  closeTimeoutMs = 5000,
  forcedCloseTimeoutMs = 5000,
} = {}) {
  const readyMarker = `sshdeck-wsl-fixture-session-${randomUUID()}`;
  const child = spawnProcess('wsl.exe', [
    '-d',
    'Ubuntu',
    '--',
    'bash',
    '-lc',
    `exec timeout --signal=TERM --kill-after=2s 170s sh -c 'printf "%s\\n" "${readyMarker}"; exec cat >/dev/null'`,
  ], {
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  let ready = false;
  let startupSettled = false;
  let startupCheckPending = false;
  let stopRequested = false;
  let closeResult;
  let resolveClose;
  let resolveSession;
  let rejectSession;
  let startupTimer;
  const closed = new Promise((resolve) => { resolveClose = resolve; });
  const waitForClose = (timeoutMs) => {
    let timer;
    return Promise.race([
      closed,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(null), timeoutMs);
      }),
    ]).finally(() => clearTimeout(timer));
  };
  const terminateAfterStartupFailure = async () => {
    const errors = [];
    if (!child.stdin.writableEnded) {
      try { child.stdin.end(); } catch (error) { errors.push(error); }
    }

    let result = closeResult;
    if (!result && child.exitCode === null && child.signalCode === null) {
      try { child.kill('SIGTERM'); } catch (error) { errors.push(error); }
    }
    if (!result) result = await waitForClose(closeTimeoutMs);
    if (!result) {
      errors.push(new Error(`WSL fixture child 在 SIGTERM 後 ${closeTimeoutMs}ms 內未 close`));
      if (!closeResult && child.exitCode === null && child.signalCode === null) {
        try { child.kill('SIGKILL'); } catch (error) { errors.push(error); }
      }
      result = closeResult || await waitForClose(forcedCloseTimeoutMs);
      if (!result) errors.push(new Error(`WSL fixture child 在 SIGKILL 後 ${forcedCloseTimeoutMs}ms 內仍未 close`));
    }
    return { result, errors };
  };
  const sessionReady = new Promise((resolve, reject) => {
    resolveSession = resolve;
    rejectSession = reject;
  });
  const settleStartup = (error) => {
    if (startupSettled) return;
    startupSettled = true;
    clearTimeout(startupTimer);
    if (error) rejectSession(error);
    else {
      ready = true;
      resolveSession();
    }
  };
  const startupFailure = (reason) => {
    settleStartup(new Error(`WSL fixture session 未能啟動：${reason}`));
  };
  child.stdout.setEncoding('utf8').on('data', (chunk) => {
    stdout = `${stdout}${chunk}`.slice(-1024);
    if (!ready && !startupSettled && !startupCheckPending && stdout.includes(readyMarker)) {
      startupCheckPending = true;
      setImmediate(() => {
        startupCheckPending = false;
        if (startupSettled) return;
        if (closeResult || child.exitCode !== null || child.signalCode !== null) {
          const exit = closeResult?.code ?? closeResult?.signal ?? child.exitCode ?? child.signalCode;
          startupFailure(stderr.trim().slice(-300) || `退出碼 ${exit}`);
          return;
        }
        settleStartup();
      });
    }
  });
  child.stderr.setEncoding('utf8').on('data', (chunk) => {
    stderr = `${stderr}${chunk}`.slice(-1024);
  });
  child.stdin.on('error', () => {});
  child.once('close', (code, signal) => {
    closeResult = { code, signal };
    resolveClose(closeResult);
    if (!ready && !startupSettled) {
      startupFailure(stderr.trim().slice(-300) || `退出碼 ${code ?? signal}`);
    }
  });
  child.once('error', (error) => {
    if (!ready && !startupSettled) {
      startupFailure(`程序錯誤 ${error.code || error.name}`);
    }
  });
  startupTimer = setTimeout(() => {
    settleStartup(new Error(
      `WSL fixture session 未在期限內就緒：${stderr.trim().slice(-300) || 'ready marker missing'}`,
    ));
  }, startupTimeoutMs);

  try {
    await sessionReady;
  } catch (error) {
    const termination = await terminateAfterStartupFailure();
    if (termination.errors.length) {
      const failure = new AggregateError(
        [error, ...termination.errors],
        `WSL fixture startup failure: ${error.message}`,
        { cause: error },
      );
      if (!termination.result) {
        failure.child = child;
        failure.cleanup = async () => {
          const retry = await terminateAfterStartupFailure();
          if (!retry.result) {
            throw new AggregateError(
              retry.errors,
              'WSL fixture child 在續清理後仍未 close',
              { cause: retry.errors[0] },
            );
          }
          return retry.result;
        };
      }
      throw failure;
    }
    throw error;
  }
  return {
    get isRunning() {
      return ready && !closeResult && child.exitCode === null && child.signalCode === null;
    },
    async stop() {
      if (closeResult) {
        if (!stopRequested || closeResult.code !== 0) {
          throw new Error(`WSL fixture session 提前結束：退出碼 ${closeResult.code ?? closeResult.signal}`);
        }
        return closeResult;
      }
      stopRequested = true;
      child.stdin.end();
      const result = await waitForClose(5000);
      if (!result) {
        child.kill();
        const forcedResult = await waitForClose(5000);
        if (!forcedResult) throw new Error('WSL fixture session 未能在期限內結束');
        throw new Error('WSL fixture session 未能正常結束；已終止其專屬 wsl.exe process');
      }
      if (result.code !== 0) {
        throw new Error(`WSL fixture session 結束碼非零：${result.code}`);
      }
      return result;
    },
  };
}

async function waitForUnit(unit, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = runWslResult(['systemctl', 'is-active', unit], { timeoutMs: 5000 });
    if (result.status === 0 && (result.stdout || '').trim() === 'active') return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`OpenSSH transient unit 未在期限內啟動：${unit}`);
}

async function stopUnitAndWait(unit) {
  const active = runWslResult(['systemctl', 'is-active', unit], { timeoutMs: 5000 });
  if (active.status === 0 && (active.stdout || '').trim() === 'active') runWsl(['systemctl', 'stop', unit]);
  const deadline = Date.now() + 10_000;
  let loadState = '';
  while (Date.now() < deadline) {
    const result = runWslResult(['systemctl', 'show', '--property=LoadState', '--value', unit], { timeoutMs: 5000 });
    loadState = (result.stdout || '').trim();
    if (loadState === 'not-found') return loadState;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`OpenSSH transient unit 未卸載：${unit} ${loadState}`);
}

async function unitIsStopped(unit, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = runWslResult(['systemctl', 'show', '--property=LoadState', '--value', unit], {
      timeoutMs: 5000,
    });
    if (result.error || result.status !== 0) {
      const reason = result.error?.message || (result.stderr || '').trim().slice(0, 300) || `exit ${result.status}`;
      throw new Error(`無法確認 OpenSSH transient unit 狀態：${unit} ${reason}`);
    }
    if ((result.stdout || '').trim() === 'not-found') return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return false;
}

async function stopUnitsBestEffort(units, stopAndWaitForUnit, confirmUnitStopped) {
  const attempts = [];
  const stopped = [];
  const errors = [];
  const unresolvedUnits = [];
  for (const unit of [...units].reverse()) {
    try {
      const loadState = await stopAndWaitForUnit(unit);
      if (loadState !== 'not-found') {
        throw new Error(`未確認 OpenSSH transient unit state：${unit} ${String(loadState)}`);
      }
      const attempt = { unit, stopped: true, loadState };
      attempts.push(attempt);
      stopped.push({ unit, loadState });
    } catch (stopError) {
      errors.push({ phase: 'stop-unit', unit, error: stopError });
      let confirmedStopped = false;
      try {
        confirmedStopped = await confirmUnitStopped(unit);
      } catch (verificationError) {
        errors.push({ phase: 'verify-unit-stopped', unit, error: verificationError });
      }
      attempts.push({
        unit,
        stopped: confirmedStopped,
        stopError: stopError.message,
        ...(confirmedStopped ? { loadState: 'not-found', verifiedAfterStopError: true } : {}),
      });
      if (confirmedStopped) {
        stopped.push({ unit, loadState: 'not-found', recoveredAfterStopError: true });
      } else {
        unresolvedUnits.push(unit);
      }
    }
  }
  return {
    attempts,
    stopped,
    errors,
    unresolvedUnits,
    allStopped: unresolvedUnits.length === 0,
  };
}

function combineCleanupErrors(errors, message) {
  if (errors.length === 0) return undefined;
  if (errors.length === 1) return errors[0];
  return new AggregateError(errors, message, { cause: errors[0] });
}

function portAvailable(port, {
  platform = process.platform,
  spawnSyncProcess = spawnSync,
  runWslCommand = runWsl,
} = {}) {
  if (platform === 'win32') {
    let powershell;
    try {
      powershell = spawnSyncProcess('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        [
          "$ErrorActionPreference = 'Stop'",
          'try {',
          `$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq ${port} })`,
          "if ($listeners.Count -gt 0) { [Console]::Out.WriteLine('occupied') } else { [Console]::Out.WriteLine('free') }",
          '} catch {',
          '[Console]::Error.WriteLine($_.Exception.GetType().Name)',
          'exit 2',
          '}',
        ].join('; '),
      ], { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    } catch (error) {
      return Promise.resolve({ state: 'unknown', error });
    }
    if (powershell.error) {
      return Promise.resolve({ state: 'unknown', error: powershell.error });
    }
    if (powershell.status !== 0) {
      const stderr = (powershell.stderr || '').trim().slice(0, 300);
      return Promise.resolve({
        state: 'unknown',
        error: new Error(`Windows port probe exited with status ${powershell.status}${stderr ? `: ${stderr}` : ''}`),
      });
    }
    const hostState = (powershell.stdout || '').trim();
    if (hostState === 'occupied') {
      return Promise.resolve({ state: 'occupied', source: 'windows-host' });
    }
    if (hostState !== 'free') {
      return Promise.resolve({
        state: 'unknown',
        error: new Error(`Windows port probe returned unexpected output: ${hostState || '<empty>'}`),
      });
    }
    try {
      const wslListeners = runWslCommand(['ss', '-ltn']);
      if (wslListeners.split(/\r?\n/).some((line) => line.includes(`:${port} `))) {
        return Promise.resolve({ state: 'occupied', source: 'wsl' });
      }
      return Promise.resolve({ state: 'free', source: 'windows-and-wsl' });
    } catch (error) {
      return Promise.resolve({ state: 'unknown', error });
    }
  }
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', (error) => {
      resolve(error.code === 'EADDRINUSE'
        ? { state: 'occupied', source: 'loopback' }
        : { state: 'unknown', error });
    });
    server.listen(port, '127.0.0.1', () => {
      server.close((error) => resolve(error
        ? { state: 'unknown', error }
        : { state: 'free', source: 'loopback' }));
    });
  });
}

async function waitForPortAvailability(port, checkPortAvailable, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  const checks = [];
  while (true) {
    let probe;
    try {
      probe = normalizePortProbeResult(await checkPortAvailable(port), port);
    } catch (error) {
      probe = { state: 'unknown', error };
    }
    const free = probe.state === 'free' ? true : probe.state === 'occupied' ? false : null;
    checks.push({
      state: probe.state,
      free,
      ...(probe.source ? { source: probe.source } : {}),
      ...(probe.error ? { error: probe.error.message } : {}),
    });
    if (probe.state !== 'occupied' || Date.now() >= deadline) {
      return { state: probe.state, free, checks, ...(probe.error ? { error: probe.error } : {}) };
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

function normalizePortProbeResult(result, port) {
  if (result && ['free', 'occupied', 'unknown'].includes(result.state)) {
    if (result.state !== 'unknown') return result;
    return {
      ...result,
      error: result.error instanceof Error
        ? result.error
        : new Error(`Port ${port} probe state is unknown`),
    };
  }
  return {
    state: 'unknown',
    error: new Error(`Port ${port} probe returned an invalid result`),
  };
}

async function waitForPort(port, host = '127.0.0.1', timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.createConnection({ host, port });
        socket.once('connect', () => { socket.destroy(); resolve(); });
        socket.once('error', reject);
      });
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`OpenSSH fixture port ${port} 未在期限內就緒`);
}

async function waitForTargetPort(file, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = runWslResult(['cat', file], { timeoutMs: 5000 });
    const port = Number((result.stdout || '').trim());
    if (result.status === 0 && Number.isInteger(port) && port > 0 && port <= 65535) return port;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('direct-tcpip echo target 未在期限內就緒');
}

function targetPortListening(port) {
  if (!port) return false;
  return runWsl(['ss', '-ltn']).split(/\r?\n/)
    .some((line) => new RegExp(`:${port}(?:\\s|$)`).test(line));
}

function establishedConnections(host, port, runWslCommand = runWsl) {
  if (typeof host !== 'string' || net.isIP(host) === 0) {
    throw new Error('OpenSSH fixture connection probe host 必須是 IP 位址');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('OpenSSH fixture connection probe port 無效');
  }
  const address = net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
  return runWslCommand(['ss', '-H', '-tn', 'state', 'established', 'dst', '=', address])
    .split(/\r?\n/).filter(Boolean);
}

function fingerprintFor(path) {
  const output = runWsl(['ssh-keygen', '-lf', `${path}.pub`, '-E', 'sha256']);
  const fingerprint = output.match(/SHA256:[^\s]+/)?.[0];
  if (!fingerprint) throw new Error('無法讀取 OpenSSH fixture host fingerprint');
  return fingerprint;
}

async function createOpenSshServiceFixture({
  authorizedPublicKey,
  evidenceFile,
  enablePty = false,
  allowDirectTcpip = false,
  permitOpenTargets = [],
} = {}, dependencies = {}) {
  const {
    getPrivateWslHostAddress: resolveWslHostAddress = getPrivateWslHostAddress,
    portAvailable: checkPortAvailable = portAvailable,
    startWslSession: openWslSession = startWslSession,
    runWsl: runWslCommand = runWsl,
    waitForUnit: waitUntilUnit = waitForUnit,
    waitForPort: waitUntilPort = waitForPort,
    waitForTargetPort: waitUntilTargetPort = waitForTargetPort,
    stopUnitAndWait: stopAndWaitForUnit = stopUnitAndWait,
    unitIsStopped: confirmUnitStopped = unitIsStopped,
    targetPortListening: isTargetPortListening = targetPortListening,
    establishedConnections: listEstablishedConnections = (host, port) => (
      establishedConnections(host, port, runWslCommand)
    ),
    fingerprintFor: getFingerprint = fingerprintFor,
    portReleaseTimeoutMs = 5000,
  } = dependencies;
  if (!Array.isArray(permitOpenTargets)) {
    throw new Error('fixture PermitOpen 額外目標必須是陣列');
  }
  if (permitOpenTargets.length > 0 && !allowDirectTcpip) {
    throw new Error('fixture PermitOpen 額外目標需要啟用 direct-tcpip');
  }
  const validatedPermitOpenTargets = permitOpenTargets.map((target) => {
    if (!target || typeof target !== 'object' || Array.isArray(target)) {
      throw new Error('fixture PermitOpen 目標必須包含 IP 與 TCP port');
    }
    const keys = Object.keys(target).sort();
    if (keys.length !== 2 || keys[0] !== 'host' || keys[1] !== 'port') {
      throw new Error('fixture PermitOpen 目標只接受 host 與 port');
    }
    if (typeof target.host !== 'string' || net.isIP(target.host) === 0) {
      throw new Error('fixture PermitOpen 目標 host 必須是 IP 位址');
    }
    if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
      throw new Error('fixture PermitOpen 目標 port 必須是有效 TCP port');
    }
    const host = net.isIPv6(target.host) ? `[${target.host}]` : target.host;
    return `${host}:${target.port}`;
  });
  if (typeof authorizedPublicKey !== 'string' || !authorizedPublicKey.startsWith('ssh-ed25519 ')) {
    throw new Error('fixture 需要隔離測試用 Ed25519 公鑰');
  }
  const sshHost = resolveWslHostAddress();
  for (const port of ports) {
    let probe;
    try {
      probe = normalizePortProbeResult(await checkPortAvailable(port), port);
    } catch (error) {
      probe = { state: 'unknown', error };
    }
    if (probe.state === 'occupied') {
      throw new Error(`OpenSSH fixture port ${port} 已被占用；未停止任何既有程序`);
    }
    if (probe.state === 'unknown') {
      throw new Error(
        `無法確認 OpenSSH fixture port ${port} 狀態：${probe.error.message}`,
        { cause: probe.error },
      );
    }
  }

  const runId = randomUUID();
  let root;
  let wslSession;
  try {
    wslSession = await openWslSession();
    root = runWslCommand(['mktemp', '-d', `/tmp/sshdeck-ticket01-${runId}-XXXXXX`]);
    if (!/^\/tmp\/sshdeck-ticket01-[0-9a-f-]{36}-[A-Za-z0-9]{6}$/.test(root)) {
      throw new Error('WSL fixture 目錄格式不符；拒絕執行清理命令');
    }
  } catch (error) {
    const cleanupErrors = [];
    if (wslSession) {
      try {
        await wslSession.stop();
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    } else if (typeof error.cleanup === 'function') {
      try {
        await error.cleanup();
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    const failure = combineCleanupErrors(
      [error, ...cleanupErrors],
      'OpenSSH fixture startup 與 WSL session cleanup 均有錯誤',
    );
    if (error.child) failure.child = error.child;
    if (typeof error.cleanup === 'function') failure.cleanup = error.cleanup;
    throw failure;
  }
  const units = [
    `sshdeck-ticket01-${runId}-a.service`,
    `sshdeck-ticket01-${runId}-b.service`,
  ];
  const targetUnit = `sshdeck-ticket01-${runId}-echo.service`;
  const unitsToClean = new Set();
  let targetPort;
  const authorizedKeyOptions = [
    'no-agent-forwarding',
    ...(allowDirectTcpip ? [] : ['no-port-forwarding']),
    ...(enablePty ? [] : ['no-pty']),
  ].join(',');
  const authorizedTestKey = `${authorizedKeyOptions} ${authorizedPublicKey}`;
  const fixtureCommands = {
    'target-a': "printf 'target-a\\n'",
    'target-b': "printf 'target-b\\n'",
    'combined-a': "printf 'A-stdout\\n'; printf 'A-stderr\\n' >&2; exit 7",
    'combined-b': "printf 'B-stdout\\n'; printf 'B-stderr\\n' >&2; exit 9",
    'counted-a': `printf 'x\\n' >> '${root}/a-count'; printf 'started-a\\n'; sleep 20; printf 'finished-a\\n'`,
    'counted-b': `printf 'x\\n' >> '${root}/b-count'; printf 'started-b\\n'; sleep 20; printf 'finished-b\\n'`,
    'slow-b': "printf 'started-b\\n'; sleep 2; printf 'finished-b\\n'",
    'count-a': `[ -f '${root}/a-count' ] && cat '${root}/a-count' || printf '0\\n'`,
    'count-b': `[ -f '${root}/b-count' ] && cat '${root}/b-count' || printf '0\\n'`,
  };
  const sshdConfig = (endpoint, port) => `Port ${port}
ListenAddress 127.0.0.1
ListenAddress ${sshHost}
HostKey ${root}/host-${endpoint}
PidFile ${root}/sshd-${endpoint}.pid
AuthorizedKeysFile ${root}/authorized_keys
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
AllowUsers root
AllowTcpForwarding ${allowDirectTcpip ? 'local' : 'no'}
${allowDirectTcpip
    ? `PermitOpen ${[`127.0.0.1:${targetPort}`, ...validatedPermitOpenTargets].join(' ')}`
    : ''}
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY ${enablePty ? 'yes' : 'no'}
LogLevel ERROR
`;
  const createSshdConfigScript = () => [
    'set -eu',
    `ssh-keygen -q -t ed25519 -N '' -f '${root}/host-a'`,
    `ssh-keygen -q -t ed25519 -N '' -f '${root}/host-b'`,
    `ssh-keygen -q -t ed25519 -N '' -f '${root}/host-b-next'`,
    `cat > '${root}/sshd-a.conf' <<'FIXTURE_CONFIG_A'`,
    sshdConfig('a', ports[0]),
    'FIXTURE_CONFIG_A',
    `cat > '${root}/sshd-b.conf' <<'FIXTURE_CONFIG_B'`,
    sshdConfig('b', ports[1]),
    'FIXTURE_CONFIG_B',
    `/usr/sbin/sshd -t -f '${root}/sshd-a.conf'`,
    `/usr/sbin/sshd -t -f '${root}/sshd-b.conf'`,
  ].join('\n');

  try {
    runWslCommand(['bash', '-lc', `cat > '${root}/authorized_keys'`], { input: `${authorizedTestKey}\n` });
    if (allowDirectTcpip) {
      const echoScript = `import pathlib
import socketserver
import sys

class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)

server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
server.daemon_threads = True
server.allow_reuse_address = False
pathlib.Path(sys.argv[1]).write_text(str(server.server_address[1]), encoding="ascii")
server.serve_forever(poll_interval=0.1)
`;
      runWslCommand(['bash', '-lc', `cat > '${root}/echo.py' <<'FIXTURE_ECHO'\n${echoScript}FIXTURE_ECHO`]);
      // WSL wrapper 可能在遠端 unit 已啟動後才回報失敗，先記下唯一 unit ID。
      unitsToClean.add(targetUnit);
      runWslCommand(['systemd-run', '--collect', `--unit=${targetUnit}`, '--property=RuntimeMaxSec=900',
        'python3', '-u', `${root}/echo.py`, `${root}/target-port`]);
      targetPort = await waitUntilTargetPort(`${root}/target-port`);
    }
    runWslCommand(['bash', '-lc', createSshdConfigScript()]);
    for (const [index, endpoint] of ['a', 'b'].entries()) {
      const unit = units[index];
      // 同上：systemd-run 的遠端副作用可能先於本機 wrapper 的失敗結果。
      unitsToClean.add(unit);
      runWslCommand(['systemd-run', '--collect', `--unit=${unit}`, '--property=RuntimeMaxSec=900',
        '/usr/sbin/sshd', '-D', '-e', '-f', `${root}/sshd-${endpoint}.conf`]);
      await waitUntilUnit(unit);
      await waitUntilPort(ports[index]);
      await waitUntilPort(ports[index], sshHost);
    }
    const fingerprints = {
      a: getFingerprint(`${root}/host-a`),
      b: getFingerprint(`${root}/host-b`),
    };
    if (fingerprints.a === fingerprints.b) throw new Error('兩個 SSH fixture 必須使用不同 host key');

    let cleaned = false;
    async function rotateB() {
      runWslCommand(['cp', `${root}/host-b-next`, `${root}/host-b`]);
      runWslCommand(['cp', `${root}/host-b-next.pub`, `${root}/host-b.pub`]);
      runWslCommand(['chmod', '600', `${root}/host-b`]);
      runWslCommand(['systemctl', 'restart', units[1]]);
      await waitUntilPort(ports[1]);
      await waitUntilPort(ports[1], sshHost);
      fingerprints.rotatedB = getFingerprint(`${root}/host-b`);
      if (fingerprints.rotatedB === fingerprints.b) throw new Error('host key rotation 未產生新指紋');
      return fingerprints.rotatedB;
    }

    function readCounter(target) {
      if (!['a', 'b'].includes(target)) throw new Error(`不支援的 OpenSSH fixture counter：${target}`);
      const file = `${root}/${target}-count`;
      return runWslCommand(['bash', '-lc', `if [ -f '${file}' ]; then cat '${file}'; else printf '0\\n'; fi`]);
    }

    function isListening(port) {
      if (!ports.includes(port)) throw new Error(`不支援的 OpenSSH fixture port：${port}`);
      return runWslCommand(['ss', '-ltn']).split(/\r?\n/).some((line) => line.includes(`:${port} `));
    }

    async function cleanup() {
      if (cleaned) return;
      const cleanupErrors = [];
      const cleanupErrorDetails = [];
      const addCleanupError = (phase, resource, error) => {
        cleanupErrors.push(error);
        cleanupErrorDetails.push({ phase, resource, error: error.message });
      };
      let unitCleanup;
      const portStates = [];
      let targetPortFree;
      let wslSessionActiveBeforeStop;
      let wslSessionClose;
      const residualResources = [];
      const rootState = { path: root, removed: false, blockedBy: [] };
      try {
        unitCleanup = await stopUnitsBestEffort(
          [...unitsToClean],
          stopAndWaitForUnit,
          confirmUnitStopped,
        );
        for (const item of unitCleanup.errors) {
          addCleanupError(item.phase, item.unit, item.error);
        }

        for (const port of ports) {
          try {
            const availability = await waitForPortAvailability(
              port,
              checkPortAvailable,
              portReleaseTimeoutMs,
            );
            portStates.push({
              port,
              state: availability.state,
              free: availability.free,
              checks: availability.checks,
              ...(availability.error ? { error: availability.error.message } : {}),
            });
            if (availability.error) addCleanupError('check-ssh-port', String(port), availability.error);
          } catch (error) {
            portStates.push({ port, state: 'unknown', free: null, error: error.message });
            addCleanupError('check-ssh-port', String(port), error);
          }
        }
        if (portStates.some((item) => item.free === false)) {
          const occupiedPorts = portStates.filter((item) => item.free === false).map((item) => item.port);
          addCleanupError(
            'verify-ssh-ports',
            occupiedPorts.join(','),
            new Error(`清理後 OpenSSH fixture port 仍被占用：${occupiedPorts.join(', ')}`),
          );
          for (const port of occupiedPorts) {
            residualResources.push({
              type: 'listener',
              host: 'OpenSSH fixture',
              port,
              state: 'listening',
              reason: '確認等待後 fixture SSH port 仍被占用',
            });
          }
        }
        for (const item of portStates.filter((portState) => portState.free === null)) {
          residualResources.push({
            type: 'listener',
            host: 'OpenSSH fixture',
            port: item.port,
            state: 'unknown',
            reason: `無法確認 SSH port 狀態：${item.error || 'port probe failed'}`,
          });
        }

        if (targetPort) {
          try {
            targetPortFree = !isTargetPortListening(targetPort);
            if (!targetPortFree) {
              addCleanupError(
                'verify-target-port',
                String(targetPort),
                new Error(`清理後 direct-tcpip target port 仍被占用：${targetPort}`),
              );
              residualResources.push({
                type: 'listener',
                host: '127.0.0.1',
                port: targetPort,
                state: 'listening',
                reason: '清理後 direct-tcpip target listener 仍存在',
              });
            }
          } catch (error) {
            targetPortFree = null;
            addCleanupError('check-target-port', String(targetPort), error);
            residualResources.push({
              type: 'listener',
              host: '127.0.0.1',
              port: targetPort,
              state: 'unknown',
              reason: `無法確認 target listener 狀態：${error.message}`,
            });
          }
        }

        const rootBlockers = [...(unitCleanup?.unresolvedUnits || [])];
        for (const item of portStates) {
          if (item.free !== true) {
            rootBlockers.push(`port:${item.port}:${item.free === false ? 'occupied' : 'unknown'}`);
          }
        }
        if (targetPort && targetPortFree !== true) {
          rootBlockers.push(`target-listener:${targetPort}:${targetPortFree === false ? 'present' : 'unknown'}`);
        }
        const listenersClear = portStates.length === ports.length
          && portStates.every((item) => item.free === true)
          && (!targetPort || targetPortFree === true);
        if (root && unitCleanup?.allStopped && listenersClear) {
          try {
            runWslCommand(['rm', '-rf', '--', root]);
            rootState.removed = true;
          } catch (error) {
            addCleanupError('remove-run-root', root, error);
            residualResources.push({ type: 'directory', path: root, reason: error.message });
          }
        } else if (root) {
          rootState.blockedBy = rootBlockers;
          for (const unit of unitCleanup?.unresolvedUnits || []) {
            residualResources.push({
              type: 'systemd-unit',
              name: unit,
              state: 'not-confirmed-stopped',
              reason: '停止失敗且未能確認 unit 已卸載',
            });
          }
          residualResources.push({
            type: 'directory',
            path: root,
            reason: '尚有 unit 或 listener/port 狀態未確認清除，為避免刪除仍使用中的檔案而保留',
            blockedBy: rootBlockers,
          });
        }

        try {
          wslSessionActiveBeforeStop = wslSession.isRunning;
        } catch (error) {
          addCleanupError('check-wsl-session', 'WSL fixture session', error);
        }
      } finally {
        try {
          wslSessionClose = await wslSession.stop();
        } catch (error) {
          addCleanupError('stop-wsl-session', 'WSL fixture session', error);
        }
      }

      const evidence = {
        fixture: 'WSL Ubuntu transient OpenSSH',
        root,
        sshHost,
        ...(targetPort ? { target: { host: '127.0.0.1', port: targetPort, free: targetPortFree } } : {}),
        permitOpenTargets: validatedPermitOpenTargets,
        units: unitCleanup?.stopped || [],
        unitAttempts: unitCleanup?.attempts || [],
        rootCleanup: rootState,
        residualResources,
        ports: portStates,
        wslSession: {
          activeUntilCleanup: wslSessionActiveBeforeStop,
          close: wslSessionClose,
        },
        cleanupErrors: cleanupErrorDetails,
        cleanup: cleanupErrors.length
          ? 'cleanup incomplete; inspect cleanupErrors and residualResources'
          : 'transient units stopped; exact per-run directory removed',
      };
      if (evidenceFile) {
        try {
          fs.writeFileSync(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, {
            flag: 'wx',
            encoding: 'utf8',
          });
        } catch (error) {
          addCleanupError('write-cleanup-evidence', evidenceFile, error);
          evidence.cleanupErrors = [...cleanupErrorDetails];
          evidence.cleanup = 'cleanup evidence write failed; inspect attached cleanupReport';
        }
      }
      if (cleanupErrors.length) {
        const error = combineCleanupErrors(cleanupErrors, 'OpenSSH fixture cleanup encountered multiple errors');
        error.cleanupReport = evidence;
        throw error;
      }
      cleaned = true;
    }

    return {
      root,
      units,
      sshHost,
      targetPort,
      permitOpenTargets: [...validatedPermitOpenTargets],
      ports: [...ports],
      fingerprints,
      command(name) {
        const command = fixtureCommands[name];
        if (!command) throw new Error(`不支援的 OpenSSH fixture 指令：${name}`);
        return command;
      },
      readCounter,
      isListening,
      isWslSessionActive() { return wslSession.isRunning; },
      isTargetListening() { return isTargetPortListening(targetPort); },
      establishedConnections(host, port) { return listEstablishedConnections(host, port); },
      rotateB,
      cleanup,
    };
  } catch (error) {
    const cleanupFailures = [];
    const cleanupErrorDetails = [];
    const residualResources = [];
    const addCleanupError = (phase, resource, cleanupError) => {
      cleanupFailures.push(cleanupError);
      cleanupErrorDetails.push({ phase, resource, error: cleanupError.message });
    };
    const attemptedUnits = [...unitsToClean];
    const targetUnitAttempted = unitsToClean.has(targetUnit);
    let targetListenerFree;
    let targetPortLookupFailed = false;
    const portsAfterCleanup = [];
    let unitCleanup = {
      attempts: [],
      stopped: [],
      errors: [],
      unresolvedUnits: [...attemptedUnits],
      allStopped: attemptedUnits.length === 0,
    };
    const cleanupReport = {
      primaryError: {
        phase: 'setup',
        resource: 'OpenSSH fixture setup',
        error: error.message,
      },
      units: [],
      unitAttempts: [],
      ports: portsAfterCleanup,
      ...(targetUnitAttempted ? { target: { host: '127.0.0.1', port: null, listening: null } } : {}),
      root: { path: root, removed: false, blockedBy: [] },
      residualResources,
      errors: cleanupErrorDetails,
      wslSession: { activeUntilCleanup: null, close: null },
    };

    try {
      // 若 echo unit 的 wrapper 失敗，先從 run-scoped 檔案找回動態 port，
      // 才能在停止 unit 後確認該 listener 是否已消失。
      if (targetUnitAttempted && root && !targetPort) {
        try {
          targetPort = await waitUntilTargetPort(`${root}/target-port`, 1000);
          cleanupReport.target.port = targetPort;
        } catch (cleanupError) {
          targetPortLookupFailed = true;
          addCleanupError('resolve-target-port', targetUnit, cleanupError);
          residualResources.push({
            type: 'listener',
            unit: targetUnit,
            host: '127.0.0.1',
            port: null,
            state: 'unknown',
            reason: `無法讀取 echo target port：${cleanupError.message}`,
          });
        }
      }

      try {
        unitCleanup = await stopUnitsBestEffort(
          attemptedUnits,
          stopAndWaitForUnit,
          confirmUnitStopped,
        );
      } catch (cleanupError) {
        addCleanupError('stop-units', attemptedUnits.join(','), cleanupError);
        unitCleanup.unresolvedUnits = [...attemptedUnits];
        unitCleanup.allStopped = attemptedUnits.length === 0;
      }
      for (const item of unitCleanup.errors) {
        addCleanupError(item.phase, item.unit, item.error);
      }
      cleanupReport.units = unitCleanup.stopped;
      cleanupReport.unitAttempts = unitCleanup.attempts;

      for (const unit of unitCleanup.unresolvedUnits) {
        const attempt = unitCleanup.attempts.find((item) => item.unit === unit);
        residualResources.push({
          type: 'systemd-unit',
          name: unit,
          state: 'not-confirmed-stopped',
          reason: attempt?.stopError || '無法確認 transient unit 已卸載',
        });
      }

      if (attemptedUnits.length > 0) {
        for (const port of ports) {
          try {
            const availability = await waitForPortAvailability(
              port,
              checkPortAvailable,
              portReleaseTimeoutMs,
            );
            portsAfterCleanup.push({
              port,
              state: availability.state,
              free: availability.free,
              checks: availability.checks,
              ...(availability.error ? { error: availability.error.message } : {}),
            });
            if (availability.error) {
              addCleanupError('check-ssh-port', String(port), availability.error);
            }
            if (availability.free === false) {
              addCleanupError(
                'verify-ssh-port',
                String(port),
                new Error(`setup cleanup 後 OpenSSH fixture port 仍被占用：${port}`),
              );
              residualResources.push({
                type: 'listener',
                host: 'OpenSSH fixture',
                port,
                state: 'listening',
                reason: 'setup cleanup 後固定 SSH port 仍被占用',
              });
            }
            if (availability.free === null) {
              residualResources.push({
                type: 'listener',
                host: 'OpenSSH fixture',
                port,
                state: 'unknown',
                reason: `無法確認 SSH port 狀態：${availability.error?.message || 'port probe failed'}`,
              });
            }
          } catch (cleanupError) {
            portsAfterCleanup.push({
              port,
              state: 'unknown',
              free: null,
              error: cleanupError.message,
            });
            addCleanupError('check-ssh-port', String(port), cleanupError);
            residualResources.push({
              type: 'listener',
              host: 'OpenSSH fixture',
              port,
              state: 'unknown',
              reason: `無法確認 SSH port 狀態：${cleanupError.message}`,
            });
          }
        }
      }

      if (targetUnitAttempted && targetPort) {
        try {
          const listening = await isTargetPortListening(targetPort);
          targetListenerFree = !listening;
          cleanupReport.target = { host: '127.0.0.1', port: targetPort, listening };
          if (listening) {
            addCleanupError(
              'verify-target-port',
              String(targetPort),
              new Error(`setup cleanup 後 direct-tcpip target port 仍被占用：${targetPort}`),
            );
            residualResources.push({
              type: 'listener',
              unit: targetUnit,
              host: '127.0.0.1',
              port: targetPort,
              state: 'listening',
              reason: 'setup cleanup 後 echo target listener 仍存在',
            });
          }
        } catch (cleanupError) {
          targetListenerFree = false;
          cleanupReport.target = {
            host: '127.0.0.1',
            port: targetPort,
            listening: null,
            error: cleanupError.message,
          };
          addCleanupError('check-target-port', String(targetPort), cleanupError);
          residualResources.push({
            type: 'listener',
            unit: targetUnit,
            host: '127.0.0.1',
            port: targetPort,
            state: 'unknown',
            reason: `無法確認 target listener 狀態：${cleanupError.message}`,
          });
        }
      } else if (targetUnitAttempted) {
        targetListenerFree = false;
        cleanupReport.target = {
          host: '127.0.0.1',
          port: null,
          listening: null,
          error: targetPortLookupFailed ? 'target port lookup failed' : 'target port unavailable',
        };
      }

      const blockers = [...unitCleanup.unresolvedUnits];
      for (const item of unitCleanup.errors) {
        if (item.unit) {
          const blocker = `unit-cleanup-error:${item.unit}`;
          if (!blockers.includes(blocker)) blockers.push(blocker);
        }
      }
      for (const item of portsAfterCleanup) {
        if (item.free !== true) blockers.push(`port:${item.port}:${item.free === false ? 'occupied' : 'unknown'}`);
      }
      if (targetUnitAttempted && targetListenerFree !== true) {
        blockers.push(`target-listener:${targetPort ?? 'unknown'}:${targetListenerFree === false ? 'present-or-unknown' : 'unknown'}`);
      }
      const listenersClear = attemptedUnits.length === 0
        || (portsAfterCleanup.length === ports.length
          && portsAfterCleanup.every((item) => item.free === true)
          && (!targetUnitAttempted || targetListenerFree === true));
      const safeToRemoveRoot = unitCleanup.allStopped
        && unitCleanup.errors.length === 0
        && cleanupFailures.length === 0
        && listenersClear;
      cleanupReport.allStopped = safeToRemoveRoot;

      if (root && safeToRemoveRoot) {
        try {
          runWslCommand(['rm', '-rf', '--', root]);
          cleanupReport.root.removed = true;
        } catch (cleanupError) {
          addCleanupError('remove-run-root', root, cleanupError);
          residualResources.push({ type: 'directory', path: root, reason: cleanupError.message });
        }
      } else if (root) {
        cleanupReport.root.blockedBy = blockers;
        residualResources.push({
          type: 'directory',
          path: root,
          reason: '尚有 unit 或 listener/port 狀態未確認清除，為避免刪除仍使用中的檔案而保留',
          blockedBy: blockers,
        });
      }
    } catch (cleanupError) {
      addCleanupError('setup-cleanup', root || 'OpenSSH fixture setup', cleanupError);
      if (root && !cleanupReport.root.removed) {
        const blocker = `cleanup-error:${cleanupError.message}`;
        cleanupReport.root.blockedBy = [...cleanupReport.root.blockedBy, blocker];
        residualResources.push({
          type: 'directory',
          path: root,
          reason: 'setup cleanup 發生未預期錯誤，保留 run root',
          blockedBy: cleanupReport.root.blockedBy,
        });
      }
    } finally {
      if (wslSession) {
        try {
          cleanupReport.wslSession.activeUntilCleanup = wslSession.isRunning;
        } catch (cleanupError) {
          addCleanupError('check-wsl-session', 'WSL fixture session', cleanupError);
        }
        try {
          cleanupReport.wslSession.close = await wslSession.stop();
        } catch (cleanupError) {
          cleanupReport.wslSession.stopError = cleanupError.message;
          addCleanupError('stop-wsl-session', 'WSL fixture session', cleanupError);
        }
      } else if (typeof error.cleanup === 'function') {
        try {
          await error.cleanup();
        } catch (cleanupError) {
          cleanupReport.wslSession.childStopError = cleanupError.message;
          addCleanupError('stop-wsl-child', 'WSL fixture child', cleanupError);
        }
      } else {
        cleanupReport.wslSession.childCleanupAttempted = false;
      }
    }

    cleanupReport.residualResources = residualResources;
    cleanupReport.errors = cleanupErrorDetails;
    if (evidenceFile) {
      try {
        fs.writeFileSync(evidenceFile, `${JSON.stringify(cleanupReport, null, 2)}\n`, {
          flag: 'wx',
          encoding: 'utf8',
        });
      } catch (cleanupError) {
        addCleanupError('write-cleanup-evidence', evidenceFile, cleanupError);
        cleanupReport.errors = [...cleanupErrorDetails];
      }
    }
    const failure = combineCleanupErrors(
      [error, ...cleanupFailures],
      'OpenSSH fixture setup 與 cleanup 均有錯誤',
    );
    failure.cleanupReport = cleanupReport;
    if (error.child) failure.child = error.child;
    if (typeof error.cleanup === 'function') failure.cleanup = error.cleanup;
    throw failure;
  }
}

module.exports = { createOpenSshServiceFixture, portAvailable, startWslSession };
