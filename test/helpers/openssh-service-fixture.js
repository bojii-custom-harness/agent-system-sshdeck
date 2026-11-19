'use strict';

const fs = require('node:fs');
const net = require('node:net');
const { randomUUID } = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ports = [2227, 2228];

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

function portAvailable(port) {
  if (process.platform === 'win32') {
    const powershell = spawnSync('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `if (Get-NetTCPConnection -State Listen -LocalPort ${port} -ErrorAction SilentlyContinue) { exit 1 }`,
    ], { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    if (powershell.error || powershell.status !== 0) return Promise.resolve(false);
    const wslListeners = runWsl(['ss', '-ltn']);
    return Promise.resolve(!wslListeners.split(/\r?\n/).some((line) => line.includes(`:${port} `)));
  }
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.close((error) => error ? reject(error) : resolve(true));
    });
  });
}

async function waitForPort(port, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.createConnection({ host: '127.0.0.1', port });
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

function fingerprintFor(path) {
  const output = runWsl(['ssh-keygen', '-lf', `${path}.pub`, '-E', 'sha256']);
  const fingerprint = output.match(/SHA256:[^\s]+/)?.[0];
  if (!fingerprint) throw new Error('無法讀取 OpenSSH fixture host fingerprint');
  return fingerprint;
}

async function createOpenSshServiceFixture({ authorizedPublicKey, evidenceFile } = {}) {
  if (typeof authorizedPublicKey !== 'string' || !authorizedPublicKey.startsWith('ssh-ed25519 ')) {
    throw new Error('fixture 需要隔離測試用 Ed25519 公鑰');
  }
  for (const port of ports) {
    if (!await portAvailable(port)) throw new Error(`OpenSSH fixture port ${port} 已被占用；未停止任何既有程序`);
  }

  const runId = randomUUID();
  const root = runWsl(['mktemp', '-d', `/tmp/sshdeck-ticket01-${runId}-XXXXXX`]);
  if (!/^\/tmp\/sshdeck-ticket01-[0-9a-f-]{36}-[A-Za-z0-9]{6}$/.test(root)) {
    throw new Error('WSL fixture 目錄格式不符；拒絕執行清理命令');
  }
  const units = [
    `sshdeck-ticket01-${runId}-a.service`,
    `sshdeck-ticket01-${runId}-b.service`,
  ];
  const authorizedTestKey = `no-agent-forwarding,no-port-forwarding,no-pty ${authorizedPublicKey}`;
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
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
LogLevel ERROR
`;
  const script = [
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

  let startedUnits = 0;
  try {
    runWsl(['bash', '-lc', `cat > '${root}/authorized_keys'`], { input: `${authorizedTestKey}\n` });
    runWsl(['bash', '-lc', script]);
    for (const [index, endpoint] of ['a', 'b'].entries()) {
      const unit = units[index];
      runWsl(['systemd-run', '--collect', `--unit=${unit}`, '--property=RuntimeMaxSec=900',
        '/usr/sbin/sshd', '-D', '-e', '-f', `${root}/sshd-${endpoint}.conf`]);
      startedUnits += 1;
      await waitForUnit(unit);
      await waitForPort(ports[index]);
    }
    const fingerprints = {
      a: fingerprintFor(`${root}/host-a`),
      b: fingerprintFor(`${root}/host-b`),
    };
    if (fingerprints.a === fingerprints.b) throw new Error('兩個 SSH fixture 必須使用不同 host key');

    let cleaned = false;
    async function rotateB() {
      runWsl(['cp', `${root}/host-b-next`, `${root}/host-b`]);
      runWsl(['cp', `${root}/host-b-next.pub`, `${root}/host-b.pub`]);
      runWsl(['chmod', '600', `${root}/host-b`]);
      runWsl(['systemctl', 'restart', units[1]]);
      await waitForPort(ports[1]);
      fingerprints.rotatedB = fingerprintFor(`${root}/host-b`);
      if (fingerprints.rotatedB === fingerprints.b) throw new Error('host key rotation 未產生新指紋');
      return fingerprints.rotatedB;
    }

    function readCounter(target) {
      if (!['a', 'b'].includes(target)) throw new Error(`不支援的 OpenSSH fixture counter：${target}`);
      const file = `${root}/${target}-count`;
      return runWsl(['bash', '-lc', `if [ -f '${file}' ]; then cat '${file}'; else printf '0\\n'; fi`]);
    }

    function isListening(port) {
      if (!ports.includes(port)) throw new Error(`不支援的 OpenSSH fixture port：${port}`);
      return runWsl(['ss', '-ltn']).split(/\r?\n/).some((line) => line.includes(`:${port} `));
    }

    async function cleanup() {
      if (cleaned) return;
      const stopped = [];
      for (const unit of units.slice(0, startedUnits)) {
        const loadState = await stopUnitAndWait(unit);
        stopped.push({ unit, loadState });
      }
      runWsl(['rm', '-rf', '--', root]);
      const portStates = [];
      for (const port of ports) {
        let free = false;
        try { free = await portAvailable(port); } catch { free = false; }
        portStates.push({ port, free });
      }
      cleaned = true;
      const evidence = {
        fixture: 'WSL Ubuntu transient OpenSSH',
        root,
        units: stopped,
        ports: portStates,
        cleanup: 'transient units stopped; exact per-run directory removed',
      };
      if (evidenceFile) fs.writeFileSync(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx', encoding: 'utf8' });
      if (portStates.some((item) => !item.free)) throw new Error('清理後 OpenSSH fixture port 仍被占用');
    }

    return {
      root,
      units,
      ports: [...ports],
      fingerprints,
      command(name) {
        const command = fixtureCommands[name];
        if (!command) throw new Error(`不支援的 OpenSSH fixture 指令：${name}`);
        return command;
      },
      readCounter,
      isListening,
      rotateB,
      cleanup,
    };
  } catch (error) {
    for (const unit of units.slice(0, startedUnits)) {
      try { await stopUnitAndWait(unit); } catch { /* 保留原始錯誤與精確 unit 名稱供診斷 */ }
    }
    try { runWsl(['rm', '-rf', '--', root]); } catch { /* 目錄僅在該 run 建立 */ }
    throw error;
  }
}

module.exports = { createOpenSshServiceFixture };
