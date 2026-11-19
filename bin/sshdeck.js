#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { StringDecoder } = require('node:string_decoder');
const { WebSocketServer, WebSocket } = require('ws');
const ssh = require('../lib/ssh');

function normalizeBasePath(value = '') {
  if (typeof value !== 'string') throw new Error('SSHDECK_BASE_PATH 必須是絕對路徑');
  if (value === '' || value === '/') return '';
  const normalized = value.replace(/\/+$/, '');
  if (!normalized.startsWith('/')
    || normalized.startsWith('//')
    || normalized.includes('\\')
    || normalized.includes('%')
    || normalized.includes('?')
    || normalized.includes('#')
    || /[\u0000-\u001f\u007f]/.test(normalized)
    || normalized.split('/').slice(1).some((segment) => !segment || segment === '.' || segment === '..' || !/^[A-Za-z0-9._~-]+$/.test(segment))) {
    throw new Error('SSHDECK_BASE_PATH 必須是安全的絕對路徑，例如 /sshdeck');
  }
  return normalized;
}

function listSetting(value, name) {
  if (value === undefined || value === '') return [];
  const values = value.split(',').map((item) => item.trim()).filter(Boolean);
  if (values.some((item) => /[\s,]/.test(item))) throw new Error(`${name} 含有無效項目`);
  return values;
}

function validateServiceUiConfig(env) {
  if (typeof env.SSHDECK_SERVICE_URL !== 'string' || !env.SSHDECK_SERVICE_URL.trim()) {
    throw new Error('service UI adapter 必須設定 SSHDECK_SERVICE_URL');
  }
  let serviceUrl;
  try { serviceUrl = new URL(env.SSHDECK_SERVICE_URL); } catch {
    throw new Error('SSHDECK_SERVICE_URL 格式無效');
  }
  if (!['http:', 'https:'].includes(serviceUrl.protocol)
    || serviceUrl.username || serviceUrl.password || serviceUrl.search || serviceUrl.hash
    || (serviceUrl.pathname !== '/' && serviceUrl.pathname !== '')) {
    throw new Error('SSHDECK_SERVICE_URL 必須是無憑證、無路徑的 HTTP(S) origin');
  }
  if (typeof env.SSHDECK_UI_TOKEN !== 'string' || env.SSHDECK_UI_TOKEN.length < 32) {
    throw new Error('service UI adapter 必須設定至少 32 個字元的 SSHDECK_UI_TOKEN');
  }
  if (env.SSHDECK_SERVICE_TOKEN && env.SSHDECK_SERVICE_TOKEN === env.SSHDECK_UI_TOKEN) {
    throw new Error('SSHDECK_UI_TOKEN 不可與 SSHDECK_SERVICE_TOKEN 相同');
  }
  const allowedHosts = listSetting(env.SSHDECK_UI_ALLOWED_HOSTS, 'SSHDECK_UI_ALLOWED_HOSTS');
  const allowedOrigins = listSetting(env.SSHDECK_UI_ALLOWED_ORIGINS, 'SSHDECK_UI_ALLOWED_ORIGINS');
  for (const origin of allowedOrigins) {
    let parsed;
    try { parsed = new URL(origin); } catch { throw new Error('SSHDECK_UI_ALLOWED_ORIGINS 必須是完整 origin 清單'); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== origin || parsed.username || parsed.password) {
      throw new Error('SSHDECK_UI_ALLOWED_ORIGINS 必須是精確的 HTTP(S) origin 清單');
    }
  }
  if ((allowedHosts.length === 0) !== (allowedOrigins.length === 0)) {
    throw new Error('代理部署時必須同時設定 SSHDECK_UI_ALLOWED_HOSTS 與 SSHDECK_UI_ALLOWED_ORIGINS');
  }
  return {
    origin: serviceUrl.origin,
    token: env.SSHDECK_UI_TOKEN,
    allowedHosts: allowedHosts.map((host) => host.toLowerCase()),
    allowedOrigins,
  };
}

function safeReturnPath(value) {
  const fallback = '/workspace';
  if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('/') || value.startsWith('//')
    || value.includes('\\') || /[\u0000-\u001f\u007f]/.test(value)) return fallback;
  let parsed;
  try { parsed = new URL(value, 'http://sshdeck.invalid'); } catch { return fallback; }
  if (parsed.origin !== 'http://sshdeck.invalid' || parsed.search || parsed.hash) return fallback;
  const segments = parsed.pathname.split('/');
  if (segments[0] !== '' || segments[1] !== 'workspace' || segments.length > 5) return fallback;
  const decoded = [];
  try {
    for (const segment of segments.slice(1)) decoded.push(decodeURIComponent(segment));
  } catch { return fallback; }
  if (decoded.length < 1 || decoded[0] !== 'workspace'
    || decoded.slice(1).some((segment) => !segment || segment === '.' || segment === '..'
      || segment.includes('/') || segment.includes('\\') || segment.includes('%')
      || /[\u0000-\u001f\u007f]/.test(segment))) return fallback;
  if (decoded.length === 1) return fallback;
  if (decoded.length === 2) return `/workspace/${encodeURIComponent(decoded[1])}`;
  if (decoded.length === 4 && decoded[2] === 'session') {
    return `/workspace/${encodeURIComponent(decoded[1])}/session/${encodeURIComponent(decoded[3])}`;
  }
  return fallback;
}

function trustedUiRequest(req, port, { allowedHosts = [], allowedOrigins = [] } = {}) {
  if (allowedHosts.length) {
    const host = String(req.headers.host || '').toLowerCase();
    if (!allowedHosts.includes(host)) return false;
    if (!req.headers.origin) return ['GET', 'HEAD'].includes(req.method);
    try {
      const origin = new URL(req.headers.origin);
      return allowedOrigins.includes(origin.origin) && origin.host.toLowerCase() === host;
    } catch { return false; }
  }
  return trustedRequest(req, port);
}

function readJsonBody(req, maxBytes = 128 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        reject(Object.assign(new Error('要求內容超過大小限制'), { status: 413 }));
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text ? JSON.parse(text) : {});
      } catch {
        reject(Object.assign(new Error('要求內容必須是有效 JSON'), { status: 400 }));
      }
    });
    req.on('aborted', () => reject(Object.assign(new Error('要求已中斷'), { status: 400 })));
    req.on('error', reject);
  });
}

function dataFileFor({ platform = process.platform, env = process.env, home = os.homedir() } = {}) {
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  if (env.SSHDECK_HOME) return pathApi.join(env.SSHDECK_HOME, 'hosts.json');

  let base;
  if (platform === 'win32') base = env.APPDATA || pathApi.join(home, 'AppData', 'Roaming');
  else if (platform === 'darwin') base = pathApi.join(home, 'Library', 'Application Support');
  else base = env.XDG_DATA_HOME && pathApi.isAbsolute(env.XDG_DATA_HOME)
    ? env.XDG_DATA_HOME
    : pathApi.join(home, '.local', 'share');

  return pathApi.join(base, 'sshdeck', 'hosts.json');
}

function readHosts(dataFile) {
  try {
    const hosts = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
    if (!Array.isArray(hosts)) throw new Error('Host data must be a list');
    return hosts;
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error(`無法讀取主機設定：${error.message}`);
  }
}

function processIsRunning(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

function acquireLock(lockFile, timeoutMs = 5000) {
  const token = `${process.pid}:${randomUUID()}`;
  const deadline = Date.now() + timeoutMs;
  const waitBuffer = new Int32Array(new SharedArrayBuffer(4));

  while (Date.now() < deadline) {
    try {
      const descriptor = fs.openSync(lockFile, 'wx', 0o600);
      fs.writeFileSync(descriptor, JSON.stringify({ pid: process.pid, token }));
      return () => {
        fs.closeSync(descriptor);
        try {
          const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
          if (lock.token === token) fs.unlinkSync(lockFile);
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
      };
    } catch (error) {
      if (error.code !== 'EEXIST' && !(error.code === 'EPERM' && fs.existsSync(lockFile))) throw error;
    }

    try {
      const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
      const ageMs = Date.now() - fs.statSync(lockFile).mtimeMs;
      if (ageMs > 30_000 && !processIsRunning(lock.pid)) fs.unlinkSync(lockFile);
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      if (error instanceof SyntaxError) {
        try {
          if (Date.now() - fs.statSync(lockFile).mtimeMs > 30_000) fs.unlinkSync(lockFile);
        } catch (statError) {
          if (statError.code !== 'ENOENT') throw statError;
        }
      } else if (error.code !== 'ENOENT') {
        throw error;
      }
    }
    Atomics.wait(waitBuffer, 0, 0, 10);
  }

  throw new Error('等待主機設定鎖定逾時；請確認沒有其他 sshdeck 程序正在修改設定。');
}

function writeHosts(dataFile, hosts) {
  fs.mkdirSync(path.dirname(dataFile), { recursive: true, mode: 0o700 });
  const temporaryFile = `${dataFile}.${process.pid}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporaryFile, `${JSON.stringify(hosts, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporaryFile, dataFile);
  } finally {
    try { fs.unlinkSync(temporaryFile); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function mutateHosts(dataFile, change) {
  fs.mkdirSync(path.dirname(dataFile), { recursive: true, mode: 0o700 });
  const release = acquireLock(`${dataFile}.lock`);
  try {
    const hosts = readHosts(dataFile);
    const result = change(hosts);
    writeHosts(dataFile, hosts);
    return result;
  } finally {
    release();
  }
}

function validateHost(input) {
  const host = { ...input };
  for (const field of ['alias', 'hostname', 'username']) {
    if (typeof host[field] !== 'string' || !host[field].trim()) throw new Error(`${field} 必須是非空文字`);
    host[field] = host[field].trim();
  }
  host.port = Number(host.port ?? 22);
  if (!Number.isInteger(host.port) || host.port < 1 || host.port > 65535) {
    throw new Error('port 必須是 1 到 65535 的整數');
  }
  if (host.keyPath !== undefined && typeof host.keyPath !== 'string') throw new Error('keyPath 必須是文字');
  return {
    alias: host.alias,
    hostname: host.hostname,
    port: host.port,
    username: host.username,
    ...(host.keyPath === undefined ? {} : { keyPath: host.keyPath }),
  };
}

function parseOptions(args) {
  const values = {};
  const names = { user: 'username', username: 'username', key: 'keyPath', 'key-path': 'keyPath', hostname: 'hostname', port: 'port' };
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index].match(/^--(hostname|port|user|username|key|key-path)$/);
    if (!option || !args[index + 1] || args[index + 1].startsWith('--')) throw new Error(`無效的選項：${args[index]}`);
    values[names[option[1]]] = args[index + 1];
    index += 1;
  }
  return values;
}

function dockerStatusLabel(docker) {
  if (!docker) return '未檢查';
  if (docker.state === 'available') return `可用 ${docker.version}`;
  if (docker.state === 'permission-denied') return '權限不足';
  if (docker.state === 'missing-cli') return 'CLI 未安裝';
  if (docker.state === 'daemon-unavailable') return 'daemon 不可用';
  if (docker.state === 'not-run') return '未執行';
  return '無法使用';
}

function hostList(hosts, statuses = {}) {
  if (!hosts.length) return '尚未設定主機。';
  return hosts.map((host) => {
    const state = statuses[host.alias]?.state;
    const check = state === 'success' ? 'SSH 成功'
      : state === 'untrusted' ? '等待主機指紋確認'
        : state === 'changed' ? '主機指紋已變更'
          : state === 'failure' ? 'SSH 失敗' : '未檢查';
    const docker = statuses[host.alias]?.docker;
    const dockerCheck = `Docker ${dockerStatusLabel(docker)}`;
    const checkedAt = statuses[host.alias]?.checkedAt;
    return `${host.alias}\t${host.hostname}:${host.port}\t${host.username}\t${host.keyPath || '未設定金鑰'}\t${check}${checkedAt ? `（${checkedAt}）` : ''}\t${dockerCheck}`;
  }).join('\n');
}

async function readSecret(prompt, input = process.stdin, output = process.stderr) {
  output.write(prompt);
  const wasRaw = input.isRaw;
  const canHide = Boolean(input.isTTY && typeof input.setRawMode === 'function');
  if (canHide) input.setRawMode(true);
  const readline = require('node:readline/promises');
  const terminal = readline.createInterface({ input, output, terminal: false });
  try {
    return await terminal.question('');
  } finally {
    terminal.close();
    if (canHide) input.setRawMode(Boolean(wasRaw));
    output.write('\n');
  }
}

async function hostCommand(dataFile, args) {
  const action = args[1];
  if (action === 'check') {
    const host = readHosts(dataFile).find((item) => item.alias === args[2]);
    if (!host) throw new Error(`找不到主機：${args[2] || ''}`);
    const passphrase = await readSecret('登入金鑰密語（輸入隱藏；未加密請按 Enter）：');
    let result;
    try {
      result = await ssh.checkWithDocker(dataFile, host, passphrase);
    } catch (error) {
      if (!['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(error.code)) {
        if (ssh.getStatuses(dataFile)[host.alias]?.docker?.state === 'not-run') {
          console.error('Docker 檢查：未執行（SSH 檢查未成功）');
        }
        throw error;
      }
      const readline = require('node:readline/promises');
      const prompt = readline.createInterface({ input: process.stdin, output: process.stderr });
      let answer;
      try {
        const previous = error.previousFingerprint ? `（原信任指紋 ${error.previousFingerprint}）` : '';
        answer = await prompt.question(`主機指紋 ${error.fingerprint}${previous}。確認信任此主機？[y/N] `);
      } finally { prompt.close(); }
      if (!/^y(es)?$/i.test(answer.trim())) throw new Error('已拒絕主機指紋；未執行登入');
      result = await ssh.checkWithDocker(dataFile, host, passphrase, { expectedFingerprint: error.fingerprint });
    }
    console.log(`SSH 登入檢查成功：${host.alias}（${result.fingerprint}）`);
    if (result.docker.state === 'available') {
      console.log(`Docker daemon 可用：${result.docker.version}`);
    } else {
      console.error(`Docker 檢查：${dockerStatusLabel(result.docker)}${result.docker.diagnostic ? `\n診斷：${result.docker.diagnostic}` : ''}`);
      process.exitCode = 1;
    }
    return;
  }
  if (action === 'list') {
    console.log(hostList(readHosts(dataFile), ssh.getStatuses(dataFile)));
    return;
  }
  if (!['add', 'update', 'delete', 'remove'].includes(action)) {
    throw new Error('用法：sshdeck host <add|list|update|delete|check> ...');
  }

  const alias = args[2];
  if (!alias) throw new Error('請提供主機別名');
  const options = parseOptions(args.slice(3));
  let updated;
  mutateHosts(dataFile, (hosts) => {
    const index = hosts.findIndex((host) => host.alias === alias);
    if (action === 'add') {
      if (index >= 0) throw new Error(`主機別名已存在：${alias}`);
      hosts.push(validateHost({ alias, ...options }));
    } else {
      if (index < 0) throw new Error(`找不到主機：${alias}`);
      if (action === 'delete' || action === 'remove') hosts.splice(index, 1);
      else { hosts[index] = validateHost({ ...hosts[index], ...options }); updated = hosts[index]; }
    }
  });
  if (updated) ssh.updateManagedKeyProfile(dataFile, updated);
  const description = action === 'add' ? '新增' : action === 'update' ? '更新' : '刪除';
  console.log(`已${description}主機設定：${alias}`);
}

async function keyCommand(dataFile, args) {
  const action = args[1]; const alias = args[2];
  if (action === 'list') {
    const hosts = readHosts(dataFile);
    const records = ssh.listManagedKeys(dataFile);
    if (!records.length) { console.log('尚無 sshdeck 管理的金鑰。'); return; }
    console.log(records.map((record) => {
      const aliases = hosts.filter((host) => host.keyPath === record.keyPath).map((host) => host.alias);
      return `${record.id}\t${record.alias}\t${record.username || '未設定帳號'}@${record.hostname || '未設定主機'}:${record.port || 22}\t${aliases.length ? `使用中：${aliases.join(', ')}` : '未關聯'}`;
    }).join('\n'));
    return;
  }
  if (!alias) throw new Error('請提供主機別名或金鑰 ID');
  const host = readHosts(dataFile).find((item) => item.alias === alias);
  if (action === 'create') {
    if (!host) throw new Error(`找不到主機：${alias}`);
    if (host.keyPath) throw new Error('此主機已關聯登入金鑰；請先解除外部金鑰關聯或刪除 sshdeck 金鑰，再建立新金鑰');
    const passphrase = await readSecret('設定新金鑰密語（輸入隱藏）：');
    const created = ssh.createManagedKey(dataFile, alias, passphrase, host);
    try { mutateHosts(dataFile, (hosts) => { const current = hosts.find((item) => item.alias === alias); if (!current) throw new Error(`找不到主機：${alias}`); current.keyPath = created.keyPath; }); }
    catch (error) { ssh.deleteManagedKey(dataFile, created.keyPath); throw error; }
    console.log(`已建立金鑰：${alias}\n公鑰：${created.publicKey}`);
    return;
  }
  if (action === 'show') {
    const record = host?.keyPath ? ssh.managedKeyForPath(dataFile, host.keyPath) : ssh.resolveManagedKey(dataFile, alias);
    const keyPath = host?.keyPath || record?.keyPath;
    if (!keyPath) throw new Error(`找不到關聯金鑰：${alias}`);
    console.log(ssh.managedPublicKey(keyPath));
    return;
  }
  if (action === 'guide') {
    const record = host?.keyPath ? ssh.managedKeyForPath(dataFile, host.keyPath) : ssh.resolveManagedKey(dataFile, alias);
    const keyPath = host?.keyPath || record?.keyPath;
    if (!keyPath) throw new Error(`找不到關聯金鑰：${alias}`);
    console.log(ssh.installationGuide(host?.keyPath ? host : record, ssh.managedPublicKey(keyPath)));
    return;
  }
  if (action === 'unlink') {
    if (!host) throw new Error(`找不到主機：${alias}`);
    if (!host.keyPath) throw new Error('此主機尚未關聯登入金鑰');
    const managed = ssh.isManagedKeyPath(dataFile, host.keyPath);
    mutateHosts(dataFile, (hosts) => {
      const current = hosts.find((item) => item.alias === alias);
      if (!current) throw new Error(`找不到主機：${alias}`);
      delete current.keyPath;
    });
    console.log(managed
      ? `已解除主機 ${alias} 的金鑰關聯；金鑰仍保留在 sshdeck 管理清單，遠端授權不變`
      : `已解除主機 ${alias} 的既有金鑰關聯；未刪除原私鑰或遠端公鑰授權`);
    return;
  }
  if (action === 'delete') {
    if (host?.keyPath && !ssh.isManagedKeyPath(dataFile, host.keyPath)) throw new Error('此金鑰非 sshdeck 建立，請使用 key unlink 解除關聯；不會刪除使用者檔案');
    const record = host?.keyPath ? ssh.managedKeyForPath(dataFile, host.keyPath) : ssh.resolveManagedKey(dataFile, alias);
    const keyPath = host?.keyPath || record?.keyPath;
    if (!keyPath || !ssh.isManagedKeyPath(dataFile, keyPath)) throw new Error(`找不到 sshdeck 管理的金鑰：${alias}`);
    const users = readHosts(dataFile).filter((item) => item.keyPath === keyPath);
    if (users.length > 1) throw new Error(`此金鑰仍由其他設定共用：${users.filter((item) => item.alias !== alias).map((item) => item.alias).join(', ')}；請先解除關聯`);
    const publicKey = ssh.managedPublicKey(keyPath);
    const guide = ssh.installationGuide(host || record, publicKey);
    if (users.length === 1) mutateHosts(dataFile, (hosts) => {
      const current = hosts.find((item) => item.keyPath === keyPath);
      if (current) delete current.keyPath;
    });
    try { ssh.deleteManagedKey(dataFile, keyPath); }
    catch (error) {
      if (users.length === 1) {
        try { mutateHosts(dataFile, (hosts) => { const current = hosts.find((item) => item.alias === users[0].alias); if (current) current.keyPath = keyPath; }); }
        catch (restoreError) { throw new Error(`本機私鑰刪除失敗，且無法恢復主機關聯：${error.message}; ${restoreError.message}`); }
      }
      throw error;
    }
    console.log(`已刪除本機私鑰：${record?.alias || alias}\n遠端 authorized_keys 授權不會自動撤銷；請手動依下列公鑰撤銷指南操作：\n${guide}`);
    return;
  }
  throw new Error('用法：sshdeck key <list|create|show|guide|unlink|delete> [別名|金鑰 ID]');
}

function trustedRequest(req, port) {
  let requestUrl;
  try { requestUrl = new URL(`http://${req.headers.host}`); } catch { return false; }
  const localHost = ['127.0.0.1', 'localhost'].includes(requestUrl.hostname.toLowerCase());
  if (!localHost || Number(requestUrl.port || 80) !== port) return false;

  if (!req.headers.origin) return true;
  try {
    const origin = new URL(req.headers.origin);
    return origin.protocol === 'http:'
      && ['127.0.0.1', 'localhost'].includes(origin.hostname.toLowerCase())
      && origin.host.toLowerCase() === requestUrl.host.toLowerCase();
  } catch {
    return false;
  }
}

const page = `<!doctype html>
<html lang="zh-Hant">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<link rel="stylesheet" href="__SSHDECK_BASE_PATH__/assets/xterm.css">
<link rel="stylesheet" href="__SSHDECK_BASE_PATH__/assets/workspace.css?v=2">
<title>sshdeck 主機設定</title>
<body>
<a class="skip-link" href="#main">跳到主要內容</a>
<aside class="sidebar">
  <p class="brand">sshdeck</p>
  <a id="return-to-workspace" href="__SSHDECK_RETURN_TO__">返回工作區</a>
  <button id="navigation-toggle" type="button" aria-expanded="false" aria-controls="navigation">開啟導覽</button>
  <nav id="navigation" aria-label="主要導覽">
    <div role="tablist" aria-label="工作區分頁" aria-orientation="vertical">
      <button id="hosts-tab" type="button" role="tab" aria-controls="hosts-panel" aria-selected="true">主機操作</button>
      <button id="guide-tab" type="button" role="tab" aria-controls="guide-panel" aria-selected="false" tabindex="-1">建立指南</button>
    </div>
  </nav>
</aside>
<main id="main" tabindex="-1">
<h1>主機設定管理</h1>
<p id="service-mode-note" hidden>服務模式：登入金鑰由 SSHDeck service 加密保管；此介面不提供互動終端機。金鑰信任與遠端公鑰安裝仍須由使用者明確確認。</p>
<p id="error" role="alert"></p>
<section id="hosts-panel" role="tabpanel" aria-labelledby="hosts-tab" tabindex="-1">
  <h2>主機操作</h2>
  <p>先選取受管主機，再開始操作。選取不會自動建立 SSH 終端連線。</p>
  <h3>全部受管主機</h3>
  <p id="hosts-loading" role="status">正在載入受管主機…</p>
  <div id="empty-hosts" hidden><p>尚未加入受管主機。</p><button type="button" data-page="guide">開始建立指南</button></div>
  <ul id="hosts" class="host-list" aria-label="受管主機"></ul>
  <button id="open-legacy-management" type="button">全域登入金鑰管理</button>
  <p id="select-host-hint">請從上方選取操作目標。</p>
  <section id="host-workspace" aria-labelledby="target-heading" hidden>
    <h3 id="target-heading">操作目標：<span id="target-alias"></span></h3>
    <dl class="target-info"><dt>主機位址</dt><dd id="target-address"></dd><dt>登入帳號</dt><dd id="target-username"></dd></dl>
    <div id="host-actions"><button id="connect-host" type="button">連線</button><button id="check-selected-host" type="button">立即檢查</button></div>
    <div id="terminal-workspace"><h3>SSH 互動終端機</h3><p id="terminal-status" role="status">尚未開啟終端機</p><div id="shell-sessions"></div></div>
     <details id="advanced-management"><summary>進階管理</summary>
       <div id="advanced-host-actions">
         <div id="selected-host-actions"></div>
         <details id="advanced-exec"><summary>對選定主機執行單次遠端命令</summary>
           <p id="exec-target-hint" role="status"></p>
           <form id="exec-form"><label>遠端命令 <input id="exec-command" required></label><button>執行</button></form>
           <div id="exec-sessions" aria-live="polite"></div>
         </details>
       </div>
     </details>
   </section>
   <details id="legacy-management" hidden><summary>全域登入金鑰管理</summary>
     <button id="lock-keys" type="button">鎖定已解鎖金鑰</button>
     <h3>本機管理金鑰</h3><ul id="managed-keys"></ul>
   </details>
</section>
<section id="guide-panel" role="tabpanel" aria-labelledby="guide-tab" tabindex="-1" hidden>
<h2>建立指南</h2>
<div id="connection-guide">
<p>依序準備連線資料、登入金鑰及遠端授權，再主動檢查 SSH 連線。</p>
<div id="connection-guide-app"></div>
</div>
</section>
<dialog id="unlock-dialog">
  <form id="unlock-form">
    <label>登入金鑰密語 <input id="passphrase" type="password" autocomplete="current-password"></label>
    <button type="submit">解鎖</button>
    <button id="cancel-unlock" type="button">取消</button>
  </form>
</dialog>
<dialog id="key-create-dialog">
  <form id="key-create-form">
    <label>新 Ed25519 金鑰密語 <input id="new-key-passphrase" type="password" autocomplete="new-password" required></label>
    <label>再次輸入密語 <input id="confirm-key-passphrase" type="password" autocomplete="new-password" required></label>
    <button type="submit">建立金鑰</button>
    <button id="cancel-key-create" type="button">取消</button>
  </form>
</dialog>
<dialog id="key-import-dialog">
  <form id="key-import-form">
    <label>OpenSSH 私鑰檔案 <input id="private-key-file" type="file" accept=".pem,.key,.pubkey,text/plain,application/octet-stream" required></label>
    <label>私鑰密語（未加密請留空） <input id="import-key-passphrase" type="password" autocomplete="off"></label>
    <p>私鑰只會傳送至目前受信任的 SSHDeck 服務，不會儲存在瀏覽器或一般回應中。</p>
    <button type="submit">匯入登入金鑰</button>
    <button id="cancel-key-import" type="button">取消</button>
  </form>
</dialog>
<section id="key-info" aria-label="登入金鑰資訊" hidden>
  <label id="guide-username-label" hidden>指南中的遠端使用者名稱 <input id="guide-username" autocomplete="off"></label>
  <pre id="key-output"></pre>
  <button id="copy-public-key" type="button" disabled>複製公鑰</button>
  <button id="copy-guide" type="button" disabled>複製授權指令</button>
</section>
</main>
<script>window.sshdeckConfig = __SSHDECK_CONFIG__;</script>
<script src="__SSHDECK_BASE_PATH__/assets/xterm.js"></script>
<script src="__SSHDECK_BASE_PATH__/assets/addon-fit.js"></script>
<script src="__SSHDECK_BASE_PATH__/assets/workspace.js"></script>
<script>
const sshdeckConfig = window.sshdeckConfig;
const basePath = sshdeckConfig.basePath;
window.sshdeckApiPath = (route) => basePath + route;
const nativeFetch = window.fetch.bind(window);
window.fetch = (input, options) => {
  const source = input instanceof Request ? input.url : input;
  const url = new URL(source, location.href);
  if (url.origin === location.origin && basePath && (url.pathname.startsWith('/api/') || url.pathname.startsWith('/assets/'))) {
    url.pathname = basePath + url.pathname;
    input = input instanceof Request ? new Request(url, input) : url.href;
  }
  return nativeFetch(input, options);
};
const selectedHostActions = document.querySelector('#selected-host-actions');
const managedKeys = document.querySelector('#managed-keys');
const shellSessions = document.querySelector('#shell-sessions');
const error = document.querySelector('#error');
const unlockDialog = document.querySelector('#unlock-dialog');
const unlockForm = document.querySelector('#unlock-form');
const passphraseInput = document.querySelector('#passphrase');
const keyCreateDialog = document.querySelector('#key-create-dialog');
const keyCreateForm = document.querySelector('#key-create-form');
const newKeyPassphrase = document.querySelector('#new-key-passphrase');
const confirmKeyPassphrase = document.querySelector('#confirm-key-passphrase');
const keyImportDialog = document.querySelector('#key-import-dialog');
const keyImportForm = document.querySelector('#key-import-form');
const privateKeyFile = document.querySelector('#private-key-file');
const importKeyPassphrase = document.querySelector('#import-key-passphrase');
const keyOutput = document.querySelector('#key-output');
const copyPublicKey = document.querySelector('#copy-public-key');
const copyGuide = document.querySelector('#copy-guide');
const keyInfo = document.querySelector('#key-info');
const guideUsernameLabel = document.querySelector('#guide-username-label');
const guideUsername = document.querySelector('#guide-username');
let currentPublicKey = '';
let currentGuide = '';
let currentGuideUsername = '';

async function request(url, method = 'GET', body) {
  const response = await fetch(url, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const value = response.status === 204 ? null : await response.json();
  return { response, value };
}

async function send(url, method, body) {
  const { response, value } = await request(url, method, body);
  if (!response.ok) {
    const reason = Error(value?.error || '操作失敗');
    reason.code = value?.code;
    reason.fingerprint = value?.fingerprint;
    reason.previousFingerprint = value?.previousFingerprint;
    throw reason;
  }
  return value;
}

function askPassphrase() {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      unlockDialog.removeEventListener('cancel', cancel);
      unlockDialog.close();
      passphraseInput.value = '';
      resolve(value);
    };
    const cancel = (event) => { event.preventDefault(); finish(null); };
    unlockDialog.addEventListener('cancel', cancel, { once: true });
    unlockForm.onsubmit = (event) => { event.preventDefault(); finish(passphraseInput.value); };
    document.querySelector('#cancel-unlock').onclick = () => finish(null);
    unlockDialog.showModal();
    passphraseInput.focus();
  });
}

function askNewKeyPassphrase() {
  if (sshdeckConfig.mode === 'service') return Promise.resolve('');
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      keyCreateDialog.removeEventListener('cancel', cancel);
      keyCreateDialog.close();
      newKeyPassphrase.value = '';
      confirmKeyPassphrase.value = '';
      resolve(value);
    };
    const cancel = (event) => { event.preventDefault(); finish(null); };
    keyCreateDialog.addEventListener('cancel', cancel, { once: true });
    keyCreateForm.onsubmit = (event) => {
      event.preventDefault();
      if (!newKeyPassphrase.value) { error.textContent = '金鑰密語不可空白'; return; }
      if (newKeyPassphrase.value !== confirmKeyPassphrase.value) { error.textContent = '兩次輸入的金鑰密語不一致'; return; }
      finish(newKeyPassphrase.value);
    };
    document.querySelector('#cancel-key-create').onclick = () => finish(null);
    keyCreateDialog.showModal();
    newKeyPassphrase.focus();
  });
}

function askPrivateKeyFile() {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      keyImportDialog.removeEventListener('cancel', cancel);
      keyImportDialog.close();
      importKeyPassphrase.value = '';
      privateKeyFile.value = '';
      resolve(value);
    };
    const cancel = (event) => { event.preventDefault(); finish(null); };
    keyImportDialog.addEventListener('cancel', cancel, { once: true });
    keyImportForm.onsubmit = async (event) => {
      event.preventDefault();
      const file = privateKeyFile.files?.[0];
      if (!file) { error.textContent = '請選擇 OpenSSH 私鑰檔案'; return; }
      try {
        const privateKey = await file.text();
        if (!privateKey.trim()) { error.textContent = '私鑰檔案是空的'; return; }
        const value = { privateKey, passphrase: importKeyPassphrase.value };
        finish(value);
      } catch {
        error.textContent = '無法讀取私鑰檔案，請重新選取';
        privateKeyFile.value = '';
      }
    };
    document.querySelector('#cancel-key-import').onclick = () => finish(null);
    keyImportDialog.showModal();
    privateKeyFile.focus();
  });
}

function showKeyInfo(publicKey, guide = '') {
  currentPublicKey = publicKey || '';
  currentGuide = guide;
  keyInfo.hidden = !currentPublicKey && !currentGuide;
  const hasGuide = Boolean(guide);
  guideUsernameLabel.hidden = !hasGuide;
  if (hasGuide) {
    currentGuideUsername = guide.match(/登入帳號：([^\\n]+)/)?.[1] || '';
    guideUsername.value = currentGuideUsername;
  }
  renderKeyInfo();
  copyPublicKey.disabled = !currentPublicKey;
  copyGuide.disabled = !currentGuide;
}

function renderKeyInfo() {
  const quote = (value) => "'" + value.replaceAll("'", "'\\\\''") + "'";
  const guide = currentGuide.replaceAll('登入帳號：' + currentGuideUsername, '登入帳號：' + guideUsername.value)
    .replaceAll(quote(currentGuideUsername), quote(guideUsername.value));
  keyOutput.textContent = (currentPublicKey ? '公鑰：\\n' + currentPublicKey + '\\n\\n' : '') + guide;
}

function shellCommands(text) {
  return text.split(/\\r?\\n/).filter((line) => /^ {2,}\\S/.test(line)).map((line) => line.trim()).join('\\n');
}

guideUsername.addEventListener('input', renderKeyInfo);

copyPublicKey.onclick = async () => {
  try { await navigator.clipboard.writeText(currentPublicKey); error.textContent = '已複製公鑰'; }
  catch (reason) { error.textContent = '無法複製公鑰，請手動選取複製'; }
};

copyGuide.onclick = async () => {
  try { await navigator.clipboard.writeText(shellCommands(currentGuide.split(/\\n遠端撤銷/)[0])); error.textContent = '已複製授權指令'; }
  catch (reason) { error.textContent = '無法複製指令，請手動選取複製'; }
};

async function unlock(host) {
  if (sshdeckConfig.mode === 'service') {
    if (!confirm('SSHDeck service 目前已手動鎖定。要重新解鎖服務金鑰嗎？')) return false;
    await send('/api/unlock', 'POST', {});
    return true;
  }
  const passphrase = await askPassphrase();
  if (passphrase === null) return false;
  await send('/api/unlock', 'POST', { alias: host.alias, passphrase });
  return true;
}

async function checkHost(host, options = {}) {
  const automatic = options && options.automatic === true;
  const expectedFingerprint = options && options.expectedFingerprint;
  const route = '/api/hosts/' + encodeURIComponent(host.alias) + (automatic ? '/ssh-check' : '/check');
  const body = expectedFingerprint ? { expectedFingerprint } : {};
  let { response, value } = await request(route, 'POST', body);
  if (response.status === 428) {
    if (automatic) return { state: 'needs-unlock', error: value.error };
    if (!await unlock(host)) return;
    ({ response, value } = await request(route, 'POST', body));
  }
  if (response.status === 423 && value.code === 'SERVICE_LOCKED' && !automatic) {
    if (!await unlock(host)) return;
    ({ response, value } = await request(route, 'POST', body));
  }
  if (response.status === 423 && value.code === 'SERVICE_LOCKED' && automatic) {
    return { state: 'needs-unlock', error: value.error };
  }
  if (response.status === 409 && ['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(value.code)) {
    if (automatic) return { state: value.code === 'HOST_KEY_CHANGED' ? 'changed' : 'untrusted', error: value.error, fingerprint: value.fingerprint };

    const previous = value.previousFingerprint ? '（原信任 ' + value.previousFingerprint + '）' : '';
    if (!confirm('SSH 主機指紋：' + value.fingerprint + previous + '。你已從可信管道核對此指紋嗎？')) {
      const reason = Error('已拒絕主機指紋');
      reason.code = value.code;
      throw reason;
    }
    return checkHost(host, { expectedFingerprint: value.fingerprint });
  }
  if (!response.ok) throw Error(value.error || 'SSH 檢查失敗');
  return value;
}

function startShell(host, { onState = () => {} } = {}) {
  const section = document.createElement('section');
  section.dataset.alias = host.alias;
  const heading = document.createElement('h3');
  heading.textContent = '終端機：' + host.alias + '（' + host.username + '@' + host.hostname + ':' + host.port + '）';
  const close = document.createElement('button');
  close.textContent = '關閉終端機';
  const terminalElement = document.createElement('div');
  terminalElement.className = 'sshdeck-terminal';
  terminalElement.style.cssText = 'height:360px; min-width:0; background:#111; padding:6px;';
  section.append(heading, close, terminalElement);
  shellSessions.prepend(section);

  const terminal = new window.Terminal({ cursorBlink: true, convertEol: true, scrollback: 2000 });
  const fit = new window.FitAddon.FitAddon();
  terminal.loadAddon(fit);
  terminal.open(terminalElement);
  fit.fit();
  terminal.focus();
  let socket;
  let finished = false;
  let readySettled = false;
  let terminalDisposed = false;
  let resolveReady;
  let rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const handle = {
    ready,
    fit: () => resize(),
    close: () => {
      if (finished) return;
      finished = true;
      resizeObserver.disconnect();
      closeSocket();
      if (!terminalDisposed) { terminalDisposed = true; terminal.dispose(); }
      section.remove();
      if (!readySettled) { readySettled = true; rejectReady(new Error('終端連線已中斷。')); }
    },
  };
  const closeSocket = () => {
    if (socket && socket.readyState < WebSocket.CLOSING) socket.close(1000, 'terminal closed');
  };
  close.onclick = handle.close;
  onState('connecting');

  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(protocol + '//' + location.host + window.sshdeckApiPath('/api/shell') + '?alias=' + encodeURIComponent(host.alias));
  socket.binaryType = 'arraybuffer';
  const sendControl = (value) => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value));
  };
  const resize = () => {
    try { fit.fit(); sendControl({ type: 'resize', cols: terminal.cols, rows: terminal.rows }); }
    catch { /* 終端機隱藏或已移除時，等待下一次尺寸更新。 */ }
  };
  const terminalEncoder = new TextEncoder();
  terminal.onData((data) => {
    if (socket.readyState === WebSocket.OPEN) socket.send(terminalEncoder.encode(data));
  });
  terminal.onResize(({ cols, rows }) => sendControl({ type: 'resize', cols, rows }));
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(terminalElement);

  socket.onopen = resize;
  socket.onmessage = async (event) => {
    if (finished) return;
    if (typeof event.data !== 'string') {
      terminal.write(new Uint8Array(event.data));
      return;
    }
    let message;
    try { message = JSON.parse(event.data); }
    catch { terminal.write(event.data); return; }
    if (message.type === 'unlock-required') {
      try {
        if (!await unlock(host)) { socket.close(1000, 'unlock cancelled'); return; }
        sendControl({ type: 'unlocked' });
      } catch (reason) {
        terminal.write('\\r\\n金鑰解鎖失敗：' + reason.message + '\\r\\n');
        socket.close(1011, 'unlock failed');
      }
    } else if (message.type === 'trust-required' || message.type === 'host-key-changed') {
      const previous = message.previousFingerprint ? '（原信任 ' + message.previousFingerprint + '）' : '';
      if (confirm('SSH 主機指紋：' + message.fingerprint + previous + '。你已從可信管道核對此指紋嗎？')) {
        sendControl({ type: 'trust', fingerprint: message.fingerprint });
      } else {
        terminal.write('\\r\\n已拒絕主機指紋。\\r\\n');
        sendControl({ type: 'trust-reject' });
      }
    } else if (message.type === 'started') {
      terminal.write('已連線。輸入 exit 或關閉此終端機結束工作階段。\\r\\n');
      resize();
      terminal.focus();
      if (!readySettled) { readySettled = true; resolveReady(handle); }
      onState('connected');
    } else if (message.type === 'error') {
      terminal.write('\\r\\nSSH 終端機錯誤：' + message.error + '\\r\\n');
      if (!readySettled) { readySettled = true; rejectReady(new Error(message.error || 'SSH 終端機連線失敗')); }
      onState('failed', message.error || 'SSH 終端機連線失敗');
      handle.close();
    } else if (message.type === 'closed') {
      const detail = message.error ? '：' + message.error : message.code === undefined ? '' : '（結束狀態 ' + message.code + '）';
      terminal.write('\\r\\n終端機已關閉' + detail + '\\r\\n');
      finished = true;
      close.disabled = true;
      resizeObserver.disconnect();
      section.remove();
      if (!readySettled) { readySettled = true; rejectReady(new Error(message.error || '終端機在連線完成前已關閉')); }
      onState('closed', message.error || '終端機已關閉');
    }
  };
  socket.onerror = () => {
    if (finished) return;
    terminal.write('\\r\\nWebSocket 終端機連線失敗。\\r\\n');
    if (!readySettled) { readySettled = true; rejectReady(new Error('WebSocket 終端機連線失敗')); }
    onState('failed', 'WebSocket 終端機連線失敗');
    handle.close();
  };
  socket.onclose = (event) => {
    if (!finished && event.code !== 1000) terminal.write('\\r\\n終端機連線中斷（' + event.code + '）。\\r\\n');
    finished = true;
    close.disabled = true;
    resizeObserver.disconnect();
    section.remove();
    if (!terminalDisposed) { terminalDisposed = true; terminal.dispose(); }
    if (!readySettled) { readySettled = true; rejectReady(new Error('終端機連線在完成前中斷')); }
    onState('closed', event.code === 1000 ? '終端機已中斷。' : '終端機連線已中斷。');
  };
  return handle;
}

async function refresh() {
  const list = await send('/api/hosts');
  window.sshdeck.setHosts(list);
  selectedHostActions.replaceChildren();
  const selectedHost = window.sshdeck.selectedHost;
  for (const host of list) {
    if (selectedHost?.alias !== host.alias) continue;
    const item = document.createElement('section');
    item.dataset.alias = host.alias;
    const state = host.check?.state === 'success' ? 'SSH 成功'
      : host.check?.state === 'failure' ? 'SSH 失敗'
        : host.check?.state === 'changed' ? '指紋已變更'
          : host.check?.state === 'untrusted' ? '等待指紋確認' : '未檢查';
    const docker = host.check?.docker;
    const dockerState = !docker ? '未檢查'
      : docker.state === 'available' ? '可用 ' + docker.version
        : docker.state === 'permission-denied' ? '權限不足'
          : docker.state === 'missing-cli' ? 'CLI 未安裝'
            : docker.state === 'daemon-unavailable' ? 'daemon 不可用'
              : docker.state === 'not-run' ? '未執行'
                : '無法使用';
    const checked = host.check?.checkedAt ? '，最近檢查 ' + host.check.checkedAt : '';
    item.title = docker?.diagnostic || '';
    item.textContent = host.alias + ' — ' + host.username + '@' + host.hostname + ':' + host.port + '（SSH：' + state + '；Docker：' + dockerState + checked + '） ';

    const check = document.createElement('button');
    check.textContent = '檢查 SSH 與 Docker';
    check.onclick = async () => {
      error.textContent = '';
      try { await window.sshdeck.services.checkHost(host); await refresh(); }
      catch (reason) { error.textContent = reason.message; await refresh(); }
    };

    const edit = document.createElement('button');
    edit.textContent = '編輯';
    edit.onclick = async () => {
      const hostname = prompt('主機名稱', host.hostname);
      if (hostname === null) return;
      const port = prompt('連接埠', host.port);
      if (port === null) return;
      const username = prompt('登入帳號', host.username);
      if (username === null) return;
      try {
        const updated = { hostname, port: Number(port), username };
        if (sshdeckConfig.mode !== 'service') {
          const keyPath = prompt('既有金鑰路徑', host.keyPath || '');
          if (keyPath === null) return;
          updated.keyPath = keyPath;
        }
        await send('/api/hosts/' + encodeURIComponent(host.alias), 'PUT', updated);
        await refresh();
      } catch (reason) { error.textContent = reason.message; }
    };

    const remove = document.createElement('button');
    remove.textContent = '刪除';
    remove.onclick = async () => {
      try { await send('/api/hosts/' + encodeURIComponent(host.alias), 'DELETE'); await refresh(); }
      catch (reason) { error.textContent = reason.message; }
    };
    const publicKey = document.createElement('button');
    publicKey.textContent = '檢視公鑰';
    publicKey.disabled = !host.keyPath;
    publicKey.onclick = async () => {
      try {
        const result = await send('/api/hosts/' + encodeURIComponent(host.alias) + '/key/public');
        showKeyInfo(result.publicKey);
      } catch (reason) { error.textContent = reason.message; }
    };

    const guide = document.createElement('button');
    guide.textContent = '授權／撤銷指南';
    guide.disabled = !host.keyPath;
    guide.onclick = async () => {
      try {
        const result = await send('/api/hosts/' + encodeURIComponent(host.alias) + '/guide');
        showKeyInfo(result.publicKey, result.guide);
      } catch (reason) { error.textContent = reason.message; }
    };

    const keyAction = document.createElement('button');
    keyAction.textContent = host.keyPath ? (host.keyManaged ? '刪除本機金鑰' : '解除既有金鑰關聯') : '建立登入金鑰';
    keyAction.onclick = async () => {
      error.textContent = '';
      try {
        if (!host.keyPath) {
          const passphrase = await askNewKeyPassphrase();
          if (passphrase === null) return;
          const result = await send('/api/hosts/' + encodeURIComponent(host.alias) + '/key', 'POST', { passphrase });
          await refresh();
          showKeyInfo(result.publicKey, result.guide);
          return;
        }
        if (!host.keyManaged) {
          if (!confirm('只解除此主機與既有私鑰的關聯，不會刪除本機私鑰或遠端公鑰。')) return;
          await send('/api/hosts/' + encodeURIComponent(host.alias) + '/key/unlink', 'POST', {});
          await refresh();
          error.textContent = '已解除金鑰關聯；原私鑰與遠端授權均保留';
          return;
        }
        if (!confirm('刪除 sshdeck 管理的本機私鑰？遠端 authorized_keys 授權不會自動撤銷。請先取得／保存撤銷指南。')) return;
        const result = await send('/api/hosts/' + encodeURIComponent(host.alias) + '/key/delete', 'POST', {});
        await refresh();
        showKeyInfo(result.publicKey, result.guide);
        error.textContent = '本機私鑰已刪除；遠端公鑰仍授權，請手動依指南撤銷';
      } catch (reason) { error.textContent = reason.message; }
    };

    item.append(check, edit, remove, publicKey, guide, keyAction);
    const importKey = document.createElement('button');
    importKey.textContent = '匯入登入金鑰';
    importKey.disabled = Boolean(host.keyPath);
    importKey.onclick = async () => {
      error.textContent = '';
      const input = await askPrivateKeyFile();
      if (!input) return;
      try {
        const result = await send('/api/hosts/' + encodeURIComponent(host.alias) + '/key/import', 'POST', input);
        await refresh();
        showKeyInfo(result.publicKey, result.guide);
      } catch (reason) {
        error.textContent = reason.message + '；可重新選取私鑰檔案後再試';
      } finally {
        input.privateKey = '';
        input.passphrase = '';
      }
    };
    item.append(importKey);
    if (host.keyPath && host.keyManaged) {
      const unlinkManaged = document.createElement('button');
      unlinkManaged.textContent = '解除此主機關聯';
      unlinkManaged.onclick = async () => {
        if (!confirm('只解除主機關聯；sshdeck 管理的本機金鑰會保留在金鑰清單，遠端授權不變。')) return;
        try {
          await send('/api/hosts/' + encodeURIComponent(host.alias) + '/key/unlink', 'POST', {});
          await refresh();
          error.textContent = '已解除主機關聯；本機金鑰與遠端授權均保留';
        } catch (reason) { error.textContent = reason.message; }
      };
      item.append(unlinkManaged);
    }
    const heading = document.createElement('h3');
    heading.textContent = '選定主機：' + host.alias + '（' + host.username + '@' + host.hostname + ':' + host.port + '）';
    selectedHostActions.append(heading, item);
  }
  const execTargetHint = document.querySelector('#exec-target-hint');
  execTargetHint.textContent = selectedHost ? '遠端命令目標：' + selectedHost.alias + '（' + selectedHost.username + '@' + selectedHost.hostname + ':' + selectedHost.port + '）' : '請先從主機列表選取操作目標。';
  document.querySelector('#exec-form button').disabled = !selectedHost;
  const records = await send('/api/keys');
  managedKeys.replaceChildren();
  for (const record of records) {
    const item = document.createElement('li');
    item.dataset.keyId = record.id;
    const state = record.associatedAliases.length ? '使用中：' + record.associatedAliases.join(', ') : '未關聯主機';
    item.textContent = record.alias + '（' + record.id + '）— ' + (record.username || '未設定帳號') + '@' + (record.hostname || '未設定主機') + '；' + state + ' ';
    const view = document.createElement('button');
    view.textContent = '公鑰／撤銷指南';
    view.onclick = async () => {
      try {
        const info = await send('/api/keys/' + encodeURIComponent(record.id) + '/guide');
        showKeyInfo(info.publicKey, info.guide);
      } catch (reason) { error.textContent = reason.message; }
    };
    const remove = document.createElement('button');
    remove.textContent = '刪除本機金鑰';
    remove.onclick = async () => {
      if (record.associatedAliases.length) { error.textContent = '金鑰仍被主機設定使用，請先解除所有關聯'; return; }
      if (!confirm('刪除本機私鑰？遠端 authorized_keys 不會自動撤銷。請先保存撤銷指南。')) return;
      try {
        const result = await send('/api/keys/' + encodeURIComponent(record.id) + '/delete', 'POST', {});
        showKeyInfo(result.publicKey, result.guide);
        error.textContent = '本機金鑰已刪除；遠端授權仍存在，請手動撤銷';
        await refresh();
      } catch (reason) { error.textContent = reason.message; }
    };
    item.append(view, remove);
    managedKeys.append(item);
  }
}

async function runRemoteCommand(host, command, controller, output, expectedFingerprint) {
  let response = await fetch('/api/exec', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ alias: host.alias, command, ...(expectedFingerprint ? { expectedFingerprint } : {}) }),
    signal: controller.signal,
  });
  if (response.status === 428) {
    if (!await unlock(host)) throw Error('已取消金鑰解鎖');
    return runRemoteCommand(host, command, controller, output, expectedFingerprint);
  }
  if (response.status === 423 && sshdeckConfig.mode === 'service') {
    if (!await unlock(host)) throw Error('已取消服務解鎖');
    return runRemoteCommand(host, command, controller, output, expectedFingerprint);
  }
  if (response.status === 409) {
    const challenge = await response.json();
    if (['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(challenge.code)) {
      const previous = challenge.previousFingerprint ? '（原信任 ' + challenge.previousFingerprint + '）' : '';
      if (!confirm('SSH 主機指紋：' + challenge.fingerprint + previous + '。你已從可信管道核對此指紋嗎？')) throw Error('已拒絕主機指紋；未執行命令');
      return runRemoteCommand(host, command, controller, output, challenge.fingerprint);
    }
    throw Error(challenge.error || '遠端命令失敗');
  }
  if (!response.ok) throw Error((await response.json()).error || '遠端命令失敗');

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    pending += decoder.decode(value, { stream: true });
    const lines = pending.split('\\n');
    pending = lines.pop();
    for (const line of lines) {
      if (!line) continue;
      const event = JSON.parse(line);
      if (event.type === 'stdout' || event.type === 'stderr') output.textContent += event.data;
      else if (event.type === 'exit') output.textContent += '\\n結束狀態：' + event.code;
      else if (event.type === 'error') throw Error(event.error || '遠端命令失敗');
    }
  }
}

document.querySelector('#exec-form').onsubmit = async (event) => {
  event.preventDefault();
  const sessions = document.querySelector('#exec-sessions');
  const alias = window.sshdeck.selectedHost?.alias;
  const command = document.querySelector('#exec-command').value;
  if (!alias || !command.trim()) return;
  const host = (await send('/api/hosts')).find((item) => item.alias === alias);
  if (!host) { error.textContent = '找不到主機：' + alias; return; }
  const section = document.createElement('section');
  section.dataset.alias = host.alias;
  const heading = document.createElement('h3');
  heading.textContent = '目標：' + host.alias + '（' + host.username + '@' + host.hostname + ':' + host.port + '） ' + command;
  const output = document.createElement('pre');
  const cancel = document.createElement('button');
  cancel.textContent = '取消此命令';
  const controller = new AbortController();
  cancel.onclick = () => controller.abort();
  section.append(heading, cancel, output);
  sessions.prepend(section);
  output.textContent = '';
  try { await runRemoteCommand(host, command, controller, output); }
  catch (reason) { output.textContent += '\\n' + (reason.name === 'AbortError' ? '已取消' : reason.message); }
  finally { cancel.disabled = true; }
};

document.querySelector('#lock-keys').onclick = async () => {
  try { await send('/api/lock', 'POST', {}); error.textContent = '已鎖定所有登入金鑰'; }
  catch (reason) { error.textContent = reason.message; }
};

window.sshdeck.configure({ request, send, unlock, checkHost, checkSSH: (host, options = {}) => checkHost(host, { ...options, automatic: true }), startShell, refresh, showKeyInfo, askNewKeyPassphrase });
if (sshdeckConfig.mode === 'service') {
  document.querySelector('#service-mode-note').hidden = false;
  document.querySelector('#connect-host').hidden = true;
  document.querySelector('#terminal-workspace').hidden = true;
  document.querySelector('#lock-keys').textContent = '手動鎖定 service 金鑰';
  document.querySelector('#lock-keys').onclick = async () => {
    try { await send('/api/lock', 'POST', {}); error.textContent = '服務金鑰已手動鎖定；重新檢查時可明確解鎖'; }
    catch (reason) { error.textContent = reason.message; }
  };
}
window.sshdeck.on('selectionchange', (event) => { if (event.detail.reason === 'select') window.sshdeck.services.refresh().catch((reason) => { error.textContent = reason.message; }); });
refresh().catch((reason) => { error.textContent = reason.message; document.querySelector('#hosts-loading').textContent = '無法載入受管主機，請重新整理重試。'; });
</script>
<script src="__SSHDECK_BASE_PATH__/assets/terminal.js"></script>
<script src="__SSHDECK_BASE_PATH__/assets/connection-guide.js?v=2"></script>
</body>
</html>`;

function renderPage({ basePath = '', mode = 'standalone', returnTo = '/workspace' } = {}) {
  const configuration = JSON.stringify({ basePath, mode })
    .replaceAll('<', '\\u003c')
    .replaceAll('>', '\\u003e')
    .replaceAll('&', '\\u0026')
    .replaceAll('\u2028', '\\u2028')
    .replaceAll('\u2029', '\\u2029');
  const safeReturnTo = safeReturnPath(returnTo)
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
  return page
    .replaceAll('__SSHDECK_BASE_PATH__', basePath)
    .replace('__SSHDECK_RETURN_TO__', safeReturnTo)
    .replace('__SSHDECK_CONFIG__', configuration);
}

async function handleServiceUiRequest(routePath, req, res, serviceConfig, send) {
  const serviceRequest = async (route, method = 'GET', body, signal) => fetch(`${serviceConfig.origin}${route}`, {
    method,
    headers: {
      authorization: `Bearer ${serviceConfig.token}`,
      accept: 'application/json',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    ...(signal ? { signal } : { signal: AbortSignal.timeout(15_000) }),
  });
  const readPayload = async (response) => {
    if (response.status === 204) return null;
    try { return await response.json(); } catch {
      throw Object.assign(new Error('SSHDeck service 回應格式無效'), { status: 502, code: 'SERVICE_RESPONSE_INVALID' });
    }
  };
  const proxyJson = async (route, method = 'GET', body, transform) => {
    const response = await serviceRequest(route, method, body);
    const payload = await readPayload(response);
    return send(response.status, response.ok && transform ? transform(payload) : payload);
  };
  const requestJson = async () => {
    try { return await readJsonBody(req); }
    catch (error) { return send(error.status || 400, { error: error.message }); }
  };
  const aliasRoute = /^\/api\/hosts\/([^/]+)(?:\/(check|ssh-check|key(?:\/(?:create|import|link|unlink|delete))?|guide|key\/public))?$/.exec(routePath);
  const alias = aliasRoute ? decodeURIComponent(aliasRoute[1]) : null;
  const action = aliasRoute?.[2] || '';

  if (req.method === 'GET' && routePath === '/api/hosts') {
    const [hostsResponse, keysResponse] = await Promise.all([
      serviceRequest('/v1/hosts'),
      serviceRequest('/v1/keys'),
    ]);
    const hosts = await readPayload(hostsResponse);
    if (!hostsResponse.ok) return send(hostsResponse.status, hosts);
    const keys = await readPayload(keysResponse);
    if (!keysResponse.ok) return send(keysResponse.status, keys);
    const keyByAlias = new Map();
    for (const record of keys) {
      for (const associatedAlias of record.associatedAliases || []) keyByAlias.set(associatedAlias, record);
    }
    return send(200, hosts.map((host) => {
      const record = keyByAlias.get(host.alias);
      return {
        ...host,
        ...(record ? { keyPath: `service-key:${record.id}` } : {}),
        keyManaged: Boolean(record),
      };
    }));
  }
  if (req.method === 'GET' && routePath === '/api/keys') {
    return proxyJson('/v1/keys', 'GET', undefined, (records) => records.map((record) => ({
      ...record,
      keyPath: `service-key:${record.id}`,
    })));
  }
  if (req.method === 'POST' && routePath === '/api/lock') return proxyJson('/v1/lock', 'POST', {});
  if (req.method === 'POST' && routePath === '/api/unlock') return proxyJson('/v1/unlock', 'POST', {});
  if (req.method === 'POST' && routePath === '/api/hosts') {
    const body = await requestJson();
    if (!body || res.writableEnded) return;
    if (Object.hasOwn(body, 'keyPath')) return send(400, { code: 'INVALID_HOST', error: '服務主機不可指定本機私鑰路徑' });
    return proxyJson('/v1/hosts', 'POST', body);
  }
  if (req.method === 'POST' && routePath === '/api/exec') {
    const body = await requestJson();
    if (!body || res.writableEnded) return;
    if (typeof body.alias !== 'string' || !body.alias || typeof body.command !== 'string' || !body.command.trim()) {
      return send(400, { code: 'INVALID_COMMAND', error: '請提供主機別名與遠端命令' });
    }
    const controller = new AbortController();
    const abort = () => controller.abort();
    req.once('aborted', abort);
    res.once('close', () => { if (!res.writableEnded) abort(); });
    try {
      const response = await serviceRequest(`/v1/hosts/${encodeURIComponent(body.alias)}/exec`, 'POST', {
        command: body.command,
        ...(typeof body.expectedFingerprint === 'string' ? { expectedFingerprint: body.expectedFingerprint } : {}),
      }, controller.signal);
      if (!response.ok) return send(response.status, await readPayload(response));
      res.writeHead(response.status, {
        'content-type': response.headers.get('content-type') || 'application/x-ndjson; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'x-accel-buffering': 'no',
      });
      if (response.body) {
        for await (const chunk of response.body) {
          if (res.destroyed) break;
          if (!res.write(Buffer.from(chunk))) await new Promise((resolve) => res.once('drain', resolve));
        }
      }
      if (!res.destroyed) res.end();
    } catch (error) {
      if (!res.destroyed && !res.headersSent) send(error.status || 502, { code: error.code || 'SERVICE_DISCONNECTED', error: error.message || 'SSHDeck service 連線中斷' });
      else if (!res.destroyed) res.destroy(error);
    } finally {
      req.off('aborted', abort);
    }
    return;
  }

  const keyRecordRoute = /^\/api\/keys\/([^/]+)\/(public|guide|delete)$/.exec(routePath);
  if (keyRecordRoute) {
    const id = decodeURIComponent(keyRecordRoute[1]);
    const actionName = keyRecordRoute[2];
    const keysResponse = await serviceRequest('/v1/keys');
    const keys = await readPayload(keysResponse);
    if (!keysResponse.ok) return send(keysResponse.status, keys);
    const record = keys.find((item) => item.id === id);
    if (!record) return send(404, { code: 'KEY_NOT_FOUND', error: '找不到服務管理的金鑰' });
    const guide = ssh.installationGuide(record, record.publicKey);
    if (req.method === 'GET' && actionName !== 'delete') {
      return send(200, actionName === 'public' ? { publicKey: record.publicKey } : { publicKey: record.publicKey, guide });
    }
    if (req.method === 'POST' && actionName === 'delete') {
      if (record.associatedAliases?.length) return send(409, { code: 'KEY_IN_USE', error: '金鑰仍與主機設定關聯，請先解除所有關聯' });
      const response = await serviceRequest(`/v1/keys/${encodeURIComponent(id)}`, 'DELETE');
      const payload = await readPayload(response);
      return send(response.status, response.ok ? { ...payload, publicKey: record.publicKey, guide } : payload);
    }
  }

  if (aliasRoute) {
    const encodedAlias = encodeURIComponent(alias);
    if (!action && req.method === 'PUT') {
      const body = await requestJson();
      if (!body || res.writableEnded) return;
      if (Object.hasOwn(body, 'alias') || Object.hasOwn(body, 'keyPath')) {
        return send(400, { code: 'INVALID_HOST', error: '服務主機不可指定 alias 或本機私鑰路徑' });
      }
      return proxyJson(`/v1/hosts/${encodedAlias}`, 'PUT', body);
    }
    if (!action && req.method === 'DELETE') return proxyJson(`/v1/hosts/${encodedAlias}`, 'DELETE');
    if ((action === 'check' || action === 'ssh-check') && req.method === 'POST') {
      const body = await requestJson();
      if (!body || res.writableEnded) return;
      return proxyJson(`/v1/hosts/${encodedAlias}/check`, 'POST', body);
    }
    if ((action === 'guide' || action === 'key/public') && req.method === 'GET') {
      const response = await serviceRequest(`/v1/hosts/${encodedAlias}/key`);
      const payload = await readPayload(response);
      if (!response.ok) return send(response.status, payload);
      return send(200, action === 'key/public' ? { publicKey: payload.publicKey } : payload);
    }
    if (action === 'key' && req.method === 'POST') {
      return proxyJson(`/v1/hosts/${encodedAlias}/key/create`, 'POST', {});
    }
    if (action === 'key/import' && req.method === 'POST') {
      const body = await requestJson();
      if (!body || res.writableEnded) return;
      if (typeof body.privateKey !== 'string' || !body.privateKey.trim()
        || (body.passphrase !== undefined && typeof body.passphrase !== 'string')) {
        return send(400, { code: 'INVALID_KEY', error: '匯入需要 OpenSSH 私鑰檔案及可選密語' });
      }
      return proxyJson(`/v1/hosts/${encodedAlias}/key/import`, 'POST', body);
    }
    if (action === 'key/link' && req.method === 'POST') {
      const body = await requestJson();
      if (!body || res.writableEnded) return;
      const keysResponse = await serviceRequest('/v1/keys');
      const keys = await readPayload(keysResponse);
      if (!keysResponse.ok) return send(keysResponse.status, keys);
      const record = keys.find((item) => item.id === body.keyId || `service-key:${item.id}` === body.keyPath);
      if (!record) return send(404, { code: 'KEY_NOT_FOUND', error: '找不到服務管理的金鑰' });
      return proxyJson(`/v1/hosts/${encodedAlias}/key/link`, 'POST', { keyId: record.id });
    }
    if (action === 'key/unlink' && req.method === 'POST') return proxyJson(`/v1/hosts/${encodedAlias}/key/unlink`, 'POST', {});
    if (action === 'key/delete' && req.method === 'POST') {
      const keysResponse = await serviceRequest('/v1/keys');
      const keys = await readPayload(keysResponse);
      if (!keysResponse.ok) return send(keysResponse.status, keys);
      const record = keys.find((item) => item.associatedAliases?.includes(alias));
      if (!record) return send(404, { code: 'KEY_NOT_FOUND', error: '找不到此主機關聯的服務管理金鑰' });
      if (record.associatedAliases.length > 1) return send(409, { code: 'KEY_IN_USE', error: '此金鑰仍與其他主機共用，請先解除所有關聯' });
      const guide = ssh.installationGuide(record, record.publicKey);
      const unlinked = await serviceRequest(`/v1/hosts/${encodedAlias}/key/unlink`, 'POST', {});
      const unlinkPayload = await readPayload(unlinked);
      if (!unlinked.ok) return send(unlinked.status, unlinkPayload);
      const deleted = await serviceRequest(`/v1/keys/${encodeURIComponent(record.id)}`, 'DELETE');
      const deletePayload = await readPayload(deleted);
      if (!deleted.ok) {
        return send(deleted.status, {
          ...deletePayload,
          error: `已解除主機關聯，但金鑰尚未刪除；請重新整理後確認狀態。${deletePayload?.error ? ` ${deletePayload.error}` : ''}`,
        });
      }
      return send(deleted.status, { ...deletePayload, publicKey: record.publicKey, guide });
    }
  }

  return send(404, { code: 'NOT_FOUND', error: '找不到路徑' });
}

function createServer({
  dataFile,
  port,
  basePath = '',
  mode = 'standalone',
  serviceConfig,
  allowedHosts = [],
  allowedOrigins = [],
}) {
  const unlockedKeys = new Map();
  const webSocketServer = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024, perMessageDeflate: false });
  const assets = {
    '/assets/xterm.js': [require.resolve('@xterm/xterm/lib/xterm.js', { paths: [__dirname] }), 'text/javascript'],
    '/assets/xterm.css': [require.resolve('@xterm/xterm/css/xterm.css', { paths: [__dirname] }), 'text/css'],
    '/assets/addon-fit.js': [require.resolve('@xterm/addon-fit/lib/addon-fit.js', { paths: [__dirname] }), 'text/javascript'],
    '/assets/workspace.js': [path.join(__dirname, '..', 'public', 'workspace.js'), 'text/javascript'],
    '/assets/workspace.css': [path.join(__dirname, '..', 'public', 'workspace.css'), 'text/css'],
    '/assets/terminal.js': [path.join(__dirname, '..', 'public', 'terminal.js'), 'text/javascript'],
    '/assets/connection-guide.js': [path.join(__dirname, '..', 'public', 'connection-guide.js'), 'text/javascript'],
  };
  const server = http.createServer((req, res) => {
    const send = (status, value, contentType = 'application/json') => {
      res.writeHead(status, { 'content-type': `${contentType}; charset=utf-8`, 'cache-control': 'no-store' });
      res.end(contentType === 'application/json' ? JSON.stringify(value) : value);
    };
    const requestUrl = new URL(req.url, `http://127.0.0.1:${server.address()?.port || port}`);
    if (!trustedUiRequest(req, server.address()?.port || port, { allowedHosts, allowedOrigins })) {
      return send(403, { error: '不允許的 Host 或 Origin' });
    }
    if (basePath && requestUrl.pathname === basePath && req.method === 'GET') {
      res.writeHead(308, { location: `${basePath}/${requestUrl.search}`, 'cache-control': 'no-store' });
      return res.end();
    }
    if (basePath && requestUrl.pathname !== basePath && !requestUrl.pathname.startsWith(`${basePath}/`)) {
      return send(404, { error: '找不到路徑' });
    }
    const routePath = basePath ? requestUrl.pathname.slice(basePath.length) || '/' : requestUrl.pathname;
    if (req.method === 'GET' && routePath === '/') {
      const returnTo = requestUrl.searchParams.get('returnTo') ?? requestUrl.searchParams.get('return');
      return send(200, renderPage({ basePath, mode, returnTo }), 'text/html');
    }
    const assetPath = routePath;
    if (req.method === 'GET' && assets[assetPath]) {
      const [file, contentType] = assets[assetPath];
      if (!fs.existsSync(file)) return send(404, { error: '找不到靜態資產' });
      const stream = fs.createReadStream(file);
      stream.once('error', () => {
        if (res.headersSent) res.destroy();
        else send(500, { error: '無法讀取靜態資產' });
      });
      res.writeHead(200, { 'content-type': `${contentType}; charset=utf-8`, 'cache-control': 'no-store' });
      stream.pipe(res);
      return;
    }
    if (mode === 'service') {
      handleServiceUiRequest(routePath, req, res, serviceConfig, send).catch((error) => {
        if (!res.destroyed && !res.headersSent) send(error.status || 502, {
          code: error.code || 'SERVICE_UNAVAILABLE',
          error: error.message || 'SSHDeck service 無法連線',
        });
        else if (!res.destroyed) res.destroy(error);
      });
      return;
    }
    if (req.method === 'GET' && routePath === '/api/keys') {
      try {
        const hosts = readHosts(dataFile);
        const records = ssh.listManagedKeys(dataFile).map((record) => ({
          ...record,
          associatedAliases: hosts.filter((host) => host.keyPath === record.keyPath).map((host) => host.alias),
        }));
        return send(200, records);
      } catch (error) { return send(500, { error: error.message }); }
    }
    const managedKeyRoute = routePath.match(/^\/api\/keys\/([^/?]+)\/(public|guide|delete)$/);
    if (req.method === 'GET' && managedKeyRoute && managedKeyRoute[2] !== 'delete') {
      try {
        const record = ssh.resolveManagedKey(dataFile, decodeURIComponent(managedKeyRoute[1]));
        const publicKey = ssh.managedPublicKey(record.keyPath);
        return send(200, managedKeyRoute[2] === 'public' ? { publicKey } : { publicKey, guide: ssh.installationGuide(record, publicKey) });
      } catch (error) { return send(404, { error: error.message }); }
    }
    if (req.method === 'GET' && routePath === '/api/hosts') {
      try {
        return send(200, readHosts(dataFile).map((host) => ({
          ...host,
          keyManaged: ssh.isManagedKeyPath(dataFile, host.keyPath),
          check: ssh.statusForHost(dataFile, host),
        })));
      } catch (error) { return send(500, { error: error.message }); }
    }

    if (req.method === 'POST' && routePath === '/api/lock') {
      unlockedKeys.clear();
      res.writeHead(204, { 'cache-control': 'no-store' });
      return res.end();
    }
    const match = routePath.match(/^\/api\/hosts\/([^/?]+)(?:\/(check|ssh-check))?$/);
    const checking = Boolean(match && ['check', 'ssh-check'].includes(match[2]));
    const sshOnlyCheck = Boolean(match && match[2] === 'ssh-check');
    const keyActionMatch = routePath.match(/^\/api\/hosts\/([^/?]+)\/key\/(delete|unlink)$/);
    const managedKeyDelete = Boolean(managedKeyRoute && managedKeyRoute[2] === 'delete' && req.method === 'POST');
    const keyPublicMatch = routePath.match(/^\/api\/hosts\/([^/?]+)\/key\/public$/);
    const keyGuideMatch = routePath.match(/^\/api\/hosts\/([^/?]+)\/guide$/);
    const keyCreate = req.method === 'POST' && /^\/api\/hosts\/[^/?]+\/key$/.test(routePath);
    const keyImport = req.method === 'POST' && /^\/api\/hosts\/[^/?]+\/key\/import$/.test(routePath);
    const collection = routePath === '/api/hosts';
    const unlockRequest = req.method === 'POST' && routePath === '/api/unlock';
    const executing = req.method === 'POST' && routePath === '/api/exec';
    if (req.method === 'GET' && (keyPublicMatch || keyGuideMatch)) {
      try {
        const alias = decodeURIComponent((keyPublicMatch || keyGuideMatch)[1]);
        const host = readHosts(dataFile).find((item) => item.alias === alias);
        if (!host || !host.keyPath) return send(404, { error: `找不到登入金鑰：${alias}` });
        const publicKey = ssh.managedPublicKey(host.keyPath);
        return send(200, keyPublicMatch ? { publicKey } : { publicKey, guide: ssh.installationGuide(host, publicKey) });
      } catch (error) { return send(400, { error: error.message }); }
    }
    const keyOperation = Boolean(keyActionMatch && req.method === 'POST');
    if (!unlockRequest && !executing && !keyCreate && !keyImport && !keyOperation && !managedKeyDelete && !(collection && req.method === 'POST') && !(checking && req.method === 'POST') && !(match && !checking && ['PUT', 'DELETE'].includes(req.method))) return send(404, { error: '找不到路徑' });
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > 256 * 1024) {
        send(413, { error: '要求內容過大' });
        req.destroy();
      }
    });
    req.on('end', async () => {
      try {
        const alias = match && decodeURIComponent(match[1]);
        const input = JSON.parse(body || '{}');
        if (executing) {
          const host = readHosts(dataFile).find((item) => item.alias === input.alias);
          if (!host) return send(404, { error: `找不到主機：${input.alias || ''}` });
          const keyPath = ssh.keyPathFor(host);
          if (!unlockedKeys.has(keyPath)) return send(428, { error: '請先解鎖此主機的登入金鑰' });
          const abort = new AbortController();
          res.on('close', () => { if (!res.writableEnded) abort.abort(); });
          const stdoutDecoder = new StringDecoder('utf8');
          const stderrDecoder = new StringDecoder('utf8');
          const writeOutput = (type, text) => { if (text && !res.destroyed) res.write(JSON.stringify({ type, data: text }) + '\n'); };
          let started = false;
          try {
            const code = await ssh.exec(dataFile, host, unlockedKeys.get(keyPath), input.command, {
              signal: abort.signal,
              ...(typeof input.expectedFingerprint === 'string' ? { expectedFingerprint: input.expectedFingerprint } : {}),
              onStart: () => {
                started = true;
                res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store' });
                res.flushHeaders();
              },
              onStdout: (chunk) => writeOutput('stdout', stdoutDecoder.write(chunk)),
              onStderr: (chunk) => writeOutput('stderr', stderrDecoder.write(chunk)),
            });
            writeOutput('stdout', stdoutDecoder.end());
            writeOutput('stderr', stderrDecoder.end());
            if (!res.destroyed) res.end(JSON.stringify({ type: 'exit', code }) + '\n');
          } catch (error) {
            if (error.code === 'INVALID_KEY_PASSPHRASE' || error.code === 'INVALID_PRIVATE_KEY') unlockedKeys.delete(keyPath);
            if (res.destroyed) return;
            if (!started) {
              const status = ['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(error.code) ? 409 : error.code === 'AUTHENTICATION_FAILED' ? 401 : 502;
              return send(status, { code: error.code || 'REMOTE_EXEC_FAILED', error: error.message, fingerprint: error.fingerprint, previousFingerprint: error.previousFingerprint });
            }
            writeOutput('stdout', stdoutDecoder.end());
            writeOutput('stderr', stderrDecoder.end());
            res.end(JSON.stringify({ type: 'error', code: error.code, error: error.message }) + '\n');
          }
          return;
        }
        if (managedKeyDelete) {
          const id = decodeURIComponent(managedKeyRoute[1]);
          const record = ssh.resolveManagedKey(dataFile, id);
          const associated = readHosts(dataFile).filter((host) => host.keyPath === record.keyPath);
          if (associated.length) return send(409, { error: `金鑰仍由主機設定使用：${associated.map((host) => host.alias).join(', ')}` });
          const publicKey = ssh.managedPublicKey(record.keyPath);
          const guide = ssh.installationGuide(record, publicKey);
          unlockedKeys.delete(record.keyPath);
          ssh.deleteManagedKey(dataFile, record.keyPath);
          return send(200, { deleted: true, publicKey, guide });
        }
        if (keyOperation) {
          const keyAlias = decodeURIComponent(keyActionMatch[1]);
          const action = keyActionMatch[2];
          const host = readHosts(dataFile).find((item) => item.alias === keyAlias);
          if (!host || !host.keyPath) return send(404, { error: `找不到已關聯的登入金鑰：${keyAlias}` });
          const managed = ssh.isManagedKeyPath(dataFile, host.keyPath);
          if (action === 'unlink') {
            const oldPath = ssh.keyPathFor(host);
            mutateHosts(dataFile, (hosts) => {
              const current = hosts.find((item) => item.alias === keyAlias);
              if (!current) throw new Error(`找不到主機：${keyAlias}`);
              delete current.keyPath;
            });
            unlockedKeys.delete(oldPath);
            res.writeHead(204, { 'cache-control': 'no-store' });
            return res.end();
          }
          if (!managed) return send(409, { error: '此私鑰由使用者管理；解除關聯不會刪除檔案' });
          const shared = readHosts(dataFile).filter((item) => item.alias !== keyAlias && item.keyPath === host.keyPath);
          if (shared.length) return send(409, { error: `此金鑰仍由其他設定共用：${shared.map((item) => item.alias).join(', ')}` });
          const publicKey = ssh.managedPublicKey(host.keyPath);
          const guide = ssh.installationGuide(host, publicKey);
          mutateHosts(dataFile, (hosts) => {
            const current = hosts.find((item) => item.alias === keyAlias);
            if (!current) throw new Error(`找不到主機：${keyAlias}`);
            delete current.keyPath;
          });
          try { ssh.deleteManagedKey(dataFile, host.keyPath); }
          catch (error) {
            try { mutateHosts(dataFile, (hosts) => { const current = hosts.find((item) => item.alias === keyAlias); if (current) current.keyPath = host.keyPath; }); }
            catch (restoreError) { return send(500, { error: `本機金鑰刪除失敗，且無法恢復設定：${error.message}; ${restoreError.message}` }); }
            throw error;
          }
          unlockedKeys.delete(host.keyPath);
          return send(200, { deleted: true, publicKey, guide });
        }
        if (keyCreate) {
          const keyAlias = decodeURIComponent(routePath.match(/^\/api\/hosts\/([^/?]+)\/key$/)[1]);
          const host = readHosts(dataFile).find((item) => item.alias === keyAlias);
          if (!host) return send(404, { error: `找不到主機：${keyAlias}` });
          if (host.keyPath) return send(409, { error: '此主機已關聯登入金鑰，請先解除關聯或刪除 sshdeck 金鑰' });
          const made = ssh.createManagedKey(dataFile, keyAlias, input.passphrase, host);
          try { mutateHosts(dataFile, (hosts) => { const target = hosts.find((item) => item.alias === keyAlias); if (!target) throw new Error(`找不到主機：${keyAlias}`); target.keyPath = made.keyPath; }); }
          catch (error) { ssh.deleteManagedKey(dataFile, made.keyPath); throw error; }
          unlockedKeys.set(made.keyPath, input.passphrase);
          return send(201, { publicKey: made.publicKey, guide: ssh.installationGuide(host, made.publicKey) });
        }
        if (keyImport) {
          const keyAlias = decodeURIComponent(routePath.match(/^\/api\/hosts\/([^/?]+)\/key\/import$/)[1]);
          const host = readHosts(dataFile).find((item) => item.alias === keyAlias);
          if (!host) return send(404, { error: `找不到主機：${keyAlias}` });
          if (host.keyPath) return send(409, { error: '此主機已關聯登入金鑰，請先解除關聯' });
          if (typeof input.privateKey !== 'string' || !input.privateKey.trim()
            || (input.passphrase !== undefined && typeof input.passphrase !== 'string')) {
            return send(400, { code: 'INVALID_KEY', error: '匯入需要 OpenSSH 私鑰檔案及可選密語' });
          }
          const passphrase = input.passphrase || '';
          let stored;
          try {
            const privateKey = Buffer.from(input.privateKey);
            const parsed = ssh.parsePrivateKey(privateKey, passphrase);
            const publicKey = `${parsed.type} ${parsed.getPublicSSH().toString('base64')}`;
            stored = ssh.storeManagedKey(dataFile, { alias: keyAlias, privateKey, publicKey, profile: host });
            try {
              mutateHosts(dataFile, (hosts) => {
                const target = hosts.find((item) => item.alias === keyAlias);
                if (!target || target.keyPath) throw new Error('主機設定已變更，拒絕覆寫金鑰關聯');
                target.keyPath = stored.keyPath;
              });
            } catch (error) {
              ssh.deleteManagedKey(dataFile, stored.keyPath);
              throw error;
            }
            unlockedKeys.set(stored.keyPath, passphrase);
            return send(201, {
              id: stored.id,
              publicKey: stored.publicKey,
              guide: ssh.installationGuide(host, stored.publicKey),
            });
          } catch (error) {
            return send(error.status || 400, {
              code: error.code || 'INVALID_KEY',
              error: error.message || '私鑰匯入失敗',
            });
          }
        }
        if (unlockRequest) {
          const host = readHosts(dataFile).find((item) => item.alias === input.alias);
          if (!host) return send(404, { error: `找不到主機：${input.alias || ''}` });
          const keyPath = ssh.validateKey(host, typeof input.passphrase === 'string' ? input.passphrase : '');
          unlockedKeys.set(keyPath, typeof input.passphrase === 'string' ? input.passphrase : '');
          res.writeHead(204, { 'cache-control': 'no-store' });
          return res.end();
        }
        if (checking) {
          const host = readHosts(dataFile).find((item) => item.alias === alias);
          if (!host) return send(404, { error: `找不到主機：${alias}` });
          const keyPath = ssh.keyPathFor(host);
          if (!unlockedKeys.has(keyPath)) return send(428, { code: 'NEEDS_UNLOCK', error: '請先解鎖此主機的登入金鑰' });
          try {
            const result = sshOnlyCheck
              ? await ssh.checkSSH(dataFile, host, unlockedKeys.get(keyPath), { ...(typeof input.expectedFingerprint === 'string' ? { expectedFingerprint: input.expectedFingerprint } : {}) })
              : await ssh.checkWithDocker(dataFile, host, unlockedKeys.get(keyPath), {
              ...(typeof input.expectedFingerprint === 'string' ? { expectedFingerprint: input.expectedFingerprint } : {}),
            });
            return send(200, result);
          } catch (error) {
            if (error.code === 'INVALID_KEY_PASSPHRASE' || error.code === 'INVALID_PRIVATE_KEY') unlockedKeys.delete(keyPath);
            if (['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(error.code)) {
              return send(409, {
                code: error.code,
                error: error.message,
                fingerprint: error.fingerprint,
                previousFingerprint: error.previousFingerprint,
              });
            }
            const status = error.code === 'AUTHENTICATION_FAILED' ? 401 : 502;
            return send(status, {
              code: error.code || 'SSH_CHECK_FAILED',
              error: error.message,
              docker: ssh.getStatuses(dataFile)[alias]?.docker,
            });
          }
        }
        if (req.method === 'DELETE') {
          mutateHosts(dataFile, (hosts) => {
            const index = hosts.findIndex((host) => host.alias === alias);
            if (index < 0) throw new Error(`找不到主機：${alias}`);
            hosts.splice(index, 1);
          });
          res.writeHead(204, { 'cache-control': 'no-store' });
          return res.end();
        }
        if (req.method === 'POST') {
          let created;
          mutateHosts(dataFile, (hosts) => {
            created = validateHost(input);
            if (hosts.some((host) => host.alias === created.alias)) throw new Error(`主機別名已存在：${created.alias}`);
            hosts.push(created);
          });
          return send(201, created);
        }
        let updated;
        mutateHosts(dataFile, (hosts) => {
          const index = hosts.findIndex((host) => host.alias === alias);
          if (index < 0) throw new Error(`找不到主機：${alias}`);
          const patch = { ...input };
          delete patch.alias;
          updated = validateHost({ ...hosts[index], ...patch });
          hosts[index] = updated;
        });
        ssh.updateManagedKeyProfile(dataFile, updated);
        return send(200, updated);
      } catch (error) {
        return send(400, { error: error.message });
      }
    });
  });
  server.on('upgrade', (req, socket, head) => {
    let requestUrl;
    try { requestUrl = new URL(req.url, `http://127.0.0.1:${server.address()?.port || port}`); }
    catch {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    if (basePath && (requestUrl.pathname === basePath || !requestUrl.pathname.startsWith(`${basePath}/`))) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const socketPath = basePath ? requestUrl.pathname.slice(basePath.length) : requestUrl.pathname;
    if (mode !== 'standalone' || socketPath !== '/api/shell'
      || !trustedUiRequest(req, server.address()?.port || port, { allowedHosts, allowedOrigins })
      || !req.headers.origin) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const alias = requestUrl.searchParams.get('alias');
    let knownAlias = false;
    try { knownAlias = Boolean(alias && readHosts(dataFile).some((host) => host.alias === alias)); }
    catch {
      socket.write('HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    if (!knownAlias) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    webSocketServer.handleUpgrade(req, socket, head, (webSocket) => {
      webSocketServer.emit('connection', webSocket, req, alias);
    });
  });

  webSocketServer.on('connection', (webSocket, _request, alias) => {
    let session;
    let pendingFingerprint;
    let closing = false;
    let unlockRequested = false;
    const sendControl = (message) => {
      if (webSocket.readyState === WebSocket.OPEN) webSocket.send(JSON.stringify(message));
    };
    const closeSocket = (code, reason) => {
      if (webSocket.readyState === WebSocket.OPEN || webSocket.readyState === WebSocket.CONNECTING) {
        try { webSocket.close(code, reason); } catch { webSocket.terminate(); }
      }
    };
    const startShell = async (expectedFingerprint) => {
      if (closing || webSocket.readyState !== WebSocket.OPEN) return;
      const host = readHosts(dataFile).find((item) => item.alias === alias);
      if (!host) { sendControl({ type: 'error', error: `找不到主機：${alias}` }); closeSocket(1008, 'unknown host'); return; }
      let keyPath;
      try { keyPath = ssh.keyPathFor(host); }
      catch (error) { sendControl({ type: 'error', error: error.message }); closeSocket(1008, 'missing key'); return; }
      if (!unlockedKeys.has(keyPath)) {
        if (!unlockRequested) { unlockRequested = true; sendControl({ type: 'unlock-required' }); }
        return;
      }
      try {
        const openedSession = await ssh.openShell(dataFile, host, unlockedKeys.get(keyPath), {
          cols: 80,
          rows: 24,
          ...(expectedFingerprint ? { expectedFingerprint } : {}),
          onData: (chunk) => {
            if (webSocket.readyState === WebSocket.OPEN) webSocket.send(chunk, { binary: true });
          },
          onClose: ({ error, code, signal }) => {
            if (closing) return;
            closing = true;
            sendControl({ type: 'closed', ...(error ? { error: error.message } : {}), ...(code === undefined ? {} : { code }), ...(signal ? { signal } : {}) });
            closeSocket(1000, 'ssh shell closed');
          },
        });
        if (closing || webSocket.readyState !== WebSocket.OPEN) { openedSession.close(); return; }
        session = openedSession;
        sendControl({ type: 'started', alias, username: host.username, cols: 80, rows: 24 });
      } catch (error) {
        if (webSocket.readyState !== WebSocket.OPEN) return;
        if (error.code === 'INVALID_KEY_PASSPHRASE' || error.code === 'INVALID_PRIVATE_KEY') unlockedKeys.delete(keyPath);
        if (['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(error.code)) {
          pendingFingerprint = error.fingerprint;
          sendControl({
            type: error.code === 'HOST_KEY_CHANGED' ? 'host-key-changed' : 'trust-required',
            code: error.code,
            fingerprint: error.fingerprint,
            previousFingerprint: error.previousFingerprint,
          });
          return;
        }
        sendControl({ type: 'error', code: error.code || 'SSH_SHELL_FAILED', error: error.message });
        closeSocket(1011, 'ssh shell failed');
      }
    };

    webSocket.on('message', (data, isBinary) => {
      if (isBinary) { session?.write(data); return; }
      let message;
      try { message = JSON.parse(data.toString()); }
      catch { sendControl({ type: 'error', error: '無效的終端機控制訊息' }); return; }
      if (message.type === 'resize') { session?.resize(message.cols, message.rows); return; }
      if (message.type === 'unlock') {
        const host = readHosts(dataFile).find((item) => item.alias === alias);
        if (!host) { closeSocket(1008, 'unknown host'); return; }
        try {
          const keyPath = ssh.validateKey(host, typeof message.passphrase === 'string' ? message.passphrase : '');
          unlockedKeys.set(keyPath, typeof message.passphrase === 'string' ? message.passphrase : '');
          unlockRequested = false;
          sendControl({ type: 'unlocked' });
          startShell();
        } catch (error) {
          sendControl({ type: 'error', code: error.code || 'KEY_UNLOCK_FAILED', error: error.message });
          closeSocket(1008, 'key unlock failed');
        }
        return;
      }
      if (message.type === 'unlocked') {
        unlockRequested = false;
        startShell();
        return;
      }
      if (message.type === 'trust') {
        if (!pendingFingerprint || message.fingerprint !== pendingFingerprint) {
          sendControl({ type: 'error', error: '主機指紋確認資料不符' });
          closeSocket(1008, 'invalid trust confirmation');
          return;
        }
        const confirmedFingerprint = pendingFingerprint;
        pendingFingerprint = undefined;
        startShell(confirmedFingerprint);
        return;
      }
      if (message.type === 'trust-reject') {
        sendControl({ type: 'error', code: 'HOST_TRUST_REJECTED', error: '已拒絕主機指紋' });
        closeSocket(1008, 'host key rejected');
        return;
      }
      if (message.type === 'close') closeSocket(1000, 'client closed');
    });

    webSocket.on('close', () => {
      if (closing) return;
      closing = true;
      session?.close();
    });
    webSocket.on('error', () => {
      if (closing) return;
      closing = true;
      session?.close();
    });
    startShell();
  });

  server.on('close', () => {
    unlockedKeys.clear();
    for (const webSocket of webSocketServer.clients) webSocket.terminate();
    webSocketServer.close();
  });
  const closeHttpServer = server.close.bind(server);
  server.close = (callback) => {
    for (const webSocket of webSocketServer.clients) webSocket.terminate();
    return closeHttpServer(callback);
  };
  return server;
}

function openBrowser(url, platform = process.platform, spawnProcess = spawn) {
  const command = platform === 'win32' ? 'cmd' : platform === 'darwin' ? 'open' : 'xdg-open';
  const args = platform === 'win32' ? ['/c', 'start', '', url] : [url];
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnProcess(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
    } catch (error) {
      reject(error);
      return;
    }
    child.once('error', reject);
    child.once('close', (code) => code === 0 ? resolve() : reject(new Error(`瀏覽器啟動程序結束，代碼 ${code}`)));
    child.unref();
  });
}

async function startUi({
  port = 8787,
  host = process.env.SSHDECK_UI_HOST || '127.0.0.1',
  dataFile = dataFileFor(),
  mode = process.env.SSHDECK_MODE === 'service' ? 'service' : 'standalone',
  env = process.env,
  basePath = env.SSHDECK_BASE_PATH ?? (mode === 'service' ? '/sshdeck' : ''),
  allowedHosts = listSetting(env.SSHDECK_UI_ALLOWED_HOSTS, 'SSHDECK_UI_ALLOWED_HOSTS'),
  allowedOrigins = listSetting(env.SSHDECK_UI_ALLOWED_ORIGINS, 'SSHDECK_UI_ALLOWED_ORIGINS'),
  openBrowser: browserOpener = openBrowser,
  log = console.log,
} = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('port 必須是 0 到 65535 的整數');
  if (!['standalone', 'service'].includes(mode)) throw new Error('UI 模式僅支援 standalone 或 service');
  const normalizedBasePath = normalizeBasePath(basePath);
  let serviceConfig;
  if (mode === 'service') {
    serviceConfig = validateServiceUiConfig(env);
    if ((allowedHosts.length === 0) !== (allowedOrigins.length === 0)) {
      throw new Error('代理部署時必須同時設定 SSHDECK_UI_ALLOWED_HOSTS 與 SSHDECK_UI_ALLOWED_ORIGINS');
    }
  }
  if (!['127.0.0.1', '::1', 'localhost'].includes(host) && (!allowedHosts.length || !allowedOrigins.length)) {
    throw new Error('非 loopback UI listener 必須明確設定 SSHDECK_UI_ALLOWED_HOSTS 與 SSHDECK_UI_ALLOWED_ORIGINS');
  }
  const server = createServer({
    dataFile,
    port,
    basePath: normalizedBasePath,
    mode,
    serviceConfig,
    allowedHosts: allowedHosts.map((value) => value.toLowerCase()),
    allowedOrigins,
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const displayHost = ['0.0.0.0', '::'].includes(host) ? '127.0.0.1' : host;
  const addressHost = displayHost.includes(':') ? `[${displayHost}]` : displayHost;
  const url = `http://${addressHost}:${server.address().port}${normalizedBasePath}${normalizedBasePath ? '/' : ''}`;
  server.url = url;
  server.basePath = normalizedBasePath;
  server.uiMode = mode;
  log(`sshdeck UI：${url}`);
  try {
    await browserOpener(url);
  } catch {
    log(`無法自動開啟瀏覽器，請手動開啟：${url}`);
  }
  return server;
}

function parseExecArgs(args) {
  const separator = args.indexOf('--');
  if (separator !== 2 || !args[1]) throw new Error('用法：sshdeck exec <別名> -- <遠端命令>');
  const command = args.slice(separator + 1).join(' ');
  if (!command.trim()) throw new Error('遠端命令不可空白');
  return { alias: args[1], command };
}

async function execCommand(dataFile, args) {
  const { alias, command } = parseExecArgs(args);
  const host = readHosts(dataFile).find((item) => item.alias === alias);
  if (!host) throw new Error(`找不到主機：${alias}`);
  const passphrase = await readSecret('登入金鑰密語（輸入隱藏；未加密請按 Enter）：');
  const controller = new AbortController(); const interrupt = () => controller.abort(); process.once('SIGINT', interrupt);
  console.log(`目標：${host.alias}（${host.username}@${host.hostname}:${host.port}）`);
  try {
    const options = { signal: controller.signal, onStdout: (chunk) => process.stdout.write(chunk), onStderr: (chunk) => process.stderr.write(chunk) };
    let code;
    try { code = await ssh.exec(dataFile, host, passphrase, command, options); }
    catch (error) {
      if (!['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(error.code)) throw error;
      const prompt = require('node:readline/promises').createInterface({ input: process.stdin, output: process.stderr }); let answer;
      try { answer = await prompt.question(`主機指紋 ${error.fingerprint}。請先由可信管道核對，確認信任？[y/N] `); } finally { prompt.close(); }
      if (!/^y(es)?$/i.test(answer.trim())) throw new Error('已拒絕主機指紋；未執行命令');
      code = await ssh.exec(dataFile, host, passphrase, command, { ...options, expectedFingerprint: error.fingerprint });
    }
    console.log(`\n結束狀態：${code}`); if (code !== 0) process.exitCode = code;
  } finally { process.removeListener('SIGINT', interrupt); }
}

function parseShellArgs(args) {
  if (args.length !== 2 || args[0] !== 'shell' || !args[1]) throw new Error('用法：sshdeck shell <別名>');
  return { alias: args[1] };
}

async function connectInteractiveShell(dataFile, host, passphrase, options = {}) {
  let expectedFingerprint;
  for (;;) {
    try {
      return await ssh.openShell(dataFile, host, passphrase, {
        cols: options.cols || process.stdout.columns || 80,
        rows: options.rows || process.stdout.rows || 24,
        ...(expectedFingerprint ? { expectedFingerprint } : {}),
        onData: options.onData,
        onClose: options.onClose,
      });
    } catch (error) {
      if (!['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(error.code) || options.confirmTrust === false) throw error;
      if (options.confirmTrust) {
        if (!await options.confirmTrust(error)) throw new Error('已拒絕主機指紋；未開啟終端機');
      } else {
        const prompt = require('node:readline/promises').createInterface({ input: process.stdin, output: process.stderr });
        let answer;
        try {
          const previous = error.previousFingerprint ? `（原信任指紋 ${error.previousFingerprint}）` : '';
          answer = await prompt.question(`主機指紋 ${error.fingerprint}${previous}。請先由可信管道核對，確認信任？[y/N] `);
        } finally { prompt.close(); }
        if (!/^y(es)?$/i.test(answer.trim())) throw new Error('已拒絕主機指紋；未開啟終端機');
      }
      expectedFingerprint = error.fingerprint;
    }
  }
}

function attachLocalTerminal(session, {
  input = process.stdin,
  output = process.stdout,
  signalSource = process,
  onInterrupt = () => session.close(),
} = {}) {
  const previousRawMode = input.isRaw;
  const canSetRawMode = Boolean(input.isTTY && typeof input.setRawMode === 'function');
  if (canSetRawMode) input.setRawMode(true);
  const forwardInput = (data) => session.write(data);
  const resize = () => session.resize(output.columns || 80, output.rows || 24);
  input.on('data', forwardInput);
  input.resume();
  output.on('resize', resize);
  signalSource.once('SIGINT', onInterrupt);

  let restored = false;
  return () => {
    if (restored) return;
    restored = true;
    input.off('data', forwardInput);
    output.off('resize', resize);
    signalSource.removeListener('SIGINT', onInterrupt);
    if (canSetRawMode) {
      try { input.setRawMode(Boolean(previousRawMode)); } catch { /* stdin may already be closed */ }
    }
    input.pause();
  };
}

async function shellCommand(dataFile, args) {
  const { alias } = parseShellArgs(args);
  const host = readHosts(dataFile).find((item) => item.alias === alias);
  if (!host) throw new Error(`找不到主機：${alias}`);
  const passphrase = await readSecret('登入金鑰密語（輸入隱藏；未加密請按 Enter）：');
  let resolveClosed;
  const closed = new Promise((resolve) => { resolveClosed = resolve; });
  let session;
  let restoreTerminal;
  const interrupt = () => {
    process.exitCode = 130;
    session?.close();
  };
  try {
    session = await connectInteractiveShell(dataFile, host, passphrase, {
      cols: process.stdout.columns || 80,
      rows: process.stdout.rows || 24,
      onData: (chunk) => process.stdout.write(chunk),
      onClose: ({ error, code, signal }) => {
        if (error) {
          process.stderr.write(`\r\nSSH 終端機錯誤：${error.message}\r\n`);
          process.exitCode = 1;
        } else if (signal) {
          process.stderr.write(`\r\n遠端 shell 由 ${signal} 結束。\r\n`);
          process.exitCode = 1;
        }
        else if (code !== undefined && code !== 0) process.exitCode = code;
        resolveClosed();
      },
    });
    process.stderr.write(`已連線至 ${host.alias}（${host.username}@${host.hostname}:${host.port}），Ctrl+D 結束終端機。\r\n`);
    restoreTerminal = attachLocalTerminal(session, { onInterrupt: interrupt });
    await closed;
  } finally {
    restoreTerminal?.();
  }
}

async function main(args, { openBrowser: browserOpener } = {}) {
  if (process.env.SSHDECK_MODE === 'service') {
    if (args[0] !== 'ui') {
      const { runCli } = require('../lib/service-client');
      await runCli(args);
      return;
    }
  }
  if (process.env.SSHDECK_MODE && !['standalone', 'service'].includes(process.env.SSHDECK_MODE)) {
    throw new Error('SSHDECK_MODE 僅支援 standalone 或 service');
  }
  if (args[0] === 'service') {
    if (args[1] !== 'start') throw new Error('用法：sshdeck service start [--host <位址>] [--port <連接埠>]');
    let host = '127.0.0.1';
    let port = 8788;
    for (let index = 2; index < args.length; index += 1) {
      if (!['--host', '--port'].includes(args[index]) || !args[index + 1]) {
        throw new Error('用法：sshdeck service start [--host <位址>] [--port <連接埠>]');
      }
      if (args[index] === '--host') host = args[index + 1];
      else port = Number(args[index + 1]);
      index += 1;
    }
    const { startService } = require('../lib/service-server');
    const server = await startService({ host, port });
    console.log(`sshdeck service：${server.url}`);
    await new Promise((resolve) => {
      const shutdown = async () => {
        process.removeListener('SIGINT', shutdown);
        process.removeListener('SIGTERM', shutdown);
        await server.closeAsync();
        resolve();
      };
      process.once('SIGINT', shutdown);
      process.once('SIGTERM', shutdown);
    });
    return;
  }
  if (args[0] === 'ui') {
    let port = 8787;
    let host = process.env.SSHDECK_UI_HOST || '127.0.0.1';
    for (let index = 1; index < args.length; index += 1) {
      if (!['--port', '--host'].includes(args[index]) || !args[index + 1]) {
        throw new Error('用法：sshdeck ui [--host <位址>] [--port <連接埠>]');
      }
      if (args[index] === '--port') port = Number(args[index + 1]);
      else host = args[index + 1];
      index += 1;
    }
    return startUi({
      port,
      host,
      ...(browserOpener ? { openBrowser: browserOpener } : {}),
    });
  }
  if (args[0] === 'exec') { await execCommand(dataFileFor(), args); return; }
  if (args[0] === 'shell') { await shellCommand(dataFileFor(), args); return; }
  if (args[0] === 'key') { await keyCommand(dataFileFor(), args); return; }
  if (args[0] === 'guide') {
    const dataFile = dataFileFor();
    const selector = args[1];
    if (!selector) throw new Error('請提供主機別名或金鑰 ID');
    const host = readHosts(dataFile).find((item) => item.alias === selector);
    const record = host?.keyPath ? ssh.managedKeyForPath(dataFile, host.keyPath) : ssh.resolveManagedKey(dataFile, selector);
    const keyPath = host?.keyPath || record?.keyPath;
    if (!keyPath) throw new Error(`找不到關聯金鑰：${selector}`);
    console.log(ssh.installationGuide(host || record, ssh.managedPublicKey(keyPath)));
    return;
  }
  if (args[0] !== 'host') throw new Error('用法：sshdeck exec <別名> -- <命令> | sshdeck shell <別名> | sshdeck host ... | sshdeck key ... | sshdeck guide <別名> | sshdeck ui');
  await hostCommand(dataFileFor(), args);
}

module.exports = {
  attachLocalTerminal,
  connectInteractiveShell,
  dataFileFor,
  hostList,
  openBrowser,
  parseExecArgs,
  parseShellArgs,
  readSecret,
  readHosts,
  mutateHosts,
  validateHost,
  shellCommand,
  startUi,
  main,
};

if (require.main === module) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`sshdeck：${error.message}`);
    process.exitCode = 1;
  });
}
