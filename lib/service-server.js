'use strict';

const fs = require('node:fs');
const http = require('node:http');
const { isIP } = require('node:net');
const path = require('node:path');
const { randomBytes, timingSafeEqual } = require('node:crypto');
const { StringDecoder } = require('node:string_decoder');
const { utils } = require('ssh2');
const { WebSocket, WebSocketServer } = require('ws');
const ssh = require('./ssh');
const { PROTOCOL_VERSION } = require('./service-contract');
const store = require('./service-store');
const { dataFileFor, readHosts, mutateHosts, validateHost } = require('../bin/sshdeck');

const MAX_BODY_BYTES = 256 * 1024;

function httpError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        reject(httpError(413, 'REQUEST_TOO_LARGE', '要求內容超過大小限制'));
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
        reject(httpError(400, 'INVALID_JSON', '要求內容必須是有效 JSON'));
      }
    });
    req.on('aborted', () => reject(httpError(400, 'REQUEST_ABORTED', '要求已中斷')));
    req.on('error', reject);
  });
}

function sendJson(res, status, value) {
  if (res.destroyed) return;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(value));
}

function sendEmpty(res, status = 204) {
  if (res.destroyed) return;
  res.writeHead(status, { 'cache-control': 'no-store' });
  res.end();
}

function tokenMatches(supplied, expected) {
  if (typeof supplied !== 'string' || !expected) return false;
  const left = Buffer.from(supplied);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function authenticate(req, tokens) {
  const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization || '');
  if (!match) return null;
  if (tokenMatches(match[1], tokens.ui)) return 'ui';
  if (tokenMatches(match[1], tokens.cli)) return 'cli';
  if (tokenMatches(match[1], tokens.tunnel)) return 'tunnel';
  return null;
}

function requireRole(role, allowed) {
  if (!allowed.includes(role)) throw httpError(403, 'FORBIDDEN', '此操作不允許目前的服務憑證');
}

function publicHost(dataFile, host) {
  return {
    alias: host.alias,
    hostname: host.hostname,
    port: host.port,
    username: host.username,
    hasKey: Boolean(host.keyPath),
    keyManaged: Boolean(host.keyPath && ssh.isManagedKeyPath(dataFile, host.keyPath)),
    check: ssh.statusForHost(dataFile, host),
  };
}

function decodeSegment(value) {
  try { return decodeURIComponent(value); } catch { throw httpError(400, 'INVALID_PATH', '路徑編碼無效'); }
}

function validateTunnelTarget(input) {
  const validShape = input && typeof input === 'object' && !Array.isArray(input)
    && Object.keys(input).every((key) => key === 'targetHost' || key === 'targetPort');
  if (!validShape || !isSpecificIpLiteral(input.targetHost)
    || !Number.isInteger(input.targetPort) || input.targetPort < 1 || input.targetPort > 65535) {
    throw httpError(400, 'INVALID_TARGET', 'target 必須是非 wildcard IPv4／IPv6 literal 與 1–65535 整數 port');
  }
  return { targetHost: input.targetHost, targetPort: input.targetPort };
}

function isSpecificIpLiteral(value) {
  const family = typeof value === 'string' ? isIP(value) : 0;
  if (family === 0) return false;
  if (family === 4) return value !== '0.0.0.0';
  try {
    return new URL(`http://[${value}]/`).hostname.toLowerCase() !== '[::]';
  } catch {
    return false;
  }
}

function tunnelTargetGrantForHost(grants, dataFile, state, alias, targetId) {
  const grant = grants.get(targetId);
  if (!grant || grant.alias !== alias) return undefined;
  if (state.manuallyLocked) {
    grants.delete(targetId);
    return undefined;
  }
  const host = readHosts(dataFile).find((item) => item.alias === alias);
  if (!host || !host.keyPath || path.resolve(host.keyPath) !== grant.keyPath
    || !ssh.isManagedKeyPath(dataFile, host.keyPath)
    || !ssh.managedKeyForPath(dataFile, host.keyPath)
    || !state.credentials.has(grant.keyPath)
    || ssh.trustedFingerprintForHost(dataFile, host) !== grant.fingerprint
    || JSON.stringify([host.hostname, host.port, host.username, path.resolve(host.keyPath)]) !== grant.hostProfile) {
    grants.delete(targetId);
    return undefined;
  }
  return {
    targetId: grant.targetId,
    alias: grant.alias,
    targetHost: grant.targetHost,
    targetPort: grant.targetPort,
  };
}

function takeTunnelTargetGrantInvalidations(grants, { alias, keyPath, targetId: scopedTargetId, reason }) {
  if (typeof reason !== 'string' || !reason) throw new TypeError('target grant invalidation reason is required');
  const resolvedKeyPath = keyPath === undefined ? undefined : path.resolve(keyPath);
  const events = [];
  for (const [targetId, grant] of grants) {
    if ((alias === undefined || grant.alias === alias)
      && (scopedTargetId === undefined || targetId === scopedTargetId)
      && (resolvedKeyPath === undefined || grant.keyPath === resolvedKeyPath)) {
      grants.delete(targetId);
      events.push({
        alias: grant.alias,
        targetId,
        keyPath: grant.keyPath,
        event: Object.freeze({ alias: grant.alias, targetId, reason }),
      });
    }
  }
  return events;
}

function asCredentialHost(host, credentials, manuallyLocked) {
  if (manuallyLocked) throw httpError(423, 'SERVICE_LOCKED', 'SSHDeck service 已手動鎖定');
  if (!host.keyPath) throw httpError(428, 'KEY_REQUIRED', '此主機尚未關聯登入金鑰');
  const credential = credentials.get(path.resolve(host.keyPath));
  if (!credential) throw httpError(500, 'CREDENTIAL_UNAVAILABLE', '服務金鑰快取不完整；拒絕執行');
  return {
    ...host,
    [ssh.SERVICE_PRIVATE_KEY]: credential.privateKey,
  };
}

function safeFailure(error) {
  if (error.status) return { status: error.status, code: error.code, message: error.message };
  if (error.code === 'HOST_TRUST_REQUIRED' || error.code === 'HOST_KEY_CHANGED') {
    return { status: 409, code: error.code, message: error.message, fingerprint: error.fingerprint,
      ...(error.previousFingerprint ? { previousFingerprint: error.previousFingerprint } : {}) };
  }
  if (error.code === 'AUTHENTICATION_FAILED') return { status: 401, code: error.code, message: error.message };
  if (error.code === 'INVALID_KEY_PASSPHRASE' || error.code === 'INVALID_PRIVATE_KEY') {
    return { status: 400, code: error.code, message: error.message };
  }
  if (error.code === 'DATA_CORRUPT' || error.code === 'ENCRYPTION_KEY_REQUIRED') {
    return { status: 503, code: error.code, message: error.message };
  }
  return { status: 502, code: error.code || 'SERVICE_OPERATION_FAILED', message: error.message || '服務操作失敗' };
}

function serviceTokens(env) {
  const cli = env.SSHDECK_SERVICE_TOKEN;
  const ui = env.SSHDECK_UI_TOKEN;
  const tunnel = env.SSHDECK_TUNNEL_TOKEN;
  if (typeof cli !== 'string' || cli.length < 32) {
    throw store.failure('SERVICE_TOKEN_REQUIRED', 'SSHDECK_SERVICE_TOKEN 必須至少 32 個字元；服務未啟動');
  }
  if (typeof ui !== 'string' || ui.length < 32 || tokenMatches(cli, ui)) {
    throw store.failure('UI_TOKEN_REQUIRED', 'SSHDECK_UI_TOKEN 必須至少 32 個字元，且不可與 CLI token 相同；服務未啟動');
  }
  if (typeof tunnel !== 'string' || tunnel.length < 32) {
    throw store.failure('TUNNEL_TOKEN_REQUIRED', 'SSHDECK_TUNNEL_TOKEN 必須至少 32 個字元；服務未啟動');
  }
  const conflictsWithExistingCredential = [
    cli,
    ui,
    env.SSHDECK_ENCRYPTION_KEY,
  ].some((credential) => tokenMatches(tunnel, credential));
  if (conflictsWithExistingCredential) {
    throw store.failure('TUNNEL_TOKEN_INVALID', 'SSHDECK_TUNNEL_TOKEN 必須與其他服務憑證及加密金鑰不同；服務未啟動');
  }
  return { cli, ui, tunnel };
}

function serviceTerminalOrigin(env) {
  const value = env.SSHDECK_SERVICE_TERMINAL_ORIGIN;
  if (value === undefined || value === '') return null;
  if (typeof value !== 'string' || value.trim() !== value) {
    throw store.failure('SERVICE_TERMINAL_ORIGIN_INVALID', 'SSHDECK_SERVICE_TERMINAL_ORIGIN 必須是精確的 HTTP(S) origin');
  }
  let origin;
  try { origin = new URL(value); } catch {
    throw store.failure('SERVICE_TERMINAL_ORIGIN_INVALID', 'SSHDECK_SERVICE_TERMINAL_ORIGIN 必須是精確的 HTTP(S) origin');
  }
  if (!['http:', 'https:'].includes(origin.protocol)
    || origin.username || origin.password || origin.pathname !== '/'
    || origin.search || origin.hash || origin.origin !== value) {
    throw store.failure('SERVICE_TERMINAL_ORIGIN_INVALID', 'SSHDECK_SERVICE_TERMINAL_ORIGIN 必須是精確的 HTTP(S) origin');
  }
  return origin;
}

function serviceTerminalSourceAllowed(req, config, port) {
  if (typeof req.headers.host !== 'string' || typeof req.headers.origin !== 'string') return false;
  let origin;
  try {
    origin = new URL(req.headers.origin);
  } catch {
    return false;
  }
  if (config.terminalOrigin) {
    let hostUrl;
    try {
      hostUrl = new URL(`${config.terminalOrigin.protocol}//${req.headers.host}`);
    } catch {
      return false;
    }
    return hostUrl.username === ''
      && hostUrl.password === ''
      && hostUrl.pathname === '/'
      && hostUrl.search === ''
      && hostUrl.hash === ''
      && hostUrl.origin === config.terminalOrigin.origin
      && origin.protocol === config.terminalOrigin.protocol
      && origin.origin === config.terminalOrigin.origin
      && origin.username === ''
      && origin.password === ''
      && origin.pathname === '/'
      && origin.search === ''
      && origin.hash === '';
  }

  let hostUrl;
  try { hostUrl = new URL(`http://${req.headers.host}`); } catch {
    return false;
  }
  const effectivePort = (url) => Number(
    url.port || (url.protocol === 'https:' ? 443 : 80),
  );
  if (hostUrl.username || hostUrl.password || hostUrl.pathname !== '/' || hostUrl.search || hostUrl.hash
    || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash
    || !['http:', 'https:'].includes(origin.protocol)
    || effectivePort(hostUrl) !== port
    || effectivePort(origin) !== port
    || origin.hostname.toLowerCase() !== hostUrl.hostname.toLowerCase()) return false;

  const requestHost = hostUrl.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const configuredHost = config.host.replace(/^\[|\]$/g, '').toLowerCase();
  return ['0.0.0.0', '::'].includes(configuredHost) || requestHost === configuredHost;
}

function rejectUpgrade(socket, status, code, message) {
  const body = Buffer.from(JSON.stringify({ code, error: message }));
  const reason = http.STATUS_CODES[status] || 'Bad Request';
  const headers = Buffer.from([
    `HTTP/1.1 ${status} ${reason}`,
    'Connection: close',
    'Cache-Control: no-store',
    'Content-Type: application/json; charset=utf-8',
    `Content-Length: ${body.length}`,
    '',
    '',
  ].join('\r\n'));
  socket.end(Buffer.concat([headers, body]));
}

function canonicalPathForComparison(filePath) {
  const unresolvedSegments = [];
  let candidate = path.resolve(filePath);

  while (true) {
    try {
      const canonicalPath = path.resolve(fs.realpathSync.native(candidate), ...unresolvedSegments);
      return process.platform === 'win32' ? canonicalPath.toLowerCase() : canonicalPath;
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;

      let link;
      try {
        link = fs.lstatSync(candidate);
      } catch (statError) {
        if (statError.code !== 'ENOENT' && statError.code !== 'ENOTDIR') throw statError;
      }
      if (link?.isSymbolicLink()) {
        candidate = path.resolve(path.dirname(candidate), fs.readlinkSync(candidate));
        continue;
      }

      const parent = path.dirname(candidate);
      if (parent === candidate) throw error;
      unresolvedSegments.unshift(path.basename(candidate));
      candidate = parent;
    }
  }
}

function startOptions({ env = process.env, host = '127.0.0.1', port = 8788 } = {}) {
  if (typeof env.SSHDECK_SERVICE_HOME !== 'string' || !path.isAbsolute(env.SSHDECK_SERVICE_HOME)) {
    throw store.failure('SERVICE_HOME_REQUIRED', 'SSHDECK_SERVICE_HOME 必須是絕對路徑；不會讀取 standalone 資料');
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error('port 必須是 0 到 65535 的整數');
  }
  const home = path.resolve(env.SSHDECK_SERVICE_HOME);
  const standaloneHome = path.resolve(path.dirname(dataFileFor({ env })));
  const sameHome = canonicalPathForComparison(home) === canonicalPathForComparison(standaloneHome);
  if (sameHome) {
    throw store.failure('SERVICE_HOME_CONFLICT', 'SSHDECK_SERVICE_HOME 不得與 standalone 資料目錄相同；服務未啟動');
  }
  return {
    env,
    host,
    port,
    home,
    dataFile: path.join(home, 'hosts.json'),
    key: store.encryptionKey(env.SSHDECK_ENCRYPTION_KEY),
    tokens: serviceTokens(env),
    terminalOrigin: serviceTerminalOrigin(env),
  };
}

function endpointFor(url) {
  try { return new URL(url, 'http://127.0.0.1'); } catch { throw httpError(400, 'INVALID_PATH', '要求路徑無效'); }
}

function publicKeyRecord(dataFile, record, hosts) {
  const associatedAliases = hosts.filter((host) => host.keyPath && path.resolve(host.keyPath) === path.resolve(record.keyPath))
    .map((host) => host.alias);
  return {
    id: record.id,
    alias: record.alias,
    hostname: record.hostname,
    port: record.port,
    username: record.username,
    associatedAliases,
    publicKey: ssh.managedPublicKey(record.keyPath),
  };
}

async function startService(options = {}) {
  const config = startOptions(options);
  const { dataFile, home, key, tokens } = config;
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') fs.chmodSync(home, 0o700);

  // 啟動前只讀驗證完整服務資料；解密或格式錯誤時不會改寫既有資料。
  const hosts = readHosts(dataFile).map(validateHost);
  const records = ssh.listManagedKeys(dataFile);
  const allCredentials = store.validateStoredCredentials({ dataFile, hosts, records, key });
  const manuallyLocked = store.readManualLockState(dataFile);
  const credentials = manuallyLocked ? new Map() : allCredentials;
  const activeExecutions = new Set();
  const activeTerminals = new Set();
  const tunnelTargetGrants = new Map();
  const pendingTunnelTargetGrantInvalidations = new Map();
  const tunnelTargetGrantInvalidationSubscribers = new Set();
  let shutdownStarted = false;
  const state = { manuallyLocked, credentials };
  const version = require('../package.json').version;
  const terminalWebSocketServer = new WebSocketServer({
    noServer: true,
    maxPayload: 64 * 1024,
    perMessageDeflate: false,
  });
  const sendTerminalControl = (terminal, message) => {
    if (terminal.socket.readyState === WebSocket.OPEN) terminal.socket.send(JSON.stringify(message));
  };
  const finishTerminal = (terminal, { error, code, signal } = {}) => {
    if (terminal.closing) return;
    terminal.closing = true;
    terminal.session = null;
    sendTerminalControl(terminal, {
      type: 'closed',
      ...(error ? { error: error.message } : {}),
      ...(code === undefined ? {} : { code }),
      ...(signal ? { signal } : {}),
    });
    terminal.socket.close(1000, 'SSH terminal closed');
    terminal.closeTimer = setTimeout(() => terminal.socket.terminate(), 1000);
    terminal.closeTimer.unref?.();
  };
  const closeTerminal = (terminal, {
    statusCode = 1000,
    reason = 'terminal closed',
    error,
    force = false,
  } = {}) => {
    if (terminal.closing) {
      if (force && terminal.socket.readyState !== WebSocket.CLOSED) terminal.socket.terminate();
      return;
    }
    terminal.closing = true;
    if (error) sendTerminalControl(terminal, { type: 'error', code: error.code, error: error.message });
    terminal.abortController.abort();
    terminal.session?.close();
    terminal.session = null;
    if (force) terminal.socket.terminate();
    else if (terminal.socket.readyState === WebSocket.OPEN) terminal.socket.close(statusCode, reason);
    else terminal.socket.terminate();
    if (!force) {
      terminal.closeTimer = setTimeout(() => terminal.socket.terminate(), 1000);
      terminal.closeTimer.unref?.();
    }
  };
  const closeTerminalsForAlias = (alias, error) => {
    for (const terminal of activeTerminals) {
      if (alias === undefined || terminal.alias === alias) {
        closeTerminal(terminal, {
          statusCode: 1012,
          reason: 'host or service state changed',
          ...(error ? { error } : {}),
        });
      }
    }
  };
  const subscribeTunnelTargetGrantInvalidation = (listener) => {
    if (shutdownStarted) throw httpError(503, 'SERVICE_SHUTTING_DOWN', 'SSHDeck service 正在停止');
    if (typeof listener !== 'function') throw new TypeError('grant invalidation subscriber must be a function');
    const subscriber = { listener, active: true };
    tunnelTargetGrantInvalidationSubscribers.add(subscriber);
    return () => {
      if (!subscriber.active) return;
      subscriber.active = false;
      tunnelTargetGrantInvalidationSubscribers.delete(subscriber);
    };
  };
  const invalidateTunnelTargetGrants = async (scope) => {
    const events = takeTunnelTargetGrantInvalidations(tunnelTargetGrants, scope);
    for (const invalidation of events) {
      const pending = {
        alias: invalidation.alias,
        targetId: invalidation.targetId,
        keyPath: invalidation.keyPath,
      };
      pending.promise = Promise.resolve().then(async () => {
        let failed = false;
        const subscribers = [...tunnelTargetGrantInvalidationSubscribers];
        await Promise.all(subscribers.map(async (subscriber) => {
          if (!subscriber.active) return;
          try {
            await subscriber.listener(invalidation.event);
          } catch {
            subscriber.active = false;
            tunnelTargetGrantInvalidationSubscribers.delete(subscriber);
            failed = true;
          }
        }));
        if (failed) throw httpError(502, 'TUNNEL_INVALIDATION_FAILED', '無法完成 target grant 失效通知');
      });
      pendingTunnelTargetGrantInvalidations.set(pending.targetId, pending);
      const clearPending = () => {
        if (pendingTunnelTargetGrantInvalidations.get(pending.targetId) === pending) {
          pendingTunnelTargetGrantInvalidations.delete(pending.targetId);
        }
      };
      void pending.promise.then(clearPending, clearPending);
    }
    const resolvedKeyPath = scope.keyPath === undefined ? undefined : path.resolve(scope.keyPath);
    const matchingPending = [...pendingTunnelTargetGrantInvalidations.values()].filter((pending) =>
      (scope.alias === undefined || pending.alias === scope.alias)
      && (scope.targetId === undefined || pending.targetId === scope.targetId)
      && (resolvedKeyPath === undefined || pending.keyPath === resolvedKeyPath));
    const results = await Promise.allSettled(matchingPending.map((pending) => pending.promise));
    if (results.some((result) => result.status === 'rejected')) {
      throw httpError(502, 'TUNNEL_INVALIDATION_FAILED', '無法完成 target grant 失效通知');
    }
  };

  const server = http.createServer((req, res) => {
    const dispatch = async () => {
      const url = endpointFor(req.url);
      if (req.method === 'GET' && url.pathname === '/v1/health') {
        return sendJson(res, 200, { status: 'ok', protocolVersion: PROTOCOL_VERSION });
      }
      if (req.method === 'GET' && url.pathname === '/v1/version') {
        return sendJson(res, 200, { name: 'sshdeck-service', version, protocolVersion: PROTOCOL_VERSION });
      }
      if (!url.pathname.startsWith('/v1/')) return sendJson(res, 404, { code: 'NOT_FOUND', error: '找不到路徑' });

      const role = authenticate(req, tokens);
      if (!role) return sendJson(res, 401, { code: 'UNAUTHORIZED', error: '需要有效的 Bearer token' });
      requireRole(role, ['ui', 'cli']);

      const targetCollection = /^\/v1\/hosts\/([^/]+)\/tcp-tunnel-targets$/.exec(url.pathname);
      if (targetCollection && req.method === 'POST') {
        requireRole(role, ['ui']);
        if (url.search) throw httpError(400, 'INVALID_PATH', 'target grant 路徑不可包含 query');
        const alias = decodeSegment(targetCollection[1]);
        if (alias.includes('/')) throw httpError(400, 'INVALID_PATH', '主機別名路徑無效');
        const input = validateTunnelTarget(await readJson(req));
        const host = readHosts(dataFile).find((item) => item.alias === alias);
        if (!host) throw httpError(404, 'HOST_NOT_FOUND', '找不到主機設定');
        asCredentialHost(host, state.credentials, state.manuallyLocked);
        if (!ssh.isManagedKeyPath(dataFile, host.keyPath)
          || !ssh.managedKeyForPath(dataFile, host.keyPath)) {
          throw httpError(409, 'KEY_NOT_MANAGED', 'target grant 只允許關聯服務管理的登入金鑰');
        }
        const trustedFingerprint = ssh.trustedFingerprintForHost(dataFile, host);
        if (!trustedFingerprint) {
          throw httpError(409, 'HOST_TRUST_REQUIRED', '建立 target grant 前必須先完成主機指紋 trust');
        }
        let targetId;
        do {
          targetId = randomBytes(32).toString('base64url');
        } while (tunnelTargetGrants.has(targetId));
        const keyPath = path.resolve(host.keyPath);
        tunnelTargetGrants.set(targetId, {
          targetId,
          alias,
          targetHost: input.targetHost,
          targetPort: input.targetPort,
          keyPath,
          fingerprint: trustedFingerprint,
          hostProfile: JSON.stringify([host.hostname, host.port, host.username, keyPath]),
        });
        return sendJson(res, 201, { targetId });
      }

      const targetRevoke = /^\/v1\/hosts\/([^/]+)\/tcp-tunnel-targets\/([^/]+)$/.exec(url.pathname);
      if (targetRevoke && req.method === 'DELETE') {
        requireRole(role, ['ui']);
        if (url.search) throw httpError(400, 'INVALID_PATH', 'target grant 路徑不可包含 query');
        const alias = decodeSegment(targetRevoke[1]);
        const targetId = decodeSegment(targetRevoke[2]);
        await invalidateTunnelTargetGrants({ alias, reason: 'revoked', targetId });
        return sendEmpty(res);
      }

      if (req.method === 'GET' && url.pathname === '/v1/hosts') {
        const currentHosts = readHosts(dataFile);
        return sendJson(res, 200, currentHosts.map((host) => publicHost(dataFile, host)));
      }
      if (req.method === 'GET' && url.pathname === '/v1/keys') {
        requireRole(role, ['ui']);
        const currentHosts = readHosts(dataFile);
        return sendJson(res, 200, ssh.listManagedKeys(dataFile).map((record) => publicKeyRecord(dataFile, record, currentHosts)));
      }
      if (req.method === 'POST' && url.pathname === '/v1/lock') {
        requireRole(role, ['ui']);
        store.writeManualLockState(dataFile, true);
        state.manuallyLocked = true;
        const invalidation = invalidateTunnelTargetGrants({ reason: 'service-locked' });
        for (const item of activeExecutions) item.controller.abort();
        closeTerminalsForAlias(undefined, {
          code: 'SERVICE_LOCKED',
          message: 'SSHDeck service 已手動鎖定',
        });
        state.credentials.clear();
        await invalidation;
        return sendEmpty(res);
      }
      if (req.method === 'POST' && url.pathname === '/v1/unlock') {
        requireRole(role, ['ui']);
        const recovered = store.validateStoredCredentials({
          dataFile, hosts: readHosts(dataFile), records: ssh.listManagedKeys(dataFile), key,
        });
        store.writeManualLockState(dataFile, false);
        state.credentials = recovered;
        state.manuallyLocked = false;
        return sendEmpty(res);
      }
      if (req.method === 'POST' && url.pathname === '/v1/hosts') {
        requireRole(role, ['ui']);
        const input = await readJson(req);
        if (Object.hasOwn(input, 'keyPath')) throw httpError(400, 'INVALID_HOST', '服務主機不可指定本機私鑰路徑');
        let created;
        mutateHosts(dataFile, (currentHosts) => {
          created = validateHost(input);
          if (currentHosts.some((item) => item.alias === created.alias)) throw httpError(409, 'HOST_EXISTS', '主機別名已存在');
          currentHosts.push(created);
        });
        return sendJson(res, 201, publicHost(dataFile, created));
      }

      const hostMatch = /^\/v1\/hosts\/([^/]+)(?:\/(check|exec|key(?:\/(?:create|import|link|unlink))?))?$/.exec(url.pathname);
      if (hostMatch) {
        const alias = decodeSegment(hostMatch[1]);
        const action = hostMatch[2] || '';
        let currentHosts = readHosts(dataFile);
        const existing = currentHosts.find((item) => item.alias === alias);
        if (!existing && !(req.method === 'PUT' && !action)) {
          throw httpError(404, 'HOST_NOT_FOUND', '找不到主機設定');
        }

        if (!action && req.method === 'PUT') {
          requireRole(role, ['ui']);
          const input = await readJson(req);
          if (Object.hasOwn(input, 'alias') || Object.hasOwn(input, 'keyPath')) {
            throw httpError(400, 'INVALID_HOST', '更新主機不可指定 alias 或本機私鑰路徑');
          }
          let updated;
          mutateHosts(dataFile, (items) => {
            const index = items.findIndex((item) => item.alias === alias);
            if (index < 0) throw httpError(404, 'HOST_NOT_FOUND', '找不到主機設定');
            updated = validateHost({ ...items[index], ...input });
            items[index] = updated;
          });
          const invalidation = invalidateTunnelTargetGrants({ alias, reason: 'host-updated' });
          ssh.updateManagedKeyProfile(dataFile, updated);
          ssh.clearHostStatus(dataFile, alias);
          if (ssh.endpoint(existing) !== ssh.endpoint(updated)
            && !readHosts(dataFile).some((item) => ssh.endpoint(item) === ssh.endpoint(existing))) {
            ssh.clearHostTrust(dataFile, existing);
          }
          for (const item of activeExecutions) if (item.alias === alias) item.controller.abort();
          closeTerminalsForAlias(alias, {
            code: 'HOST_CHANGED',
            message: '主機設定已變更；終端連線已關閉',
          });
          await invalidation;
          return sendJson(res, 200, publicHost(dataFile, updated));
        }

        if (!action && req.method === 'DELETE') {
          requireRole(role, ['ui']);
          mutateHosts(dataFile, (items) => {
            const index = items.findIndex((item) => item.alias === alias);
            if (index < 0) throw httpError(404, 'HOST_NOT_FOUND', '找不到主機設定');
            items.splice(index, 1);
          });
          const invalidation = invalidateTunnelTargetGrants({ alias, reason: 'host-removed' });
          ssh.clearHostStatus(dataFile, alias);
          if (!readHosts(dataFile).some((item) => ssh.endpoint(item) === ssh.endpoint(existing))) {
            ssh.clearHostTrust(dataFile, existing);
          }
          for (const item of activeExecutions) if (item.alias === alias) item.controller.abort();
          closeTerminalsForAlias(alias, {
            code: 'HOST_NOT_FOUND',
            message: '主機設定已刪除；終端連線已關閉',
          });
          await invalidation;
          return sendEmpty(res);
        }

        if (action === 'key' && req.method === 'GET') {
          requireRole(role, ['ui']);
          if (!existing.keyPath) throw httpError(404, 'KEY_NOT_FOUND', '此主機尚未關聯登入金鑰');
          const record = ssh.managedKeyForPath(dataFile, existing.keyPath);
          if (!record) throw httpError(409, 'KEY_NOT_MANAGED', '服務拒絕讀取非服務管理的私鑰');
          const publicKey = ssh.managedPublicKey(existing.keyPath);
          return sendJson(res, 200, { publicKey, guide: ssh.installationGuide(existing, publicKey) });
        }

        if (action === 'key/unlink' && req.method === 'POST') {
          requireRole(role, ['ui']);
          if (!existing.keyPath) throw httpError(404, 'KEY_NOT_FOUND', '此主機尚未關聯登入金鑰');
          const oldPath = path.resolve(existing.keyPath);
          mutateHosts(dataFile, (items) => {
            const current = items.find((item) => item.alias === alias);
            delete current.keyPath;
          });
          const invalidation = invalidateTunnelTargetGrants({ alias, reason: 'host-key-unlinked' });
          ssh.clearHostStatus(dataFile, alias);
          if (!readHosts(dataFile).some((item) => item.keyPath && path.resolve(item.keyPath) === oldPath)) {
            state.credentials.delete(oldPath);
          }
          for (const item of activeExecutions) if (item.alias === alias) item.controller.abort();
          closeTerminalsForAlias(alias, {
            code: 'KEY_REQUIRED',
            message: '主機金鑰關聯已解除；終端連線已關閉',
          });
          await invalidation;
          return sendEmpty(res);
        }

        if (action === 'key/link' && req.method === 'POST') {
          requireRole(role, ['ui']);
          if (existing.keyPath) throw httpError(409, 'KEY_ALREADY_LINKED', '此主機已關聯金鑰，請先解除關聯');
          const input = await readJson(req);
          if (typeof input.keyId !== 'string' || !input.keyId) throw httpError(400, 'INVALID_KEY', '請提供服務金鑰 ID');
          let record;
          try { record = ssh.resolveManagedKey(dataFile, input.keyId); } catch {
            throw httpError(404, 'KEY_NOT_FOUND', '找不到服務管理的金鑰');
          }
          const credential = store.loadCredentialFile(record.keyPath, key);
          mutateHosts(dataFile, (items) => {
            const current = items.find((item) => item.alias === alias);
            if (!current || current.keyPath) throw httpError(409, 'KEY_ALREADY_LINKED', '主機狀態已變更，拒絕覆寫金鑰關聯');
            current.keyPath = record.keyPath;
          });
          const invalidation = invalidateTunnelTargetGrants({ alias, reason: 'host-key-linked' });
          if (!state.manuallyLocked) state.credentials.set(path.resolve(record.keyPath), credential);
          ssh.clearHostStatus(dataFile, alias);
          await invalidation;
          return sendJson(res, 200, { linked: true, keyId: record.id, alias });
        }

        if ((action === 'key/create' || action === 'key/import') && req.method === 'POST') {
          requireRole(role, ['ui']);
          if (existing.keyPath) throw httpError(409, 'KEY_ALREADY_LINKED', '此主機已關聯金鑰，請先解除關聯');
          const input = await readJson(req);
          let privateKey;
          let passphrase;
          let publicKey;
          try {
            if (action === 'key/create') {
              const pair = utils.generateKeyPairSync('ed25519', { comment: `sshdeck:${alias}` });
              privateKey = Buffer.from(pair.private);
              passphrase = '';
              publicKey = pair.public.trim();
            } else {
              if (typeof input.privateKey !== 'string' || !input.privateKey.trim()
                || (input.passphrase !== undefined && typeof input.passphrase !== 'string')) {
                throw httpError(400, 'INVALID_KEY', '匯入需要 privateKey 與文字格式 passphrase');
              }
              privateKey = Buffer.from(input.privateKey);
              passphrase = input.passphrase || '';
              const parsed = ssh.parsePrivateKey(privateKey, passphrase);
              publicKey = `${parsed.type} ${parsed.getPublicSSH().toString('base64')}`;
            }
            const credential = { alias, privateKey, passphrase, profile: existing };
            const stored = store.persistCredential({ dataFile, key, credential });
            try {
              mutateHosts(dataFile, (items) => {
                const current = items.find((item) => item.alias === alias);
                if (!current || current.keyPath) throw httpError(409, 'KEY_ALREADY_LINKED', '主機狀態已變更，拒絕覆寫金鑰關聯');
                current.keyPath = stored.keyPath;
              });
            } catch (error) {
              ssh.deleteManagedKey(dataFile, stored.keyPath);
              throw error;
            }
            if (!state.manuallyLocked) state.credentials.set(path.resolve(stored.keyPath), stored.credential);
            ssh.clearHostStatus(dataFile, alias);
            await invalidateTunnelTargetGrants({
              alias,
              reason: action === 'key/create' ? 'managed-key-created' : 'managed-key-imported',
            });
            return sendJson(res, 201, {
              id: stored.id,
              publicKey: stored.publicKey,
              guide: ssh.installationGuide(existing, stored.publicKey),
            });
          } catch (error) {
            if (error.code) throw error;
            throw httpError(400, error.code || 'INVALID_KEY', error.message);
          }
        }

        if (action === 'check' && req.method === 'POST') {
          const input = await readJson(req);
          const credentialHost = asCredentialHost(existing, state.credentials, state.manuallyLocked);
          const credential = state.credentials.get(path.resolve(existing.keyPath));
          try {
            const result = await ssh.checkSSH(dataFile, credentialHost, credential.passphrase, {
              ...(typeof input.expectedFingerprint === 'string' ? { expectedFingerprint: input.expectedFingerprint } : {}),
              onTrustChange: ({ alias: trustedAlias }) => invalidateTunnelTargetGrants({
                alias: trustedAlias,
                reason: 'fingerprint-trust-changed',
              }),
            });
            return sendJson(res, 200, result);
          } catch (error) {
            const safe = safeFailure(error);
            return sendJson(res, safe.status, {
              code: safe.code,
              error: safe.message,
              ...(safe.fingerprint ? { fingerprint: safe.fingerprint } : {}),
              ...(safe.previousFingerprint ? { previousFingerprint: safe.previousFingerprint } : {}),
            });
          }
        }

        if (action === 'exec' && req.method === 'POST') {
          const input = await readJson(req);
          if (typeof input.command !== 'string' || !input.command.trim()) {
            throw httpError(400, 'INVALID_COMMAND', '遠端命令不可空白');
          }
          const credentialHost = asCredentialHost(existing, state.credentials, state.manuallyLocked);
          const credential = state.credentials.get(path.resolve(existing.keyPath));
          const controller = new AbortController();
          const execution = { alias, keyPath: path.resolve(existing.keyPath), controller };
          activeExecutions.add(execution);
          const abort = () => controller.abort();
          req.once('aborted', abort);
          res.once('close', () => { if (!res.writableEnded) abort(); });
          const stdoutDecoder = new StringDecoder('utf8');
          const stderrDecoder = new StringDecoder('utf8');
          let started = false;
          const writeEvent = (type, data) => {
            if (!res.destroyed && data) res.write(`${JSON.stringify({ type, data })}\n`);
          };
          try {
            const code = await ssh.exec(dataFile, credentialHost, credential.passphrase, input.command, {
              signal: controller.signal,
              ...(typeof input.expectedFingerprint === 'string' ? { expectedFingerprint: input.expectedFingerprint } : {}),
              onTrustChange: ({ alias: trustedAlias }) => invalidateTunnelTargetGrants({
                alias: trustedAlias,
                reason: 'fingerprint-trust-changed',
              }),
              onStart: () => {
                started = true;
                res.writeHead(200, {
                  'content-type': 'application/x-ndjson; charset=utf-8',
                  'cache-control': 'no-store',
                  'x-content-type-options': 'nosniff',
                  'x-accel-buffering': 'no',
                });
                res.flushHeaders();
              },
              onStdout: (chunk) => writeEvent('stdout', stdoutDecoder.write(chunk)),
              onStderr: (chunk) => writeEvent('stderr', stderrDecoder.write(chunk)),
            });
            writeEvent('stdout', stdoutDecoder.end());
            writeEvent('stderr', stderrDecoder.end());
            if (!res.destroyed) {
              res.end(`${JSON.stringify({ type: 'exit', code })}\n`);
            }
          } catch (error) {
            if (res.destroyed) return;
            if (!started) {
              const safe = safeFailure(error);
              return sendJson(res, safe.status, {
                code: safe.code,
                error: safe.message,
                ...(safe.fingerprint ? { fingerprint: safe.fingerprint } : {}),
                ...(safe.previousFingerprint ? { previousFingerprint: safe.previousFingerprint } : {}),
              });
            }
            writeEvent('stdout', stdoutDecoder.end());
            writeEvent('stderr', stderrDecoder.end());
            res.end(`${JSON.stringify({ type: 'error', code: error.code || 'REMOTE_EXEC_FAILED', error: error.message })}\n`);
          } finally {
            activeExecutions.delete(execution);
            req.off('aborted', abort);
          }
          return;
        }

        if (!action && req.method === 'GET') return sendJson(res, 200, publicHost(dataFile, existing));
      }

      const keyDelete = /^\/v1\/keys\/([^/]+)$/.exec(url.pathname);
      if (keyDelete && req.method === 'DELETE') {
        requireRole(role, ['ui']);
        const selector = decodeSegment(keyDelete[1]);
        let record;
        try { record = ssh.resolveManagedKey(dataFile, selector); } catch { throw httpError(404, 'KEY_NOT_FOUND', '找不到服務管理的金鑰'); }
        const associated = readHosts(dataFile).filter((host) => host.keyPath && path.resolve(host.keyPath) === path.resolve(record.keyPath));
        if (associated.length) throw httpError(409, 'KEY_IN_USE', '金鑰仍與主機關聯，請先解除所有關聯');
        ssh.deleteManagedKey(dataFile, record.keyPath);
        const invalidation = invalidateTunnelTargetGrants({ keyPath: record.keyPath, reason: 'managed-key-removed' });
        state.credentials.delete(path.resolve(record.keyPath));
        await invalidation;
        return sendJson(res, 200, { deleted: true });
      }

      return sendJson(res, 404, { code: 'NOT_FOUND', error: '找不到路徑' });
    };

    dispatch().catch((error) => {
      if (res.headersSent && !res.destroyed) {
        res.end(`${JSON.stringify({ type: 'error', code: error.code || 'SERVICE_OPERATION_FAILED', error: error.message })}\n`);
        return;
      }
      if (!res.destroyed) {
        const safe = safeFailure(error);
        sendJson(res, safe.status, {
          code: safe.code,
          error: safe.message,
          ...(safe.fingerprint ? { fingerprint: safe.fingerprint } : {}),
          ...(safe.previousFingerprint ? { previousFingerprint: safe.previousFingerprint } : {}),
        });
      }
    });
  });

  server.on('upgrade', (req, socket, head) => {
    let url;
    try {
      url = endpointFor(req.url);
    } catch (error) {
      rejectUpgrade(socket, error.status || 400, error.code || 'INVALID_PATH', error.message);
      return;
    }
    const match = /^\/v1\/hosts\/([^/]+)\/terminal$/.exec(url.pathname);
    if (req.method !== 'GET' || !match || url.search) {
      rejectUpgrade(socket, 404, 'NOT_FOUND', '找不到服務終端路徑');
      return;
    }
    if (!serviceTerminalSourceAllowed(req, config, server.address()?.port || config.port)) {
      rejectUpgrade(socket, 403, 'FORBIDDEN', '不允許的服務終端 Host 或 Origin');
      return;
    }
    const role = authenticate(req, tokens);
    if (!role) {
      rejectUpgrade(socket, 401, 'UNAUTHORIZED', '需要有效的 UI Bearer token');
      return;
    }
    if (role !== 'ui') {
      rejectUpgrade(socket, 403, 'FORBIDDEN', '服務終端僅允許 UI 憑證');
      return;
    }
    if (state.manuallyLocked) {
      rejectUpgrade(socket, 423, 'SERVICE_LOCKED', 'SSHDeck service 已手動鎖定');
      return;
    }
    let alias;
    try {
      alias = decodeSegment(match[1]);
      if (alias.includes('/')) throw httpError(400, 'INVALID_PATH', '主機別名路徑無效');
    } catch (error) {
      rejectUpgrade(socket, error.status || 400, error.code || 'INVALID_PATH', error.message);
      return;
    }
    let host;
    try {
      host = readHosts(dataFile).find((item) => item.alias === alias);
      if (!host) throw httpError(404, 'HOST_NOT_FOUND', '找不到主機設定');
      asCredentialHost(host, state.credentials, state.manuallyLocked);
    } catch (error) {
      const safe = safeFailure(error);
      rejectUpgrade(socket, safe.status, safe.code, safe.message);
      return;
    }
    terminalWebSocketServer.handleUpgrade(req, socket, head, (webSocket) => {
      terminalWebSocketServer.emit('connection', webSocket, req, alias);
    });
  });

  terminalWebSocketServer.on('connection', (webSocket, _req, alias) => {
    let resolveClosed;
    let removed = false;
    const terminal = {
      alias,
      socket: webSocket,
      session: null,
      pendingFingerprint: undefined,
      abortController: new AbortController(),
      columns: 80,
      rows: 24,
      closing: false,
      closeTimer: undefined,
      closed: new Promise((resolve) => { resolveClosed = resolve; }),
    };
    activeTerminals.add(terminal);

    const removeTerminal = () => {
      if (removed) return;
      removed = true;
      if (terminal.closeTimer) clearTimeout(terminal.closeTimer);
      terminal.abortController.abort();
      terminal.session?.close();
      terminal.session = null;
      activeTerminals.delete(terminal);
      resolveClosed();
    };
    const startTerminal = async (expectedFingerprint) => {
      if (terminal.closing || terminal.abortController.signal.aborted || state.manuallyLocked) return;
      let currentHost;
      try {
        currentHost = readHosts(dataFile).find((item) => item.alias === alias);
      } catch (error) {
        const safe = safeFailure(error);
        closeTerminal(terminal, {
          statusCode: 1011,
          reason: 'host configuration unavailable',
          error: { code: safe.code, message: safe.message },
        });
        return;
      }
      if (!currentHost) {
        closeTerminal(terminal, {
          statusCode: 1008,
          reason: 'unknown host',
          error: { code: 'HOST_NOT_FOUND', message: '找不到主機設定' },
        });
        return;
      }
      let credentialHost;
      try {
        credentialHost = asCredentialHost(currentHost, state.credentials, state.manuallyLocked);
      } catch (error) {
        const safe = safeFailure(error);
        closeTerminal(terminal, {
          statusCode: 1011,
          reason: 'service unavailable',
          error: { code: safe.code, message: safe.message },
        });
        return;
      }
      const credential = state.credentials.get(path.resolve(currentHost.keyPath));
      if (!credential) {
        closeTerminal(terminal, {
          statusCode: 1011,
          reason: 'credential unavailable',
          error: { code: 'CREDENTIAL_UNAVAILABLE', message: '服務金鑰目前無法使用' },
        });
        return;
      }
      try {
        const session = await ssh.openShell(dataFile, credentialHost, credential.passphrase, {
          cols: terminal.columns,
          rows: terminal.rows,
          signal: terminal.abortController.signal,
          ...(expectedFingerprint ? { expectedFingerprint } : {}),
          onTrustChange: ({ alias: trustedAlias }) => invalidateTunnelTargetGrants({
            alias: trustedAlias,
            reason: 'fingerprint-trust-changed',
          }),
          onData: (chunk) => {
            if (webSocket.readyState === WebSocket.OPEN && !terminal.closing) {
              webSocket.send(chunk, { binary: true });
            }
          },
          onClose: ({ error, code, signal }) => {
            terminal.session = null;
            finishTerminal(terminal, { error, code, signal });
          },
        });
        if (terminal.closing || terminal.abortController.signal.aborted || state.manuallyLocked) {
          session.close();
          return;
        }
        terminal.session = session;
        sendTerminalControl(terminal, {
          type: 'started',
          alias,
          username: currentHost.username,
          cols: terminal.columns,
          rows: terminal.rows,
        });
      } catch (error) {
        if (terminal.closing || terminal.abortController.signal.aborted) return;
        if (['HOST_TRUST_REQUIRED', 'HOST_KEY_CHANGED'].includes(error.code)) {
          terminal.pendingFingerprint = error.fingerprint;
          sendTerminalControl(terminal, {
            type: error.code === 'HOST_KEY_CHANGED' ? 'host-key-changed' : 'trust-required',
            code: error.code,
            fingerprint: error.fingerprint,
            ...(error.previousFingerprint ? { previousFingerprint: error.previousFingerprint } : {}),
          });
          return;
        }
        closeTerminal(terminal, {
          statusCode: 1011,
          reason: 'ssh terminal failed',
          error: {
            code: error.code || 'SSH_SHELL_FAILED',
            message: error.message || 'SSH 終端機連線失敗',
          },
        });
      }
    };

    webSocket.on('message', (data, isBinary) => {
      if (terminal.closing) return;
      if (isBinary) {
        terminal.session?.write(data);
        return;
      }
      let message;
      try { message = JSON.parse(data.toString()); } catch {
        closeTerminal(terminal, {
          statusCode: 1008,
          reason: 'invalid control frame',
          error: { code: 'INVALID_TERMINAL_FRAME', message: '終端控制訊息格式無效' },
        });
        return;
      }
      if (!message || typeof message !== 'object' || Array.isArray(message)) {
        closeTerminal(terminal, {
          statusCode: 1008,
          reason: 'invalid control frame',
          error: { code: 'INVALID_TERMINAL_FRAME', message: '終端控制訊息格式無效' },
        });
        return;
      }
      if (message.type === 'resize') {
        if (!Number.isInteger(message.cols) || !Number.isInteger(message.rows)
          || message.cols < 1 || message.rows < 1 || message.cols > 1000 || message.rows > 1000) {
          closeTerminal(terminal, {
            statusCode: 1008,
            reason: 'invalid terminal resize',
            error: { code: 'INVALID_TERMINAL_FRAME', message: '終端尺寸必須為 1 到 1000 的整數' },
          });
          return;
        }
        terminal.columns = message.cols;
        terminal.rows = message.rows;
        terminal.session?.resize(message.cols, message.rows);
        return;
      }
      if (message.type === 'trust') {
        if (!terminal.pendingFingerprint || message.fingerprint !== terminal.pendingFingerprint) {
          closeTerminal(terminal, {
            statusCode: 1008,
            reason: 'invalid trust confirmation',
            error: { code: 'INVALID_TRUST_CONFIRMATION', message: '主機指紋確認資料不符' },
          });
          return;
        }
        const confirmedFingerprint = terminal.pendingFingerprint;
        terminal.pendingFingerprint = undefined;
        startTerminal(confirmedFingerprint);
        return;
      }
      if (message.type === 'trust-reject') {
        closeTerminal(terminal, {
          statusCode: 1008,
          reason: 'host key rejected',
          error: { code: 'HOST_TRUST_REJECTED', message: '已拒絕主機指紋；未開啟終端機' },
        });
        return;
      }
      if (message.type === 'close') {
        closeTerminal(terminal, { reason: 'client closed' });
        return;
      }
      closeTerminal(terminal, {
        statusCode: 1008,
        reason: 'unsupported control frame',
        error: { code: 'INVALID_TERMINAL_FRAME', message: '不支援的終端控制訊息' },
      });
    });
    webSocket.once('close', removeTerminal);
    webSocket.once('error', removeTerminal);
    startTerminal();
  });

  let shutdownPromise;
  let closePromise;
  const shutdown = () => {
    if (shutdownPromise) return shutdownPromise;
    shutdownStarted = true;
    let resolveShutdown;
    let rejectShutdown;
    shutdownPromise = new Promise((resolve, reject) => {
      resolveShutdown = resolve;
      rejectShutdown = reject;
    });
    const invalidation = invalidateTunnelTargetGrants({ reason: 'service-shutdown' });
    for (const item of activeExecutions) item.controller.abort();
    activeExecutions.clear();
    closeTerminalsForAlias(undefined, {
      code: 'SERVICE_SHUTDOWN',
      message: 'SSHDeck service 已停止',
    });
    for (const terminal of activeTerminals) {
      closeTerminal(terminal, { statusCode: 1001, reason: 'service shutdown', force: true });
    }
    state.credentials.clear();
    Promise.resolve(invalidation).finally(() => {
      for (const subscriber of tunnelTargetGrantInvalidationSubscribers) subscriber.active = false;
      tunnelTargetGrantInvalidationSubscribers.clear();
    }).then(resolveShutdown, rejectShutdown);
    return shutdownPromise;
  };
  server.on('close', () => { void shutdown().catch(() => {}); });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });
  const address = server.address();
  server.url = `http://${config.host.includes(':') ? `[${config.host}]` : config.host}:${address.port}`;
  server.protocolVersion = PROTOCOL_VERSION;
  server.closeAsync = () => {
    if (closePromise) return closePromise;
    let resolveClose;
    let rejectClose;
    closePromise = new Promise((resolve, reject) => {
      resolveClose = resolve;
      rejectClose = reject;
    });
    const shutdownCompletion = shutdown();
    const terminalCloses = [...activeTerminals].map((terminal) => terminal.closed);
    const resourceClose = Promise.all(terminalCloses)
      .then(() => new Promise((resolve, reject) => {
        terminalWebSocketServer.close(() => {
          server.close((error) => error ? reject(error) : resolve());
        });
      }));
    Promise.allSettled([shutdownCompletion, resourceClose]).then(([shutdownResult, closeResult]) => {
      if (closeResult.status === 'rejected') rejectClose(closeResult.reason);
      else if (shutdownResult.status === 'rejected') rejectClose(shutdownResult.reason);
      else resolveClose();
    });
    return closePromise;
  };
  Object.defineProperty(server, 'activeTerminalCount', { get: () => activeTerminals.size });
  // 供後續 tunnel handler 共用認證角色判定，不擴大任何 HTTP 管理路徑權限。
  server.isTunnelAuthorizedRequest = (req) => authenticate(req, tokens) === 'tunnel';
  // 供服務內部 tunnel handler 訂閱撤銷，不新增 UI、CLI 或 Bot 可呼叫的管理路徑。
  server.subscribeTunnelTargetGrantInvalidation = subscribeTunnelTargetGrantInvalidation;
  server.getTunnelTargetGrant = (alias, targetId) => tunnelTargetGrantForHost(
    tunnelTargetGrants, dataFile, state, alias, targetId,
  );
  return server;
}

module.exports = {
  PROTOCOL_VERSION,
  startService,
  startOptions,
  readJson,
  tokenMatches,
};
