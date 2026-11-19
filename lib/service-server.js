'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { timingSafeEqual } = require('node:crypto');
const { StringDecoder } = require('node:string_decoder');
const { utils } = require('ssh2');
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
  if (typeof cli !== 'string' || cli.length < 32) {
    throw store.failure('SERVICE_TOKEN_REQUIRED', 'SSHDECK_SERVICE_TOKEN 必須至少 32 個字元；服務未啟動');
  }
  if (typeof ui !== 'string' || ui.length < 32 || tokenMatches(cli, ui)) {
    throw store.failure('UI_TOKEN_REQUIRED', 'SSHDECK_UI_TOKEN 必須至少 32 個字元，且不可與 CLI token 相同；服務未啟動');
  }
  return { cli, ui };
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
  const state = { manuallyLocked, credentials };
  const version = require('../package.json').version;

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
        for (const item of activeExecutions) item.controller.abort();
        state.credentials.clear();
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
          ssh.updateManagedKeyProfile(dataFile, updated);
          ssh.clearHostStatus(dataFile, alias);
          if (ssh.endpoint(existing) !== ssh.endpoint(updated)
            && !readHosts(dataFile).some((item) => ssh.endpoint(item) === ssh.endpoint(existing))) {
            ssh.clearHostTrust(dataFile, existing);
          }
          for (const item of activeExecutions) if (item.alias === alias) item.controller.abort();
          return sendJson(res, 200, publicHost(dataFile, updated));
        }

        if (!action && req.method === 'DELETE') {
          requireRole(role, ['ui']);
          mutateHosts(dataFile, (items) => {
            const index = items.findIndex((item) => item.alias === alias);
            if (index < 0) throw httpError(404, 'HOST_NOT_FOUND', '找不到主機設定');
            items.splice(index, 1);
          });
          ssh.clearHostStatus(dataFile, alias);
          if (!readHosts(dataFile).some((item) => ssh.endpoint(item) === ssh.endpoint(existing))) {
            ssh.clearHostTrust(dataFile, existing);
          }
          for (const item of activeExecutions) if (item.alias === alias) item.controller.abort();
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
          ssh.clearHostStatus(dataFile, alias);
          if (!readHosts(dataFile).some((item) => item.keyPath && path.resolve(item.keyPath) === oldPath)) {
            state.credentials.delete(oldPath);
          }
          for (const item of activeExecutions) if (item.alias === alias) item.controller.abort();
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
          if (!state.manuallyLocked) state.credentials.set(path.resolve(record.keyPath), credential);
          ssh.clearHostStatus(dataFile, alias);
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
        state.credentials.delete(path.resolve(record.keyPath));
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

  let shutdownStarted = false;
  let closePromise;
  const shutdown = () => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    for (const item of activeExecutions) item.controller.abort();
    activeExecutions.clear();
    state.credentials.clear();
  };
  server.on('close', shutdown);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });
  const address = server.address();
  server.url = `http://${config.host.includes(':') ? `[${config.host}]` : config.host}:${address.port}`;
  server.protocolVersion = PROTOCOL_VERSION;
  server.closeAsync = () => {
    if (closePromise) return closePromise;
    shutdown();
    closePromise = new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    return closePromise;
  };
  return server;
}

module.exports = {
  PROTOCOL_VERSION,
  startService,
  startOptions,
  readJson,
  tokenMatches,
};
