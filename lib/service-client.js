'use strict';

const { PROTOCOL_VERSION } = require('./service-contract');

class ServiceClientError extends Error {
  constructor(message, { code = 'SERVICE_REQUEST_FAILED', status, fingerprint, previousFingerprint } = {}) {
    super(message);
    this.name = 'ServiceClientError';
    this.code = code;
    this.status = status;
    this.fingerprint = fingerprint;
    this.previousFingerprint = previousFingerprint;
  }
}

function clientConfig(env = process.env) {
  if (typeof env.SSHDECK_SERVICE_URL !== 'string' || !env.SSHDECK_SERVICE_URL.trim()) {
    throw new ServiceClientError('service mode 必須設定 SSHDECK_SERVICE_URL', { code: 'SERVICE_CONFIG_REQUIRED' });
  }
  if (typeof env.SSHDECK_SERVICE_TOKEN !== 'string' || env.SSHDECK_SERVICE_TOKEN.length < 32) {
    throw new ServiceClientError('service mode 必須設定有效的 SSHDECK_SERVICE_TOKEN', { code: 'SERVICE_CONFIG_REQUIRED' });
  }
  let base;
  try { base = new URL(env.SSHDECK_SERVICE_URL); } catch {
    throw new ServiceClientError('SSHDECK_SERVICE_URL 格式無效', { code: 'SERVICE_CONFIG_INVALID' });
  }
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash
    || (base.pathname !== '/' && base.pathname !== '')) {
    throw new ServiceClientError('SSHDECK_SERVICE_URL 必須是無憑證、無路徑的 HTTP(S) origin', { code: 'SERVICE_CONFIG_INVALID' });
  }
  return { base: base.origin, token: env.SSHDECK_SERVICE_TOKEN };
}

class ServiceClient {
  constructor({ env = process.env, fetchImpl = fetch } = {}) {
    const config = clientConfig(env);
    this.base = config.base;
    this.token = config.token;
    this.fetch = fetchImpl;
    this.versionVerified = false;
  }

  async verifyVersion() {
    if (this.versionVerified) return;
    let response;
    try {
      response = await this.fetch(`${this.base}/v1/version`, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      throw new ServiceClientError('SSHDeck service 無法連線；不會改用 standalone 資料', { code: 'SERVICE_UNAVAILABLE' });
    }
    if (!response.ok) throw new ServiceClientError(`SSHDeck service 版本查詢失敗（HTTP ${response.status}）`, {
      code: 'SERVICE_VERSION_UNAVAILABLE', status: response.status,
    });
    let payload;
    try { payload = await response.json(); } catch {
      throw new ServiceClientError('SSHDeck service 版本回應格式無效', { code: 'SERVICE_VERSION_INVALID' });
    }
    if (payload.protocolVersion !== PROTOCOL_VERSION) {
      throw new ServiceClientError(`SSHDeck service 協定版本不相容（CLI ${PROTOCOL_VERSION}、service ${String(payload.protocolVersion)}）`, {
        code: 'SERVICE_VERSION_MISMATCH',
      });
    }
    this.versionVerified = true;
  }

  async request(route, { method = 'GET', body, signal } = {}) {
    await this.verifyVersion();
    let response;
    try {
      response = await this.fetch(`${this.base}${route}`, {
        method,
        headers: {
          authorization: `Bearer ${this.token}`,
          accept: 'application/json',
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        ...(signal ? { signal } : { signal: AbortSignal.timeout(10_000) }),
      });
    } catch (error) {
      if (signal?.aborted) throw new ServiceClientError('服務要求已取消；不會重送命令', { code: 'SERVICE_CANCELLED' });
      throw new ServiceClientError('SSHDeck service 連線中斷；不會重送命令', { code: 'SERVICE_DISCONNECTED' });
    }
    if (response.status === 204) return null;
    let payload;
    try { payload = await response.json(); } catch {
      throw new ServiceClientError(`SSHDeck service 回應格式無效（HTTP ${response.status}）`, {
        code: 'SERVICE_RESPONSE_INVALID', status: response.status,
      });
    }
    if (!response.ok) {
      throw new ServiceClientError(payload.error || `SSHDeck service 要求失敗（HTTP ${response.status}）`, {
        code: payload.code || 'SERVICE_REQUEST_FAILED',
        status: response.status,
        fingerprint: payload.fingerprint,
        previousFingerprint: payload.previousFingerprint,
      });
    }
    return payload;
  }

  async listHosts() {
    return this.request('/v1/hosts');
  }

  async checkHost(alias, expectedFingerprint) {
    return this.request(`/v1/hosts/${encodeURIComponent(alias)}/check`, {
      method: 'POST',
      body: expectedFingerprint ? { expectedFingerprint } : {},
    });
  }

  async exec(alias, command, { signal, onStdout = () => {}, onStderr = () => {} } = {}) {
    await this.verifyVersion();
    let response;
    try {
      response = await this.fetch(`${this.base}/v1/hosts/${encodeURIComponent(alias)}/exec`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.token}`,
          accept: 'application/x-ndjson',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ command }),
        signal,
      });
    } catch {
      if (signal?.aborted) throw new ServiceClientError('服務要求已取消；不會重送命令', { code: 'SERVICE_CANCELLED' });
      throw new ServiceClientError('SSHDeck service 連線中斷；不會重送命令', { code: 'SERVICE_DISCONNECTED' });
    }
    if (!response.ok) {
      let payload = {};
      try { payload = await response.json(); } catch { /* 保留穩定 HTTP 狀態錯誤 */ }
      throw new ServiceClientError(payload.error || `SSHDeck service 要求失敗（HTTP ${response.status}）`, {
        code: payload.code || 'SERVICE_REQUEST_FAILED',
        status: response.status,
        fingerprint: payload.fingerprint,
        previousFingerprint: payload.previousFingerprint,
      });
    }
    if (!response.body) throw new ServiceClientError('SSHDeck service 未提供命令串流；不會重送命令', {
      code: 'SERVICE_STREAM_MISSING',
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let pending = '';
    let exitCode;
    try {
      while (true) {
        const { done, value } = await reader.read();
        pending += decoder.decode(value || new Uint8Array(), { stream: !done });
        let newline;
        while ((newline = pending.indexOf('\n')) >= 0) {
          const line = pending.slice(0, newline);
          pending = pending.slice(newline + 1);
          if (!line) continue;
          let event;
          try { event = JSON.parse(line); } catch {
            throw new ServiceClientError('SSHDeck service 命令串流格式無效；不會重送命令', {
              code: 'SERVICE_STREAM_INVALID',
            });
          }
          if (event.type === 'stdout') onStdout(event.data);
          else if (event.type === 'stderr') onStderr(event.data);
          else if (event.type === 'exit' && Number.isInteger(event.code)) exitCode = event.code;
          else if (event.type === 'error') {
            throw new ServiceClientError(event.error || '遠端命令失敗', { code: event.code || 'REMOTE_EXEC_FAILED' });
          } else {
            throw new ServiceClientError('SSHDeck service 命令串流包含未知事件', { code: 'SERVICE_STREAM_INVALID' });
          }
        }
        if (done) break;
      }
    } catch (error) {
      try { await reader.cancel(); } catch { /* 連線可能已中斷 */ }
      if (error instanceof ServiceClientError) throw error;
      if (signal?.aborted) throw new ServiceClientError('服務要求已取消；不會重送命令', { code: 'SERVICE_CANCELLED' });
      throw new ServiceClientError('SSHDeck service 串流中斷；不會重送命令', { code: 'SERVICE_DISCONNECTED' });
    } finally {
      reader.releaseLock();
    }
    if (pending.trim() || exitCode === undefined) {
      throw new ServiceClientError('SSHDeck service 串流未收到完整 exit 事件；不會重送命令', {
        code: 'SERVICE_DISCONNECTED',
      });
    }
    return exitCode;
  }
}

async function runCli(args, { env = process.env, stdout = process.stdout, stderr = process.stderr, processObject = process } = {}) {
  const client = new ServiceClient({ env });
  if (args[0] === 'exec') {
    const separator = args.indexOf('--');
    if (separator !== 2 || !args[1]) throw new ServiceClientError('用法：sshdeck exec <別名> -- <遠端命令>', { code: 'USAGE' });
    const command = args.slice(separator + 1).join(' ');
    if (!command.trim()) throw new ServiceClientError('遠端命令不可空白', { code: 'INVALID_COMMAND' });
    const controller = new AbortController();
    const interrupt = () => controller.abort();
    processObject.once('SIGINT', interrupt);
    try {
      try {
        const code = await client.exec(args[1], command, {
          signal: controller.signal,
          onStdout: (text) => stdout.write(text),
          onStderr: (text) => stderr.write(text),
        });
        if (code < 0 || code > 255) throw new ServiceClientError('遠端命令回傳無效結束碼', { code: 'INVALID_EXIT_CODE' });
        processObject.exitCode = code;
      } catch (error) {
        if (controller.signal.aborted && error.code === 'SERVICE_CANCELLED') {
          processObject.exitCode = 130;
          return;
        }
        throw error;
      }
    } finally {
      processObject.removeListener('SIGINT', interrupt);
    }
    return;
  }

  if (args[0] === 'host' && args[1] === 'list' && args.length === 2) {
    const hosts = await client.listHosts();
    stdout.write(hosts.length
      ? `${hosts.map((host) => `${host.alias}\t${host.hostname}:${host.port}\t${host.username}\t${host.hasKey ? '已關聯服務金鑰' : '未設定金鑰'}`).join('\n')}\n`
      : '尚未設定主機。\n');
    return;
  }
  if (args[0] === 'host' && args[1] === 'check' && args[2]) {
    const result = await client.checkHost(args[2]);
    stdout.write(`SSH 登入檢查成功：${result.fingerprint}\n`);
    return;
  }
  if (args[0] === 'host' && args[1] === 'trust' && args[2] && args[3] === '--fingerprint' && args[4]) {
    const result = await client.checkHost(args[2], args[4]);
    stdout.write(`已核對並信任 ${args[2]}：${result.fingerprint}\n`);
    return;
  }
  throw new ServiceClientError(
    'service mode 僅支援 exec、host list、host check 與明確指紋核對的 host trust；不會回退至 standalone',
    { code: 'SERVICE_COMMAND_UNSUPPORTED' },
  );
}

module.exports = { ServiceClient, ServiceClientError, clientConfig, runCli };
