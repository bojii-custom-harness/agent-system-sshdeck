'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createCipheriv, createDecipheriv } = require('node:crypto');
const ssh = require('./ssh');

const ENVELOPE_FORMAT = 'sshdeck-service-credential-v1';
const LOCK_FORMAT = 'sshdeck-service-state-v1';
const AAD = Buffer.from(ENVELOPE_FORMAT);

function failure(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function encryptionKey(value) {
  if (typeof value !== 'string' || !/^[\da-f]{64}$/i.test(value)) {
    throw failure('ENCRYPTION_KEY_REQUIRED', 'SSHDECK_ENCRYPTION_KEY 必須是 64 位十六進位字元；服務未啟動');
  }
  return Buffer.from(value, 'hex');
}

function parseCredential(value) {
  if (!value || typeof value !== 'object' || typeof value.privateKey !== 'string'
    || typeof value.passphrase !== 'string') {
    throw failure('DATA_CORRUPT', '服務憑證資料格式錯誤');
  }
  return { privateKey: Buffer.from(value.privateKey, 'base64'), passphrase: value.passphrase };
}

function encryptCredential(credential, key) {
  const iv = require('node:crypto').randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(AAD);
  const plaintext = Buffer.from(JSON.stringify({
    privateKey: Buffer.from(credential.privateKey).toString('base64'),
    passphrase: credential.passphrase,
  }));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.from(JSON.stringify({
    format: ENVELOPE_FORMAT,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  }) + '\n');
}

function decryptCredential(envelopeBytes, key) {
  let envelope;
  try {
    envelope = JSON.parse(Buffer.from(envelopeBytes).toString('utf8'));
    if (envelope.format !== ENVELOPE_FORMAT) throw new Error('format');
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    if (iv.length !== 12 || tag.length !== 16 || !ciphertext.length) throw new Error('shape');
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(AAD);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return parseCredential(JSON.parse(plaintext.toString('utf8')));
  } catch {
    throw failure('DATA_CORRUPT', '服務憑證資料無法驗證或解密；原始資料已保留');
  }
}

function publicKeyFor(privateKey, passphrase) {
  const parsed = ssh.parsePrivateKey(privateKey, passphrase);
  const publicLine = `${parsed.type} ${parsed.getPublicSSH().toString('base64')}`;
  return { parsed, publicLine };
}

function normalizePublicKey(value) {
  return typeof value === 'string' ? value.trim().split(/\s+/).slice(0, 2).join(' ') : '';
}

function loadCredentialFile(keyPath, key) {
  let stored;
  try { stored = fs.readFileSync(keyPath); } catch {
    throw failure('DATA_CORRUPT', '服務憑證檔案不存在或無法讀取；原始資料已保留');
  }
  const credential = decryptCredential(stored, key);
  const { publicLine } = publicKeyFor(credential.privateKey, credential.passphrase);
  let publicKey;
  try { publicKey = fs.readFileSync(`${keyPath}.pub`, 'utf8'); } catch {
    throw failure('DATA_CORRUPT', '服務公鑰檔案不存在或無法讀取；原始資料已保留');
  }
  if (normalizePublicKey(publicLine) !== normalizePublicKey(publicKey)) {
    throw failure('DATA_CORRUPT', '服務私鑰與公鑰不相符；原始資料已保留');
  }
  return credential;
}

function stateFileFor(dataFile) {
  return `${dataFile}.service-state.json`;
}

function readManualLockState(dataFile) {
  try {
    const state = JSON.parse(fs.readFileSync(stateFileFor(dataFile), 'utf8'));
    if (state.format !== LOCK_FORMAT || typeof state.manuallyLocked !== 'boolean') {
      throw failure('DATA_CORRUPT', '服務鎖定狀態資料格式錯誤；原始資料已保留');
    }
    return state.manuallyLocked;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    if (error.code === 'DATA_CORRUPT') throw error;
    throw failure('DATA_CORRUPT', '服務鎖定狀態資料無法讀取；原始資料已保留');
  }
}

function writeManualLockState(dataFile, manuallyLocked) {
  const file = stateFileFor(dataFile);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify({
      format: LOCK_FORMAT,
      manuallyLocked,
      updatedAt: new Date().toISOString(),
    }, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, file);
  } finally {
    try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function validateStoredCredentials({ dataFile, hosts, records, key }) {
  const byPath = new Map(records.map((record) => [path.resolve(record.keyPath), record]));
  for (const host of hosts) {
    if (!host.keyPath) continue;
    if (!ssh.isManagedKeyPath(dataFile, host.keyPath) || !byPath.has(path.resolve(host.keyPath))) {
      throw failure('DATA_CORRUPT', '服務主機關聯了非服務管理的金鑰；原始資料已保留');
    }
  }

  const credentials = new Map();
  for (const record of records) {
    if (!ssh.isManagedKeyPath(dataFile, record.keyPath)) {
      throw failure('DATA_CORRUPT', '服務金鑰索引包含無效路徑；原始資料已保留');
    }
    credentials.set(path.resolve(record.keyPath), loadCredentialFile(record.keyPath, key));
  }
  return credentials;
}

function persistCredential({ dataFile, key, credential }) {
  const encrypted = encryptCredential(credential, key);
  const parsed = publicKeyFor(credential.privateKey, credential.passphrase);
  const stored = ssh.storeManagedKey(dataFile, {
    alias: credential.alias,
    privateKey: encrypted,
    publicKey: parsed.publicLine,
    profile: credential.profile,
  });
  return { ...stored, credential: { privateKey: Buffer.from(credential.privateKey), passphrase: credential.passphrase } };
}

module.exports = {
  ENVELOPE_FORMAT,
  encryptionKey,
  encryptCredential,
  decryptCredential,
  publicKeyFor,
  loadCredentialFile,
  stateFileFor,
  readManualLockState,
  writeManualLockState,
  validateStoredCredentials,
  persistCredential,
  failure,
};
