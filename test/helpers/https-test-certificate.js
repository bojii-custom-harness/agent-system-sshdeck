'use strict';

const crypto = require('node:crypto');

function der(tag, content) {
  const length = content.length;
  if (length < 0x80) return Buffer.concat([Buffer.from([tag, length]), content]);
  const bytes = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 0x100);
  }
  return Buffer.concat([Buffer.from([tag, 0x80 | bytes.length, ...bytes]), content]);
}

function sequence(...values) {
  return der(0x30, Buffer.concat(values));
}

function encodeOid(value) {
  const parts = value.split('.').map(BigInt);
  const encoded = [];
  for (const part of [40n * parts[0] + parts[1], ...parts.slice(2)]) {
    const bytes = [Number(part & 0x7fn)];
    let remaining = part >> 7n;
    while (remaining > 0n) {
      bytes.unshift(Number(remaining & 0x7fn) | 0x80);
      remaining >>= 7n;
    }
    encoded.push(...bytes);
  }
  return der(0x06, Buffer.from(encoded));
}

function certificateExtension(oid, value, critical = false) {
  return sequence(
    encodeOid(oid),
    ...(critical ? [der(0x01, Buffer.from([0xff]))] : []),
    der(0x04, value),
  );
}

function utcTime(value) {
  const timestamp = value.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}/, '');
  return der(0x17, Buffer.from(`${timestamp.slice(2, 14)}Z`));
}

function createHttpsTestCertificate() {
  const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
  const serial = crypto.randomBytes(16);
  serial[0] &= 0x7f;
  if (serial.every((byte) => byte === 0)) serial[serial.length - 1] = 1;
  const serialStart = serial.findIndex((byte) => byte !== 0);
  const serialValue = serial.subarray(serialStart);
  const name = sequence(der(0x31, sequence(
    encodeOid('2.5.4.3'),
    der(0x0c, Buffer.from('SSHDeck ephemeral HTTPS ingress test')),
  )));
  const algorithm = sequence(encodeOid('1.2.840.113549.1.1.11'), der(0x05, Buffer.alloc(0)));
  const subjectAltName = sequence(
    der(0x87, Buffer.from([127, 0, 0, 1])),
    der(0x82, Buffer.from('localhost')),
  );
  const extensions = sequence(
    certificateExtension('2.5.29.19', sequence(der(0x01, Buffer.from([0xff]))), true),
    certificateExtension('2.5.29.15', der(0x03, Buffer.from([2, 0xa4])), true),
    certificateExtension('2.5.29.37', sequence(encodeOid('1.3.6.1.5.5.7.3.1'))),
    certificateExtension('2.5.29.17', subjectAltName),
  );
  const now = Date.now();
  const tbs = sequence(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, serialValue),
    algorithm,
    name,
    sequence(utcTime(new Date(now - 60_000)), utcTime(new Date(now + 24 * 60 * 60_000))),
    name,
    keyPair.publicKey.export({ type: 'spki', format: 'der' }),
    der(0xa3, extensions),
  );
  const signature = crypto.sign('sha256', tbs, {
    key: keyPair.privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });
  const certificate = sequence(tbs, algorithm, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const certificatePem = `-----BEGIN CERTIFICATE-----\n${certificate.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  return { certificatePem, privateKeyPem };
}

module.exports = { createHttpsTestCertificate };
