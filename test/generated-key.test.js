'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { utils } = require('ssh2');
const { generateManagedKeyPair } = require('../lib/ssh');

test('新金鑰產生後先驗證，畸形資料不寫入且最多重建三次', () => {
  let calls = 0;
  const valid = generateManagedKeyPair({ comment: 'generation-fixture' });
  const result = generateManagedKeyPair({}, () => {
    calls += 1;
    return calls < 3 ? { private: 'invalid', public: 'invalid' } : valid;
  });
  assert.equal(calls, 3);
  assert.equal(result, valid);
  calls = 0;
  assert.throws(() => generateManagedKeyPair({}, () => {
    calls += 1;
    return { private: 'invalid', public: 'invalid' };
  }), /無法產生有效/);
  assert.equal(calls, 3);
});

test('經驗證的 Ed25519 產生器保留加密與非加密契約', () => {
  for (const options of [{}, { passphrase: 'fixture-only-password', cipher: 'aes256-cbc' }]) {
    const pair = generateManagedKeyPair(options);
    assert.ok(!(utils.parseKey(pair.private, options.passphrase) instanceof Error));
    assert.match(pair.public, /^ssh-ed25519 /);
    if (options.passphrase) assert.ok(utils.parseKey(pair.private, 'wrong') instanceof Error);
  }
});
