'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { randomUUID } = require('node:crypto');
const {
  createOpenSshServiceFixture,
  startWslSession,
} = require('./helpers/openssh-service-fixture');

class FakeChild extends EventEmitter {
  constructor({ finishOnStdinEof = false } = {}) {
    super();
    this.stdin = new PassThrough();
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.exitCode = null;
    this.signalCode = null;
    this.closed = false;
    this.stdinEof = false;
    this.killCalls = 0;
    this.stdin.once('finish', () => {
      this.stdinEof = true;
      if (finishOnStdinEof) this.finish(0, null);
    });
  }

  kill(signal = 'SIGTERM') {
    this.killCalls += 1;
    this.finish(null, signal);
    return true;
  }

  finish(code, signal) {
    if (this.closed) return;
    this.closed = true;
    this.exitCode = code;
    this.signalCode = signal;
    this.stdout.end();
    this.stderr.end();
    this.emit('close', code, signal);
  }
}

function fakeSpawn(mode) {
  let child;
  let command;
  const spawnProcess = (_command, args) => {
    child = new FakeChild({ finishOnStdinEof: mode === 'wait-for-stdin-eof' });
    command = args.at(-1);
    const marker = args.at(-1).match(/sshdeck-wsl-fixture-session-[0-9a-f-]+/)?.[0];
    process.nextTick(() => {
      if (mode === 'fail-before-marker') {
        child.stderr.write('keeper command failed');
        child.finish(17, null);
        return;
      }
      if (mode === 'spawn-error') {
        const error = Object.assign(new Error('spawn failed'), { code: 'ENOENT' });
        child.emit('error', error);
        child.finish(1, null);
        return;
      }
      child.stdout.write(`${marker}\n`);
      if (mode === 'exit-after-marker') {
        process.nextTick(() => child.finish(23, null));
      }
    });
    return child;
  };
  return {
    spawnProcess,
    get command() { return command; },
    get child() { return child; },
  };
}

function fakeFixtureDependencies({
  sessionError,
  portError,
  failUnitCleanup = true,
} = {}) {
  const runId = randomUUID();
  const primaryError = new Error('fixture unit cleanup failed');
  let portCheckCalls = 0;
  const session = {
    isRunning: true,
    stopCalls: 0,
    async stop() {
      this.stopCalls += 1;
      if (sessionError) throw sessionError;
      return { code: 0, signal: null };
    },
  };
  const dependencies = {
    getPrivateWslHostAddress: () => '172.19.24.36',
    portAvailable: async () => {
      portCheckCalls += 1;
      if (portError && portCheckCalls === 3) throw portError;
      return true;
    },
    startWslSession: async () => session,
    runWsl(args) {
      if (args[0] === 'mktemp') return `/tmp/sshdeck-ticket01-${runId}-Abc123`;
      return '';
    },
    waitForUnit: async () => {},
    waitForPort: async () => {},
    stopUnitAndWait: async () => {
      if (failUnitCleanup) throw primaryError;
      return 'not-found';
    },
    fingerprintFor(file) {
      return file.endsWith('/host-a') ? 'SHA256:host-a' : 'SHA256:host-b';
    },
  };
  return {
    dependencies,
    primaryError,
    session,
  };
}

test('WSL fixture keeper 在 readiness marker 後立即退出時 startup fail closed', async () => {
  const fake = fakeSpawn('exit-after-marker');
  await assert.rejects(
    startWslSession({ spawnProcess: fake.spawnProcess, startupTimeoutMs: 100 }),
    /WSL fixture session 未能啟動：退出碼 23/,
  );
  assert.ok(
    fake.command.indexOf('exec timeout') < fake.command.indexOf('printf')
      && fake.command.indexOf('printf') < fake.command.indexOf('exec cat'),
    'readiness marker 必須由 timeout 管理的 foreground keeper 輸出',
  );
  assert.equal(fake.child.stdin.writableEnded, true, 'startup failure 必須送出 stdin EOF');
  assert.equal(fake.child.closed, true, 'startup failure 必須收斂至 child close');
});

test('WSL fixture keeper 未輸出 readiness marker 即失敗時保留診斷並收斂 child', async () => {
  const fake = fakeSpawn('fail-before-marker');
  await assert.rejects(
    startWslSession({ spawnProcess: fake.spawnProcess, startupTimeoutMs: 100 }),
    /WSL fixture session 未能啟動：keeper command failed/,
  );
  assert.equal(fake.child.stdin.writableEnded, true, 'startup failure 必須送出 stdin EOF');
  assert.equal(fake.child.closed, true, 'startup failure 必須收斂至 child close');
});

test('WSL fixture spawn error 保留錯誤分類並等待 child close', async () => {
  const fake = fakeSpawn('spawn-error');
  await assert.rejects(
    startWslSession({ spawnProcess: fake.spawnProcess, startupTimeoutMs: 100 }),
    /WSL fixture session 未能啟動：程序錯誤 ENOENT/,
  );
  assert.equal(fake.child.stdin.writableEnded, true, 'spawn failure 必須送出 stdin EOF');
  assert.equal(fake.child.closed, true, 'spawn failure 必須等待 child close');
});

test('WSL fixture stop 以 stdin EOF 關閉 keeper 並收斂而不強制終止 child', async () => {
  const fake = fakeSpawn('wait-for-stdin-eof');
  const session = await startWslSession({
    spawnProcess: fake.spawnProcess,
    startupTimeoutMs: 100,
  });

  assert.equal(session.isRunning, true);
  assert.deepEqual(await session.stop(), { code: 0, signal: null });
  assert.equal(fake.child.stdinEof, true, '正常停止必須先關閉 stdin');
  assert.equal(fake.child.closed, true, '正常停止必須等待 child close');
  assert.equal(fake.child.killCalls, 0, 'stdin EOF 已正常收斂時不得強制終止 child');
  assert.equal(session.isRunning, false);
});

test('OpenSSH fixture 前置 cleanup 失敗時仍會停止 WSL session 並保留主要錯誤', async () => {
  const fake = fakeFixtureDependencies();
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
  }, fake.dependencies);

  await assert.rejects(fixture.cleanup(), (error) => error === fake.primaryError);
  assert.equal(fake.session.stopCalls, 1, '即使 unit cleanup 失敗仍須嘗試停止 WSL session');
});

test('OpenSSH fixture cleanup 同時失敗時保留主要與 session-stop 錯誤', async () => {
  const sessionError = new Error('WSL session stop failed');
  const fake = fakeFixtureDependencies({ sessionError });
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
  }, fake.dependencies);

  await assert.rejects(fixture.cleanup(), (error) => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, [fake.primaryError, sessionError]);
    return true;
  });
  assert.equal(fake.session.stopCalls, 1, 'session stop 必須只嘗試一次');
});

test('OpenSSH fixture port cleanup 診斷與 session-stop 錯誤均保留', async () => {
  const portError = new Error('port release check failed');
  const sessionError = new Error('WSL session stop failed');
  const fake = fakeFixtureDependencies({
    sessionError,
    portError,
    failUnitCleanup: false,
  });
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
  }, fake.dependencies);

  await assert.rejects(fixture.cleanup(), (error) => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, [portError, sessionError]);
    return true;
  });
  assert.equal(fake.session.stopCalls, 1);
});
