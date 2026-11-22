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
  constructor({ finishOnStdinEof = false, killBehavior } = {}) {
    super();
    this.stdin = new PassThrough();
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.exitCode = null;
    this.signalCode = null;
    this.closed = false;
    this.stdinEof = false;
    this.killCalls = 0;
    this.killSignals = [];
    this.killBehavior = killBehavior;
    this.stdin.once('finish', () => {
      this.stdinEof = true;
      if (finishOnStdinEof) this.finish(0, null);
    });
  }

  kill(signal = 'SIGTERM') {
    this.killCalls += 1;
    this.killSignals.push(signal);
    if (this.killBehavior) return this.killBehavior(this, signal);
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
    child = new FakeChild({
      finishOnStdinEof: mode === 'wait-for-stdin-eof',
      killBehavior: mode === 'ignore-term'
        ? (instance, signal) => {
          if (signal === 'SIGKILL') instance.finish(null, signal);
          return true;
        }
        : mode === 'ignore-all-kills'
          ? () => true
          : undefined,
    });
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
      if (mode === 'ignore-term' || mode === 'ignore-all-kills') return;
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
  targetPortError,
  failUnitCleanup = true,
  unitStopped = async () => false,
} = {}) {
  const runId = randomUUID();
  const primaryError = new Error('fixture unit cleanup failed');
  const unitCleanupCalls = [];
  const runWslCalls = [];
  const portChecks = [];
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
    portAvailable: async (port) => {
      portChecks.push(port);
      if (portError && portChecks.length === 3) throw portError;
      return true;
    },
    startWslSession: async () => session,
    runWsl(args) {
      runWslCalls.push(args);
      if (args[0] === 'mktemp') return `/tmp/sshdeck-ticket01-${runId}-Abc123`;
      return '';
    },
    waitForUnit: async () => {},
    waitForPort: async () => {},
    waitForTargetPort: async () => 34567,
    stopUnitAndWait: async (unit) => {
      unitCleanupCalls.push(unit);
      if (failUnitCleanup && unitCleanupCalls.length === 1) throw primaryError;
      return 'not-found';
    },
    unitIsStopped: unitStopped,
    targetPortListening() {
      if (targetPortError) throw targetPortError;
      return false;
    },
    fingerprintFor(file) {
      return file.endsWith('/host-a') ? 'SHA256:host-a' : 'SHA256:host-b';
    },
  };
  return {
    dependencies,
    primaryError,
    session,
    unitCleanupCalls,
    runWslCalls,
    portChecks,
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

test('WSL fixture startup timeout 在 child 忽略一般終止後升級並確認 close', async () => {
  const fake = fakeSpawn('ignore-term');
  await assert.rejects(
    startWslSession({
      spawnProcess: fake.spawnProcess,
      startupTimeoutMs: 20,
      closeTimeoutMs: 20,
      forcedCloseTimeoutMs: 20,
    }),
    /WSL fixture session 未在期限內就緒/,
  );
  assert.deepEqual(fake.child.killSignals, ['SIGTERM', 'SIGKILL']);
  assert.equal(fake.child.closed, true, 'startup timeout 必須等待強制終止後的 child close');
});

test('WSL fixture startup timeout 保留未收斂 child 與 close error，並提供續清理入口', async () => {
  const fake = fakeSpawn('ignore-all-kills');
  let startupError;
  try {
    await startWslSession({
      spawnProcess: fake.spawnProcess,
      startupTimeoutMs: 20,
      closeTimeoutMs: 20,
      forcedCloseTimeoutMs: 20,
    });
  } catch (error) {
    startupError = error;
  }

  try {
    assert.ok(startupError instanceof AggregateError, 'startup 與 child cleanup 失敗必須合併回報');
    assert.match(startupError.errors[0].message, /未在期限內就緒/);
    assert.ok(
      startupError.errors.some((error) => /close|終止/i.test(error.message)),
      'AggregateError 必須保留 child close／termination failure',
    );
    assert.equal(startupError.child, fake.child, '錯誤必須保留未收斂 child 的 owner');
    assert.equal(typeof startupError.cleanup, 'function', '呼叫端必須能續作 child cleanup');

    fake.child.killBehavior = (instance, signal) => {
      if (signal === 'SIGKILL') instance.finish(null, signal);
      return true;
    };
    await startupError.cleanup();
    assert.equal(fake.child.closed, true, '續清理入口必須等待 child close');
  } finally {
    if (fake.child && !fake.child.closed) fake.child.finish(0, null);
  }
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

test('OpenSSH fixture 首個 unit cleanup 失敗仍處理其他 unit 與 ports，並保留不安全 root', async () => {
  const fake = fakeFixtureDependencies({ unitStopped: async () => false });
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
    allowDirectTcpip: true,
  }, fake.dependencies);
  let cleanupError;
  try {
    await fixture.cleanup();
  } catch (error) {
    cleanupError = error;
  }

  assert.equal(cleanupError, fake.primaryError);
  assert.equal(fake.unitCleanupCalls.length, 3, '第一個 unit 失敗後仍須逐一嘗試其他 unit');
  assert.equal(fake.runWslCalls.some((args) => args[0] === 'rm'), false, '無法確認 unit 已停止時不得移除其 root');
  assert.equal(fake.portChecks.length, 4, '即使 unit/root 清理受阻仍須檢查兩個 SSH ports');
  assert.equal(fake.session.stopCalls, 1, 'cleanup 失敗時仍須停止 session');
  assert.equal(cleanupError.cleanupReport.rootCleanup.path, fixture.root);
  assert.equal(cleanupError.cleanupReport.rootCleanup.removed, false);
  assert.deepEqual(cleanupError.cleanupReport.rootCleanup.blockedBy, [fake.unitCleanupCalls[0]]);
  assert.ok(
    cleanupError.cleanupReport.residualResources.some((resource) => resource.path === fixture.root),
    'cleanup report 必須列出精確殘留 root',
  );
});

test('OpenSSH fixture 只有在確認所有 unit 停止後才移除 root', async () => {
  const fake = fakeFixtureDependencies({ unitStopped: async () => true });
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
  }, fake.dependencies);

  await assert.rejects(fixture.cleanup(), (error) => error === fake.primaryError);
  assert.equal(fake.unitCleanupCalls.length, 2, '首個 unit 失敗後仍須處理另一個 unit');
  assert.equal(fake.runWslCalls.some((args) => args[0] === 'rm'), true, '狀態確認所有 unit 停止後可移除 root');
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

test('OpenSSH fixture cleanup 聚合 port、target probe 與 session-stop errors', async () => {
  const portError = new Error('port release check failed');
  const targetPortError = new Error('target port probe failed');
  const sessionError = new Error('WSL session stop failed');
  const fake = fakeFixtureDependencies({
    sessionError,
    portError,
    targetPortError,
    failUnitCleanup: false,
  });
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
    allowDirectTcpip: true,
  }, fake.dependencies);

  await assert.rejects(fixture.cleanup(), (error) => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, [portError, targetPortError, sessionError]);
    assert.deepEqual(
      error.cleanupReport.cleanupErrors.map((item) => item.error),
      [portError.message, targetPortError.message, sessionError.message],
    );
    return true;
  });
  assert.equal(fake.session.stopCalls, 1);
});
