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
  portAvailability,
  portReleaseTimeoutMs,
} = {}) {
  const runId = randomUUID();
  const primaryError = new Error('fixture unit cleanup failed');
  const unitCleanupCalls = [];
  const runWslCalls = [];
  const portChecks = [];
  const portCheckCounts = new Map();
  const events = [];
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
    ...(portReleaseTimeoutMs === undefined ? {} : { portReleaseTimeoutMs }),
    portAvailable: async (port) => {
      portChecks.push(port);
      if (portError && portChecks.length === 3) throw portError;
      const count = (portCheckCounts.get(port) || 0) + 1;
      portCheckCounts.set(port, count);
      const free = count === 1
        ? true
        : portAvailability
          ? portAvailability(port, count)
          : true;
      events.push({ type: 'port-check', port, free });
      return free;
    },
    startWslSession: async () => session,
    runWsl(args) {
      runWslCalls.push(args);
      if (args[0] === 'rm') events.push({ type: 'remove-root', path: args.at(-1) });
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
    events,
  };
}

function fakeSetupFailureDependencies({
  stopError,
  stopErrorAfterStopping = false,
  stopResult = 'not-found',
  sessionError,
  occupiedPorts = [],
  portReleaseTimeoutMs,
} = {}) {
  const runId = randomUUID();
  const root = `/tmp/sshdeck-ticket01-${runId}-Abc123`;
  const wrapperError = new Error('wsl.exe wrapper timed out after remote systemd-run side effect');
  const systemdRunUnits = [];
  const unitCleanupCalls = [];
  const unitStateChecks = [];
  const runWslCalls = [];
  const portChecks = [];
  const targetPortChecks = [];
  const targetPortResolutions = [];
  const portCheckCounts = new Map();
  const activeUnits = new Set();
  const listeningTargetPorts = new Set();
  const session = {
    stopCalls: 0,
    get isRunning() {
      return this.stopCalls === 0;
    },
    async stop() {
      this.stopCalls += 1;
      if (sessionError) throw sessionError;
      return { code: 0, signal: null };
    },
  };
  const dependencies = {
    getPrivateWslHostAddress: () => '172.19.24.36',
    ...(portReleaseTimeoutMs === undefined ? {} : { portReleaseTimeoutMs }),
    portAvailable: async (port) => {
      portChecks.push(port);
      const calls = (portCheckCounts.get(port) || 0) + 1;
      portCheckCounts.set(port, calls);
      return calls === 1 || !occupiedPorts.includes(port);
    },
    startWslSession: async () => session,
    runWsl(args) {
      runWslCalls.push(args);
      if (args[0] === 'mktemp') return root;
      if (args[0] === 'systemd-run') {
        const unit = args.find((argument) => argument.startsWith('--unit='))?.slice('--unit='.length);
        systemdRunUnits.push(unit);
        activeUnits.add(unit);
        if (unit.endsWith('-echo.service')) listeningTargetPorts.add(34567);
        throw wrapperError;
      }
      return '';
    },
    waitForUnit: async () => {},
    waitForPort: async () => {},
    waitForTargetPort: async (file) => {
      targetPortResolutions.push(file);
      return 34567;
    },
    stopUnitAndWait: async (unit) => {
      unitCleanupCalls.push(unit);
      if (stopError) {
        if (stopErrorAfterStopping) {
          activeUnits.delete(unit);
          if (unit.endsWith('-echo.service')) listeningTargetPorts.delete(34567);
        }
        throw stopError;
      }
      if (stopResult !== 'not-found') return stopResult;
      activeUnits.delete(unit);
      if (unit.endsWith('-echo.service')) listeningTargetPorts.delete(34567);
      return stopResult;
    },
    unitIsStopped: async (unit) => {
      unitStateChecks.push(unit);
      return !activeUnits.has(unit);
    },
    targetPortListening(port) {
      targetPortChecks.push(port);
      return listeningTargetPorts.has(port);
    },
    fingerprintFor: () => 'SHA256:fixture',
  };
  return {
    dependencies,
    root,
    wrapperError,
    systemdRunUnits,
    unitCleanupCalls,
    unitStateChecks,
    runWslCalls,
    portChecks,
    targetPortChecks,
    targetPortResolutions,
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

test('OpenSSH fixture wrapper 在遠端 unit 啟動後失敗時確認 unit 與 listeners 再移除 root', async () => {
  const fake = fakeSetupFailureDependencies();
  let setupError;
  try {
    await createOpenSshServiceFixture({
      authorizedPublicKey: 'ssh-ed25519 test-key',
      allowDirectTcpip: true,
    }, fake.dependencies);
  } catch (error) {
    setupError = error;
  }

  assert.equal(fake.systemdRunUnits.length, 1, 'fake systemd-run 必須先產生遠端啟動副作用');
  const attemptedUnit = fake.systemdRunUnits[0];
  assert.ok(fake.unitCleanupCalls.includes(attemptedUnit), 'wrapper 失敗後仍須以 exact unit ID 執行 cleanup');
  assert.deepEqual(fake.targetPortResolutions, [`${fake.root}/target-port`]);
  assert.deepEqual(fake.targetPortChecks, [34567], 'target listener 必須在 root 移除前查核');
  assert.deepEqual(fake.portChecks.slice(0, 2), [2227, 2228], 'setup failure 後須重查兩個 SSH ports');
  assert.equal(fake.portChecks.at(-1), 2228);
  assert.ok(fake.portChecks.slice(2, -1).every((port) => port === 2227), '占用 port 必須有界重查');
  assert.equal(fake.session.stopCalls, 1, 'setup failure cleanup 必須停止 WSL session');
  assert.ok(setupError, 'setup 必須保留 wrapper failure');
  assert.equal(setupError.message, fake.wrapperError.message);
  assert.deepEqual(setupError.cleanupReport.primaryError, {
    phase: 'setup',
    resource: 'OpenSSH fixture setup',
    error: fake.wrapperError.message,
  });
  assert.equal(setupError.cleanupReport.root.path, fake.root);
  assert.equal(setupError.cleanupReport.root.removed, true);
  assert.ok(
    setupError.cleanupReport.units.some((unit) => unit.unit === attemptedUnit && unit.loadState === 'not-found'),
    'cleanup evidence 必須確認遠端 unit 已卸載',
  );
  assert.deepEqual(setupError.cleanupReport.ports.map(({ port, free }) => ({ port, free })), [
    { port: 2227, free: true },
    { port: 2228, free: true },
  ]);
  assert.deepEqual(setupError.cleanupReport.target, {
    host: '127.0.0.1',
    port: 34567,
    listening: false,
  });
  assert.deepEqual(setupError.cleanupReport.wslSession, {
    activeUntilCleanup: true,
    close: { code: 0, signal: null },
  });
});

test('OpenSSH fixture setup cleanup 無法停止 active unit 時保留 listener 與 run root', async () => {
  const stopError = new Error('systemd unit stop failed');
  const sessionError = new Error('WSL fixture session stop failed');
  const fake = fakeSetupFailureDependencies({ stopError, sessionError });
  let setupError;
  try {
    await createOpenSshServiceFixture({
      authorizedPublicKey: 'ssh-ed25519 test-key',
      allowDirectTcpip: true,
    }, fake.dependencies);
  } catch (error) {
    setupError = error;
  }

  assert.ok(setupError instanceof AggregateError, 'setup 與 cleanup error 必須同時回報');
  assert.equal(setupError.errors[0], fake.wrapperError, 'primary setup error 不得被 cleanup error 覆蓋');
  assert.ok(setupError.errors.includes(stopError), 'unit stop error 必須保留');
  assert.ok(setupError.errors.includes(sessionError), 'session stop error 必須與 setup error 一併保留');
  assert.equal(fake.systemdRunUnits.length, 1, '遠端副作用必須先於 wrapper error 發生');
  const attemptedUnit = fake.systemdRunUnits[0];
  assert.ok(fake.unitCleanupCalls.includes(attemptedUnit), '必須停止 exact run-scoped unit');
  assert.ok(fake.unitStateChecks.includes(attemptedUnit), 'stop 失敗後必須查詢 exact unit 狀態');
  assert.deepEqual(fake.targetPortChecks, [34567], '即使 unit 未停止仍須查核 listener');
  assert.equal(fake.session.stopCalls, 1, '不安全 cleanup 仍須停止 WSL session');
  assert.deepEqual(setupError.cleanupReport.wslSession, {
    activeUntilCleanup: true,
    close: null,
    stopError: sessionError.message,
  });
  assert.equal(setupError.cleanupReport.root.path, fake.root);
  assert.equal(setupError.cleanupReport.root.removed, false, 'unit/listener 未清除時不得移除 root');
  assert.ok(setupError.cleanupReport.root.blockedBy.includes(attemptedUnit));
  assert.ok(setupError.cleanupReport.root.blockedBy.includes('target-listener:34567:present-or-unknown'));
  assert.ok(
    setupError.cleanupReport.residualResources.some(
      (resource) => resource.type === 'systemd-unit' && resource.name === attemptedUnit,
    ),
    'cleanup report 必須列出仍未確認停止的 unit',
  );
  assert.ok(
    setupError.cleanupReport.residualResources.some(
      (resource) => resource.type === 'listener' && resource.port === 34567 && resource.state === 'listening',
    ),
    'cleanup report 必須列出殘留 target listener',
  );
  assert.ok(
    setupError.cleanupReport.residualResources.some(
      (resource) => resource.type === 'directory' && resource.path === fake.root,
    ),
    'cleanup report 必須列出保留的精確 run root',
  );
  assert.deepEqual(
    setupError.cleanupReport.errors.map(({ phase }) => phase),
    ['stop-unit', 'verify-target-port', 'stop-wsl-session'],
  );
});

test('OpenSSH fixture setup cleanup 遇到未確認 unit state 時保留 run root', async () => {
  const fake = fakeSetupFailureDependencies({ stopResult: 'active' });
  let setupError;
  try {
    await createOpenSshServiceFixture({
      authorizedPublicKey: 'ssh-ed25519 test-key',
    }, fake.dependencies);
  } catch (error) {
    setupError = error;
  }

  assert.ok(setupError instanceof AggregateError, '未知 unit state 必須視為 cleanup failure');
  assert.equal(setupError.errors[0], fake.wrapperError);
  const attemptedUnit = fake.systemdRunUnits[0];
  assert.ok(fake.unitCleanupCalls.includes(attemptedUnit));
  assert.ok(fake.unitStateChecks.includes(attemptedUnit), '非 not-found 狀態後必須再查詢 unit');
  assert.equal(setupError.cleanupReport.root.removed, false, '未知 unit state 時不得移除 root');
  assert.ok(setupError.cleanupReport.root.blockedBy.includes(attemptedUnit));
  assert.ok(
    setupError.cleanupReport.residualResources.some(
      (resource) => resource.type === 'systemd-unit'
        && resource.name === attemptedUnit
        && resource.state === 'not-confirmed-stopped',
    ),
    'cleanup report 必須將未知 state 明列為 unit residual',
  );
  assert.ok(setupError.errors.some((cleanupError) => /未確認.*unit state/.test(cleanupError.message)));
  assert.equal(fake.runWslCalls.some((args) => args[0] === 'rm'), false);
  assert.equal(fake.session.stopCalls, 1);
});

test('OpenSSH fixture setup cleanup stop 回報錯誤時即使確認 unit 已停止仍保留 run root', async () => {
  const stopError = new Error('systemd stop wrapper failed after remote stop');
  const fake = fakeSetupFailureDependencies({
    stopError,
    stopErrorAfterStopping: true,
  });
  let setupError;
  try {
    await createOpenSshServiceFixture({
      authorizedPublicKey: 'ssh-ed25519 test-key',
    }, fake.dependencies);
  } catch (error) {
    setupError = error;
  }

  assert.ok(setupError instanceof AggregateError, 'stop wrapper error 必須與 setup error 一併保留');
  assert.equal(setupError.errors[0], fake.wrapperError);
  assert.ok(setupError.errors.includes(stopError));
  const attemptedUnit = fake.systemdRunUnits[0];
  assert.ok(fake.unitStateChecks.includes(attemptedUnit), 'stop error 後必須查詢 exact unit state');
  assert.ok(
    setupError.cleanupReport.unitAttempts.some(
      (attempt) => attempt.unit === attemptedUnit && attempt.verifiedAfterStopError === true,
    ),
    'evidence 必須呈現 stop error 後的狀態查核',
  );
  assert.equal(setupError.cleanupReport.root.removed, false, 'stop/query error 時不得移除 root');
  assert.equal(setupError.cleanupReport.allStopped, false, 'stop/query error 時不得宣稱整體已停止');
  assert.ok(setupError.cleanupReport.root.blockedBy.includes(`unit-cleanup-error:${attemptedUnit}`));
  assert.equal(fake.runWslCalls.some((args) => args[0] === 'rm'), false);
});

test('OpenSSH fixture setup cleanup 發現固定 SSH port 殘留時保留 run root', async () => {
  const fake = fakeSetupFailureDependencies({ occupiedPorts: [2227], portReleaseTimeoutMs: 1 });
  let setupError;
  try {
    await createOpenSshServiceFixture({
      authorizedPublicKey: 'ssh-ed25519 test-key',
      allowDirectTcpip: true,
    }, fake.dependencies);
  } catch (error) {
    setupError = error;
  }

  assert.ok(setupError instanceof AggregateError, 'setup 與殘留 listener 錯誤必須一併回報');
  assert.equal(setupError.errors[0], fake.wrapperError);
  const attemptedUnit = fake.systemdRunUnits[0];
  assert.ok(fake.unitCleanupCalls.includes(attemptedUnit), '先停止造成 setup 失敗的 exact unit');
  assert.deepEqual(fake.targetPortChecks, [34567], '仍須確認 echo target listener 已關閉');
  assert.deepEqual(fake.portChecks.slice(0, 2), [2227, 2228]);
  assert.equal(fake.portChecks.at(-1), 2228);
  assert.equal(fake.session.stopCalls, 1);
  assert.equal(setupError.cleanupReport.root.removed, false, '固定 SSH port 殘留時不得移除 root');
  assert.ok(setupError.cleanupReport.root.blockedBy.includes('port:2227:occupied'));
  assert.ok(
    setupError.cleanupReport.residualResources.some(
      (resource) => resource.type === 'listener' && resource.port === 2227 && resource.state === 'listening',
    ),
    'cleanup report 必須列出殘留固定 SSH listener',
  );
  assert.ok(setupError.errors.some((cleanupError) => /port 仍被占用：2227/.test(cleanupError.message)));
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

test('OpenSSH fixture cleanup 在 port 短暫仍占用時重查後才移除 root', async () => {
  const fake = fakeFixtureDependencies({
    failUnitCleanup: false,
    portAvailability: (port, call) => port !== 2227 || call >= 3,
  });
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
  }, fake.dependencies);

  await fixture.cleanup();

  const port2227Checks = fake.events.filter((event) => event.type === 'port-check' && event.port === 2227);
  assert.deepEqual(port2227Checks, [
    { type: 'port-check', port: 2227, free: true },
    { type: 'port-check', port: 2227, free: false },
    { type: 'port-check', port: 2227, free: true },
  ], '清理須保留短暫占用觀察並重查至 listener 消失');
  const finalPortCheck = Math.max(...fake.events
    .map((event, index) => event.type === 'port-check' ? index : -1));
  const rootRemoval = fake.events.findIndex((event) => event.type === 'remove-root');
  assert.ok(rootRemoval > finalPortCheck, '所有 listener/port 狀態確認後才能移除 root');
});

test('OpenSSH fixture cleanup port listener 持續存在時保留 root', async () => {
  const fake = fakeFixtureDependencies({
    failUnitCleanup: false,
    portReleaseTimeoutMs: 1,
    portAvailability: (port) => port !== 2227,
  });
  const fixture = await createOpenSshServiceFixture({
    authorizedPublicKey: 'ssh-ed25519 test-key',
  }, fake.dependencies);
  let cleanupError;
  try {
    await fixture.cleanup();
  } catch (error) {
    cleanupError = error;
  }

  assert.ok(cleanupError, '仍占用的 fixture port 必須作為 cleanup error 回報');
  assert.equal(cleanupError.cleanupReport.rootCleanup.removed, false, 'port 仍占用時不得移除 root');
  assert.ok(cleanupError.cleanupReport.rootCleanup.blockedBy.includes('port:2227:occupied'));
  assert.ok(fake.events.every((event) => event.type !== 'remove-root'));
  assert.ok(
    cleanupError.cleanupReport.residualResources.some(
      (resource) => resource.type === 'listener' && resource.port === 2227 && resource.state === 'listening',
    ),
    'cleanup evidence 必須列出仍占用的 listener',
  );
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
