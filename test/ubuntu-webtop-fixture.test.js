'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { IMAGE, createUbuntuWebtopFixture } = require('./helpers/ubuntu-webtop-fixture');

const runId = '123e4567-e89b-12d3-a456-426614174000';
const containerId = 'container-id-ticket03';
const networkId = 'network-id-ticket03';

function createWslDockerStub({ dockerActiveAtStart = false } = {}) {
  const shortId = runId.replaceAll('-', '').slice(0, 12);
  const owner = `ticket03-${shortId}`;
  const containerName = `sshdeck-${owner}-webtop`;
  const networkName = `sshdeck-${owner}-network`;
  const calls = [];
  const containers = new Map();
  const networks = new Map();
  if (dockerActiveAtStart) {
    containers.set('pre-existing-container-id', {
      id: 'pre-existing-container-id',
      name: 'unrelated-existing-service',
      labels: 'other-ticket other-run',
    });
  }
  let dockerActive = dockerActiveAtStart;
  let firstContainerRemoval = true;
  let enabledState = dockerActiveAtStart ? 'enabled' : 'disabled';

  function respond(status, stdout = '', stderr = '') {
    return {
      status,
      signal: null,
      stdout: Buffer.from(stdout, 'utf8'),
      stderr: Buffer.from(stderr, 'utf8'),
    };
  }

  function spawnSyncProcess(command, args) {
    assert.equal(command, 'wsl.exe');
    assert.deepEqual(args.slice(0, 5), ['-d', 'Ubuntu', '-u', 'root', '--']);
    const operation = args.slice(5);
    calls.push([...operation]);
    const commandOperation = operation[0] === 'timeout' ? operation.slice(4) : operation;

    if (commandOperation[0] === 'id' && commandOperation[1] === '-u') return respond(0, '0\n');
    if (commandOperation[0] === 'systemctl' && commandOperation[1] === 'is-active') {
      return dockerActive ? respond(0, 'active\n') : respond(3, 'inactive\n');
    }
    if (commandOperation[0] === 'systemctl' && commandOperation[1] === 'is-enabled') {
      return respond(enabledState === 'enabled' ? 0 : 1, `${enabledState}\n`);
    }
    if (commandOperation[0] === 'systemctl' && commandOperation[1] === 'start') {
      dockerActive = true;
      return respond(0);
    }
    if (commandOperation[0] === 'systemctl' && commandOperation[1] === 'stop') {
      dockerActive = false;
      return respond(0);
    }
    if (commandOperation[0] === 'bash' && commandOperation[1] === '-lc') {
      const script = commandOperation[2] || '';
      if (script.includes('DOCKER_HOST')) return respond(0, 'empty\n');
      return respond(0);
    }
    if (commandOperation[0] !== 'docker') {
      throw new Error(`unexpected WSL command: ${commandOperation.join(' ')}`);
    }

    const argsWithoutDocker = commandOperation.slice(1);
    const [group, action] = argsWithoutDocker;
    if (group === 'context' && action === 'show') return respond(0, 'default\n');
    if (group === 'context' && action === 'inspect') return respond(0, 'unix:///var/run/docker.sock\n');
    if (group === 'info') {
      const format = argsWithoutDocker[argsWithoutDocker.indexOf('--format') + 1];
      const values = {
        '{{.ServerVersion}}': '29.1.3',
        '{{.OSType}}': 'linux',
        '{{.Name}}': 'ubuntu-test-daemon',
        '{{.DockerRootDir}}': '/var/lib/docker',
      };
      if (format === 'if [ -n "${DOCKER_HOST:-}" ]; then printf configured; else printf empty; fi') {
        return respond(0, 'empty\n');
      }
      if (!(format in values)) throw new Error(`unexpected docker info format: ${format}`);
      return respond(0, `${values[format]}\n`);
    }
    if (group === 'ps' && action === '-a') {
      return respond(0, `${[...containers.keys()].join('\n')}${containers.size ? '\n' : ''}`);
    }
    if (group === 'image' && action === 'inspect') return respond(0, 'sha256:pinned-image-id\n');
    if (group === 'container' && action === 'ls') {
      const filterIndex = argsWithoutDocker.indexOf('--filter');
      const filter = filterIndex >= 0 ? argsWithoutDocker[filterIndex + 1] : '';
      let ids = [...containers.keys()];
      if (filter.startsWith('name=')) {
        const name = filter.slice('name='.length).replace(/^\\?\/|[\\^$]/g, '');
        ids = ids.filter((id) => containers.get(id).name === name);
      } else if (filter.startsWith('id=')) {
        ids = ids.filter((id) => id === filter.slice('id='.length));
      }
      return respond(0, `${ids.join('\n')}${ids.length ? '\n' : ''}`);
    }
    if (group === 'network' && action === 'ls') {
      const filterIndex = argsWithoutDocker.indexOf('--filter');
      const filter = filterIndex >= 0 ? argsWithoutDocker[filterIndex + 1] : '';
      let ids = [...networks.keys()];
      if (filter.startsWith('name=')) {
        const name = filter.slice('name='.length).replace(/[\^$]/g, '');
        ids = ids.filter((id) => networks.get(id).name === name);
      } else if (filter.startsWith('id=')) {
        ids = ids.filter((id) => id === filter.slice('id='.length));
      }
      return respond(0, `${ids.join('\n')}${ids.length ? '\n' : ''}`);
    }
    if (group === 'network' && action === 'inspect') {
      const format = argsWithoutDocker[argsWithoutDocker.indexOf('--format') + 1];
      const resource = argsWithoutDocker.at(-1);
      const network = networks.get(resource)
        || [...networks.values()].find((item) => item.name === resource);
      if (!network) throw new Error(`network inspect requested for unknown resource ${resource}`);
      const values = {
        '{{.Id}}': network.id,
        [`{{index .Labels "com.agent-system.sshdeck.ticket"}} {{index .Labels "com.agent-system.sshdeck.run"}}`]:
          network.labels,
      };
      if (!(format in values)) throw new Error(`unexpected network inspect format: ${format}`);
      return respond(0, `${values[format]}\n`);
    }
    if (group === 'network' && action === 'create') {
      const name = argsWithoutDocker.at(-1);
      networks.set(networkId, { id: networkId, name, labels: `03 ${owner}` });
      return respond(0, `${networkId}\n`);
    }
    if (group === 'run') {
      containers.set(containerId, { id: containerId, name: containerName, labels: `03 ${owner}` });
      return respond(0, 'container-started\n');
    }
    if (group === 'inspect') {
      const format = argsWithoutDocker[argsWithoutDocker.indexOf('--format') + 1];
      const resource = argsWithoutDocker.at(-1);
      const container = containers.get(resource)
        || [...containers.values()].find((item) => item.name === resource);
      if (container) {
        const values = {
          '{{.Id}}': container.id,
          '{{.State.Running}}': 'true',
          '{{.Config.Image}}': IMAGE,
          [`{{index .Config.Labels "com.agent-system.sshdeck.ticket"}} {{index .Config.Labels "com.agent-system.sshdeck.run"}}`]:
            container.labels,
          '{{json .HostConfig.PortBindings}}': 'null',
          '{{json .NetworkSettings.Networks}}': JSON.stringify({
            [networkName]: { NetworkID: networkId, IPAddress: '172.18.0.2' },
          }),
        };
        if (!(format in values)) throw new Error(`unexpected container inspect format: ${format}`);
        return respond(0, `${values[format]}\n`);
      }
      const network = networks.get(resource)
        || [...networks.values()].find((item) => item.name === resource);
      if (network) {
        const values = {
          '{{.Id}}': network.id,
          [`{{index .Labels "com.agent-system.sshdeck.ticket"}} {{index .Labels "com.agent-system.sshdeck.run"}}`]:
            network.labels,
        };
        if (!(format in values)) throw new Error(`unexpected network inspect format: ${format}`);
        return respond(0, `${values[format]}\n`);
      }
      throw new Error(`inspect requested for unknown resource ${resource}`);
    }
    if (group === 'port') return respond(0);
    if (group === 'rm' && argsWithoutDocker[1] === '--force') {
      const id = argsWithoutDocker[2];
      if (firstContainerRemoval) {
        firstContainerRemoval = false;
        return respond(1, '', 'simulated transient container removal failure');
      }
      if (!containers.delete(id)) return respond(1, '', 'container not found');
      return respond(0);
    }
    if (group === 'network' && action === 'rm') {
      const id = argsWithoutDocker[2];
      if ([...containers.values()].some((item) => item.name === containerName)) {
        return respond(1, '', 'network is still in use');
      }
      if (!networks.delete(id)) return respond(1, '', 'network not found');
      return respond(0);
    }
    throw new Error(`unexpected Docker command: ${argsWithoutDocker.join(' ')}`);
  }

  return {
    spawnSyncProcess,
    calls,
    containers,
    networks,
    get dockerActive() { return dockerActive; },
    get enabledState() { return enabledState; },
    set enabledState(value) { enabledState = value; },
    containerName,
    networkName,
  };
}

async function verifyCleanupRetry({ dockerActiveAtStart }) {
  const evidenceDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-ticket03-cleanup-'));
  const evidenceFile = path.join(evidenceDirectory, 'fixture.json');
  const docker = createWslDockerStub({ dockerActiveAtStart });

  try {
    const fixture = createUbuntuWebtopFixture({
      runId,
      evidenceFile,
      spawnSyncProcess: docker.spawnSyncProcess,
    });
    assert.equal(fixture.containerName, docker.containerName);
    assert.equal(fixture.networkName, docker.networkName);
    assert.equal(docker.dockerActive, true);

    await assert.rejects(fixture.cleanup(), AggregateError);
    assert.equal(docker.containers.has(containerId), true,
      '首次 transient failure 必須保留仍存在的 task-owned container');
    assert.equal(docker.networks.has(networkId), true,
      '首次清理未完成時必須保留仍存在的 task-owned network');
    assert.equal(docker.dockerActive, true,
      'task-owned resource 尚未清理完成時不得停止原本 inactive 的 Docker daemon');

    await fixture.cleanup();
    const finalCallCount = docker.calls.length;
    await fixture.cleanup();

    assert.equal(docker.calls.length, finalCallCount, '成功清理後重複呼叫必須冪等');
    assert.equal(docker.containers.has(containerId), false, 'task-owned container 必須已移除');
    assert.equal(docker.containers.size, dockerActiveAtStart ? 1 : 0,
      '只能移除 task-owned container，不得影響其他 container');
    assert.equal(docker.networks.size, 0, 'task-owned network 必須已移除');
    assert.equal(docker.dockerActive, dockerActiveAtStart,
      'daemon 必須恢復／保留執行前的 active 狀態');
    assert.equal(docker.enabledState, dockerActiveAtStart ? 'enabled' : 'disabled',
      'daemon enabled 狀態必須保持不變');
    assert.equal(docker.calls.some((args) => args[0] === 'systemctl' && args[1] === 'enable'), false,
      'cleanup 不得修改 Docker service enabled 狀態');
    const daemonStopCount = docker.calls.filter((args) =>
      args[0] === 'timeout' && args.includes('stop')).length;
    assert.equal(daemonStopCount, dockerActiveAtStart ? 0 : 1,
      '只可在成功清理後停止本次啟動的 daemon，必須保留原先 active 的 daemon');

    const removalCommands = docker.calls.filter((args) =>
      (args[0] === 'docker' && args[1] === 'rm')
      || (args[0] === 'docker' && args[1] === 'network' && args[2] === 'rm'));
    assert.deepEqual(removalCommands, [
      ['docker', 'rm', '--force', containerId],
      ['docker', 'network', 'rm', networkId],
      ['docker', 'rm', '--force', containerId],
      ['docker', 'network', 'rm', networkId],
    ], '每次移除只可操作已驗證的精確 resource ID');

    const evidence = JSON.parse(fs.readFileSync(evidenceFile, 'utf8'));
    assert.equal(evidence.cleanup.status, 'passed');
    assert.equal(evidence.cleanup.containerRemoved, true);
    assert.equal(evidence.cleanup.networkRemoved, true);
    assert.equal(evidence.cleanup.dockerDaemon, dockerActiveAtStart ? 'active' : 'inactive');
    if (dockerActiveAtStart) {
      assert.equal(docker.containers.has('pre-existing-container-id'), true,
        '既有的非 task container 必須保留');
      assert.equal(evidence.cleanup.containerInventoryAfter.originalContainersPreserved, true);
      assert.equal(evidence.cleanup.containerInventoryAfter.unrelatedNewCount, 0);
    }
    assert.deepEqual(evidence.cleanup.errors, []);
  } finally {
    fs.rmSync(evidenceDirectory, { recursive: true, force: true });
  }
}

test('Docker fixture cleanup can retry exact owned resources after a transient removal failure', {
  skip: process.platform !== 'win32',
}, () => verifyCleanupRetry({ dockerActiveAtStart: false }));

test('Docker fixture cleanup preserves a pre-existing daemon and unrelated containers across retry', {
  skip: process.platform !== 'win32',
}, () => verifyCleanupRetry({ dockerActiveAtStart: true }));
