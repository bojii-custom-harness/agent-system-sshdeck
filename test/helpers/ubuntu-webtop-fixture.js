'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawnSync } = require('node:child_process');

const IMAGE = 'lscr.io/linuxserver/webtop@sha256:767557e48118456e18e4ba2d51880fc818d1f4deab661f24e2ed7370cb37f5fe';
const TICKET_LABEL = 'com.agent-system.sshdeck.ticket';
const RUN_LABEL = 'com.agent-system.sshdeck.run';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function createUbuntuWebtopFixture({ runId, evidenceFile } = {}) {
  if (process.platform !== 'win32') {
    throw new Error('Webtop fixture 只支援從 Windows runner 操作 Ubuntu WSL');
  }
  if (typeof runId !== 'string' || !/^[a-f0-9-]{36}$/i.test(runId)) {
    throw new Error('Webtop fixture 需要 UUID run ID');
  }
  if (typeof evidenceFile !== 'string' || !evidenceFile) {
    throw new Error('Webtop fixture 需要外部 evidence file');
  }

  const shortId = runId.replaceAll('-', '').slice(0, 12).toLowerCase();
  const owner = `ticket03-${shortId}`;
  const containerName = `sshdeck-${owner}-webtop`;
  const networkName = `sshdeck-${owner}-network`;
  const evidence = {
    fixture: 'Ubuntu WSL native Docker Webtop/Pelorus',
    runId,
    image: IMAGE,
    owner,
    resources: { containerName, networkName, containerId: null, networkId: null },
    commands: [],
    cleanup: { status: 'pending', imageCachePreserved: true },
  };
  let dockerWasActive;
  let dockerStartedByFixture = false;
  let originalContainerIds = [];
  let containerId;
  let networkId;
  let targetIp;
  let containerCreateAttempted = false;
  let networkCreateAttempted = false;
  let cleaned = false;
  let evidenceWritten = false;

  function runWsl(args, {
    label,
    timeoutMs = 20_000,
    acceptedStatuses = [0],
  } = {}) {
    const started = Date.now();
    const result = spawnSync('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--', ...args], {
      encoding: 'buffer',
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    });
    const stdout = result.stdout || Buffer.alloc(0);
    const stderr = result.stderr || Buffer.alloc(0);
    const record = {
      label,
      command: ['wsl.exe', '-d', 'Ubuntu', '-u', 'root', '--', ...args],
      elapsedMs: Date.now() - started,
      timeoutMs,
      status: result.status,
      signal: result.signal || null,
      spawnErrorCode: result.error?.code || null,
      stdoutBytes: stdout.length,
      stderrBytes: stderr.length,
      stdoutSha256: sha256(stdout),
      stderrSha256: sha256(stderr),
    };
    evidence.commands.push(record);
    if (result.error || !acceptedStatuses.includes(result.status)) {
      const failure = new Error(
        `Ubuntu Webtop fixture ${label} failed (${result.error?.code || result.status})`,
      );
      failure.code = result.error?.code || `EXIT_${result.status}`;
      failure.stderr = stderr.toString('utf8').slice(0, 500);
      throw failure;
    }
    return stdout.toString('utf8').trim();
  }

  function containerInventory() {
    const output = runWsl(['docker', 'ps', '-a', '-q', '--no-trunc'], { label: 'container-inventory' });
    return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).sort();
  }

  function writeEvidence() {
    fs.writeFileSync(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, {
      encoding: 'utf8',
      flag: evidenceWritten ? 'w' : 'wx',
    });
    evidenceWritten = true;
  }

  function assertOwnedContainer() {
    if (!containerId && containerCreateAttempted) {
      const discovered = runWsl([
        'docker', 'container', 'ls', '-a', '--no-trunc',
        '--filter', `name=^/${containerName}$`, '--format', '{{.ID}}',
      ], { label: 'recover-task-container-id' });
      if (discovered) {
        containerId = discovered.split(/\r?\n/)[0].trim();
        evidence.resources.containerId = containerId;
      }
    }
    if (!containerId) return false;
    const actualId = runWsl(['docker', 'inspect', '--format', '{{.Id}}', containerName], {
      label: 'verify-container-id',
    });
    const actualLabels = runWsl([
      'docker', 'inspect', '--format',
      `{{index .Config.Labels "${TICKET_LABEL}"}} {{index .Config.Labels "${RUN_LABEL}"}}`,
      containerName,
    ], { label: 'verify-container-labels' });
    if (actualId !== containerId || actualLabels !== `03 ${owner}`) {
      throw new Error('拒絕清理：container ID 或 task ownership labels 不符');
    }
    return true;
  }

  function assertOwnedNetwork() {
    if (!networkId && networkCreateAttempted) {
      const discovered = runWsl([
        'docker', 'network', 'ls', '--no-trunc',
        '--filter', `name=^${networkName}$`, '--format', '{{.ID}}',
      ], { label: 'recover-task-network-id' });
      if (discovered) {
        networkId = discovered.split(/\r?\n/)[0].trim();
        evidence.resources.networkId = networkId;
      }
    }
    if (!networkId) return false;
    const actualId = runWsl(['docker', 'network', 'inspect', '--format', '{{.Id}}', networkName], {
      label: 'verify-network-id',
    });
    const actualLabels = runWsl([
      'docker', 'network', 'inspect', '--format',
      `{{index .Labels "${TICKET_LABEL}"}} {{index .Labels "${RUN_LABEL}"}}`,
      networkName,
    ], { label: 'verify-network-labels' });
    if (actualId !== networkId || actualLabels !== `03 ${owner}`) {
      throw new Error('拒絕清理：network ID 或 task ownership labels 不符');
    }
    return true;
  }

  function cleanupOwnedResources(errors) {
    if (containerId || containerCreateAttempted) {
      try {
        if (assertOwnedContainer()) {
          runWsl(['docker', 'rm', '--force', '--time', '10', containerName], {
            label: 'remove-task-container',
            timeoutMs: 30_000,
          });
          const remaining = runWsl([
            'docker', 'container', 'ls', '-a', '--no-trunc',
            '--filter', `id=${containerId}`, '--format', '{{.ID}}',
          ], { label: 'verify-container-removed' });
          if (remaining) throw new Error('task-owned container 清理後仍存在');
          evidence.cleanup.containerRemoved = true;
        } else {
          evidence.cleanup.containerRemoved = true;
        }
      } catch (error) {
        errors.push(error);
        evidence.cleanup.containerRemoved = false;
        evidence.cleanup.containerError = error.message;
      }
    }
    if (networkId || networkCreateAttempted) {
      try {
        if (assertOwnedNetwork()) {
          runWsl(['docker', 'network', 'rm', networkName], {
            label: 'remove-task-network',
            timeoutMs: 20_000,
          });
          const remaining = runWsl([
            'docker', 'network', 'ls', '--no-trunc',
            '--filter', `id=${networkId}`, '--format', '{{.ID}}',
          ], { label: 'verify-network-removed' });
          if (remaining) throw new Error('task-owned network 清理後仍存在');
          evidence.cleanup.networkRemoved = true;
        } else {
          evidence.cleanup.networkRemoved = true;
        }
      } catch (error) {
        errors.push(error);
        evidence.cleanup.networkRemoved = false;
        evidence.cleanup.networkError = error.message;
      }
    }
  }

  function stopDockerIfRestoredToEmptyBaseline(errors) {
    if (!dockerStartedByFixture) {
      evidence.cleanup.dockerDaemon = 'preserved-preexisting-state';
      if (dockerWasActive) {
        try {
          const afterIds = containerInventory();
          const missingOriginal = originalContainerIds.filter((id) => !afterIds.includes(id));
          evidence.cleanup.containerInventoryAfter = {
            count: afterIds.length,
            sha256: sha256(afterIds.join('\n')),
            originalContainersPreserved: missingOriginal.length === 0,
            unrelatedNewCount: afterIds.filter((id) => id !== containerId && !originalContainerIds.includes(id)).length,
          };
          if (missingOriginal.length > 0) {
            throw new Error('Docker inventory changed: a pre-existing container is missing');
          }
          evidence.cleanup.dockerDaemon = runWsl(['systemctl', 'is-active', 'docker'], {
            label: 'docker-service-after',
            acceptedStatuses: [0, 3],
          });
        } catch (error) {
          errors.push(error);
          evidence.cleanup.dockerDaemon = 'pre-existing-state-check-failed';
          evidence.cleanup.dockerDaemonError = error.message;
        }
      }
      return;
    }
    try {
      const afterIds = containerInventory();
      const missingOriginal = originalContainerIds.filter((id) => !afterIds.includes(id));
      const unrelatedNew = afterIds.filter((id) => id !== containerId && !originalContainerIds.includes(id));
      evidence.cleanup.containerInventoryAfter = {
        count: afterIds.length,
        sha256: sha256(afterIds.join('\n')),
        originalContainersPreserved: missingOriginal.length === 0,
        unrelatedNewCount: unrelatedNew.length,
      };
      if (missingOriginal.length > 0) {
        throw new Error('Docker inventory changed: a pre-existing container is missing');
      }
      if (unrelatedNew.length > 0) {
        evidence.cleanup.dockerDaemon = 'kept-active-for-other-containers';
        return;
      }
      if (afterIds.length > 0) {
        evidence.cleanup.dockerDaemon = afterIds.includes(containerId)
          ? 'kept-active-for-task-residual'
          : 'kept-active-for-pre-existing-containers';
        return;
      }
      runWsl([
        'timeout', '--signal=TERM', '--kill-after=10s', '60s',
        'systemctl', 'stop', 'docker',
      ], { label: 'restore-docker-inactive-state', timeoutMs: 75_000 });
      const state = runWsl(['systemctl', 'is-active', 'docker'], {
        label: 'verify-docker-restored-inactive',
        acceptedStatuses: [0, 3],
      });
      evidence.cleanup.dockerDaemon = state;
      if (state === 'active') throw new Error('Docker service remains active after owned cleanup');
    } catch (error) {
      errors.push(error);
      evidence.cleanup.dockerDaemon = 'cleanup-failed-or-preserved';
      evidence.cleanup.dockerDaemonError = error.message;
    }
  }

  function cleanup() {
    if (cleaned) return;
    const errors = [];
    if (dockerWasActive === true || dockerStartedByFixture) {
      cleanupOwnedResources(errors);
      stopDockerIfRestoredToEmptyBaseline(errors);
    } else {
      evidence.cleanup.dockerDaemon = 'not-started-by-fixture';
    }
    evidence.cleanup.status = errors.length ? 'incomplete' : 'passed';
    evidence.cleanup.errors = errors.map((error) => error.message);
    try {
      writeEvidence();
    } catch (error) {
      errors.push(error);
      evidence.cleanup.status = 'evidence-write-failed';
      evidence.cleanup.errors = errors.map((item) => item.message);
    }
    if (errors.length) {
      throw new AggregateError(errors, 'Ubuntu Webtop fixture cleanup failed');
    }
    cleaned = true;
  }

  try {
    if (runWsl(['id', '-u'], { label: 'verify-root-user' }) !== '0') {
      throw new Error('Ubuntu Webtop fixture 未以 root 執行');
    }
    const activeResult = runWsl(['systemctl', 'is-active', 'docker'], {
      label: 'docker-service-before',
      acceptedStatuses: [0, 3],
    });
    const enabledResult = runWsl(['systemctl', 'is-enabled', 'docker'], {
      label: 'docker-enabled-before',
      acceptedStatuses: [0, 1, 3, 4],
    });
    dockerWasActive = activeResult === 'active';
    evidence.docker = {
      serviceBefore: activeResult,
      enabledBefore: enabledResult,
      contextBeforeStart: null,
      serverVersion: null,
      osType: null,
      imageId: null,
    };

    if (dockerWasActive) {
      originalContainerIds = containerInventory();
    } else {
      const filesystemIds = runWsl([
        'bash', '-lc',
        "find /var/lib/docker/containers -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' 2>/dev/null | sort",
      ], { label: 'container-metadata-before-start' }).split(/\r?\n/).filter(Boolean);
      originalContainerIds = filesystemIds;
      evidence.docker.containerMetadataBeforeStart = {
        count: filesystemIds.length,
        sha256: sha256(filesystemIds.join('\n')),
      };
      dockerStartedByFixture = true;
      runWsl([
        'timeout', '--signal=TERM', '--kill-after=10s', '60s',
        'systemctl', 'start', 'docker',
      ], { label: 'start-ubuntu-native-docker', timeoutMs: 75_000 });
      runWsl([
        'timeout', '--signal=TERM', '--kill-after=10s', '45s',
        'bash', '-lc', 'until docker info --format "{{.ServerVersion}}" >/dev/null 2>&1; do sleep 1; done',
      ], { label: 'wait-for-docker-daemon', timeoutMs: 60_000 });
    }

    const context = runWsl(['docker', 'context', 'show'], { label: 'docker-context' });
    const contextHost = runWsl([
      'docker', 'context', 'inspect', 'default', '--format', '{{.Endpoints.docker.Host}}',
    ], { label: 'docker-context-endpoint' });
    const dockerHost = runWsl([
      'bash', '-lc', 'if [ -n "${DOCKER_HOST:-}" ]; then printf configured; else printf empty; fi',
    ], { label: 'docker-host-environment' });
    const serverVersion = runWsl([
      'docker', 'info', '--format', '{{.ServerVersion}}',
    ], { label: 'docker-engine-server-version' });
    const osType = runWsl([
      'docker', 'info', '--format', '{{.OSType}}',
    ], { label: 'docker-engine-os-type' });
    const dockerName = runWsl([
      'docker', 'info', '--format', '{{.Name}}',
    ], { label: 'docker-engine-name' });
    const dockerRoot = runWsl([
      'docker', 'info', '--format', '{{.DockerRootDir}}',
    ], { label: 'docker-engine-root' });
    evidence.docker = {
      ...evidence.docker,
      context,
      contextEndpoint: contextHost,
      dockerHostEnvironment: dockerHost,
      serverVersion,
      osType,
      dockerName,
      dockerRoot,
    };
    if (context !== 'default' || contextHost !== 'unix:///var/run/docker.sock' || dockerHost !== 'empty') {
      throw new Error('拒絕操作非 Ubuntu native default Docker endpoint');
    }
    if (serverVersion !== '29.1.3' || osType !== 'linux') {
      throw new Error('Ubuntu native Docker Engine version/OS 不符已核對基線');
    }

    const allBeforeCreate = containerInventory();
    if (originalContainerIds.some((id) => !allBeforeCreate.includes(id))) {
      throw new Error('Docker 啟動後原有 container inventory 不一致');
    }
    evidence.docker.containerInventoryBefore = {
      count: allBeforeCreate.length,
      sha256: sha256(allBeforeCreate.join('\n')),
      preExistingPreserved: true,
    };
    originalContainerIds = allBeforeCreate;

    const imageInspect = runWsl([
      'docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE,
    ], {
      label: 'inspect-pinned-webtop-image',
      acceptedStatuses: [0, 1],
    });
    let imageId = imageInspect;
    if (!imageId) {
      imageId = runWsl([
        'timeout', '--signal=TERM', '--kill-after=15s', '600s',
        'docker', 'pull', '--quiet', IMAGE,
      ], { label: 'pull-pinned-webtop-image', timeoutMs: 630_000 });
      imageId = runWsl([
        'docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE,
      ], { label: 'verify-pulled-webtop-image' });
    }
    evidence.docker.imageId = imageId;

    const existingContainer = runWsl([
      'docker', 'container', 'ls', '-a', '--filter', `name=^/${containerName}$`, '--format', '{{.ID}}',
    ], { label: 'check-task-container-name' });
    const existingNetwork = runWsl([
      'docker', 'network', 'ls', '--filter', `name=^${networkName}$`, '--format', '{{.ID}}',
    ], { label: 'check-task-network-name' });
    if (existingContainer || existingNetwork) {
      throw new Error('task run-scoped Docker resource name already exists; refusing overwrite');
    }

    networkCreateAttempted = true;
    networkId = runWsl([
      'docker', 'network', 'create',
      '--label', `${TICKET_LABEL}=03`,
      '--label', `${RUN_LABEL}=${owner}`,
      networkName,
    ], { label: 'create-task-network' });
    evidence.resources.networkId = networkId;
    containerCreateAttempted = true;
    runWsl([
      'docker', 'run', '--detach',
      '--name', containerName,
      '--label', `${TICKET_LABEL}=03`,
      '--label', `${RUN_LABEL}=${owner}`,
      '--network', networkName,
      '--shm-size=1g',
      '--env', 'PELORUS=true',
      IMAGE,
    ], { label: 'start-task-webtop-container', timeoutMs: 60_000 });
    containerId = runWsl([
      'docker', 'inspect', '--format', '{{.Id}}', containerName,
    ], { label: 'read-task-container-id' });
    evidence.resources.containerId = containerId;

    const running = runWsl([
      'docker', 'inspect', '--format', '{{.State.Running}}', containerName,
    ], { label: 'verify-task-container-running' });
    const image = runWsl([
      'docker', 'inspect', '--format', '{{.Config.Image}}', containerName,
    ], { label: 'verify-task-container-image' });
    const labels = runWsl([
      'docker', 'inspect', '--format',
      `{{index .Config.Labels "${TICKET_LABEL}"}} {{index .Config.Labels "${RUN_LABEL}"}}`,
      containerName,
    ], { label: 'read-task-container-labels' });
    const bindings = runWsl([
      'docker', 'inspect', '--format', '{{json .HostConfig.PortBindings}}', containerName,
    ], { label: 'verify-no-host-port-bindings' });
    const publishedPorts = runWsl(['docker', 'port', containerName], {
      label: 'verify-no-published-ports',
    });
    const networkAddresses = JSON.parse(runWsl([
      'docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', containerName,
    ], { label: 'read-task-container-network' }));
    const attachedNetworks = Object.keys(networkAddresses);
    const taskNetwork = networkAddresses[networkName];
    targetIp = taskNetwork?.IPAddress;
    if (running !== 'true' || image !== IMAGE || labels !== `03 ${owner}`) {
      throw new Error('task Webtop container identity/state mismatch');
    }
    if (bindings !== 'null' && bindings !== '{}') {
      throw new Error('Webtop container unexpectedly has host port bindings');
    }
    if (publishedPorts) throw new Error('Webtop container unexpectedly publishes host ports');
    if (attachedNetworks.length !== 1 || !taskNetwork || taskNetwork.NetworkID !== networkId) {
      throw new Error('Webtop container is not exclusively attached to its task-owned network');
    }
    if (!targetIp || !net.isIPv4(targetIp)) throw new Error('Webtop container private IPv4 is unavailable');
    evidence.resources.target = { host: targetIp, port: 3001, networkName };
    evidence.resources.hostPortBindings = bindings;
    evidence.resources.publishedPorts = publishedPorts;
    evidence.resources.running = true;
    evidence.setup = 'passed';

    let fixtureCleaned = false;
    return {
      image: IMAGE,
      imageId,
      owner,
      containerName,
      containerId,
      networkName,
      networkId,
      targetIp,
      async cleanup() {
        if (fixtureCleaned) return;
        fixtureCleaned = true;
        cleanup();
      },
    };
  } catch (error) {
    evidence.setup = 'failed';
    evidence.setupFailure = { name: error.name, code: error.code || null, message: error.message };
    const cleanupErrors = [];
    try {
      if (dockerWasActive === true || dockerStartedByFixture) {
        cleanupOwnedResources(cleanupErrors);
        stopDockerIfRestoredToEmptyBaseline(cleanupErrors);
      }
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
    evidence.cleanup.status = cleanupErrors.length ? 'incomplete' : 'passed';
    evidence.cleanup.errors = cleanupErrors.map((item) => item.message);
    try { writeEvidence(); } catch (evidenceError) {
      cleanupErrors.push(evidenceError);
    }
    if (cleanupErrors.length) {
      throw new AggregateError([error, ...cleanupErrors], 'Ubuntu Webtop setup and cleanup failed', { cause: error });
    }
    throw error;
  }
}

module.exports = { createUbuntuWebtopFixture, IMAGE };
