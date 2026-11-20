'use strict';

const { startService } = require('../lib/service-server');

async function main() {
  let service;
  try {
    service = await startService({
      env: process.env,
      host: process.env.SSHDECK_TEST_SERVICE_CHILD_HOST,
      port: Number(process.env.SSHDECK_TEST_SERVICE_CHILD_PORT),
    });
  } catch (error) {
    process.send?.({ type: 'startup-error', code: error.code || 'SERVICE_START_FAILED' });
    process.disconnect?.();
    process.exitCode = 1;
    return;
  }

  process.send({ type: 'ready', port: service.address().port });
  process.on('message', async (message) => {
    if (message?.type === 'stats') {
      process.send({ requestId: message.requestId, activeTerminalCount: service.activeTerminalCount });
      return;
    }
    if (message?.type !== 'close') return;
    try {
      await service.closeAsync();
      process.send({
        requestId: message.requestId,
        activeTerminalCount: service.activeTerminalCount,
      }, () => {
        process.disconnect();
        process.exitCode = 0;
      });
    } catch {
      process.send({
        requestId: message.requestId,
        activeTerminalCount: service.activeTerminalCount,
        closeFailed: true,
      }, () => {
        process.disconnect();
        process.exitCode = 1;
      });
    }
  });
}

main();
