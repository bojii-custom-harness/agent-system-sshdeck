'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  applyTicket03TokenSentinels,
} = require('./helpers/service-test-utils');

const root = path.resolve(__dirname, '..');

function listFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    return entry.isDirectory() ? listFiles(absolute) : [absolute];
  });
}

test('package candidate 包含 service/API handoff，Bot-readable 文件不嵌入 token sentinel', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const packageFiles = new Set(manifest.files);
  assert.ok(fs.statSync(path.join(root, 'README.md')).isFile(), 'README 必須存在於 package source');
  assert.ok(packageFiles.has('docs/service-api.md'));
  assert.ok(packageFiles.has('docs/service-deployment.md'));
  assert.ok(packageFiles.has('.opencode/skills/agent-system-sshdeck/'));

  const env = {};
  const sentinels = applyTicket03TokenSentinels(env);
  assert.equal(new Set(sentinels).size, 3, '三種合成 token sentinel 必須互不相同');
  const readableFiles = [
    path.join(root, 'README.md'),
    path.join(root, 'docs/service-api.md'),
    path.join(root, 'docs/service-deployment.md'),
    ...listFiles(path.join(root, '.opencode/skills/agent-system-sshdeck')),
  ];
  const readableText = readableFiles.map((file) => fs.readFileSync(file, 'utf8')).join('\n');
  for (const sentinel of sentinels) {
    assert.equal(readableText.includes(sentinel), false,
      '隨包 README、service docs 與 skill 不得包含執行期 token sentinel');
  }
  for (const tokenName of ['SSHDECK_SERVICE_TOKEN', 'SSHDECK_UI_TOKEN', 'SSHDECK_TUNNEL_TOKEN']) {
    assert.ok(readableText.includes(tokenName), 'Bot-readable package handoff 必須說明 token role');
  }
  assert.ok(readableText.includes('/v1/hosts/{alias}/tcp-tunnel-targets'));
  assert.ok(readableText.includes('/v1/hosts/{alias}/tcp-tunnel'));
  assert.ok(readableText.includes('direct-tcpip'));
  assert.ok(readableText.includes('外部 Agent System backend/browser/Bot runtime'),
    'handoff 必須清楚界定 SSHDeck package 與外部 Bot runtime 的驗證邊界');
});
