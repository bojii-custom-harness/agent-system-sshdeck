'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const requiredFiles = [
  'README.md',
  'bin/sshdeck.js',
  'lib/service-server.js',
  'docs/service-api.md',
  'docs/service-deployment.md',
  '.opencode/skills/agent-system-sshdeck/SKILL.md',
  '.opencode/skills/agent-system-sshdeck/references/install.md',
];
const requiredDocumentation = {
  'README.md': [
    'docs/service-api.md',
    'docs/service-deployment.md',
    'SSHDECK_SERVICE_TOKEN',
    'SSHDECK_UI_TOKEN',
    'SSHDECK_TUNNEL_TOKEN',
  ],
  'docs/service-api.md': [
    'SSHDECK_SERVICE_TOKEN',
    'SSHDECK_UI_TOKEN',
    'SSHDECK_TUNNEL_TOKEN',
    '/v1/hosts/{alias}/tcp-tunnel-targets',
    '/v1/hosts/{alias}/tcp-tunnel',
    'direct-tcpip',
  ],
  'docs/service-deployment.md': [
    'SSHDECK_SERVICE_HOME',
    'SSHDECK_ENCRYPTION_KEY',
    'SSHDECK_SERVICE_TOKEN',
    'SSHDECK_UI_TOKEN',
    'SSHDECK_TUNNEL_TOKEN',
    '不代理 grant/tunnel 路由',
    '不授權修改其他 repo 的 deployment pin',
  ],
};
const forbiddenDocumentation = {
  'docs/service-api.md': [
    '不代表本版本已建立 WebSocket tunnel',
  ],
};

function readArgument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) {
    throw new Error(`缺少參數：${name}`);
  }
  return process.argv[index + 1];
}

function verifyLocalCandidateVersion(root) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const candidateVersionPattern = /本機 source candidate 版本：`(\d+\.\d+\.\d+)`（未發布）/g;
  const candidateVersions = [...readme.matchAll(candidateVersionPattern)];
  assert.equal(
    candidateVersions.length,
    1,
    'README 必須且只能記載一個未發布的本機 source candidate 版本',
  );
  assert.equal(
    candidateVersions[0][1],
    manifest.version,
    'README 本機 source candidate 版本必須與同一 package root 的 package.json.version 一致',
  );
}

function verifyPacklist(file) {
  const records = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(Array.isArray(records) && records.length === 1, 'npm pack 必須回傳單一套件清單');
  const record = records[0];
  assert.equal(record.name, 'agent-system-sshdeck');
  assert.match(record.version, /^\d+\.\d+\.\d+$/);
  const files = new Set(record.files.map((item) => item.path.replaceAll('\\', '/').replace(/^\.\//, '')));
  for (const filePath of requiredFiles) {
    assert.ok(files.has(filePath), `正式附件缺少必要檔案：${filePath}`);
  }
  console.log(`套件清單通過：${record.name}@${record.version}，包含 ${requiredFiles.length} 項必要檔案`);
}

function verifyDocumentation(root) {
  for (const [filePath, phrases] of Object.entries(requiredDocumentation)) {
    const content = fs.readFileSync(path.join(root, filePath), 'utf8');
    for (const phrase of phrases) {
      assert.ok(content.includes(phrase), `${filePath} 缺少 service 契約：${phrase}`);
    }
  }
  for (const [filePath, phrases] of Object.entries(forbiddenDocumentation)) {
    const content = fs.readFileSync(path.join(root, filePath), 'utf8');
    for (const phrase of phrases) {
      assert.equal(content.includes(phrase), false, `${filePath} 含過時 service 契約：${phrase}`);
    }
  }
}

function verifySourcePacklist() {
  const root = path.resolve(__dirname, '..');
  verifyLocalCandidateVersion(root);
  verifyDocumentation(root);
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli && path.isAbsolute(npmCli), '請透過 npm run verify:package 執行來源套件檢查');
  const result = spawnSync(process.execPath, [npmCli, 'pack', '--dry-run', '--json'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `npm pack --dry-run 失敗：${result.stderr}`);
  const records = JSON.parse(result.stdout);
  const temporaryFile = path.join(require('node:os').tmpdir(), `sshdeck-packlist-${process.pid}.json`);
  try {
    fs.writeFileSync(temporaryFile, JSON.stringify(records), { flag: 'wx' });
    verifyPacklist(temporaryFile);
  } finally {
    try { fs.unlinkSync(temporaryFile); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function verifyInstalled(directory) {
  const root = path.resolve(directory);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.name, 'agent-system-sshdeck');
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  for (const filePath of requiredFiles) {
    assert.ok(fs.statSync(path.join(root, filePath)).isFile(), `已安裝附件缺少必要檔案：${filePath}`);
  }
  verifyLocalCandidateVersion(root);
  verifyDocumentation(root);
  console.log(`已安裝套件通過：${manifest.name}@${manifest.version}，skill 與執行檔均可讀取`);
}

if (process.argv.includes('--packlist')) {
  verifyPacklist(readArgument('--packlist'));
} else if (process.argv.includes('--installed')) {
  verifyInstalled(readArgument('--installed'));
} else if (process.argv.includes('--source')) {
  verifySourcePacklist();
} else {
  throw new Error('用法：node scripts/verify-release-package.js --source | --packlist <JSON> | --installed <套件目錄>');
}
