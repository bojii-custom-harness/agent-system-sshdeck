'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  applyTicket03TokenSentinels,
} = require('./helpers/service-test-utils');

const root = path.resolve(__dirname, '..');

function runGit(cwd, args, options = {}) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: options.encoding === undefined ? 'utf8' : options.encoding,
    timeout: options.timeout ?? 10_000,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `git ${args[0]} 必須成功`);
  return result.stdout;
}

function listFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    return entry.isDirectory() ? listFiles(absolute) : [absolute];
  });
}

function writeVerifierFixture(packageRoot, candidateVersion) {
  fs.mkdirSync(packageRoot, { recursive: true });
  const packageManifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
    name: packageManifest.name,
    version: candidateVersion,
  }));
  fs.writeFileSync(path.join(packageRoot, 'README.md'), [
    `本機 source candidate 版本：\`${candidateVersion}\`（未發布）`,
    'docs/service-api.md',
    'docs/service-deployment.md',
    'SSHDECK_SERVICE_TOKEN',
    'SSHDECK_UI_TOKEN',
    'SSHDECK_TUNNEL_TOKEN',
  ].join('\n'));

  const requiredFiles = [
    'bin/sshdeck.js',
    'lib/service-server.js',
    'docs/service-api.md',
    'docs/service-deployment.md',
    '.opencode/skills/agent-system-sshdeck/SKILL.md',
    '.opencode/skills/agent-system-sshdeck/references/install.md',
  ];
  for (const filePath of requiredFiles) {
    const destination = path.join(packageRoot, filePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(root, filePath), destination);
  }
}

function runInstalledPackageVerifier(packageRoot) {
  const result = spawnSync(process.execPath, [
    path.join(root, 'scripts/verify-release-package.js'),
    '--installed',
    packageRoot,
  ], {
    cwd: root,
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  return result;
}

test('package verifier 拒絕 README 與同一 package root 版本不一致的候選', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-readme-version-'));
  const packageRoot = path.join(tempRoot, 'package');
  const packageVersion = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  const mismatchedVersion = packageVersion === '0.0.0' ? '0.0.1' : '0.0.0';
  try {
    writeVerifierFixture(packageRoot, packageVersion);
    const matching = runInstalledPackageVerifier(packageRoot);
    assert.equal(matching.status, 0, `版本一致的 package 應通過 verifier：${matching.stderr}`);

    const packageManifestPath = path.join(packageRoot, 'package.json');
    const mismatchedManifest = JSON.parse(fs.readFileSync(packageManifestPath, 'utf8'));
    mismatchedManifest.version = mismatchedVersion;
    fs.writeFileSync(packageManifestPath, JSON.stringify(mismatchedManifest));
    const mismatched = runInstalledPackageVerifier(packageRoot);
    assert.notEqual(mismatched.status, 0, 'verifier 必須拒絕 README 與 package.json 版本不一致');
    assert.match(
      mismatched.stderr,
      /README 本機 source candidate 版本必須與同一 package root 的 package\.json\.version 一致/,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('candidate-eol: fresh core.autocrlf=true checkout reproduces tracked source candidate', {
  timeout: 120_000,
}, (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sshdeck-candidate-eol-'));
  const checkout = path.join(tempRoot, 'checkout');
  const output = path.join(tempRoot, 'candidate-output');
  t.after(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    assert.equal(fs.existsSync(tempRoot), false, 'fresh checkout 與 candidate 暫存資源必須清理');
  });

  const sourceCommit = runGit(root, ['rev-parse', 'HEAD']).trim();
  runGit(root, ['clone', '--no-hardlinks', '--no-checkout', root, checkout], { timeout: 30_000 });
  runGit(checkout, ['config', 'core.autocrlf', 'true']);
  runGit(checkout, ['checkout', '--detach', sourceCommit], { timeout: 30_000 });

  const checkoutCommit = runGit(checkout, ['rev-parse', 'HEAD']).trim();
  const coreAutocrlf = runGit(checkout, ['config', '--get', 'core.autocrlf']).trim();
  const canonicalReadme = runGit(checkout, ['show', `${checkoutCommit}:README.md`], { encoding: null });
  const checkedOutReadme = fs.readFileSync(path.join(checkout, 'README.md'));

  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli && path.isAbsolute(npmCli), '請透過 npm test 執行 candidate regression');
  const candidateRun = spawnSync(process.execPath, [
    npmCli,
    'run',
    'candidate:source',
    '--',
    '--output-dir',
    output,
  ], {
    cwd: checkout,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (candidateRun.error) throw candidateRun.error;
  assert.equal(candidateRun.status, 0, 'fresh clean checkout 的 candidate:source 必須成功');

  const generated = JSON.parse(fs.readFileSync(path.join(output, 'candidate-manifest.json'), 'utf8'));
  const tracked = JSON.parse(fs.readFileSync(path.join(checkout, 'candidate/ticket-03-candidate.json'), 'utf8'));
  const packageManifest = JSON.parse(fs.readFileSync(path.join(checkout, 'package.json'), 'utf8'));
  const matches = {
    candidateUsesCheckoutCommit: generated.sourceCommit === checkoutCommit,
    checkoutIsClean: runGit(checkout, ['status', '--porcelain']).trim() === '',
    coreAutocrlfIsTrue: coreAutocrlf === 'true',
    readmeMatchesCanonicalGitBlob: checkedOutReadme.equals(canonicalReadme),
    packageVersionMatchesManifest: packageManifest.version === tracked.package.version
      && generated.package.name === tracked.package.name
      && generated.package.version === tracked.package.version,
    archiveFilenameMatches: generated.archive.filename === tracked.archive.filename,
    archiveBytesMatch: generated.archive.bytes === tracked.archive.bytes,
    archiveSha256Matches: generated.archive.sha256 === tracked.archive.sha256,
    fullFileListMatches: JSON.stringify(generated.files) === JSON.stringify(tracked.files),
    packRunsAreReproducible: generated.reproducibility.packRuns === 2
      && generated.reproducibility.archiveSha256Matches
      && generated.reproducibility.archiveSizesMatch
      && generated.reproducibility.fileListsMatch,
  };
  assert.deepEqual(matches, {
    candidateUsesCheckoutCommit: true,
    checkoutIsClean: true,
    coreAutocrlfIsTrue: true,
    readmeMatchesCanonicalGitBlob: true,
    packageVersionMatchesManifest: true,
    archiveFilenameMatches: true,
    archiveBytesMatch: true,
    archiveSha256Matches: true,
    fullFileListMatches: true,
    packRunsAreReproducible: true,
  }, 'fresh core.autocrlf=true checkout 必須產生與 tracked manifest 一致的 source candidate');
});

test('package candidate 包含 service/API handoff，Bot-readable 文件不嵌入 token sentinel', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const packageFiles = new Set(manifest.files);
  assert.ok(fs.statSync(path.join(root, 'README.md')).isFile(), 'README 必須存在於 package source');
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.ok(
    readme.includes(`本機 source candidate 版本：\`${manifest.version}\`（未發布）`),
    'README 本機候選版本必須明確等於 package.json.version',
  );
  assert.doesNotMatch(
    readme,
    /(?:git tag -a|git push origin|npm version (?:patch|minor|major))/,
    'README 不得留下可直接執行的未授權發版命令',
  );
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
