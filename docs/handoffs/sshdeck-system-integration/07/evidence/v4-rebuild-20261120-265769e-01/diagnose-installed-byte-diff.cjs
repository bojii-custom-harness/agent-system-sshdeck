'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const repo = process.cwd();
const evidence = path.join(
  repo,
  'docs/handoffs/sshdeck-system-integration/07/evidence/v4-rebuild-20261120-265769e-01',
);
const installed = path.join(
  process.env.LOCALAPPDATA,
  'Temp/opencode/sshdeck-ticket07-v4-265769e-01/node_modules/agent-system-sshdeck',
);
const candidate = path.join(
  repo,
  'docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3',
);
const archive = path.join(candidate, 'agent-system-sshdeck-0.1.3.tgz');
const packlist = JSON.parse(fs.readFileSync(path.join(evidence, 'packlist.json'), 'utf8'))[0];

function details(left, right) {
  const common = Math.min(left.length, right.length);
  const mismatches = [];
  for (let index = 0; index < common && mismatches.length < 8; index += 1) {
    if (left[index] !== right[index]) {
      mismatches.push({
        offset: index,
        left: left.subarray(Math.max(0, index - 3), index + 5).toString('hex'),
        right: right.subarray(Math.max(0, index - 3), index + 5).toString('hex'),
      });
    }
  }
  const count = (buffer, byte) => {
    let total = 0;
    for (const value of buffer) if (value === byte) total += 1;
    return total;
  };
  return {
    leftSize: left.length,
    rightSize: right.length,
    equal: left.equals(right),
    mismatches,
    leftCRLF: left.toString('binary').match(/\r\n/g)?.length ?? 0,
    rightCRLF: right.toString('binary').match(/\r\n/g)?.length ?? 0,
    leftLF: count(left, 10),
    rightLF: count(right, 10),
    leftLastBytes: left.subarray(-8).toString('hex'),
    rightLastBytes: right.subarray(-8).toString('hex'),
  };
}

const results = packlist.files.map(({ path: filePath }) => {
  const source = fs.readFileSync(path.join(repo, filePath));
  const installedFile = fs.readFileSync(path.join(installed, filePath));
  const extracted = spawnSync('tar.exe', ['-xOf', archive, `package/${filePath}`], {
    cwd: repo,
    encoding: null,
    timeout: 10_000,
    windowsHide: true,
    maxBuffer: 2 * 1024 * 1024,
  });
  if (extracted.error || extracted.status !== 0) {
    throw new Error(`tar extraction failed for ${filePath}: ${extracted.error?.message || extracted.stderr}`);
  }
  return {
    path: filePath,
    archiveVsSource: details(extracted.stdout, source),
    installedVsArchive: details(installedFile, extracted.stdout),
  };
});

process.stdout.write(`${JSON.stringify({
  nodeVersion: process.version,
  platform: process.platform,
  tarTool: 'Windows tar.exe -xOf',
  resultCount: results.length,
  differingFiles: results.filter((result) => !result.archiveVsSource.equal || !result.installedVsArchive.equal),
  results,
}, null, 2)}\n`);
