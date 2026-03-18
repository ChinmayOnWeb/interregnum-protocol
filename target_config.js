'use strict';

const path = require('node:path');
const { readCurrentCustomTargetSync } = require('./custom_target');

const ROOT_DIR = __dirname;
const PATCHED_PACKAGE_DIR = path.join(ROOT_DIR, 'patched-package');

const TARGETS = {
  'mixin-deep': {
    key: 'mixin-deep',
    packageName: 'mixin-deep',
    ecosystem: 'npm',
    cve: 'CVE-2019-10746',
    severity: 'High',
    affectedRange: '< 1.3.2',
    vulnerableClass: 'Prototype Pollution',
    vulnerableDir: path.join(ROOT_DIR, 'vulnerable-package'),
    sourcePath: path.join(ROOT_DIR, 'vulnerable-package', 'index.js'),
    sourceRelPath: 'index.js',
    cvePath: path.join(ROOT_DIR, 'cve_descriptions', 'CVE-2019-10746.txt'),
    reportSummary:
      '`CVE-2019-10746` affects `mixin-deep` before version 1.3.2 and version 2.0.0. The vulnerable merge logic can be abused with a `constructor -> prototype` payload to pollute `Object.prototype`.',
    demoButtonLabel: 'Run Demo (mixin-deep)',
    dashboardSummary:
      'A crafted constructor -> prototype payload can pollute Object.prototype in vulnerable mixin-deep builds. This dashboard shows the exploit reproduced against the vulnerable source, the minimal patch applied, and the remediation validated with real tests.'
  },
  'set-value': {
    key: 'set-value',
    packageName: 'set-value',
    ecosystem: 'npm',
    cve: 'CVE-2019-10747',
    severity: 'High',
    affectedRange: '3.0.0 - 3.0.1',
    vulnerableClass: 'Prototype Pollution',
    vulnerableDir: path.join(ROOT_DIR, 'vulnerable-package-2'),
    sourcePath: path.join(ROOT_DIR, 'vulnerable-package-2', 'index.js'),
    sourceRelPath: 'index.js',
    cvePath: path.join(ROOT_DIR, 'cve_descriptions', 'CVE-2019-10747.txt'),
    reportSummary:
      '`CVE-2019-10747` affects `set-value` 3.0.0 and 3.0.1. The vulnerable path setter accepts untrusted path segments like `__proto__`, allowing attacker-controlled writes onto `Object.prototype`.',
    demoButtonLabel: 'Run Demo (set-value)',
    dashboardSummary:
      'A crafted `__proto__.polluted` path can write attacker-controlled data onto Object.prototype in vulnerable set-value builds. This dashboard shows the issue reproduced against the vulnerable source, the path-segment guard added, and the remediation validated with real tests.'
  },
  'request': {
    key: 'request',
    packageName: 'request',
    ecosystem: 'npm',
    cve: 'CVE-2023-28155',
    severity: 'Medium',
    affectedRange: '<= 2.88.2',
    vulnerableClass: 'Insufficient Input Validation',
    vulnerableDir: path.join(ROOT_DIR, 'vulnerable-package-3'),
    sourcePath: path.join(ROOT_DIR, 'vulnerable-package-3', 'index.js'),
    sourceRelPath: 'index.js',
    cvePath: path.join(ROOT_DIR, 'cve_descriptions', 'CVE-2023-28155.txt'),
    reportSummary:
      '`CVE-2023-28155` affects `request` through 2.88.2. Cross-protocol redirects can bypass SSRF mitigations, and the package is no longer maintained by the original maintainer.',
    demoButtonLabel: 'Run Demo (request)',
    dashboardSummary:
      'A cross-protocol redirect can bypass redirect protocol checks in vulnerable request builds. This dashboard shows the SSRF condition reproduced against the vulnerable source, the redirect validation patched, and the remediation validated with real tests.'
  }
};

function getCurrentCustomTarget() {
  return readCurrentCustomTargetSync();
}

function getTargetConfig(targetKey = 'mixin-deep') {
  if (targetKey === 'custom') {
    return getCurrentCustomTarget() || TARGETS['mixin-deep'];
  }

  return TARGETS[targetKey] || TARGETS['mixin-deep'];
}

function listAvailableTargets() {
  const targets = Object.values(TARGETS);
  const customTarget = getCurrentCustomTarget();
  if (customTarget) {
    targets.push({
      ...customTarget,
      demoButtonLabel: 'Custom Package'
    });
  }

  return targets;
}

function parseTargetFlag(argv = []) {
  const targetIndex = argv.indexOf('--target');
  if (targetIndex !== -1 && argv[targetIndex + 1]) {
    return argv[targetIndex + 1];
  }

  return 'mixin-deep';
}

function parseInputFlag(argv = []) {
  const inputIndex = argv.indexOf('--input');
  if (inputIndex !== -1 && argv[inputIndex + 1]) {
    return argv[inputIndex + 1];
  }

  return '';
}

function parseCveFlag(argv = []) {
  const cveIndex = argv.indexOf('--cve');
  if (cveIndex !== -1 && argv[cveIndex + 1]) {
    return argv[cveIndex + 1];
  }

  return '';
}

module.exports = {
  TARGETS,
  PATCHED_PACKAGE_DIR,
  getTargetConfig,
  listAvailableTargets,
  parseTargetFlag,
  parseInputFlag,
  parseCveFlag
};
