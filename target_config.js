'use strict';

const path = require('node:path');

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
    cvePath: path.join(ROOT_DIR, 'cve_descriptions', 'CVE-2019-10747.txt'),
    reportSummary:
      '`CVE-2019-10747` affects `set-value` 3.0.0 and 3.0.1. The vulnerable path setter accepts untrusted path segments like `__proto__`, allowing attacker-controlled writes onto `Object.prototype`.',
    demoButtonLabel: 'Run Demo (set-value)',
    dashboardSummary:
      'A crafted `__proto__.polluted` path can write attacker-controlled data onto Object.prototype in vulnerable set-value builds. This dashboard shows the issue reproduced against the vulnerable source, the path-segment guard added, and the remediation validated with real tests.'
  }
};

function getTargetConfig(targetKey = 'mixin-deep') {
  return TARGETS[targetKey] || TARGETS['mixin-deep'];
}

function parseTargetFlag(argv = []) {
  const targetIndex = argv.indexOf('--target');
  if (targetIndex !== -1 && argv[targetIndex + 1]) {
    return argv[targetIndex + 1];
  }

  return 'mixin-deep';
}

module.exports = {
  TARGETS,
  PATCHED_PACKAGE_DIR,
  getTargetConfig,
  parseTargetFlag
};
