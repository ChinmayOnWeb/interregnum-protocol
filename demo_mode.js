'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { ANALYZER_OUTPUT_PATH } = require('./analyzer');
const { PATCH_OUTPUT_PATH } = require('./patcher');
const { CLASSIFICATION_OUTPUT_PATH } = require('./classify_vulnerabilities');
const { getTargetConfig, PATCHED_PACKAGE_DIR } = require('./target_config');

const MIXIN_CLASSIFICATION_OUTPUT = {
  target: 'mixin-deep',
  package_name: 'mixin-deep',
  cve: 'CVE-2019-10746',
  findings: [
    {
      vulnerability_class: 'Prototype Pollution',
      file: 'vulnerable-package/index.js',
      line: 24,
      severity: 'high',
      confidence: 97,
      explanation: 'Recursive merge logic accepts unsafe keys and can descend into the prototype chain through constructor and prototype.'
    }
  ],
  independent_detection: true,
  matched_known_cve: true,
  additional_findings: []
};

const MIXIN_ANALYZER_OUTPUT = {
  target: 'mixin-deep',
  package_name: 'mixin-deep',
  cve: 'CVE-2019-10746',
  root_cause:
    'The vulnerable merge logic only blocks the "__proto__" key at the current property level. When attacker-controlled input uses the path constructor -> prototype -> polluted, the code reads this["constructor"] from the target object, which resolves to the built-in Object constructor. The recursive mixin then descends into Object.prototype and writes attacker data there, polluting every plain object.',
  dangerous_lines: [
    { line: 24, code: "if (key === '__proto__') {", reason: 'This guard is incomplete because it ignores the constructor/prototype prototype-pollution path.' },
    { line: 28, code: 'var obj = this[key];', reason: 'Reading this["constructor"] resolves to Object, which gives the attacker access to Object.prototype during recursion.' },
    { line: 30, code: 'mixinDeep(obj, val);', reason: 'Recursive descent continues into the inherited constructor/prototype chain and writes attacker-controlled properties.' }
  ],
  patch_strategy:
    'Reject dangerous keys before any read or recursive merge happens. Add a shared unsafe-key check that returns true for "__proto__", "constructor", and "prototype", and short-circuit the copy operation for those keys. Keep the rest of the merge behavior unchanged.'
};

const MIXIN_STRATEGIES = [
  {
    name: 'Key Blocklist',
    approach: 'Skip __proto__, constructor, and prototype keys before any recursive merge or assignment occurs.',
    score_breakdown: { minimality: 24, safety: 25, convention_match: 24, side_effect_risk: 24 },
    score: 97,
    selected: true
  },
  {
    name: 'Null Prototype Base',
    approach: 'Rewrite merge targets to use Object.create(null) so recursive merges never inherit a prototype chain.',
    score_breakdown: { minimality: 10, safety: 23, convention_match: 12, side_effect_risk: 14 },
    score: 59,
    selected: false
  },
  {
    name: 'hasOwnProperty Guard',
    approach: 'Gate recursion through own-property checks so inherited constructor/prototype traversal cannot continue.',
    score_breakdown: { minimality: 18, safety: 19, convention_match: 20, side_effect_risk: 18 },
    score: 75,
    selected: false
  }
];

const MIXIN_PATCHED_CODE = `'use strict';

var isExtendable = require('is-extendable');
var forIn = require('for-in');

function mixinDeep(target, objects) {
  var len = arguments.length;
  var i = 0;

  while (++i < len) {
    var obj = arguments[i];
    if (isObject(obj)) {
      forIn(obj, copy, target);
    }
  }
  return target;
}

function copy(val, key) {
  if (isUnsafeKey(key)) {
    return;
  }

  var obj = this[key];
  if (isObject(val) && isObject(obj)) {
    mixinDeep(obj, val);
  } else {
    this[key] = val;
  }
}

function isUnsafeKey(key) {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
}

function isObject(val) {
  return isExtendable(val) && !Array.isArray(val);
}

module.exports = mixinDeep;
`;

const MIXIN_PATCH_OUTPUT = {
  target: 'mixin-deep',
  package_name: 'mixin-deep',
  cve: 'CVE-2019-10746',
  strategies: MIXIN_STRATEGIES,
  selected_strategy: 'Key Blocklist',
  reasoning: 'Highest combined score. It is the smallest change, fully blocks the prototype pollution vectors, matches the existing function-based style, and carries the lowest regression risk.',
  patch_diff: `--- a/index.js
+++ b/index.js
@@
-  if (key === '__proto__') {
+  if (isUnsafeKey(key)) {
     return;
   }
@@
 }
+
+function isUnsafeKey(key) {
+  return key === '__proto__' || key === 'constructor' || key === 'prototype';
+}`,
  patched_code: MIXIN_PATCHED_CODE
};

const SET_VALUE_CLASSIFICATION_OUTPUT = {
  target: 'set-value',
  package_name: 'set-value',
  cve: 'CVE-2019-10747',
  findings: [
    {
      vulnerability_class: 'Prototype Pollution',
      file: 'vulnerable-package-2/index.js',
      line: 25,
      severity: 'high',
      confidence: 96,
      explanation: 'Path-based setter logic accepts __proto__ as a normal segment and can write attacker data onto Object.prototype.'
    },
    {
      vulnerability_class: 'Insufficient Input Validation',
      file: 'vulnerable-package-2/index.js',
      line: 10,
      severity: 'medium',
      confidence: 71,
      explanation: 'Path input is normalized without any validation of reserved or dangerous segment values.'
    }
  ],
  independent_detection: true,
  matched_known_cve: true,
  additional_findings: [
    {
      vulnerability_class: 'Insufficient Input Validation',
      file: 'vulnerable-package-2/index.js',
      line: 10,
      severity: 'medium',
      confidence: 71,
      explanation: 'Path input is normalized without any validation of reserved or dangerous segment values.'
    }
  ]
};

const SET_VALUE_ANALYZER_OUTPUT = {
  target: 'set-value',
  package_name: 'set-value',
  cve: 'CVE-2019-10747',
  root_cause:
    'The vulnerable setter treats every path segment as trusted. When attacker-controlled input includes the segment "__proto__", the loop descends into Object.prototype instead of a normal nested object and writes attacker data there. Because no guard rejects "__proto__", "constructor", or "prototype" segments, a simple path string can mutate the global prototype chain.',
  dangerous_lines: [
    { line: 23, code: 'if (nested[key] == null || !isObject(nested[key])) {', reason: 'The code accepts untrusted path segments without blocking prototype-pollution keys.' },
    { line: 27, code: 'nested = nested[key];', reason: 'When key is "__proto__", traversal moves into Object.prototype.' },
    { line: 30, code: 'nested[segments[index]] = value;', reason: 'The final write lands on the polluted prototype object.' }
  ],
  patch_strategy:
    'Normalize the path into segments, reject any segment equal to "__proto__", "constructor", or "prototype", and return the target unchanged when an unsafe segment appears. Preserve all normal path-setting behavior for safe keys.'
};

const SET_VALUE_STRATEGIES = [
  {
    name: 'Path Segment Blocklist',
    approach: 'Reject __proto__, constructor, and prototype segments before any nested traversal or final assignment.',
    score_breakdown: { minimality: 21, safety: 25, convention_match: 23, side_effect_risk: 22 },
    score: 91,
    selected: true
  },
  {
    name: 'Null Prototype Containers',
    approach: 'Create all intermediate objects with Object.create(null) so path traversal never inherits a prototype chain.',
    score_breakdown: { minimality: 12, safety: 22, convention_match: 13, side_effect_risk: 15 },
    score: 62,
    selected: false
  },
  {
    name: 'Own Property Traversal',
    approach: 'Require own-property traversal at each segment so inherited prototype nodes are never reused as path containers.',
    score_breakdown: { minimality: 17, safety: 20, convention_match: 21, side_effect_risk: 19 },
    score: 77,
    selected: false
  }
];

const SET_VALUE_PATCHED_CODE = `'use strict';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function toSegments(input) {
  if (Array.isArray(input)) {
    return input.slice();
  }

  return String(input).split('.');
}

function isUnsafeKey(key) {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
}

function setValue(target, path, value) {
  if (!isObject(target)) {
    return target;
  }

  var segments = toSegments(path);
  var index = 0;
  var nested = target;

  while (nested != null && index < segments.length - 1) {
    var key = segments[index++];

    if (isUnsafeKey(key)) {
      return target;
    }

    if (nested[key] == null || !isObject(nested[key])) {
      nested[key] = {};
    }

    nested = nested[key];
  }

  if (isUnsafeKey(segments[index])) {
    return target;
  }

  nested[segments[index]] = value;
  return target;
}

module.exports = setValue;
`;

const SET_VALUE_PATCH_OUTPUT = {
  target: 'set-value',
  package_name: 'set-value',
  cve: 'CVE-2019-10747',
  strategies: SET_VALUE_STRATEGIES,
  selected_strategy: 'Path Segment Blocklist',
  reasoning: 'Highest combined score. It fully blocks the vulnerable path segments while preserving the existing setter design and minimizing behavioral risk.',
  patch_diff: `--- a/index.js
+++ b/index.js
@@
+function isUnsafeKey(key) {
+  return key === '__proto__' || key === 'constructor' || key === 'prototype';
+}
+
 function setValue(target, path, value) {
@@
-    if (nested[key] == null || !isObject(nested[key])) {
+    if (isUnsafeKey(key)) {
+      return target;
+    }
+
+    if (nested[key] == null || !isObject(nested[key])) {
       nested[key] = {};
     }
@@
-  nested[segments[index]] = value;
+  if (isUnsafeKey(segments[index])) {
+    return target;
+  }
+
+  nested[segments[index]] = value;`,
  patched_code: SET_VALUE_PATCHED_CODE
};

const REQUEST_CLASSIFICATION_OUTPUT = {
  target: 'request',
  package_name: 'request',
  cve: 'CVE-2023-28155',
  findings: [
    {
      vulnerability_class: 'Insufficient Input Validation',
      file: 'vulnerable-package-3/index.js',
      line: 28,
      severity: 'high',
      confidence: 94,
      explanation: 'Redirect targets are followed without validating that the redirected protocol still matches the allowed protocol policy.'
    }
  ],
  independent_detection: true,
  matched_known_cve: true,
  additional_findings: []
};

const REQUEST_ANALYZER_OUTPUT = {
  target: 'request',
  package_name: 'request',
  cve: 'CVE-2023-28155',
  root_cause:
    'The vulnerable request flow validates the protocol of the initial URL but does not re-validate redirect targets. An attacker-controlled server can respond with a cross-protocol redirect from an allowed https URL to a blocked http URL, bypassing SSRF policy and causing the client to follow a destination that should have been rejected.',
  dangerous_lines: [
    { line: 17, code: 'if (!isAllowedProtocol(config.url, config.allowedProtocols)) {', reason: 'The initial request URL is validated once, which creates a false sense of safety if later redirects are not checked.' },
    { line: 29, code: 'for (const redirectUrl of config.redirects) {', reason: 'The redirect chain is processed without any per-redirect policy enforcement.' },
    { line: 32, code: 'current = redirectUrl;', reason: 'A redirected URL can switch protocols and bypass the original SSRF mitigation.' }
  ],
  patch_strategy:
    'Re-validate every redirect target against the allowed protocol set before following it. If a redirect changes to a disallowed protocol, stop and return a blocked result instead of following the redirect.'
};

const REQUEST_STRATEGIES = [
  {
    name: 'Redirect Revalidation',
    approach: 'Check each redirect target against the allowed protocol list before updating the current request URL.',
    score_breakdown: { minimality: 24, safety: 25, convention_match: 23, side_effect_risk: 24 },
    score: 96,
    selected: true
  },
  {
    name: 'Disable Cross-Protocol Redirects',
    approach: 'Record the initial protocol and reject any redirect that changes protocols, regardless of the allowlist.',
    score_breakdown: { minimality: 20, safety: 23, convention_match: 21, side_effect_risk: 20 },
    score: 84,
    selected: false
  },
  {
    name: 'Pre-Normalize Redirect Chain',
    approach: 'Normalize and pre-screen the entire redirect chain before any redirect is followed.',
    score_breakdown: { minimality: 15, safety: 22, convention_match: 16, side_effect_risk: 18 },
    score: 71,
    selected: false
  }
];

const REQUEST_PATCHED_CODE = `'use strict';

function getProtocol(rawUrl) {
  return new URL(rawUrl).protocol;
}

function isAllowedProtocol(rawUrl, allowedProtocols) {
  return allowedProtocols.includes(getProtocol(rawUrl));
}

function request(options) {
  const config = Object.assign(
    {
      url: '',
      redirects: [],
      allowedProtocols: ['https:']
    },
    options || {}
  );

  if (!isAllowedProtocol(config.url, config.allowedProtocols)) {
    return {
      ok: false,
      blocked: true,
      reason: 'initial protocol blocked',
      finalUrl: config.url
    };
  }

  let current = config.url;

  for (const redirectUrl of config.redirects) {
    if (!isAllowedProtocol(redirectUrl, config.allowedProtocols)) {
      return {
        ok: false,
        blocked: true,
        reason: 'redirect protocol blocked',
        finalUrl: current,
        blockedUrl: redirectUrl
      };
    }

    current = redirectUrl;
  }

  return {
    ok: true,
    blocked: false,
    finalUrl: current
  };
}

module.exports = request;
`;

const REQUEST_PATCH_OUTPUT = {
  target: 'request',
  package_name: 'request',
  cve: 'CVE-2023-28155',
  strategies: REQUEST_STRATEGIES,
  selected_strategy: 'Redirect Revalidation',
  reasoning: 'Highest combined score. It is the smallest behavior-preserving patch that closes the redirect validation gap without rewriting the request flow.',
  patch_diff: `--- a/index.js
+++ b/index.js
@@
   let current = config.url;
 
   for (const redirectUrl of config.redirects) {
+    if (!isAllowedProtocol(redirectUrl, config.allowedProtocols)) {
+      return {
+        ok: false,
+        blocked: true,
+        reason: 'redirect protocol blocked',
+        finalUrl: current,
+        blockedUrl: redirectUrl
+      };
+    }
+
     current = redirectUrl;
   }
`,
  patched_code: REQUEST_PATCHED_CODE
};

const DEMO_FIXTURES = {
  'mixin-deep': {
    classificationOutput: MIXIN_CLASSIFICATION_OUTPUT,
    analyzerOutput: MIXIN_ANALYZER_OUTPUT,
    patchOutput: MIXIN_PATCH_OUTPUT
  },
  'set-value': {
    classificationOutput: SET_VALUE_CLASSIFICATION_OUTPUT,
    analyzerOutput: SET_VALUE_ANALYZER_OUTPUT,
    patchOutput: SET_VALUE_PATCH_OUTPUT
  },
  'request': {
    classificationOutput: REQUEST_CLASSIFICATION_OUTPUT,
    analyzerOutput: REQUEST_ANALYZER_OUTPUT,
    patchOutput: REQUEST_PATCH_OUTPUT
  }
};

async function ensurePatchedPackageDir(targetKey) {
  const target = getTargetConfig(targetKey);
  await fs.mkdir(PATCHED_PACKAGE_DIR, { recursive: true });
  await fs.copyFile(path.join(target.vulnerableDir, 'package.json'), path.join(PATCHED_PACKAGE_DIR, 'package.json'));
}

async function writeDemoArtifacts(targetKey = 'mixin-deep') {
  const fixture = DEMO_FIXTURES[targetKey] || DEMO_FIXTURES['mixin-deep'];
  await fs.writeFile(CLASSIFICATION_OUTPUT_PATH, `${JSON.stringify(fixture.classificationOutput, null, 2)}\n`, 'utf8');
  await fs.writeFile(ANALYZER_OUTPUT_PATH, `${JSON.stringify(fixture.analyzerOutput, null, 2)}\n`, 'utf8');
  await fs.writeFile(PATCH_OUTPUT_PATH, `${JSON.stringify(fixture.patchOutput, null, 2)}\n`, 'utf8');
  await ensurePatchedPackageDir(targetKey);
  await fs.writeFile(path.join(PATCHED_PACKAGE_DIR, 'index.js'), fixture.patchOutput.patched_code, 'utf8');
  return fixture;
}

async function readVulnerableSource(targetKey = 'mixin-deep') {
  return fs.readFile(getTargetConfig(targetKey).sourcePath, 'utf8');
}

module.exports = {
  writeDemoArtifacts,
  readVulnerableSource,
  DEMO_FIXTURES
};
