'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { DEFAULT_MODEL, callOpenAIJson } = require('./openai_client');
const { getTargetConfig } = require('./target_config');
const { executeDynamicScript } = require('./safe_runtime');

const GENERATED_HARNESS_PATH = path.join(__dirname, 'generated_harness.json');

function addLineNumbers(source) {
  return source
    .split('\n')
    .slice(0, 400)
    .map((line, index) => `${index + 1}: ${line}`)
    .join('\n');
}

async function buildHarnessPrompt(target) {
  const [advisoryText, sourceCode, packageJson] = await Promise.all([
    fs.readFile(target.cvePath, 'utf8'),
    fs.readFile(target.sourcePath, 'utf8'),
    fs.readFile(path.join(target.vulnerableDir, 'package.json'), 'utf8').catch(() => '{"name":"unknown"}')
  ]);

  return [
    'You are a security test harness generation agent.',
    'Generate deterministic, local-only exploit, regression, and adversarial harnesses for a JavaScript package.',
    'Return strict JSON with this schema:',
    '{',
    '  "exploit_script": "string",',
    '  "exploit_success_message": "string",',
    '  "exploit_failure_message": "string",',
    '  "normal_tests": [',
    '    { "name": "string", "script": "string" }',
    '  ],',
    '  "adversarial_attempts": [',
    '    { "bypass_name": "string", "payload": "string", "script": "string" }',
    '  ]',
    '}',
    'Scripts execute with parameters: modulePath, helpers, assert, path, URL.',
    'helpers.requireFresh(modulePath, helpers.targetSourcePath) loads the target source file.',
    'helpers.withBlockedNetwork(() => { ... }) blocks outbound DNS, socket, HTTP, and HTTPS calls.',
    'helpers.withPatchedModule(moduleName, replacements, fn) can monkeypatch builtins locally inside a test.',
    'exploit_script must return an object: { vulnerable: boolean }.',
    'Each normal test script should throw if the test fails.',
    'Each adversarial script must return an object: { bypassed: boolean }.',
    'Do not use network, child_process, fs writes, or timers.',
    'Use only deterministic local logic. If the advisory cannot be reproduced locally with high confidence, return { vulnerable: false } honestly and state that in the failure message.',
    'Normal tests must exercise expected package behavior near the vulnerable surface.',
    'Adversarial attempts should try realistic bypasses against the chosen fix strategy without calling the public internet.',
    '',
    `PACKAGE: ${target.packageName}`,
    `VERSION: ${target.version || 'unknown'}`,
    `SOURCE FILE: ${target.sourceRelPath || path.basename(target.sourcePath)}`,
    `VULNERABILITY CLASS: ${target.vulnerableClass}`,
    '',
    'ADVISORY:',
    advisoryText,
    '',
    'PACKAGE.JSON:',
    packageJson,
    '',
    'SOURCE FILE WITH LINE NUMBERS:',
    addLineNumbers(sourceCode)
  ].join('\n');
}

async function generateDynamicHarness(targetKey, model = DEFAULT_MODEL) {
  const target = getTargetConfig(targetKey);
  const result = await callOpenAIJson({
    prompt: await buildHarnessPrompt(target),
    model,
    toolName: 'dynamic harness generator'
  });

  const harness = {
    target: target.key,
    package_name: target.packageName,
    source_rel_path: target.sourceRelPath || '.',
    exploit_script: String(result.exploit_script || '').trim(),
    exploit_success_message: String(result.exploit_success_message || 'VULNERABLE: exploit reproduced').trim(),
    exploit_failure_message: String(result.exploit_failure_message || 'SAFE: exploit blocked or not reproducible locally').trim(),
    normal_tests: Array.isArray(result.normal_tests) ? result.normal_tests.slice(0, 6) : [],
    adversarial_attempts: Array.isArray(result.adversarial_attempts) ? result.adversarial_attempts.slice(0, 8) : []
  };

  await fs.writeFile(GENERATED_HARNESS_PATH, `${JSON.stringify(harness, null, 2)}\n`, 'utf8');
  return harness;
}

async function ensureDynamicHarness(targetKey) {
  try {
    const raw = await fs.readFile(GENERATED_HARNESS_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && parsed.target === targetKey) {
      return parsed;
    }
  } catch (_) {
    // ignore and regenerate
  }

  return generateDynamicHarness(targetKey);
}

async function runDynamicExploitTest(targetKey, modulePath, expected) {
  const harness = await ensureDynamicHarness(targetKey);
  const result = executeDynamicScript(harness.exploit_script, modulePath, { targetSourcePath: harness.source_rel_path || '.' }) || { vulnerable: false };
  const vulnerable = Boolean(result.vulnerable);
  return {
    ok: (expected === 'vulnerable' && vulnerable) || (expected === 'safe' && !vulnerable),
    polluted: vulnerable,
    output: vulnerable ? harness.exploit_success_message : harness.exploit_failure_message
  };
}

async function runDynamicNormalTests(targetKey, modulePath) {
  const harness = await ensureDynamicHarness(targetKey);
  const lines = [];
  let failures = 0;

  for (const test of harness.normal_tests || []) {
    try {
      executeDynamicScript(test.script, modulePath, { targetSourcePath: harness.source_rel_path || '.' });
      lines.push(`PASS: ${test.name}`);
    } catch (error) {
      failures += 1;
      lines.push(`FAIL: ${test.name}`);
      lines.push(error.message);
    }
  }

  lines.push(failures === 0 ? 'ALL NORMAL TESTS PASSED' : `${failures} normal test(s) failed`);
  return { ok: failures === 0, output: lines.join('\n') };
}

async function runDynamicAdversarialAttempts(targetKey, modulePath) {
  const harness = await ensureDynamicHarness(targetKey);
  return (harness.adversarial_attempts || []).map((attempt) => {
    try {
      const result = executeDynamicScript(attempt.script, modulePath, { targetSourcePath: harness.source_rel_path || '.' }) || { bypassed: false };
      const bypassed = Boolean(result.bypassed);
      return {
        bypass_name: attempt.bypass_name,
        payload: attempt.payload,
        result: bypassed ? 'BYPASSED' : 'BLOCKED',
        severity: bypassed ? 'critical' : 'none'
      };
    } catch (error) {
      return {
        bypass_name: attempt.bypass_name,
        payload: attempt.payload,
        result: 'BLOCKED',
        severity: 'none',
        error: error.message
      };
    }
  });
}

module.exports = {
  GENERATED_HARNESS_PATH,
  ensureDynamicHarness,
  generateDynamicHarness,
  runDynamicExploitTest,
  runDynamicNormalTests,
  runDynamicAdversarialAttempts
};
