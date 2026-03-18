'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { PATCHED_PACKAGE_DIR, getTargetConfig, parseTargetFlag } = require('./target_config');
const { runDynamicAdversarialAttempts } = require('./dynamic_harness');

const ADVERSARIAL_RESULTS_PATH = path.join(__dirname, 'adversarial_results.json');

function loadModule(modulePath) {
  const resolved = require.resolve(modulePath);
  delete require.cache[resolved];
  return require(resolved);
}

function cleanupMarker(marker) {
  try {
    delete Object.prototype[marker];
  } catch (_) {
    // ignore cleanup failures
  }
}

function isPolluted(marker) {
  return Object.prototype[marker] === true || {}[marker] === true;
}

function makeMixinAttempts(marker) {
  return [
    { bypass_name: 'nested __proto__ payload', payload: `JSON.parse('{"safe":{"__proto__":{"${marker}":true}}}')`, execute(mixinDeep) { mixinDeep({}, JSON.parse(`{"safe":{"__proto__":{"${marker}":true}}}`)); } },
    { bypass_name: 'constructor.prototype payload', payload: `{"constructor":{"prototype":{"${marker}":true}}}`, execute(mixinDeep) { mixinDeep({}, { constructor: { prototype: { [marker]: true } } }); } },
    { bypass_name: 'Object.defineProperty __proto__ payload', payload: `defineProperty(payload, '__proto__', { value: { ${marker}: true }, enumerable: true })`, execute(mixinDeep) { const payload = {}; Object.defineProperty(payload, '__proto__', { value: { [marker]: true }, enumerable: true, configurable: true }); mixinDeep({}, payload); } },
    { bypass_name: 'unicode encoded __proto__ key', payload: `{"__pr\\u006fto__":{"${marker}":true}}`, execute(mixinDeep) { mixinDeep({}, { ['__pr' + '\u006fto__']: { [marker]: true } }); } },
    { bypass_name: 'recursive constructor chain', payload: `{"safe":{"constructor":{"prototype":{"${marker}":true}}}}`, execute(mixinDeep) { mixinDeep({}, { safe: { constructor: { prototype: { [marker]: true } } } }); } },
    { bypass_name: 'array based prototype vector', payload: `{"items":[{"constructor":{"prototype":{"${marker}":true}}}]}`, execute(mixinDeep) { mixinDeep({}, { items: [{ constructor: { prototype: { [marker]: true } } }] }); } },
    { bypass_name: 'double recursive pollution attempt', payload: `JSON.parse('{"safe":{"deep":{"constructor":{"prototype":{"${marker}":true}}}}}')`, execute(mixinDeep) { mixinDeep({}, JSON.parse(`{"safe":{"deep":{"constructor":{"prototype":{"${marker}":true}}}}}`)); } },
    { bypass_name: 'array path inside nested object', payload: `{"safe":{"arr":[{"__proto__":{"${marker}":true}}]}}`, execute(mixinDeep) { const payload = { safe: { arr: [JSON.parse(`{"__proto__":{"${marker}":true}}`)] } }; mixinDeep({}, payload); } }
  ];
}

function makeSetValueAttempts(marker) {
  return [
    { bypass_name: 'nested __proto__ path', payload: `'a.__proto__.${marker}'`, execute(setValue) { setValue({}, `a.__proto__.${marker}`, true); } },
    { bypass_name: 'constructor.prototype path', payload: `'constructor.prototype.${marker}'`, execute(setValue) { setValue({}, `constructor.prototype.${marker}`, true); } },
    { bypass_name: 'array based __proto__ path', payload: `['__proto__', '${marker}']`, execute(setValue) { setValue({}, ['__proto__', marker], true); } },
    { bypass_name: 'array based constructor path', payload: `['constructor', 'prototype', '${marker}']`, execute(setValue) { setValue({}, ['constructor', 'prototype', marker], true); } },
    { bypass_name: 'unicode encoded __proto__ segment', payload: `'__pr\\u006fto__.${marker}'`, execute(setValue) { setValue({}, `__pr${'o'}to__.${marker}`, true); } },
    { bypass_name: 'recursive nested constructor path', payload: `'safe.constructor.prototype.${marker}'`, execute(setValue) { setValue({}, `safe.constructor.prototype.${marker}`, true); } },
    { bypass_name: 'Object.defineProperty array segment', payload: `defineProperty(path, 0, { value: '__proto__', enumerable: true })`, execute(setValue) { const attackPath = [marker]; Object.defineProperty(attackPath, 0, { value: '__proto__', enumerable: true, configurable: true }); attackPath[1] = marker; setValue({}, attackPath, true); } },
    { bypass_name: 'deep array recursion path', payload: `['safe', '__proto__', '${marker}']`, execute(setValue) { setValue({}, ['safe', '__proto__', marker], true); } }
  ];
}

function makeRequestAttempts() {
  return [
    { bypass_name: 'https to http redirect', payload: '{ url: "https://public.example", redirects: ["http://169.254.169.254/latest/meta-data"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['http://169.254.169.254/latest/meta-data'], allowedProtocols: ['https:'] }); } },
    { bypass_name: 'double redirect ending in http', payload: '{ redirects: ["https://edge.example", "http://169.254.169.254/latest/meta-data"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['https://edge.example', 'http://169.254.169.254/latest/meta-data'], allowedProtocols: ['https:'] }); } },
    { bypass_name: 'uppercase protocol redirect', payload: '{ redirects: ["HTTP://169.254.169.254/latest/meta-data"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['HTTP://169.254.169.254/latest/meta-data'], allowedProtocols: ['https:'] }); } },
    { bypass_name: 'redirect to localhost metadata endpoint', payload: '{ redirects: ["http://127.0.0.1/admin"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['http://127.0.0.1/admin'], allowedProtocols: ['https:'] }); } },
    { bypass_name: 'mixed redirect chain', payload: '{ redirects: ["https://cdn.example", "http://internal.example/private"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['https://cdn.example', 'http://internal.example/private'], allowedProtocols: ['https:'] }); } },
    { bypass_name: 'array redirect to link local', payload: '{ redirects: ["http://169.254.169.254/latest"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['http://169.254.169.254/latest'], allowedProtocols: ['https:'] }); } },
    { bypass_name: 'redirect after safe hop', payload: '{ redirects: ["https://safe.example", "http://10.0.0.5/admin"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['https://safe.example', 'http://10.0.0.5/admin'], allowedProtocols: ['https:'] }); } },
    { bypass_name: 'redirect to plain http file', payload: '{ redirects: ["http://files.example/export"] }', execute(request) { return request({ url: 'https://public.example', redirects: ['http://files.example/export'], allowedProtocols: ['https:'] }); } }
  ];
}

function getAttempts(targetKey, marker, target) {
  if (target.dynamic) return [];
  if (targetKey === 'set-value') return makeSetValueAttempts(marker);
  if (targetKey === 'request') return makeRequestAttempts();
  return makeMixinAttempts(marker);
}

function executeAttempt(targetKey, modulePath, attempt, marker) {
  cleanupMarker(marker);
  const mod = loadModule(modulePath);
  try {
    const result = attempt.execute(mod);
    if (targetKey === 'request') {
      const bypassed = Boolean(result && result.blocked === false && /^http:/i.test(String(result.finalUrl || '')));
      return { bypass_name: attempt.bypass_name, payload: attempt.payload, result: bypassed ? 'BYPASSED' : 'BLOCKED', severity: bypassed ? 'critical' : 'none' };
    }
  } catch (error) {
    cleanupMarker(marker);
    return { bypass_name: attempt.bypass_name, payload: attempt.payload, result: 'BLOCKED', severity: 'none', error: error.message };
  }

  const bypassed = isPolluted(marker);
  cleanupMarker(marker);
  return { bypass_name: attempt.bypass_name, payload: attempt.payload, result: bypassed ? 'BYPASSED' : 'BLOCKED', severity: bypassed ? 'critical' : 'none' };
}

async function readPatchDiff() {
  try {
    const raw = await fs.readFile(path.join(__dirname, 'patch_output.json'), 'utf8');
    const parsed = JSON.parse(raw);
    return parsed.patch_diff || '';
  } catch (_) {
    return '';
  }
}

async function runAdversarialTests(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const target = getTargetConfig(targetKey);
  const modulePath = options.modulePath || PATCHED_PACKAGE_DIR;
  const patchDiff = options.patchDiff || (await readPatchDiff());
  const markerBase = `praetorian_${target.key.replace(/[^a-z0-9]+/gi, '_').toLowerCase()}`;

  const results = target.dynamic
    ? await runDynamicAdversarialAttempts(targetKey, modulePath)
    : getAttempts(targetKey, markerBase, target).map((attempt, index) => executeAttempt(targetKey, modulePath, attempt, `${markerBase}_${index}`));
  const bypasses = results.filter((result) => result.result === 'BYPASSED');

  const output = {
    target: target.key,
    package_name: target.packageName,
    cve: target.cve,
    patch_diff_reviewed: Boolean(patchDiff && patchDiff.trim()),
    attempts: results,
    adversarial_tests_run: results.length,
    bypasses_found: bypasses.length,
    patch_resilience_score: `${Math.round(((results.length - bypasses.length) / Math.max(results.length, 1)) * 100)}%`,
    verdict: bypasses.length === 0 ? 'HARDENED' : 'BYPASS FOUND',
    bypasses
  };

  await fs.writeFile(ADVERSARIAL_RESULTS_PATH, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  return output;
}

async function main() {
  try {
    const targetKey = parseTargetFlag(process.argv.slice(2));
    const result = await runAdversarialTests({ targetKey });
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Adversarial tester failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  runAdversarialTests,
  ADVERSARIAL_RESULTS_PATH
};
