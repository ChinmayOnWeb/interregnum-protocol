'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { getTargetConfig, parseTargetFlag } = require('./target_config');

function resolveModulePath(rawPath, targetKey) {
  if (rawPath) {
    return path.isAbsolute(rawPath) ? rawPath : path.join(__dirname, rawPath);
  }

  return getTargetConfig(targetKey).vulnerableDir;
}

function loadModule(modulePath) {
  const resolved = require.resolve(modulePath);
  delete require.cache[resolved];
  return require(resolved);
}

function runMixinDeepTests(mixinDeep) {
  const tests = [];

  tests.push(['merges nested objects', () => {
    const target = { user: { name: 'Ada', flags: { admin: false } } };
    const source = { user: { flags: { beta: true } } };
    const result = mixinDeep(target, source);
    assert.equal(result, target);
    assert.deepEqual(target, { user: { name: 'Ada', flags: { admin: false, beta: true } } });
  }]);

  tests.push(['overwrites leaf values', () => {
    const target = { retries: 1, mode: 'dev' };
    mixinDeep(target, { retries: 3 });
    assert.deepEqual(target, { retries: 3, mode: 'dev' });
  }]);

  tests.push(['merges multiple sources', () => {
    const target = { a: 1, nested: { x: true } };
    mixinDeep(target, { b: 2, nested: { y: true } }, { c: 3, nested: { z: true } });
    assert.deepEqual(target, { a: 1, b: 2, c: 3, nested: { x: true, y: true, z: true } });
  }]);

  tests.push(['replaces arrays while preserving other nested merges', () => {
    const target = { items: ['a'], meta: { keep: true } };
    mixinDeep(target, { items: ['b', 'c'], meta: { add: true } });
    assert.deepEqual(target, { items: ['b', 'c'], meta: { keep: true, add: true } });
  }]);

  return tests;
}

function runSetValueTests(setValue) {
  const tests = [];

  tests.push(['sets a top-level property', () => {
    const target = {};
    const result = setValue(target, 'name', 'praetorian');
    assert.equal(result, target);
    assert.deepEqual(target, { name: 'praetorian' });
  }]);

  tests.push(['creates nested objects from dot paths', () => {
    const target = {};
    setValue(target, 'agent.status.mode', 'active');
    assert.deepEqual(target, { agent: { status: { mode: 'active' } } });
  }]);

  tests.push(['overwrites an existing nested leaf', () => {
    const target = { config: { retries: 1 } };
    setValue(target, 'config.retries', 4);
    assert.deepEqual(target, { config: { retries: 4 } });
  }]);

  tests.push(['supports array paths', () => {
    const target = {};
    setValue(target, ['artifact', 'type'], 'report');
    assert.deepEqual(target, { artifact: { type: 'report' } });
  }]);

  return tests;
}

function runRequestTests(request) {
  const tests = [];

  tests.push(['allows a direct https request', () => {
    const result = request({ url: 'https://api.example.com/data', redirects: [], allowedProtocols: ['https:'] });
    assert.equal(result.blocked, false);
    assert.equal(result.finalUrl, 'https://api.example.com/data');
  }]);

  tests.push(['follows same-protocol https redirects', () => {
    const result = request({
      url: 'https://api.example.com/data',
      redirects: ['https://cdn.example.com/data'],
      allowedProtocols: ['https:']
    });
    assert.equal(result.blocked, false);
    assert.equal(result.finalUrl, 'https://cdn.example.com/data');
  }]);

  tests.push(['blocks an initial disallowed protocol', () => {
    const result = request({ url: 'http://internal.example', redirects: [], allowedProtocols: ['https:'] });
    assert.equal(result.blocked, true);
    assert.equal(result.reason, 'initial protocol blocked');
  }]);

  tests.push(['returns the final same-protocol redirect cleanly', () => {
    const result = request({
      url: 'https://service.example/start',
      redirects: ['https://service.example/login', 'https://service.example/final'],
      allowedProtocols: ['https:']
    });
    assert.equal(result.finalUrl, 'https://service.example/final');
    assert.equal(result.blocked, false);
  }]);

  return tests;
}

function runNormalTests(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const modulePath = options.modulePath || resolveModulePath(null, targetKey);
  const mod = loadModule(modulePath);
  const tests = targetKey === 'set-value'
    ? runSetValueTests(mod)
    : targetKey === 'request'
      ? runRequestTests(mod)
      : runMixinDeepTests(mod);

  let failures = 0;
  const lines = [];

  for (const [name, testFn] of tests) {
    try {
      testFn();
      lines.push(`PASS: ${name}`);
    } catch (error) {
      failures += 1;
      lines.push(`FAIL: ${name}`);
      lines.push(error.message);
    }
  }

  if (failures === 0) {
    lines.push('ALL NORMAL TESTS PASSED');
  } else {
    lines.push(`${failures} normal test(s) failed`);
  }

  return {
    ok: failures === 0,
    output: lines.join('\n')
  };
}

if (require.main === module) {
  const argv = process.argv.slice(2);
  const targetKey = parseTargetFlag(argv);
  const modulePathArg = argv.find((value, index) => argv[index - 1] !== '--target');
  const result = runNormalTests({
    targetKey,
    modulePath: resolveModulePath(modulePathArg, targetKey)
  });
  console.log(result.output);
  process.exit(result.ok ? 0 : 1);
}

module.exports = {
  runNormalTests
};
