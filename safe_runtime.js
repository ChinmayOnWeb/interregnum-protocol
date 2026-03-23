'use strict';

const path = require('node:path');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const dns = require('node:dns');

function resolveModulePath(modulePath, requestPath = '.') {
  return requestPath === '.' ? modulePath : path.join(modulePath, requestPath);
}

function requireFresh(modulePath, requestPath = '.') {
  const fullPath = resolveModulePath(modulePath, requestPath);
  const resolved = require.resolve(fullPath);
  delete require.cache[resolved];
  return require(resolved);
}

function patchMethod(target, methodName, replacement, undoStack) {
  const original = target[methodName];
  target[methodName] = replacement;
  undoStack.push(() => {
    target[methodName] = original;
  });
}

function createBlockedRequest(protocol) {
  return function blockedRequest() {
    const error = new Error(`Outbound ${protocol} network access is blocked during dynamic harness execution.`);
    error.code = 'PRAETORIAN_NETWORK_BLOCKED';
    throw error;
  };
}

function withBlockedNetwork(fn) {
  const undoStack = [];
  const blockedHttp = createBlockedRequest('HTTP');
  const blockedHttps = createBlockedRequest('HTTPS');
  const blockedSocket = function blockedSocket() {
    const error = new Error('Socket access is blocked during dynamic harness execution.');
    error.code = 'PRAETORIAN_NETWORK_BLOCKED';
    throw error;
  };
  const blockedDns = function blockedDns() {
    const error = new Error('DNS lookups are blocked during dynamic harness execution.');
    error.code = 'PRAETORIAN_NETWORK_BLOCKED';
    throw error;
  };

  patchMethod(http, 'request', blockedHttp, undoStack);
  patchMethod(http, 'get', blockedHttp, undoStack);
  patchMethod(https, 'request', blockedHttps, undoStack);
  patchMethod(https, 'get', blockedHttps, undoStack);
  patchMethod(net, 'connect', blockedSocket, undoStack);
  patchMethod(net, 'createConnection', blockedSocket, undoStack);
  patchMethod(tls, 'connect', blockedSocket, undoStack);
  if (typeof dns.lookup === 'function') patchMethod(dns, 'lookup', blockedDns, undoStack);
  if (typeof dns.resolve === 'function') patchMethod(dns, 'resolve', blockedDns, undoStack);
  if (typeof dns.resolve4 === 'function') patchMethod(dns, 'resolve4', blockedDns, undoStack);
  if (typeof dns.resolve6 === 'function') patchMethod(dns, 'resolve6', blockedDns, undoStack);

  try {
    return fn();
  } finally {
    while (undoStack.length > 0) {
      undoStack.pop()();
    }
  }
}

function withPatchedModule(moduleName, replacements, fn) {
  const moduleExports = require(moduleName);
  const undoStack = [];
  const entries = replacements && typeof replacements === 'object' ? Object.entries(replacements) : [];

  for (const [methodName, replacement] of entries) {
    if (!Object.prototype.hasOwnProperty.call(moduleExports, methodName)) continue;
    patchMethod(moduleExports, methodName, replacement, undoStack);
  }

  try {
    return fn(moduleExports);
  } finally {
    while (undoStack.length > 0) {
      undoStack.pop()();
    }
  }
}

function executeDynamicScript(script, modulePath, options = {}) {
  const targetSourcePath = options.targetSourcePath || '.';
  const helpers = {
    requireFresh,
    withBlockedNetwork,
    withPatchedModule,
    targetSourcePath,
    resolveModulePath
  };

  const previousMod = globalThis.mod;
  const previousAssert = globalThis.assert;
  const previousHelpers = globalThis.helpers;
  globalThis.mod = requireFresh(modulePath, targetSourcePath === '.' ? '.' : targetSourcePath);
  globalThis.assert = assert;
  globalThis.helpers = helpers;

  try {
    const fakeModule = { exports: {} };
    const runner = new Function('modulePath', 'helpers', 'assert', 'path', 'URL', 'module', 'exports', script);
    let result = runner(modulePath, helpers, assert, path, URL, fakeModule, fakeModule.exports);
    
    // Fallback: If the script assigned to module.exports wrapper function instead of returning directly
    if (result === undefined && typeof fakeModule.exports === 'function') {
      result = fakeModule.exports(modulePath, helpers, assert, path, URL);
    } else if (result === undefined && Object.keys(fakeModule.exports).length > 0) {
      result = fakeModule.exports;
    }
    
    return result;
  } finally {
    globalThis.mod = previousMod;
    globalThis.assert = previousAssert;
    globalThis.helpers = previousHelpers;
  }
}

module.exports = {
  requireFresh,
  withBlockedNetwork,
  withPatchedModule,
  executeDynamicScript,
  resolveModulePath
};
