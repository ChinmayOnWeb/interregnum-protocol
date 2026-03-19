'use strict';

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
