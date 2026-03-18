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

/**
 * Copy properties from the source object to the target object.
 *
 * This intentionally mirrors the vulnerable pre-1.3.2 behavior:
 * it blocks only "__proto__", leaving the constructor/prototype path open.
 */
function copy(val, key) {
  if (key === '__proto__') {
    return;
  }

  var obj = this[key];
  if (isObject(val) && isObject(obj)) {
    mixinDeep(obj, val);
  } else {
    this[key] = val;
  }
}

function isObject(val) {
  return isExtendable(val) && !Array.isArray(val);
}

module.exports = mixinDeep;
