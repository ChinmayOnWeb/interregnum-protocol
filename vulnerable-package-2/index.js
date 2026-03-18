'use strict';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function toSegments(input) {
  if (Array.isArray(input)) {
    return input.slice();
  }

  return String(input).split('.');
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

    if (nested[key] == null || !isObject(nested[key])) {
      nested[key] = {};
    }

    nested = nested[key];
  }

  nested[segments[index]] = value;
  return target;
}

module.exports = setValue;
