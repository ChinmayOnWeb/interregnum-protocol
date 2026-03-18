# Remediation Report

## Vulnerability Summary

`CVE-2019-10746` affects `mixin-deep` before version 1.3.2 and version 2.0.0. The vulnerable merge logic can be abused with a `constructor -> prototype` payload to pollute `Object.prototype`.

Source summary:

> CVE-2019-10746 Description: mixin-deep is vulnerable to Prototype Pollution in versions before 1.3.2 and version 2.0.0. The function mixin-deep could be tricked into adding or modifying properties of Object.prototype

## Root Cause Analysis

The vulnerable merge logic only blocks the "__proto__" key at the current property level. When attacker-controlled input uses the path constructor -> prototype -> polluted, the code reads this["constructor"] from the target object, which resolves to the built-in Object constructor. The recursive mixin then descends into Object.prototype and writes attacker data there, polluting every plain object.

### Dangerous Code Path

- Line 24: `if (key === '__proto__') {` - This guard is incomplete because it ignores the constructor/prototype prototype-pollution path.
- Line 28: `var obj = this[key];` - Reading this["constructor"] resolves to Object, which gives the attacker access to Object.prototype during recursion.
- Line 30: `mixinDeep(obj, val);` - Recursive descent continues into the inherited constructor/prototype chain and writes attacker-controlled properties.

## Patch

```diff
--- a/index.js
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
+}
```

## Test Results Before and After

### Before Patch

- Exploit test: PASS (vulnerability reproduced)
- Normal functionality tests: PASS

```text
VULNERABLE: prototype pollution confirmed
```

```text
PASS: merges nested objects
PASS: overwrites leaf values
PASS: merges multiple sources
PASS: replaces arrays while preserving other nested merges
ALL NORMAL TESTS PASSED
```

### After Patch

- Exploit test: PASS (prototype pollution blocked)
- Normal functionality tests: PASS

```text
SAFE: prototype pollution blocked
```

```text
PASS: merges nested objects
PASS: overwrites leaf values
PASS: merges multiple sources
PASS: replaces arrays while preserving other nested merges
ALL NORMAL TESTS PASSED
```

## Patch Strategy

Reject dangerous keys before any read or recursive merge happens. Add a shared unsafe-key check that returns true for "__proto__", "constructor", and "prototype", and short-circuit the copy operation for those keys. Keep the rest of the merge behavior unchanged.

## Adversarial Hardening

- Patch resilience score: 100%
- Verdict: HARDENED
- Bypasses found: 0

- nested __proto__ payload: BLOCKED
- constructor.prototype payload: BLOCKED
- Object.defineProperty __proto__ payload: BLOCKED
- unicode encoded __proto__ key: BLOCKED
- recursive constructor chain: BLOCKED
- array based prototype vector: BLOCKED
- double recursive pollution attempt: BLOCKED
- array path inside nested object: BLOCKED

## Confidence Score

**100/100**

Scoring factors:
- vulnerability reproduced on the vulnerable build
- exploit blocked on the patched build
- normal behavior preserved
- analyzer identified specific dangerous lines
- patch diff was generated
- adversarial retesting found no bypasses

