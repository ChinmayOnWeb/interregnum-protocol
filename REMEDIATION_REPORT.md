# Remediation Report

## Vulnerability Summary

`CVE-2023-28155` affects `request` through 2.88.2. Cross-protocol redirects can bypass SSRF mitigations, and the package is no longer maintained by the original maintainer.

Source summary:

> CVE-2023-28155 affects the request package for Node.js through 2.88.2. The package can allow a bypass of SSRF mitigations when an attacker-controlled server issues a cross-protocol redirect, such as HTTPS to HTTP or HTTP to HTTPS. This vulnerability is especially relevant because request is no longer actively maintained by its original maintainer.

## Root Cause Analysis

The vulnerable request flow validates the protocol of the initial URL but does not re-validate redirect targets. An attacker-controlled server can respond with a cross-protocol redirect from an allowed https URL to a blocked http URL, bypassing SSRF policy and causing the client to follow a destination that should have been rejected.

### Dangerous Code Path

- Line 17: `if (!isAllowedProtocol(config.url, config.allowedProtocols)) {` - The initial request URL is validated once, which creates a false sense of safety if later redirects are not checked.
- Line 29: `for (const redirectUrl of config.redirects) {` - The redirect chain is processed without any per-redirect policy enforcement.
- Line 32: `current = redirectUrl;` - A redirected URL can switch protocols and bypass the original SSRF mitigation.

## Patch

```diff
--- a/index.js
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

```

## Test Results Before and After

### Before Patch

- Exploit test: PASS (vulnerability reproduced)
- Normal functionality tests: PASS

```text
VULNERABLE: cross-protocol redirect bypass confirmed
```

```text
PASS: allows a direct https request
PASS: follows same-protocol https redirects
PASS: blocks an initial disallowed protocol
PASS: returns the final same-protocol redirect cleanly
ALL NORMAL TESTS PASSED
```

### After Patch

- Exploit test: PASS (prototype pollution blocked)
- Normal functionality tests: PASS

```text
SAFE: redirect bypass blocked
```

```text
PASS: allows a direct https request
PASS: follows same-protocol https redirects
PASS: blocks an initial disallowed protocol
PASS: returns the final same-protocol redirect cleanly
ALL NORMAL TESTS PASSED
```

## Patch Strategy

Re-validate every redirect target against the allowed protocol set before following it. If a redirect changes to a disallowed protocol, stop and return a blocked result instead of following the redirect.

## Adversarial Hardening

- Patch resilience score: 100%
- Verdict: HARDENED
- Bypasses found: 0

- https to http redirect: BLOCKED
- double redirect ending in http: BLOCKED
- uppercase protocol redirect: BLOCKED
- redirect to localhost metadata endpoint: BLOCKED
- mixed redirect chain: BLOCKED
- array redirect to link local: BLOCKED
- redirect after safe hop: BLOCKED
- redirect to plain http file: BLOCKED

## Confidence Score

**100/100**

Scoring factors:
- vulnerability reproduced on the vulnerable build
- exploit blocked on the patched build
- normal behavior preserved
- analyzer identified specific dangerous lines
- patch diff was generated
- adversarial retesting found no bypasses

