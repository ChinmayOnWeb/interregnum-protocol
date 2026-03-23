'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const MAX_FUZZ_ATTEMPTS = 50;
const TIMEOUT_MS = 2000;

const PAYLOADS = [
  // Prototype Pollution payloads
  `{"__proto__": {"polluted": "yes_master"}}`,
  `{"constructor": {"prototype": {"polluted": "yes_master"}}}`,
  // Command Injection payloads
  `"; touch /tmp/pwned_by_hunter #"`,
  `$(touch /tmp/pwned_by_hunter)`,
  // Path Traversal
  `../../../etc/passwd`,
];

/**
 * Unleashes a fuzzer against the provided module file, attempting to find a 0-day.
 * It does this by creating a temporary script that requires the target and blindly 
 * feeds it malicious payloads trying to trigger prototype pollution or exceptions.
 */
async function unleashHunter(targetDir, mainFile) {
  const targetScript = path.join(targetDir, mainFile || 'index.js');
  
  console.log(`\n[HUNTER] 🕵️‍♂️ Zero-Day Hunter Agent Activated on ${targetScript}`);
  console.log(`[HUNTER] 🎯 Generating adversarial fuzzing matrix...`);

  // We write a dynamic fuzzer script that will be executed in a separate process
  // to avoid crashing our main pipeline.
  const fuzzerScriptPath = path.join(__dirname, '.dynamic_fuzzer.js');
  
  const fuzzerCode = `
const path = require('node:path');
const target = require(path.resolve('${targetScript.replace(/\\/g, '/')}'));

const payloads = ${JSON.stringify(PAYLOADS)};

let found = false;
let successfulPayload = null;

// Clean up any old prototype pollution
delete Object.prototype.polluted;

function attemptFuzz(func, payloadStr) {
  try {
    const payload = payloadStr.startsWith('{') ? JSON.parse(payloadStr) : payloadStr;
    
    // Call with payload as argument 1, 2, or 3
    try { func(payload); } catch(e){}
    try { func({}, payload); } catch(e){}
    try { func({}, 'key', payload); } catch(e){}
    try { func('key', payload); } catch(e){}

    if (Object.prototype.polluted === "yes_master") {
      return true;
    }
  } catch (e) {
    // If it crashes severely, we might log it, but we mainly look for silent exploitation
  }
  return false;
}

function recursiveFuzz(obj) {
  if (typeof obj === 'function') {
    for (const p of payloads) {
      if (attemptFuzz(obj, p)) {
        found = true;
        successfulPayload = p;
        return;
      }
    }
  } else if (typeof obj === 'object' && obj !== null) {
    for (const key of Object.keys(obj)) {
      if (typeof obj[key] === 'function') {
        for (const p of payloads) {
          if (attemptFuzz(obj[key], p)) {
            found = true;
            successfulPayload = p;
            return;
          }
        }
      }
    }
  }
}

recursiveFuzz(target);

if (found) {
  console.log(JSON.stringify({ 
    success: true, 
    vulnerability: 'Prototype Pollution', 
    payload: successfulPayload 
  }));
} else {
  console.log(JSON.stringify({ success: false }));
}
  `;

  await fs.writeFile(fuzzerScriptPath, fuzzerCode, 'utf8');

  try {
    const { stdout } = await execFileAsync('node', [fuzzerScriptPath], { timeout: TIMEOUT_MS });
    const result = JSON.parse(stdout.trim());
    await fs.rm(fuzzerScriptPath, { force: true }).catch(() => {});
    
    if (result.success) {
      console.log(`[HUNTER] 🚨 CRITICAL: 0-DAY DISCOVERED!`);
      console.log(`[HUNTER] 🔪 Payload: ${result.payload}`);
      console.log(`[HUNTER] 🔬 Class: ${result.vulnerability}`);
      return result;
    }
  } catch (err) {
    // Ignore execution errors, it means the package crashed
    await fs.rm(fuzzerScriptPath, { force: true }).catch(() => {});
  }

  console.log(`[HUNTER] 🛡️ No obvious 0-days discovered by heuristic fuzzer.`);
  return { success: false };
}

module.exports = {
  unleashHunter
};
