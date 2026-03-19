'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { analyzeTargetVulnerability, ANALYZER_OUTPUT_PATH } = require('./analyzer');
const { patchTarget, PATCH_OUTPUT_PATH, PATCHED_PACKAGE_DIR } = require('./patcher');
const { runAdversarialTests, ADVERSARIAL_RESULTS_PATH } = require('./adversarial_tester');
const { writeDemoArtifacts } = require('./demo_mode');
const { runExploitTest } = require('./exploit_test');
const { runNormalTests } = require('./normal_tests');
const { getTargetConfig, parseTargetFlag } = require('./target_config');
const { gatherVulnerabilityIntel, readIntelOutput, INTEL_OUTPUT_PATH } = require('./intel_gatherer');

const REPORT_PATH = path.join(__dirname, 'REMEDIATION_REPORT.md');

async function readJsonOrNull(filePath) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function ensureArtifacts(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const target = getTargetConfig(targetKey);

  if (options.demo) {
    return writeDemoArtifacts(targetKey);
  }

  let intelOutput = await readIntelOutput();
  if (!intelOutput || intelOutput.package !== target.packageName) {
    intelOutput = await gatherVulnerabilityIntel({ targetKey });
  }

  let analyzerOutput = await readJsonOrNull(ANALYZER_OUTPUT_PATH);
  if (!analyzerOutput || analyzerOutput.target !== targetKey) {
    analyzerOutput = await analyzeTargetVulnerability({ targetKey });
    await fs.writeFile(ANALYZER_OUTPUT_PATH, `${JSON.stringify(analyzerOutput, null, 2)}\n`, 'utf8');
  }

  let patchOutput = await readJsonOrNull(PATCH_OUTPUT_PATH);
  if (!patchOutput || patchOutput.target !== targetKey) {
    patchOutput = await patchTarget({ analyzerOutput, intelOutput, targetKey });
    await fs.writeFile(PATCH_OUTPUT_PATH, `${JSON.stringify(patchOutput, null, 2)}\n`, 'utf8');
  }

  return { intelOutput, analyzerOutput, patchOutput };
}

async function collectTestResults(targetKey) {
  const target = getTargetConfig(targetKey);
  return {
    beforeExploit: runExploitTest({ expected: 'vulnerable', targetKey, modulePath: target.vulnerableDir }),
    beforeNormal: runNormalTests({ targetKey, modulePath: target.vulnerableDir }),
    afterExploit: runExploitTest({ expected: 'safe', targetKey, modulePath: PATCHED_PACKAGE_DIR }),
    afterNormal: runNormalTests({ targetKey, modulePath: PATCHED_PACKAGE_DIR })
  };
}

function computeConfidenceScore({ analyzerOutput, patchOutput, testResults, adversarialResults }) {
  let score = 0;
  if (testResults.beforeExploit.ok) score += 20;
  if (testResults.beforeExploit.ok && testResults.afterExploit.ok) score += 30;
  if (testResults.beforeNormal.ok) score += 10;
  if (testResults.afterNormal.ok) score += 15;
  if (Array.isArray(analyzerOutput.dangerous_lines) && analyzerOutput.dangerous_lines.length > 0) score += 5;
  if (typeof patchOutput.patch_diff === 'string' && patchOutput.patch_diff.trim() !== '') score += 5;
  if (adversarialResults && adversarialResults.bypasses_found === 0) score += 15;
  return Math.min(score, 100);
}

function summarizeStatus(ok, successLabel, failureLabel) {
  return ok ? successLabel : failureLabel;
}

function formatDangerousLines(lines) {
  if (!Array.isArray(lines) || lines.length === 0) {
    return '- No dangerous lines were identified by the analyzer.';
  }

  return lines.map((entry) => `- Line ${entry.line}: \`${entry.code}\` - ${entry.reason}`).join('\n');
}

function formatAdversarialAttempts(adversarialResults) {
  if (!adversarialResults || !Array.isArray(adversarialResults.attempts)) {
    return '- No adversarial attempts were recorded.';
  }

  return adversarialResults.attempts
    .map((attempt) => `- ${attempt.bypass_name}: ${attempt.result}${attempt.result === 'BYPASSED' ? ' (critical)' : ''}`)
    .join('\n');
}

function buildReport({ target, cveDescription, intelOutput, analyzerOutput, patchOutput, testResults, confidenceScore, adversarialResults }) {
  return `# Remediation Report

## Vulnerability Summary

${target.reportSummary}

Source summary:

> ${cveDescription
    .split('\n')
    .filter((line) => line.trim() !== '')
    .slice(0, 4)
    .join(' ')
    .replace(/>/g, '\\>')}

## Vulnerability Intelligence

- Intel artifact: \`${INTEL_OUTPUT_PATH}\`
- CWE: ${intelOutput && intelOutput.cwe ? `${intelOutput.cwe}${intelOutput.cwe_name ? ` (${intelOutput.cwe_name})` : ''}` : 'Unknown'}
- Known fixed version: ${intelOutput && intelOutput.fixed_version ? intelOutput.fixed_version : 'Unknown'}
- Known fix commit: ${intelOutput && intelOutput.fix_commit_url ? intelOutput.fix_commit_url : 'No known fix commit'}
- Known fix files: ${intelOutput && Array.isArray(intelOutput.fix_files_changed) && intelOutput.fix_files_changed.length > 0 ? intelOutput.fix_files_changed.join(', ') : 'Unknown'}
- Data sources: ${intelOutput && Array.isArray(intelOutput.data_sources) && intelOutput.data_sources.length > 0 ? intelOutput.data_sources.join(', ') : 'None'}

## Root Cause Analysis

${analyzerOutput.root_cause}

### Dangerous Code Path

${formatDangerousLines(analyzerOutput.dangerous_lines)}

## Patch

\`\`\`diff
${patchOutput.patch_diff || '(patch diff unavailable)'}
\`\`\`

## Test Results Before and After

### Before Patch

- Exploit test: ${summarizeStatus(testResults.beforeExploit.ok, 'PASS (vulnerability reproduced)', 'FAIL (could not reproduce vulnerability)')}
- Normal functionality tests: ${summarizeStatus(testResults.beforeNormal.ok, 'PASS', 'FAIL')}

\`\`\`text
${testResults.beforeExploit.output || '(no output)'}
\`\`\`

\`\`\`text
${testResults.beforeNormal.output || '(no output)'}
\`\`\`

### After Patch

- Exploit test: ${summarizeStatus(testResults.afterExploit.ok, 'PASS (exploit blocked)', 'FAIL (exploit still succeeded)')}
- Normal functionality tests: ${summarizeStatus(testResults.afterNormal.ok, 'PASS', 'FAIL')}

\`\`\`text
${testResults.afterExploit.output || '(no output)'}
\`\`\`

\`\`\`text
${testResults.afterNormal.output || '(no output)'}
\`\`\`

## Patch Strategy

${analyzerOutput.patch_strategy}

## Adversarial Hardening

- Patch resilience score: ${adversarialResults ? adversarialResults.patch_resilience_score : 'N/A'}
- Verdict: ${adversarialResults ? adversarialResults.verdict : 'N/A'}
- Bypasses found: ${adversarialResults ? adversarialResults.bypasses_found : 'N/A'}

${formatAdversarialAttempts(adversarialResults)}

## Confidence Score

**${confidenceScore}/100**

Scoring factors:
- vulnerability reproduced on the vulnerable build
- exploit blocked on the patched build
- normal behavior preserved
- analyzer identified specific dangerous lines
- patch diff was generated
- adversarial retesting found no bypasses
`;
}

async function verifyRemediation(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const target = getTargetConfig(targetKey);
  const { intelOutput, analyzerOutput, patchOutput } = await ensureArtifacts(options);
  const [cveDescription, testResults, existingAdversarial] = await Promise.all([
    fs.readFile(target.cvePath, 'utf8'),
    collectTestResults(targetKey),
    readJsonOrNull(ADVERSARIAL_RESULTS_PATH)
  ]);

  const adversarialResults = existingAdversarial && existingAdversarial.target === targetKey && !target.dynamic
    ? existingAdversarial
    : await runAdversarialTests({ targetKey, patchDiff: patchOutput.patch_diff });

  const confidenceScore = computeConfidenceScore({ analyzerOutput, patchOutput, testResults, adversarialResults });
  const report = buildReport({ target, cveDescription, intelOutput, analyzerOutput, patchOutput, testResults, confidenceScore, adversarialResults });
  await fs.writeFile(REPORT_PATH, `${report}\n`, 'utf8');

  return {
    target: target.key,
    package_name: target.packageName,
    cve: target.cve,
    report_path: REPORT_PATH,
    intel_path: INTEL_OUTPUT_PATH,
    confidence_score: confidenceScore,
    test_results: testResults,
    adversarial_results: adversarialResults
  };
}

async function main() {
  try {
    const argv = process.argv.slice(2);
    const result = await verifyRemediation({
      demo: argv.includes('--demo'),
      targetKey: parseTargetFlag(argv)
    });
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Verifier failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  verifyRemediation,
  computeConfidenceScore,
  REPORT_PATH
};
