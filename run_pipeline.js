'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { classifyVulnerabilities, CLASSIFICATION_OUTPUT_PATH } = require('./classify_vulnerabilities');
const { gatherVulnerabilityIntel, INTEL_OUTPUT_PATH } = require('./intel_gatherer');
const { analyzeTargetVulnerability, ANALYZER_OUTPUT_PATH } = require('./analyzer');
const { patchTarget, PATCH_OUTPUT_PATH } = require('./patcher');
const { verifyRemediation } = require('./verifier');
const { runAdversarialTests, ADVERSARIAL_RESULTS_PATH } = require('./adversarial_tester');
const { runExploitTest } = require('./exploit_test');
const { runNormalTests } = require('./normal_tests');
const { writeDemoArtifacts } = require('./demo_mode');
const { evaluateRun, PIPELINE_RUN_PATH } = require('./eval');
const { getTargetConfig, parseTargetFlag, parseInputFlag, parseCveFlag } = require('./target_config');
const { buildCustomTarget, updateCurrentCustomTargetSource } = require('./custom_target');
const { generateDynamicHarness } = require('./dynamic_harness');

function hasDemoFlag(argv) {
  return argv.includes('--demo');
}

function printSection(title) {
  console.log(`\n=== ${title} ===`);
}

async function writeJson(filePath, value) {
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function runTimedStep(runState, stepName, fn) {
  const startedAt = Date.now();
  const stepRecord = { name: stepName, started_at: new Date(startedAt).toISOString(), success: false, attempts: 1 };
  try {
    const result = await fn();
    const endedAt = Date.now();
    stepRecord.success = true;
    stepRecord.finished_at = new Date(endedAt).toISOString();
    stepRecord.duration_ms = endedAt - startedAt;
    stepRecord.attempts = result && typeof result.attempts === 'number' ? result.attempts : 1;
    if (result && result.metadata) stepRecord.metadata = result.metadata;
    runState.steps.push(stepRecord);
    return result;
  } catch (error) {
    const endedAt = Date.now();
    stepRecord.finished_at = new Date(endedAt).toISOString();
    stepRecord.duration_ms = endedAt - startedAt;
    stepRecord.error = error.message;
    if (error && typeof error.attempts === 'number') stepRecord.attempts = error.attempts;
    runState.steps.push(stepRecord);
    runState.error_log.push(`${stepName}: ${error.message}`);
    await persistRunState(runState);
    throw error;
  }
}

async function persistRunState(runState) {
  const now = Date.now();
  runState.last_updated_at = new Date(now).toISOString();
  runState.total_duration_ms = now - runState.started_at_ms;
  await writeJson(PIPELINE_RUN_PATH, {
    mode: runState.mode,
    target: runState.target,
    package_name: runState.package_name,
    cve: runState.cve,
    started_at: runState.started_at,
    finished_at: runState.finished_at || null,
    total_duration_ms: runState.total_duration_ms,
    steps: runState.steps,
    error_log: runState.error_log
  });
}

function printTestResult(title, result) {
  printSection(title);
  console.log(result.output);
}

async function resolveTargetFromArgs(argv) {
  const input = parseInputFlag(argv);
  const cve = parseCveFlag(argv);
  if (input) {
    const customTarget = await buildCustomTarget({ input, cve });
    await generateDynamicHarness(customTarget.key);
    return customTarget.key;
  }
  return parseTargetFlag(argv);
}

async function main() {
  const argv = process.argv.slice(2);
  const demo = hasDemoFlag(argv);
  const targetKey = await resolveTargetFromArgs(argv);
  const target = getTargetConfig(targetKey);
  const runState = {
    mode: demo ? 'demo' : 'live',
    target: target.key,
    package_name: target.packageName,
    cve: target.cve,
    started_at: new Date().toISOString(),
    started_at_ms: Date.now(),
    finished_at: null,
    steps: [],
    error_log: []
  };

  try {
    const beforeExploit = runExploitTest({ expected: 'vulnerable', targetKey, modulePath: target.vulnerableDir });
    printTestResult(`Before Patch: Exploit Test (${target.packageName})`, beforeExploit);

    let analyzerOutput = null;
    let patchOutput = null;
    let intelOutput = null;

    await runTimedStep(runState, 'intel', async () => {
      printSection(demo ? 'Vulnerability Intel (demo mode)' : 'Vulnerability Intel');
      intelOutput = await gatherVulnerabilityIntel({ targetKey });
      await writeJson(INTEL_OUTPUT_PATH, intelOutput);
      console.log(JSON.stringify(intelOutput, null, 2));
      return {
        attempts: 1,
        metadata: {
          cwe: intelOutput.cwe,
          fixed_version: intelOutput.fixed_version,
          fix_commit_url: intelOutput.fix_commit_url
        }
      };
    });

    await runTimedStep(runState, 'scout', async () => {
      printSection(demo ? 'Scout Classification (demo mode)' : 'Scout Classification');
      if (demo) {
        const demoArtifacts = await writeDemoArtifacts(targetKey);
        await writeJson(CLASSIFICATION_OUTPUT_PATH, demoArtifacts.classificationOutput);
        console.log(JSON.stringify(demoArtifacts.classificationOutput, null, 2));
        return { attempts: 1, metadata: { source: 'demo', findings: Array.isArray(demoArtifacts.classificationOutput.findings) ? demoArtifacts.classificationOutput.findings.length : 0, independent_detection: Boolean(demoArtifacts.classificationOutput.independent_detection) } };
      }

      const classificationOutput = await classifyVulnerabilities({ targetKey });
      if (target.dynamic && Array.isArray(classificationOutput.findings) && classificationOutput.findings.length > 0) {
        const preferred = classificationOutput.findings.find((finding) => finding.vulnerability_class === target.vulnerableClass) || classificationOutput.findings[0];
        await updateCurrentCustomTargetSource(preferred.file);
      }
      await writeJson(CLASSIFICATION_OUTPUT_PATH, classificationOutput);
      console.log(JSON.stringify(classificationOutput, null, 2));
      return { attempts: 1, metadata: { findings: Array.isArray(classificationOutput.findings) ? classificationOutput.findings.length : 0, independent_detection: Boolean(classificationOutput.independent_detection) } };
    });

    await runTimedStep(runState, 'analysis', async () => {
      printSection(demo ? 'Spotter Analysis (demo mode)' : 'Spotter Analysis');
      if (demo) {
        const demoArtifacts = await writeDemoArtifacts(targetKey);
        analyzerOutput = demoArtifacts.analyzerOutput;
        await writeJson(ANALYZER_OUTPUT_PATH, analyzerOutput);
        console.log(JSON.stringify(analyzerOutput, null, 2));
        return { attempts: 1, metadata: { source: 'demo', target: target.key } };
      }

      analyzerOutput = await analyzeTargetVulnerability({ targetKey });
      await writeJson(ANALYZER_OUTPUT_PATH, analyzerOutput);
      console.log(JSON.stringify(analyzerOutput, null, 2));
      return { attempts: 1, metadata: { dangerous_lines: Array.isArray(analyzerOutput.dangerous_lines) ? analyzerOutput.dangerous_lines.length : 0 } };
    });

    await runTimedStep(runState, 'patch', async () => {
      printSection(demo ? 'Striker Patch (demo mode)' : 'Striker Patch');
      if (demo) {
        const demoArtifacts = await writeDemoArtifacts(targetKey);
        patchOutput = demoArtifacts.patchOutput;
        await writeJson(PATCH_OUTPUT_PATH, patchOutput);
        console.log(patchOutput.patch_diff);
        return { attempts: 1, metadata: { validation_passed: true, target: target.key } };
      }

      patchOutput = await patchTarget({ targetKey, analyzerOutput, intelOutput });
      await writeJson(PATCH_OUTPUT_PATH, patchOutput);
      console.log(patchOutput.patch_diff);
      return { attempts: patchOutput.metadata && patchOutput.metadata.attempts ? patchOutput.metadata.attempts : 1, metadata: patchOutput.metadata || {} };
    });

    const afterExploit = runExploitTest({ expected: 'safe', targetKey, modulePath: path.join(__dirname, 'patched-package') });
    printTestResult('After Patch: Exploit Test', afterExploit);

    const normalTests = runNormalTests({ targetKey, modulePath: path.join(__dirname, 'patched-package') });
    printTestResult('After Patch: Normal Tests', normalTests);

    await runTimedStep(runState, 'verify', async () => {
      printSection('Generate Report');
      const verification = await verifyRemediation({ demo, targetKey });
      console.log(JSON.stringify(verification, null, 2));
      return { attempts: 1, metadata: { confidence_score: verification.confidence_score } };
    });

    await runTimedStep(runState, 'adversarial', async () => {
      printSection('Adversarial Hardening');
      let adversarialResults = await runAdversarialTests({ targetKey, patchDiff: patchOutput && patchOutput.patch_diff });
      console.log(JSON.stringify(adversarialResults, null, 2));

      if (!demo && adversarialResults.bypasses_found > 0) {
        printSection('Striker Re-engagement');
        patchOutput = await patchTarget({ targetKey, analyzerOutput, intelOutput, adversarialFindings: adversarialResults.bypasses });
        await writeJson(PATCH_OUTPUT_PATH, patchOutput);
        console.log(patchOutput.patch_diff);
        await verifyRemediation({ demo, targetKey });
        adversarialResults = await runAdversarialTests({ targetKey, patchDiff: patchOutput.patch_diff });
        await writeJson(ADVERSARIAL_RESULTS_PATH, adversarialResults);
        console.log(JSON.stringify(adversarialResults, null, 2));
      }

      return { attempts: adversarialResults.bypasses_found > 0 && !demo ? 2 : 1, metadata: { adversarial_tests_run: adversarialResults.adversarial_tests_run, bypasses_found: adversarialResults.bypasses_found, patch_resilience_score: adversarialResults.patch_resilience_score, verdict: adversarialResults.verdict } };
    });

    await verifyRemediation({ demo, targetKey });

    runState.finished_at = new Date().toISOString();
    await persistRunState(runState);

    printSection('Evaluate Agent Performance');
    const evalResults = await evaluateRun({ targetKey });
    console.log(JSON.stringify(evalResults, null, 2));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

main();
