'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { runExploitTest } = require('./exploit_test');
const { runNormalTests } = require('./normal_tests');
const { getTargetConfig, PATCHED_PACKAGE_DIR, parseTargetFlag } = require('./target_config');

const ROOT_DIR = __dirname;
const PATCH_OUTPUT_PATH = path.join(ROOT_DIR, 'patch_output.json');
const ANALYZER_OUTPUT_PATH = path.join(ROOT_DIR, 'analyzer_output.json');
const PIPELINE_RUN_PATH = path.join(ROOT_DIR, 'pipeline_run.json');
const ADVERSARIAL_RESULTS_PATH = path.join(ROOT_DIR, 'adversarial_results.json');
const EVAL_RESULTS_PATH = path.join(ROOT_DIR, 'eval_results.json');

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

function getChangedLineCount(diffText) {
  if (!diffText) return 0;
  return diffText.split('\n').filter((line) => (line.startsWith('+') || line.startsWith('-')) && !line.startsWith('+++') && !line.startsWith('---')).length;
}

function scoreLinesChanged(changedLines) {
  if (changedLines <= 6) return 20;
  if (changedLines >= 20) return 0;
  return Math.max(0, Math.round(20 * (1 - (changedLines - 6) / 14)));
}

function getAddedCodeLines(diffText) {
  if (!diffText) return [];
  return diffText
    .split('\n')
    .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
    .map((line) => line.slice(1))
    .filter((line) => line.trim() !== '' && !line.trim().startsWith('*') && !line.trim().startsWith('//'));
}

function scoreConventionMatch(sourceCode, patchedCode, diffText) {
  const addedLines = getAddedCodeLines(diffText);
  if (addedLines.length === 0) return 0;

  let score = 0;
  const sourceUsesVar = /\bvar\s+\w+/.test(sourceCode);
  const patchedUsesVar = /\bvar\s+\w+/.test(patchedCode);
  const sourceUsesSingleQuotes = (sourceCode.match(/'/g) || []).length >= (sourceCode.match(/"/g) || []).length;
  const singleQuoteAdded = addedLines.filter((line) => line.includes("'")).length;
  const doubleQuoteAdded = addedLines.filter((line) => line.includes('"')).length;
  const semicolonFriendly = addedLines.filter((line) => /[)\]\w'"]\s*;$/u.test(line.trim()) || /[{}]$/u.test(line.trim()));
  const indentFriendly = addedLines.filter((line) => line.match(/^\s*/u)[0].length % 2 === 0);

  if (sourceUsesVar && patchedUsesVar) score += 5;
  if (sourceUsesSingleQuotes && singleQuoteAdded >= doubleQuoteAdded) score += 5;
  score += Math.round(4 * (semicolonFriendly.length / addedLines.length));
  score += Math.round(3 * (indentFriendly.length / addedLines.length));
  if (/function\s+isUnsafeKey\s*\(/.test(patchedCode)) score += 3;

  return Math.min(score, 20);
}

function scoreDependencySafety(sourceCode, patchedCode) {
  const sourceRequires = sourceCode.match(/require\(/g) || [];
  const patchedRequires = patchedCode.match(/require\(/g) || [];
  const sourceImports = sourceCode.match(/import\s+/g) || [];
  const patchedImports = patchedCode.match(/import\s+/g) || [];
  return patchedRequires.length <= sourceRequires.length && patchedImports.length <= sourceImports.length ? 10 : 0;
}

function normalizeStepName(stepName) {
  switch (stepName) {
    case 'analysis': return 'Analyzer';
    case 'patch': return 'Patcher';
    case 'verify': return 'Verifier';
    case 'adversarial': return 'Adversarial Tester';
    default: return stepName;
  }
}

function buildReliabilityLog(pipelineRun) {
  if (!pipelineRun || !Array.isArray(pipelineRun.steps)) {
    return { all_succeeded_on_first_try: false, retries_needed: 0, error_log: ['No pipeline_run.json found.'], agents: [] };
  }

  const agents = pipelineRun.steps.map((step) => ({
    agent: normalizeStepName(step.name),
    success: Boolean(step.success),
    attempts: step.attempts || 1,
    succeeded_on_first_try: (step.attempts || 1) === 1 && Boolean(step.success),
    retries_needed: Math.max(0, (step.attempts || 1) - 1),
    duration_ms: step.duration_ms || 0,
    error: step.error || null
  }));

  return {
    all_succeeded_on_first_try: agents.every((agent) => agent.succeeded_on_first_try),
    retries_needed: agents.reduce((sum, agent) => sum + agent.retries_needed, 0),
    error_log: agents.filter((agent) => agent.error).map((agent) => `${agent.agent}: ${agent.error}`),
    agents
  };
}

function computeSpeedScore(totalTimeMs) {
  const totalSeconds = totalTimeMs / 1000;
  if (totalSeconds <= 5) return 100;
  if (totalSeconds >= 60) return 35;
  return Math.round(100 - ((totalSeconds - 5) / 55) * 65);
}

async function evaluateRun(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const target = getTargetConfig(targetKey);
  const [sourceCode, patchedCode, patchOutput, analyzerOutput, pipelineRun, adversarialResults] = await Promise.all([
    fs.readFile(target.sourcePath, 'utf8'),
    fs.readFile(path.join(PATCHED_PACKAGE_DIR, target.sourceRelPath || 'index.js'), 'utf8'),
    readJsonOrNull(PATCH_OUTPUT_PATH),
    readJsonOrNull(ANALYZER_OUTPUT_PATH),
    readJsonOrNull(PIPELINE_RUN_PATH),
    readJsonOrNull(ADVERSARIAL_RESULTS_PATH)
  ]);

  const beforeExploit = runExploitTest({ expected: 'vulnerable', targetKey, modulePath: target.vulnerableDir });
  const afterExploit = runExploitTest({ expected: 'safe', targetKey, modulePath: PATCHED_PACKAGE_DIR });
  const beforeNormal = runNormalTests({ targetKey, modulePath: target.vulnerableDir });
  const afterNormal = runNormalTests({ targetKey, modulePath: PATCHED_PACKAGE_DIR });

  const patchDiff = patchOutput ? patchOutput.patch_diff || '' : '';
  const changedLines = getChangedLineCount(patchDiff);
  const patchQualityBreakdown = {
    lines_changed: { points: scoreLinesChanged(changedLines), max_points: 20, changed_lines: changedLines },
    convention_match: { points: scoreConventionMatch(sourceCode, patchedCode, patchDiff), max_points: 20 },
    no_new_dependencies: { points: scoreDependencySafety(sourceCode, patchedCode), max_points: 10 },
    vulnerability_fully_blocked: { points: beforeExploit.ok && afterExploit.ok ? 30 : 0, max_points: 30 },
    no_test_regressions: { points: beforeNormal.ok && afterNormal.ok ? 20 : 0, max_points: 20 }
  };

  const patchQualityScore = Object.values(patchQualityBreakdown).reduce((sum, item) => sum + item.points, 0);
  const totalTimeMs = pipelineRun && typeof pipelineRun.total_duration_ms === 'number' ? pipelineRun.total_duration_ms : 0;
  const speedScore = computeSpeedScore(totalTimeMs);
  const reliabilityLog = buildReliabilityLog(pipelineRun);

  const evalResults = {
    target: target.key,
    package_name: target.packageName,
    cve: target.cve,
    generated_at: new Date().toISOString(),
    patch_quality_score: patchQualityScore,
    patch_quality_breakdown: patchQualityBreakdown,
    speed_score: speedScore,
    speed: {
      total_pipeline_time_ms: totalTimeMs,
      total_pipeline_time_seconds: Number((totalTimeMs / 1000).toFixed(2)),
      per_agent_step_ms: (pipelineRun && Array.isArray(pipelineRun.steps) ? pipelineRun.steps : []).map((step) => ({
        agent: normalizeStepName(step.name),
        duration_ms: step.duration_ms || 0,
        duration_seconds: Number(((step.duration_ms || 0) / 1000).toFixed(2))
      }))
    },
    reliability_log: reliabilityLog,
    adversarial: adversarialResults && adversarialResults.target === targetKey ? {
      adversarial_tests_run: adversarialResults.adversarial_tests_run,
      bypasses_found: adversarialResults.bypasses_found,
      patch_resilience_score: adversarialResults.patch_resilience_score,
      verdict: adversarialResults.verdict
    } : null,
    verification_snapshot: {
      exploit_before: beforeExploit,
      exploit_after: afterExploit,
      normal_tests_before: beforeNormal,
      normal_tests_after: afterNormal
    },
    metadata: {
      analyzer_present: Boolean(analyzerOutput),
      patch_present: Boolean(patchOutput)
    }
  };

  await fs.writeFile(EVAL_RESULTS_PATH, `${JSON.stringify(evalResults, null, 2)}\n`, 'utf8');
  return evalResults;
}

async function main() {
  try {
    const targetKey = parseTargetFlag(process.argv.slice(2));
    const results = await evaluateRun({ targetKey });
    console.log(JSON.stringify(results, null, 2));
  } catch (error) {
    console.error(`Eval failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  evaluateRun,
  EVAL_RESULTS_PATH,
  PIPELINE_RUN_PATH
};
