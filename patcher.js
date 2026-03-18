'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { DEFAULT_MODEL, callOpenAIJson } = require('./openai_client');
const { analyzeTargetVulnerability } = require('./analyzer');
const { runExploitTest } = require('./exploit_test');
const { runNormalTests } = require('./normal_tests');
const { getTargetConfig, PATCHED_PACKAGE_DIR, parseTargetFlag } = require('./target_config');

const ANALYZER_OUTPUT_PATH = path.join(__dirname, 'analyzer_output.json');
const PATCH_OUTPUT_PATH = path.join(__dirname, 'patch_output.json');

async function readSourceCode(targetKey) {
  return fs.readFile(getTargetConfig(targetKey).sourcePath, 'utf8');
}

async function readAnalyzerOutput(targetKey, filePath = ANALYZER_OUTPUT_PATH) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return analyzeTargetVulnerability({ targetKey });
    }
    throw error;
  }
}

function buildPatchPrompt({ analyzerOutput, sourceCode, previousAttempt, target, adversarialFindings }) {
  const prototypePollutionTarget = target.vulnerableClass === 'Prototype Pollution';
  const remediationRules = prototypePollutionTarget
    ? [
        'The patch must block prototype pollution through all of these keys:',
        '- __proto__',
        '- constructor',
        '- prototype'
      ]
    : [
        `Remediate the vulnerability class: ${target.vulnerableClass}.`,
        'Close the dangerous code path identified by the analyzer while preserving safe package behavior.'
      ];

  const retryContext = previousAttempt
    ? [
        '',
        'PREVIOUS PATCH ATTEMPT FAILED VALIDATION.',
        `Exploit test stderr/stdout: ${previousAttempt.exploitOutput || '(no output)'}`,
        `Normal test stderr/stdout: ${previousAttempt.normalTestOutput || '(no output)'}`,
        'Generate a safer minimal patch.'
      ].join('\n')
    : '';

  const adversarialContext = Array.isArray(adversarialFindings) && adversarialFindings.length > 0
    ? [
        '',
        'ADVERSARIAL BYPASSES WERE FOUND AGAINST THE PREVIOUS FIX.',
        'The next patch must explicitly address these bypass attempts:',
        JSON.stringify(adversarialFindings, null, 2)
      ].join('\n')
    : '';

  return [
    'You are the Striker patch generation agent.',
    `Patch the vulnerable JavaScript source for package ${target.packageName} with the smallest practical change.`,
    'First propose exactly 3 different fix strategies.',
    'For each strategy, score these dimensions from 0 to 25:',
    '- minimality',
    '- safety',
    '- convention_match',
    '- side_effect_risk',
    'The total score should be the sum of the four dimensions, on a 0-100 scale.',
    'Then choose the best strategy, explain why it wins, and generate the actual patch using that strategy.',
    ...remediationRules,
    'Preserve existing package conventions and keep the patch minimal.',
    'Return strict JSON with this schema:',
    '{',
    '  "strategies": [',
    '    {',
    '      "name": "string",',
    '      "approach": "string",',
    '      "score_breakdown": {',
    '        "minimality": number,',
    '        "safety": number,',
    '        "convention_match": number,',
    '        "side_effect_risk": number',
    '      },',
    '      "score": number,',
    '      "selected": boolean',
    '    }',
    '  ],',
    '  "selected_strategy": "string",',
    '  "reasoning": "string",',
    '  "patch_diff": "string",',
    '  "patched_code": "string"',
    '}',
    'Use exactly 3 strategy objects.',
    'Exactly one strategy must have selected=true.',
    'The selected strategy must have the highest score.',
    `The patch_diff should be a minimal unified diff for ${target.sourceRelPath || 'index.js'} only.`,
    'The patched_code should be the full fixed file contents.',
    'Do not include markdown fences or any extra commentary.',
    '',
    'ANALYZER OUTPUT:',
    JSON.stringify(analyzerOutput, null, 2),
    '',
    'VULNERABLE SOURCE FILE:',
    sourceCode,
    retryContext,
    adversarialContext
  ].join('\n');
}

async function generatePatch({ analyzerOutput, sourceCode, model, previousAttempt, target, adversarialFindings }) {
  return callOpenAIJson({
    prompt: buildPatchPrompt({ analyzerOutput, sourceCode, previousAttempt, target, adversarialFindings }),
    model,
    toolName: 'patcher'
  });
}

function hasRequiredGuards(sourceCode, target) {
  if (target.vulnerableClass !== 'Prototype Pollution') {
    return true;
  }

  return sourceCode.includes('__proto__') && sourceCode.includes('constructor') && sourceCode.includes('prototype');
}

function normalizeStrategies(rawStrategies, selectedStrategyName) {
  const strategies = Array.isArray(rawStrategies) ? rawStrategies.slice(0, 3) : [];
  const normalized = strategies.map((strategy, index) => {
    const breakdown = strategy && strategy.score_breakdown ? strategy.score_breakdown : {};
    const minimality = Number(breakdown.minimality) || 0;
    const safety = Number(breakdown.safety) || 0;
    const conventionMatch = Number(breakdown.convention_match) || 0;
    const sideEffectRisk = Number(breakdown.side_effect_risk) || 0;
    const computedScore = minimality + safety + conventionMatch + sideEffectRisk;

    return {
      name: strategy && strategy.name ? String(strategy.name) : `Strategy ${String.fromCharCode(65 + index)}`,
      approach: strategy && strategy.approach ? String(strategy.approach) : 'No approach provided.',
      score_breakdown: {
        minimality,
        safety,
        convention_match: conventionMatch,
        side_effect_risk: sideEffectRisk
      },
      score: Number(strategy && strategy.score) || computedScore,
      selected: Boolean(strategy && strategy.selected)
    };
  });

  while (normalized.length < 3) {
    normalized.push({
      name: `Strategy ${String.fromCharCode(65 + normalized.length)}`,
      approach: 'No approach provided.',
      score_breakdown: { minimality: 0, safety: 0, convention_match: 0, side_effect_risk: 0 },
      score: 0,
      selected: false
    });
  }

  let bestIndex = 0;
  normalized.forEach((strategy, index) => {
    if (strategy.score > normalized[bestIndex].score) {
      bestIndex = index;
    }
  });

  const preferredIndex = normalized.findIndex((strategy) => strategy.name === selectedStrategyName);
  if (preferredIndex !== -1 && normalized[preferredIndex].score >= normalized[bestIndex].score) {
    bestIndex = preferredIndex;
  }

  return normalized.map((strategy, index) => ({ ...strategy, selected: index === bestIndex }));
}

async function ensurePatchedPackageDir(targetKey) {
  const target = getTargetConfig(targetKey);
  await fs.rm(PATCHED_PACKAGE_DIR, { recursive: true, force: true });
  await fs.mkdir(PATCHED_PACKAGE_DIR, { recursive: true });
  await fs.cp(target.vulnerableDir, PATCHED_PACKAGE_DIR, { recursive: true, force: true });
}

async function writePatchedPackage(targetKey, patchedCode) {
  const target = getTargetConfig(targetKey);
  await ensurePatchedPackageDir(targetKey);
  const patchedSourcePath = path.join(PATCHED_PACKAGE_DIR, target.sourceRelPath || 'index.js');
  await fs.mkdir(path.dirname(patchedSourcePath), { recursive: true });
  await fs.writeFile(patchedSourcePath, patchedCode, 'utf8');
}

async function validatePatchedPackage(targetKey) {
  const exploit = runExploitTest({ expected: 'safe', targetKey, modulePath: PATCHED_PACKAGE_DIR });
  const normal = runNormalTests({ targetKey, modulePath: PATCHED_PACKAGE_DIR });

  return {
    exploitPassed: exploit.ok,
    exploitOutput: exploit.output,
    normalTestsPassed: normal.ok,
    normalTestOutput: normal.output
  };
}

async function patchTarget(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const target = getTargetConfig(targetKey);
  const model = options.model || DEFAULT_MODEL;
  const analyzerOutput = options.analyzerOutput || (await readAnalyzerOutput(targetKey));
  const sourceCode = options.sourceCode || (await readSourceCode(targetKey));
  const adversarialFindings = options.adversarialFindings || [];

  let previousAttempt = null;
  const attemptLog = [];

  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const patchResult = await generatePatch({ analyzerOutput, sourceCode, model, previousAttempt, target, adversarialFindings });
    const patchedCode = patchResult.patched_code || '';
    if (!patchedCode.trim()) {
      const error = new Error('Patcher returned empty patched_code.');
      error.attempts = attempt;
      throw error;
    }

    const strategies = normalizeStrategies(patchResult.strategies, patchResult.selected_strategy);
    const selectedStrategy = strategies.find((strategy) => strategy.selected) || strategies[0];

    if (!hasRequiredGuards(patchedCode, target)) {
      attemptLog.push({ attempt, success: false, reason: 'missing target-specific guards' });
      previousAttempt = {
        exploitOutput: target.vulnerableClass === 'Prototype Pollution'
          ? 'Rejected patch: missing one or more required key guards (__proto__, constructor, prototype).'
          : 'Rejected patch: generated code did not satisfy target-specific validation.',
        normalTestOutput: ''
      };
      continue;
    }

    await writePatchedPackage(targetKey, patchedCode);
    const validation = await validatePatchedPackage(targetKey);

    if (validation.exploitPassed && validation.normalTestsPassed) {
      return {
        target: target.key,
        package_name: target.packageName,
        cve: target.cve,
        strategies,
        selected_strategy: selectedStrategy.name,
        reasoning: patchResult.reasoning || 'Selected for highest combined score and validation success.',
        patch_diff: patchResult.patch_diff,
        patched_code: patchedCode,
        metadata: {
          attempts: attempt,
          retries_needed: attempt - 1,
          succeeded_on_first_try: attempt === 1,
          attempt_log: attemptLog.concat({ attempt, success: true, reason: 'validation passed' }),
          addressed_adversarial_findings: adversarialFindings.length > 0
        }
      };
    }

    attemptLog.push({
      attempt,
      success: false,
      reason: 'validation failed',
      exploit_output: validation.exploitOutput,
      normal_test_output: validation.normalTestOutput
    });
    previousAttempt = {
      exploitOutput: validation.exploitOutput,
      normalTestOutput: validation.normalTestOutput
    };
  }

  const error = new Error('Failed to generate a valid patch after 2 attempts.');
  error.attempts = 2;
  throw error;
}

async function main() {
  try {
    const targetKey = parseTargetFlag(process.argv.slice(2));
    const result = await patchTarget({ targetKey });
    await fs.writeFile(PATCH_OUTPUT_PATH, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Patcher failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  patchTarget,
  patchMixinDeep: patchTarget,
  buildPatchPrompt,
  hasRequiredGuards,
  validatePatchedPackage,
  PATCH_OUTPUT_PATH,
  PATCHED_PACKAGE_DIR
};
