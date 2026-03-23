'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { DEFAULT_MODEL, callOpenAIJson } = require('./llm_client');
const { analyzeTargetVulnerability } = require('./analyzer');
const { runExploitTest } = require('./exploit_test');
const { runNormalTests } = require('./normal_tests');
const { getTargetConfig, PATCHED_PACKAGE_DIR, parseTargetFlag } = require('./target_config');
const { gatherVulnerabilityIntel, readIntelOutput } = require('./intel_gatherer');
const { writePreparationStatus } = require('./custom_target');

const ANALYZER_OUTPUT_PATH = path.join(__dirname, 'analyzer_output.json');
const PATCH_OUTPUT_PATH = path.join(__dirname, 'patch_output.json');
const PATCH_TIMEOUT_MS = Number(process.env.PATCH_TIMEOUT_MS || 60000);
const PATCH_DESCRIPTION_TIMEOUT_MS = Number(process.env.PATCH_DESCRIPTION_TIMEOUT_MS || 30000);
const PATCH_MAX_TOKENS = Number(process.env.PATCH_MAX_TOKENS || 4000);
const PATCH_HEARTBEAT_MS = Number(process.env.PATCH_HEARTBEAT_MS || 4000);

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

function withTimeout(promise, timeoutMs, label) {
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${timeoutMs}ms.`));
    }, timeoutMs);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTransientPatchError(error) {
  const message = String(error && error.message ? error.message : '').toLowerCase();
  return (
    message.includes('502') ||
    message.includes('503') ||
    message.includes('504') ||
    message.includes('429') ||
    message.includes('timed out') ||
    message.includes('fetch failed') ||
    message.includes('bad gateway') ||
    message.includes('network')
  );
}

function approxTokenCount(text) {
  return Math.ceil(String(text || '').length / 4);
}

function countBraces(line) {
  const opens = (line.match(/\{/g) || []).length;
  const closes = (line.match(/\}/g) || []).length;
  return opens - closes;
}

function looksLikeFunctionStart(line) {
  const text = String(line || '').trim();
  return (
    /^function\b/.test(text) ||
    /^[A-Za-z_$][\w$]*\s*:\s*function\b/.test(text) ||
    /^[A-Za-z_$][\w$]*\s*=\s*(async\s+)?function\b/.test(text) ||
    /^[A-Za-z_$][\w$]*\s*=\s*\([^)]*\)\s*=>\s*\{?/.test(text) ||
    /^(async\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{/.test(text)
  );
}

function extractFunctionName(line) {
  const text = String(line || '').trim();
  let match = text.match(/^function\s+([A-Za-z_$][\w$]*)/);
  if (match) return match[1];
  match = text.match(/^([A-Za-z_$][\w$]*)\s*:\s*function/);
  if (match) return match[1];
  match = text.match(/^([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function/);
  if (match) return match[1];
  match = text.match(/^([A-Za-z_$][\w$]*)\s*=\s*\(/);
  if (match) return match[1];
  match = text.match(/^(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(/);
  return match ? match[1] : 'anonymous';
}

function findPrimaryDangerLine(analyzerOutput) {
  const dangerousLines = Array.isArray(analyzerOutput && analyzerOutput.dangerous_lines) ? analyzerOutput.dangerous_lines : [];
  for (const entry of dangerousLines) {
    const lineNumber = Number(entry && entry.line);
    if (lineNumber > 0) return lineNumber;
  }
  return 1;
}

function findEnclosingFunctionBounds(lines, targetLine) {
  const index = Math.max(0, Math.min(lines.length - 1, Number(targetLine || 1) - 1));

  for (let start = index; start >= Math.max(0, index - 250); start -= 1) {
    const candidate = lines[start];
    if (!candidate.includes('{') || !looksLikeFunctionStart(candidate)) {
      continue;
    }

    let balance = 0;
    let seenOpen = false;
    for (let end = start; end < Math.min(lines.length, start + 600); end += 1) {
      balance += countBraces(lines[end]);
      if (lines[end].includes('{')) seenOpen = true;
      if (seenOpen && balance <= 0) {
        return {
          startLine: start + 1,
          endLine: end + 1,
          functionName: extractFunctionName(candidate)
        };
      }
    }
  }

  return {
    startLine: Number(targetLine),
    endLine: Number(targetLine),
    functionName: 'line-only'
  };
}

function sliceLines(lines, startLine, endLine) {
  return lines.slice(Math.max(0, startLine - 1), Math.min(lines.length, endLine)).join('\n');
}

function buildLineWindow(lines, centerLine, radius) {
  const startLine = Math.max(1, centerLine - radius);
  const endLine = Math.min(lines.length, centerLine + radius);
  return {
    startLine,
    endLine,
    text: sliceLines(lines, startLine, endLine)
  };
}

function trimFixDiff(fixDiff) {
  const lines = String(fixDiff || '').split('\n');
  return lines.slice(0, 220).join('\n');
}

function buildPatchContext(sourceCode, analyzerOutput, intelOutput) {
  const lines = String(sourceCode || '').split('\n');
  const primaryDangerLine = findPrimaryDangerLine(analyzerOutput);
  const bounds = findEnclosingFunctionBounds(lines, primaryDangerLine);
  const functionText = sliceLines(lines, bounds.startLine, bounds.endLine);
  const contextualStart = Math.max(1, bounds.startLine - 30);
  const contextualEnd = Math.min(lines.length, bounds.endLine + 30);
  const contextualText = sliceLines(lines, contextualStart, contextualEnd);

  let selected = {
    mode: 'function-with-context',
    startLine: contextualStart,
    endLine: contextualEnd,
    text: contextualText
  };

  const warnings = [];
  const originalLineCount = contextualEnd - contextualStart + 1;

  if (originalLineCount > 200 || approxTokenCount(selected.text) > PATCH_MAX_TOKENS) {
    selected = {
      mode: 'function-only',
      startLine: bounds.startLine,
      endLine: bounds.endLine,
      text: functionText
    };
    warnings.push(`Context trimmed from ${originalLineCount} to ${bounds.endLine - bounds.startLine + 1} lines`);
  }

  if ((selected.endLine - selected.startLine + 1) > 160 || approxTokenCount(selected.text) > PATCH_MAX_TOKENS) {
    const tightWindow = buildLineWindow(lines, primaryDangerLine, 50);
    selected = {
      mode: 'tight-window',
      startLine: tightWindow.startLine,
      endLine: tightWindow.endLine,
      text: tightWindow.text
    };
    warnings.push(`Context trimmed from ${originalLineCount} to ${tightWindow.endLine - tightWindow.startLine + 1} lines`);
  }

  return {
    sourceLines: lines,
    fullSource: sourceCode,
    targetLine: primaryDangerLine,
    targetFilePath: analyzerOutput && analyzerOutput.target_file_path ? analyzerOutput.target_file_path : null,
    targetFunctionName: bounds.functionName,
    functionStartLine: bounds.startLine,
    functionEndLine: bounds.endLine,
    functionText,
    selectedContext: selected,
    functionOnlyContext: {
      mode: 'function-only',
      startLine: bounds.startLine,
      endLine: bounds.endLine,
      text: functionText
    },
    tightLineContext: {
      mode: 'tight-window',
      startLine: Math.max(1, primaryDangerLine - 50),
      endLine: Math.min(lines.length, primaryDangerLine + 50),
      text: sliceLines(lines, Math.max(1, primaryDangerLine - 50), Math.min(lines.length, primaryDangerLine + 50))
    },
    analyzerRootCause: analyzerOutput && analyzerOutput.root_cause ? analyzerOutput.root_cause : '',
    dangerousLines: Array.isArray(analyzerOutput && analyzerOutput.dangerous_lines) ? analyzerOutput.dangerous_lines : [],
    intelSummary: {
      cwe: intelOutput && intelOutput.cwe ? intelOutput.cwe : null,
      cwe_name: intelOutput && intelOutput.cwe_name ? intelOutput.cwe_name : null,
      fix_commit_url: intelOutput && intelOutput.fix_commit_url ? intelOutput.fix_commit_url : null,
      fix_diff: trimFixDiff(intelOutput && intelOutput.fix_diff ? intelOutput.fix_diff : '')
    },
    warnings
  };
}

function startProgressHeartbeat(target, initialMessage, progress = 94) {
  if (!target || !target.dynamic) {
    return {
      update() {},
      stop() {}
    };
  }

  let message = initialMessage;
  const write = () => writePreparationStatus({
    target: target.key,
    packageName: target.packageName,
    cve: target.cve,
    status: 'running',
    phase: 'remediate',
    progress,
    message
  }).catch(() => {});

  write();
  const interval = setInterval(write, PATCH_HEARTBEAT_MS);

  return {
    update(nextMessage, nextProgress = progress) {
      message = nextMessage;
      progress = nextProgress;
      write();
    },
    stop() {
      clearInterval(interval);
    }
  };
}

function buildPersonaPrompt({ persona, context, target, mode, otherPatches }) {
  let personaInstruction = '';
  if (persona === 'Architect') {
    personaInstruction = 'You are the Architect Agent. Your goal is maximum execution performance, zero overhead, and clean, minimal inline code changes.';
  } else if (persona === 'Cryptographer') {
    personaInstruction = 'You are the Cryptographer Agent. Your goal is absolute defense-in-depth, paranoid prototype-checking, and deep input sanitization.';
  } else if (persona === 'Judge') {
    personaInstruction = 'You are the Judge Agent. You must review the varying patches authored by the Architect and Cryptographer. Synthesize the final mathematically perfect patch that balances performance with impenetrable security.\n\nHere are the candidate patches:\n' + JSON.stringify(otherPatches, null, 2);
  }

  return [
    personaInstruction,
    `Package: ${target.packageName}`,
    `Target file: ${target.sourceRelPath || 'index.js'}`,
    `Target function: ${context.targetFunctionName}`,
    `Target lines: ${context.functionStartLine}-${context.functionEndLine}`,
    `Context mode: ${mode}`,
    `Root cause: ${context.analyzerRootCause}`,
    'Vulnerability intelligence:',
    JSON.stringify(context.intelSummary, null, 2),
    '',
    'Target vulnerable function to patch and return:',
    context.functionText,
    '',
    'Nearby context for orientation only:',
    context.selectedContext.text,
    '',
    'Return strict JSON only with this schema:',
    '{',
    '  "approach": "string",',
    '  "reasoning": "string",',
    '  "patched_function": "string"',
    '}',
    'Patch only the target function/body and return only that function/body.',
  ].join('\n');
}

async function callPatchModel({ prompt, model, timeoutMs, toolName }) {
  return withTimeout(
    callOpenAIJson({ prompt, model, toolName }),
    timeoutMs,
    `${toolName} model call`
  );
}

function normalizePatchedFunction(raw, context) {
  const value = String(raw || '').trim();
  if (!value) return '';

  const selected = String(context.selectedContext.text || '').trim();
  if (value === selected) {
    return context.functionText;
  }

  return value;
}

function replaceFunctionInSource(fullSource, context, patchedFunction) {
  const sourceLines = String(fullSource || '').split('\n');
  const patchLines = String(patchedFunction || '').split('\n');
  const start = Math.max(0, context.functionStartLine - 1);
  const deleteCount = Math.max(0, context.functionEndLine - context.functionStartLine + 1);
  sourceLines.splice(start, deleteCount, ...patchLines);
  return sourceLines.join('\n');
}

function formatDiffLine(prefix, line) {
  return `${prefix}${line}`;
}

function buildUnifiedDiff(target, context, originalFunction, patchedFunction) {
  const oldLines = String(originalFunction || '').split('\n');
  const newLines = String(patchedFunction || '').split('\n');
  const diffLines = [
    `--- a/${target.sourceRelPath || 'index.js'}`,
    `+++ b/${target.sourceRelPath || 'index.js'}`,
    `@@ -${context.functionStartLine},${oldLines.length} +${context.functionStartLine},${newLines.length} @@`
  ];

  oldLines.forEach((line) => diffLines.push(formatDiffLine('-', line)));
  newLines.forEach((line) => diffLines.push(formatDiffLine('+', line)));
  return diffLines.join('\n');
}

function buildManualReviewResult({ target, sourceCode, context, fixDescription, failureReason, warnings, intelOutput }) {
  return {
    target: target.key,
    package_name: target.packageName,
    cve: target.cve,
    strategies: [
      {
        name: 'Manual Review Required',
        approach: fixDescription && fixDescription.approach ? fixDescription.approach : 'Use the analyzer and intelligence artifacts to apply the smallest safe manual fix.',
        score_breakdown: { minimality: 0, safety: 0, convention_match: 0, side_effect_risk: 0 },
        score: 0,
        selected: true
      }
    ],
    selected_strategy: 'Manual Review Required',
    reasoning: [
      failureReason ? `Automated patch generation could not complete: ${failureReason}` : 'Automated patch generation could not complete.',
      fixDescription && fixDescription.reasoning ? fixDescription.reasoning : '',
      Array.isArray(fixDescription && fixDescription.suggested_changes) ? `Suggested changes: ${fixDescription.suggested_changes.join(' | ')}` : ''
    ].filter(Boolean).join(' '),
    patch_diff: '',
    patched_code: sourceCode,
    applied_known_fix_pattern: false,
    manual_review_required: true,
    metadata: {
      attempts: 1,
      retries_needed: 0,
      succeeded_on_first_try: false,
      attempt_log: [{ attempt: 1, success: false, reason: 'manual review required' }],
      addressed_adversarial_findings: false,
      model_attempts: 0,
      fallback_used: true,
      fallback_reason: failureReason,
      fixed_version: intelOutput && intelOutput.fixed_version ? intelOutput.fixed_version : null,
      fix_commit_url: intelOutput && intelOutput.fix_commit_url ? intelOutput.fix_commit_url : null,
      target_function: context.targetFunctionName,
      target_lines: [context.functionStartLine, context.functionEndLine],
      warnings,
      suggested_changes: Array.isArray(fixDescription && fixDescription.suggested_changes) ? fixDescription.suggested_changes : []
    }
  };
}

async function generatePatchWithResilience({ analyzerOutput, sourceCode, model, previousAttempt, target, adversarialFindings, intelOutput, progress }) {
  const context = buildPatchContext(sourceCode, analyzerOutput, intelOutput);
  const warnings = context.warnings.slice();

  warnings.forEach((warning) => {
    console.warn(warning);
  });

  let lastError = null;

  try {
    progress.update('Consortium Debate Initialized. Assembling Architect and Cryptographer...', 95);
    
    // Write debate starting to file
    const debateLogPath = path.join(__dirname, 'debate.jsonl');
    const logDebate = async (msg) => {
      try { await fs.appendFile(debateLogPath, JSON.stringify(msg) + '\\n'); } catch(e){}
    };
    await fs.writeFile(debateLogPath, ''); // clear it
    
    await logDebate({ persona: 'System', message: 'Consortium initialized. Parallel generation starting.' });

    const architectPrompt = buildPersonaPrompt({ persona: 'Architect', context, target, mode: context.selectedContext.mode });
    const cryptoPrompt = buildPersonaPrompt({ persona: 'Cryptographer', context, target, mode: context.selectedContext.mode });

    progress.update('Architect and Cryptographer are generating competing patches concurrently...', 95);
    
    const [archResult, cryptoResult] = await Promise.all([
      callPatchModel({ prompt: architectPrompt, model, timeoutMs: PATCH_TIMEOUT_MS, toolName: 'architect' }).catch(e => ({ error: e.message })),
      callPatchModel({ prompt: cryptoPrompt, model, timeoutMs: PATCH_TIMEOUT_MS, toolName: 'cryptographer' }).catch(e => ({ error: e.message }))
    ]);

    await logDebate({ persona: 'Architect', message: archResult.reasoning || archResult.error || 'Failed to generate patch' });
    await logDebate({ persona: 'Cryptographer', message: cryptoResult.reasoning || cryptoResult.error || 'Failed to generate patch' });

    progress.update('AIs have submitted patches. The Judge is reviewing and synthesizing...', 96);
    
    const judgePrompt = buildPersonaPrompt({ 
      persona: 'Judge', 
      context, target, mode: context.selectedContext.mode, 
      otherPatches: { Architect: archResult, Cryptographer: cryptoResult } 
    });

    const judgeResult = await callPatchModel({ prompt: judgePrompt, model, timeoutMs: PATCH_TIMEOUT_MS, toolName: 'judge' });
    await logDebate({ persona: 'Judge', message: judgeResult.reasoning || 'Final verdict issued.' });

    const patchedFunction = normalizePatchedFunction(judgeResult.patched_function, context);
    if (!patchedFunction) throw new Error('Judge returned empty patched_function.');

    const patchedCode = replaceFunctionInSource(sourceCode, context, patchedFunction);
    return {
      result: {
        strategies: [
          {
            name: 'Consortium Synthesis (Judge Approved)',
            approach: judgeResult.approach || 'Balanced performance and security.',
            score_breakdown: { minimality: 25, safety: 25, convention_match: 25, side_effect_risk: 25 },
            score: 100,
            selected: true
          }
        ],
        selected_strategy: 'Consortium Synthesis (Judge Approved)',
        reasoning: judgeResult.reasoning || 'Synthesized the best elements from the Architect and Cryptographer.',
        patch_diff: buildUnifiedDiff(target, context, context.functionText, patchedFunction),
        patched_code: patchedCode,
        patched_function: patchedFunction,
        target_function: context.targetFunctionName,
        target_lines: [context.functionStartLine, context.functionEndLine],
        warnings
      },
      model_attempts: 1,
      fallback_used: false,
      fallback_reason: '',
      context
    };
  } catch (error) {
    lastError = error;
  }

  return {
    result: buildManualReviewResult({
      target,
      sourceCode,
      context,
      fixDescription: null,
      failureReason: lastError ? lastError.message : 'Unknown model failure',
      warnings,
      intelOutput
    }),
    model_attempts: attempts.length,
    fallback_used: true,
    fallback_reason: lastError ? lastError.message : 'Unknown model failure',
    context
  };
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

  if (!Array.isArray(analyzerOutput.dangerous_lines) || analyzerOutput.dangerous_lines.length === 0) {
    return {
      target: target.key,
      package_name: target.packageName,
      cve: target.cve,
      strategies: [{ name: 'No-Op', approach: 'No vulnerabilities found.', score: 0, selected: true }],
      selected_strategy: 'No-Op',
      reasoning: 'System is clean.',
      patch_diff: '',
      patched_code: sourceCode,
      applied_known_fix_pattern: false,
      metadata: { attempts: 0, retries_needed: 0, succeeded_on_first_try: true }
    };
  }

  const adversarialFindings = options.adversarialFindings || [];
  const existingIntel = await readIntelOutput();
  const intelOutput = options.intelOutput || (existingIntel && existingIntel.package === target.packageName
    ? existingIntel
    : await gatherVulnerabilityIntel({ targetKey }));

  const progress = startProgressHeartbeat(target, 'Extracting vulnerable code section...', 94);
  let previousAttempt = null;
  const attemptLog = [];

  try {
    progress.update('Extracting vulnerable code section...', 94);
    progress.update('Querying known fix from intelligence data...', 95);

    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const patchGeneration = await generatePatchWithResilience({
        analyzerOutput,
        sourceCode,
        model,
        previousAttempt,
        target,
        adversarialFindings,
        intelOutput,
        progress
      });

      const patchResult = patchGeneration.result;
      const patchedCode = patchResult.patched_code || '';

      if (patchResult.manual_review_required) {
        await writePatchedPackage(targetKey, patchedCode || sourceCode);
        return {
          ...patchResult,
          metadata: {
            ...patchResult.metadata,
            attempts: attempt,
            retries_needed: attempt - 1,
            model_attempts: patchGeneration.model_attempts,
            fallback_used: patchGeneration.fallback_used,
            fallback_reason: patchGeneration.fallback_reason,
            addressed_adversarial_findings: adversarialFindings.length > 0
          }
        };
      }

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
        progress.update('Retrying with reduced context...', 96);
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
          patched_function: patchResult.patched_function || '',
          target_function: patchResult.target_function || 'unknown',
          target_lines: patchResult.target_lines || [],
          applied_known_fix_pattern: Boolean(intelOutput && intelOutput.fix_diff),
          metadata: {
            attempts: attempt,
            retries_needed: attempt - 1,
            succeeded_on_first_try: attempt === 1,
            attempt_log: attemptLog.concat({ attempt, success: true, reason: 'validation passed' }),
            addressed_adversarial_findings: adversarialFindings.length > 0,
            model_attempts: patchGeneration.model_attempts,
            fallback_used: patchGeneration.fallback_used,
            fallback_reason: patchGeneration.fallback_reason,
            fixed_version: intelOutput && intelOutput.fixed_version ? intelOutput.fixed_version : null,
            fix_commit_url: intelOutput && intelOutput.fix_commit_url ? intelOutput.fix_commit_url : null,
            context_mode: patchGeneration.context && patchGeneration.context.selectedContext ? patchGeneration.context.selectedContext.mode : 'unknown',
            warnings: patchResult.warnings || []
          }
        };
      }

      attemptLog.push({
        attempt,
        success: false,
        reason: 'validation failed',
        fallback_used: patchGeneration.fallback_used,
        exploit_output: validation.exploitOutput,
        normal_test_output: validation.normalTestOutput
      });
      previousAttempt = {
        exploitOutput: validation.exploitOutput,
        normalTestOutput: validation.normalTestOutput
      };
      progress.update('Retrying with reduced context...', 96);
    }
  } finally {
    progress.stop();
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
  hasRequiredGuards,
  validatePatchedPackage,
  generatePatchWithResilience,
  buildPatchContext,
  PATCH_OUTPUT_PATH,
  PATCHED_PACKAGE_DIR
};
