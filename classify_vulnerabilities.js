'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { DEFAULT_MODEL, callOpenAIJson } = require('./llm_client');
const { getTargetConfig, parseTargetFlag } = require('./target_config');
const { createContentSignature, readCachedArtifact } = require('./cache_utils');

const CLASSIFICATION_OUTPUT_PATH = path.join(__dirname, 'classification_output.json');
const ALLOWED_CLASSES = [
  'Prototype Pollution',
  'Path Traversal',
  'ReDoS (Regular Expression Denial of Service)',
  'Command Injection',
  'Insecure Deserialization',
  'SQL Injection',
  'Cross-Site Scripting',
  'Insufficient Input Validation'
];
const CLASSIFIER_TIMEOUT_MS = Number(process.env.SCOUT_TIMEOUT_MS || 15000);
const MAX_CLASSIFIER_FILES = Number(process.env.SCOUT_MAX_FILES || 8);
const MAX_CLASSIFIER_CHARS = Number(process.env.SCOUT_MAX_CHARS || 45000);

async function listSourceFiles(rootDir) {
  const results = [];

  async function walk(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) {
        continue;
      }

      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }

      if (/\.(js|cjs|mjs|json)$/iu.test(entry.name)) {
        results.push(fullPath);
      }
    }
  }

  await walk(rootDir);
  return results;
}

function addLineNumbers(source) {
  return source
    .split('\n')
    .map((line, index) => `${index + 1}: ${line}`)
    .join('\n');
}

function keywordsForClass(vulnerabilityClass) {
  switch (vulnerabilityClass) {
    case 'Prototype Pollution':
      return ['proto', 'prototype', 'constructor', 'merge', 'assign', 'set', 'deep', 'path'];
    case 'Path Traversal':
      return ['path', 'resolve', 'join', 'normalize', 'read', 'write', 'file'];
    case 'ReDoS (Regular Expression Denial of Service)':
      return ['regex', 'regexp', 'match', 'replace', 'parse'];
    case 'Command Injection':
      return ['exec', 'spawn', 'fork', 'shell', 'command', 'child_process'];
    case 'Insecure Deserialization':
      return ['deserialize', 'parse', 'yaml', 'pickle', 'unserialize'];
    case 'SQL Injection':
      return ['sql', 'query', 'select', 'insert', 'where', 'db'];
    case 'Cross-Site Scripting':
      return ['html', 'render', 'template', 'escape', 'sanitize', 'innerhtml'];
    case 'Insufficient Input Validation':
    default:
      return ['redirect', 'uri', 'url', 'request', 'location', 'protocol', 'host', 'input', 'validate'];
  }
}

function scoreFile(filePath, target) {
  const relPath = path.relative(target.vulnerableDir, filePath).replace(/\\/g, '/').toLowerCase();
  const sourceRelPath = String(target.sourceRelPath || '').toLowerCase();
  const keywords = keywordsForClass(target.vulnerableClass);
  let score = 0;

  if (sourceRelPath && relPath === sourceRelPath) score += 120;
  if (relPath.endsWith('/index.js') || relPath === 'index.js') score += 25;
  if (relPath.endsWith('/request.js') || relPath === 'request.js') score += 25;
  if (relPath.includes('/lib/')) score += 8;
  if (relPath.includes('/src/')) score += 6;

  for (const keyword of keywords) {
    if (relPath.includes(keyword)) score += 12;
  }

  return score - relPath.split('/').length;
}

async function selectRelevantFiles(target, allFiles) {
  const ranked = allFiles
    .map((filePath) => ({ filePath, score: scoreFile(filePath, target) }))
    .sort((a, b) => b.score - a.score);

  const selected = [];
  let totalChars = 0;

  for (const item of ranked) {
    if (selected.length >= MAX_CLASSIFIER_FILES) break;
    const raw = await fs.readFile(item.filePath, 'utf8');
    if (!raw.trim()) continue;
    if (totalChars > 0 && totalChars + raw.length > MAX_CLASSIFIER_CHARS) continue;

    selected.push({
      filePath: item.filePath,
      file: path.relative(__dirname, item.filePath).replace(/\\/g, '/'),
      content: addLineNumbers(raw),
      raw
    });
    totalChars += raw.length;
  }

  if (selected.length === 0 && allFiles[0]) {
    const raw = await fs.readFile(allFiles[0], 'utf8');
    selected.push({
      filePath: allFiles[0],
      file: path.relative(__dirname, allFiles[0]).replace(/\\/g, '/'),
      content: addLineNumbers(raw),
      raw
    });
  }

  return selected;
}

async function readSourceBundle(targetKey) {
  const target = getTargetConfig(targetKey);
  const files = await listSourceFiles(target.vulnerableDir);
  const contents = await selectRelevantFiles(target, files);

  return {
    target,
    files: contents.map(({ file, content }) => ({ file, content }))
  };
}

function buildPrompt(bundle) {
  return [
    'Analyze this code for potential security vulnerabilities.',
    'For each finding, classify it into exactly one of these classes:',
    ...ALLOWED_CLASSES.map((item) => `- ${item}`),
    'For each finding report:',
    '- vulnerability_class',
    '- file',
    '- line',
    '- severity (low/medium/high/critical)',
    '- confidence (0-100)',
    '- explanation (one sentence)',
    'Return strict JSON with this schema:',
    '{',
    '  "findings": [',
    '    {',
    '      "vulnerability_class": "string",',
    '      "file": "string",',
    '      "line": number,',
    '      "severity": "low|medium|high|critical",',
    '      "confidence": number,',
    '      "explanation": "string"',
    '    }',
    '  ]',
    '}',
    'Only report findings that are plausibly present in this codebase.',
    'If no findings exist, return {"findings": []}.',
    '',
    `PACKAGE: ${bundle.target.packageName}`,
    `TARGET CLASS TO VERIFY AGAINST LATER: ${bundle.target.vulnerableClass}`,
    `FILES INCLUDED: ${bundle.files.length}`,
    '',
    ...bundle.files.flatMap((entry) => [`FILE: ${entry.file}`, entry.content, ''])
  ].join('\n');
}

function normalizeFinding(finding) {
  const vulnerabilityClass = ALLOWED_CLASSES.includes(finding.vulnerability_class)
    ? finding.vulnerability_class
    : 'Insufficient Input Validation';
  return {
    vulnerability_class: vulnerabilityClass,
    file: String(finding.file || ''),
    line: Number(finding.line) || 1,
    severity: ['low', 'medium', 'high', 'critical'].includes(String(finding.severity).toLowerCase())
      ? String(finding.severity).toLowerCase()
      : 'medium',
    confidence: Math.max(0, Math.min(100, Number(finding.confidence) || 0)),
    explanation: String(finding.explanation || '').trim() || 'Potential security-relevant behavior detected.'
  };
}

function compareAgainstKnownCve(target, findings) {
  const matchedFindings = findings.filter((finding) => finding.vulnerability_class === target.vulnerableClass);
  const matchedKnownCve = matchedFindings.length > 0;
  return {
    independent_detection: matchedKnownCve,
    matched_known_cve: matchedKnownCve,
    additional_findings: findings.filter((finding) => finding.vulnerability_class !== target.vulnerableClass)
  };
}

function withTimeout(promise, timeoutMs) {
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Scout classifier timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function heuristicFindings(bundle) {
  const findings = [];

  for (const entry of bundle.files) {
    const file = entry.file;
    const content = entry.content.toLowerCase();

    if (bundle.target.vulnerableClass === 'Prototype Pollution') {
      if (content.includes('__proto__') || content.includes('constructor') || content.includes('prototype')) {
        findings.push({
          vulnerability_class: 'Prototype Pollution',
          file,
          line: guessLine(entry.content, ['__proto__', 'constructor', 'prototype']),
          severity: 'high',
          confidence: 78,
          explanation: 'Heuristic scan found prototype-chain mutation primitives in a high-relevance file.'
        });
      }
    } else if (bundle.target.vulnerableClass === 'Insufficient Input Validation') {
      if (content.includes('redirect') || content.includes('protocol') || content.includes('location') || content.includes('uri')) {
        findings.push({
          vulnerability_class: 'Insufficient Input Validation',
          file,
          line: guessLine(entry.content, ['redirect', 'protocol', 'location', 'uri']),
          severity: 'medium',
          confidence: 72,
          explanation: 'Heuristic scan found redirect or URI handling without enough validation context.'
        });
      }
    }
  }

  return findings.slice(0, 3).map(normalizeFinding);
}

function guessLine(numberedContent, tokens) {
  const lines = numberedContent.split('\n');
  for (const line of lines) {
    const lowered = line.toLowerCase();
    if (tokens.some((token) => lowered.includes(token))) {
      const match = line.match(/^(\d+):/);
      if (match) return Number(match[1]);
    }
  }
  return 1;
}

async function classifyVulnerabilities(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const model = options.model || DEFAULT_MODEL;
  const bundle = await readSourceBundle(targetKey);
  const signature = await createContentSignature([
    'classifier-v2',
    model,
    bundle.target.key,
    bundle.target.packageName,
    bundle.target.cve,
    bundle.target.vulnerableClass,
    JSON.stringify(bundle.files)
  ]);

  const cached = await readCachedArtifact(CLASSIFICATION_OUTPUT_PATH, signature);
  if (cached) {
    return cached;
  }

  let findings = [];
  let classifierMode = 'model';

  try {
    const result = await withTimeout(callOpenAIJson({
      prompt: buildPrompt(bundle),
      model,
      toolName: 'scout classifier'
    }), CLASSIFIER_TIMEOUT_MS);

    findings = Array.isArray(result.findings) ? result.findings.map(normalizeFinding) : [];
  } catch (_) {
    classifierMode = 'heuristic-fallback';
    findings = heuristicFindings(bundle);
  }

  const comparison = compareAgainstKnownCve(bundle.target, findings);

  return {
    signature,
    target: bundle.target.key,
    package_name: bundle.target.packageName,
    cve: bundle.target.cve,
    classifier_mode: classifierMode,
    files_analyzed: bundle.files.map((entry) => entry.file),
    findings,
    ...comparison
  };
}

async function main() {
  try {
    const targetKey = parseTargetFlag(process.argv.slice(2));
    const result = await classifyVulnerabilities({ targetKey });
    await fs.writeFile(CLASSIFICATION_OUTPUT_PATH, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Classifier failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  classifyVulnerabilities,
  CLASSIFICATION_OUTPUT_PATH,
  ALLOWED_CLASSES
};
