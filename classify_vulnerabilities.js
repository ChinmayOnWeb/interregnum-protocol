'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { DEFAULT_MODEL, callOpenAIJson } = require('./openai_client');
const { getTargetConfig, parseTargetFlag } = require('./target_config');

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

async function readSourceBundle(targetKey) {
  const target = getTargetConfig(targetKey);
  const files = await listSourceFiles(target.vulnerableDir);
  const contents = await Promise.all(files.map(async (filePath) => {
    const raw = await fs.readFile(filePath, 'utf8');
    return {
      file: path.relative(__dirname, filePath).replace(/\\/g, '/'),
      content: addLineNumbers(raw)
    };
  }));

  return { target, files: contents };
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

async function classifyVulnerabilities(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const model = options.model || DEFAULT_MODEL;
  const bundle = await readSourceBundle(targetKey);
  const result = await callOpenAIJson({
    prompt: buildPrompt(bundle),
    model,
    toolName: 'scout classifier'
  });

  const findings = Array.isArray(result.findings) ? result.findings.map(normalizeFinding) : [];
  const comparison = compareAgainstKnownCve(bundle.target, findings);

  return {
    target: bundle.target.key,
    package_name: bundle.target.packageName,
    cve: bundle.target.cve,
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
