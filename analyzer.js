'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { DEFAULT_MODEL, callOpenAIJson, extractOutputText } = require('./llm_client');
const { getTargetConfig, parseTargetFlag } = require('./target_config');
const { createContentSignature, readCachedArtifact } = require('./cache_utils');
const { gatherVulnerabilityIntel, readIntelOutput, INTEL_OUTPUT_PATH } = require('./intel_gatherer');

const ANALYZER_OUTPUT_PATH = path.join(__dirname, 'analyzer_output.json');

async function readInputs(targetKey) {
  const target = getTargetConfig(targetKey);
  const [cveDescription, sourceCode, existingIntel] = await Promise.all([
    fs.readFile(target.cvePath, 'utf8'),
    fs.readFile(target.sourcePath, 'utf8'),
    readIntelOutput()
  ]);

  const intelOutput = existingIntel && existingIntel.package === target.packageName
    ? existingIntel
    : await gatherVulnerabilityIntel({ targetKey });

  return { cveDescription, sourceCode, target, intelOutput };
}

function addLineNumbers(sourceCode) {
  return sourceCode
    .split('\n')
    .map((line, index) => `${index + 1}: ${line}`)
    .join('\n');
}

function buildPrompt(cveDescription, sourceCode, target, intelOutput) {
  return [
    'You are a security code analysis agent.',
    `Analyze the vulnerability for package ${target.packageName} in ecosystem ${target.ecosystem}.`,
    'Use the vulnerability intelligence package to ground the analysis in known upstream facts whenever it is relevant.',
    'Explain the root cause, identify the exact dangerous code path, and suggest a minimal patch strategy.',
    'Return strict JSON with this schema:',
    '{',
    '  "root_cause": "string",',
    '  "dangerous_lines": [',
    '    { "line": number, "code": "string", "reason": "string" }',
    '  ],',
    '  "patch_strategy": "string"',
    '}',
    'Do not include markdown fences or any extra commentary.',
    '',
    'CVE DESCRIPTION:',
    cveDescription,
    '',
    'VULNERABILITY INTELLIGENCE:',
    JSON.stringify(intelOutput, null, 2),
    '',
    'SOURCE FILE (with 1-based line numbers):',
    addLineNumbers(sourceCode)
  ].join('\n');
}

async function analyzeTargetVulnerability(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const model = options.model || DEFAULT_MODEL;
  const { cveDescription, sourceCode, target, intelOutput } = await readInputs(targetKey);
  const signature = await createContentSignature([
    'analyzer-v3',
    model,
    target.key,
    target.packageName,
    target.cve,
    target.sourceRelPath || '',
    cveDescription,
    JSON.stringify(intelOutput || {}),
    sourceCode
  ]);

  const cached = await readCachedArtifact(ANALYZER_OUTPUT_PATH, signature);
  if (cached) {
    return cached;
  }

  const prompt = buildPrompt(cveDescription, sourceCode, target, intelOutput);

  const result = await callOpenAIJson({
    prompt,
    model,
    toolName: 'analyzer'
  });

  return {
    signature,
    target: target.key,
    package_name: target.packageName,
    cve: target.cve,
    intel_path: INTEL_OUTPUT_PATH,
    cwe: intelOutput && intelOutput.cwe ? intelOutput.cwe : null,
    cwe_name: intelOutput && intelOutput.cwe_name ? intelOutput.cwe_name : null,
    known_fix_files: Array.isArray(intelOutput && intelOutput.fix_files_changed) ? intelOutput.fix_files_changed : [],
    root_cause: result.root_cause,
    dangerous_lines: Array.isArray(result.dangerous_lines) ? result.dangerous_lines : [],
    patch_strategy: result.patch_strategy
  };
}

async function main() {
  try {
    const targetKey = parseTargetFlag(process.argv.slice(2));
    const result = await analyzeTargetVulnerability({ targetKey });
    await fs.writeFile(ANALYZER_OUTPUT_PATH, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Analyzer failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  analyzeTargetVulnerability,
  analyzeMixinDeepVulnerability: analyzeTargetVulnerability,
  buildPrompt,
  extractOutputText,
  ANALYZER_OUTPUT_PATH
};
