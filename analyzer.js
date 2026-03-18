'use strict';

const fs = require('node:fs/promises');
const { DEFAULT_MODEL, callOpenAIJson, extractOutputText } = require('./openai_client');
const { getTargetConfig, parseTargetFlag } = require('./target_config');

const ANALYZER_OUTPUT_PATH = require('node:path').join(__dirname, 'analyzer_output.json');

async function readInputs(targetKey) {
  const target = getTargetConfig(targetKey);
  const [cveDescription, sourceCode] = await Promise.all([
    fs.readFile(target.cvePath, 'utf8'),
    fs.readFile(target.sourcePath, 'utf8')
  ]);

  return { cveDescription, sourceCode, target };
}

function addLineNumbers(sourceCode) {
  return sourceCode
    .split('\n')
    .map((line, index) => `${index + 1}: ${line}`)
    .join('\n');
}

function buildPrompt(cveDescription, sourceCode, target) {
  return [
    'You are a security code analysis agent.',
    `Analyze the vulnerability for package ${target.packageName} in ecosystem ${target.ecosystem}.`,
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
    'SOURCE FILE (with 1-based line numbers):',
    addLineNumbers(sourceCode)
  ].join('\n');
}

async function analyzeTargetVulnerability(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const model = options.model || DEFAULT_MODEL;
  const { cveDescription, sourceCode, target } = await readInputs(targetKey);
  const prompt = buildPrompt(cveDescription, sourceCode, target);

  const result = await callOpenAIJson({
    prompt,
    model,
    toolName: 'analyzer'
  });

  return {
    target: target.key,
    package_name: target.packageName,
    cve: target.cve,
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
