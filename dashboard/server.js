'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { runExploitTest } = require('../exploit_test');
const { runNormalTests } = require('../normal_tests');
const { verifyRemediation } = require('../verifier');
const { evaluateRun } = require('../eval');
const { writeDemoArtifacts } = require('../demo_mode');
const { runAdversarialTests } = require('../adversarial_tester');
const { TARGETS, getTargetConfig, listAvailableTargets } = require('../target_config');
const { buildCustomTarget, updateCurrentCustomTargetSource } = require('../custom_target');
const { generateDynamicHarness } = require('../dynamic_harness');

const ROOT_DIR = path.join(__dirname, '..');
const STATIC_DIR = __dirname;
const PORT = Number(process.env.PORT || 4173);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.svg': 'image/svg+xml'
};

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === 'POST' && url.pathname === '/api/prepare-target') {
      const body = await readRequestBody(req);
      const parsed = JSON.parse(body || '{}');
      const customTarget = await buildCustomTarget({ input: parsed.input, cve: parsed.cve });
      return sendJson(res, {
        ok: true,
        target: customTarget.key,
        packageName: customTarget.packageName,
        cve: customTarget.cve,
        inputKind: customTarget.inputKind || 'npm'
      });
    }

    if (url.pathname === '/api/dashboard-data') {
      const targetKey = url.searchParams.get('target') || 'mixin-deep';
      const isDemo = targetKey !== 'custom' && Object.prototype.hasOwnProperty.call(TARGETS, targetKey);
      const payload = await buildDashboardData(targetKey, { demo: isDemo });
      return sendJson(res, payload);
    }

    if (url.pathname === '/api/report') {
      return sendFile(res, path.join(ROOT_DIR, 'REMEDIATION_REPORT.md'));
    }

    const filePath = resolveStaticPath(url.pathname);
    return sendFile(res, filePath);
  } catch (error) {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(error.message);
  }
});

server.listen(PORT, () => {
  if (process.env.PROTOCOL_DEBUG === '1') {
    console.log(`Patchline dashboard running at http://localhost:${PORT}`);
  }
});

function resolveStaticPath(pathname) {
  const normalized = pathname === '/' ? '/index.html' : pathname;
  return path.join(STATIC_DIR, normalized.replace(/^\/+/, ''));
}

async function readRequestBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function sendFile(res, filePath) {
  try {
    const data = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }

    throw error;
  }
}

function sendJson(res, payload) {
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload, null, 2));
}

async function buildDashboardData(targetKey, options = {}) {
  let target = getTargetConfig(targetKey);
  if (options.demo) {
    await writeDemoArtifacts(target.key);
  } else if (target.dynamic) {
    const classificationOutput = await require('../classify_vulnerabilities').classifyVulnerabilities({ targetKey: target.key });
    await fs.writeFile(path.join(ROOT_DIR, 'classification_output.json'), `${JSON.stringify(classificationOutput, null, 2)}\n`, 'utf8');
    if (Array.isArray(classificationOutput.findings) && classificationOutput.findings.length > 0) {
      const preferred = classificationOutput.findings.find((finding) => finding.vulnerability_class === target.vulnerableClass) || classificationOutput.findings[0];
      await updateCurrentCustomTargetSource(preferred.file);
      target = getTargetConfig(targetKey);
    }
    await generateDynamicHarness(target.key);
  }

  const beforeExploit = runExploitTest({ expected: 'vulnerable', targetKey: target.key, modulePath: target.vulnerableDir });
  const beforeNormal = runNormalTests({ targetKey: target.key, modulePath: target.vulnerableDir });

  let verification;
  let adversarialResults;
  let evalResults;
  let classificationOutput;
  let analyzerOutput;
  let patchOutput;
  let reportMarkdown;
  let afterExploit;
  let afterNormal;
  let confidenceScore;
  let remediationError = null;

  try {
    verification = await verifyRemediation({ demo: Boolean(options.demo), targetKey: target.key });
    adversarialResults = await runAdversarialTests({ targetKey: target.key });
    evalResults = await evaluateRun({ targetKey: target.key });

    [classificationOutput, analyzerOutput, patchOutput, reportMarkdown] = await Promise.all([
      readJson(path.join(ROOT_DIR, 'classification_output.json')),
      readJson(path.join(ROOT_DIR, 'analyzer_output.json')),
      readJson(path.join(ROOT_DIR, 'patch_output.json')),
      fs.readFile(path.join(ROOT_DIR, 'REMEDIATION_REPORT.md'), 'utf8')
    ]);

    afterExploit = runExploitTest({ expected: 'safe', targetKey: target.key, modulePath: path.join(ROOT_DIR, 'patched-package') });
    afterNormal = runNormalTests({ targetKey: target.key, modulePath: path.join(ROOT_DIR, 'patched-package') });
    confidenceScore = verification.confidence_score;
  } catch (error) {
    remediationError = error;
    classificationOutput = await readJsonOrNull(path.join(ROOT_DIR, 'classification_output.json')) || { findings: [], independent_detection: false, matched_known_cve: false, additional_findings: [] };
    analyzerOutput = await readJsonOrNull(path.join(ROOT_DIR, 'analyzer_output.json')) || { root_cause: 'Analysis completed, but full remediation did not finish for this package.', dangerous_lines: [], patch_strategy: 'Manual review required.' };
    patchOutput = await readJsonOrNull(path.join(ROOT_DIR, 'patch_output.json')) || { patch_diff: '', strategies: [], selected_strategy: '', reasoning: '' };
    reportMarkdown = [
      '# Remediation Summary',
      '',
      'The package was ingested and analyzed, but the automated remediation stage did not complete successfully.',
      '',
      'Error:',
      '',
      String(error && error.message ? error.message : error)
    ].join('\n');
    afterExploit = { ok: false, polluted: false, output: 'Patch generation did not complete, so no patched exploit replay is available yet.' };
    afterNormal = { ok: false, output: 'Patched normal tests were not run because remediation did not complete.' };
    adversarialResults = {
      target: target.key,
      package_name: target.packageName,
      cve: target.cve,
      patch_diff_reviewed: false,
      attempts: [],
      adversarial_tests_run: 0,
      bypasses_found: 0,
      patch_resilience_score: '0%',
      verdict: 'NOT RUN',
      bypasses: []
    };
    confidenceScore = 20;
    evalResults = {
      patch_quality_score: 0,
      speed_score: 0,
      patch_quality_breakdown: {},
      speed: { total_pipeline_time_seconds: 0, per_agent_step_ms: [] },
      reliability_log: { all_succeeded_on_first_try: false, retries_needed: 0, error_log: [String(error && error.message ? error.message : error)], agents: [] }
    };
  }

  return {
    target: target.key,
    packageName: target.packageName,
    cve: target.cve,
    severity: target.severity,
    affectedRange: target.affectedRange,
    statusBefore: 'VULNERABLE',
    statusAfter: !remediationError && afterExploit.ok ? 'REMEDIATED' : 'UNRESOLVED',
    recommendation: !remediationError && beforeExploit.ok && afterExploit.ok && afterNormal.ok ? 'Ready for human review' : 'Needs manual review',
    recommendationCopy: !remediationError && beforeExploit.ok && afterExploit.ok && afterNormal.ok
      ? 'The exploit is blocked, regression tests still pass, and the patch diff is concise enough to review quickly.'
      : 'The package was ingested and analyzed, but automated remediation needs human follow-up before it can be trusted.',
    vulnerabilitySummary: target.dashboardSummary,
    rootCause: analyzerOutput.root_cause,
    dangerousLines: analyzerOutput.dangerous_lines,
    patchStrategy: analyzerOutput.patch_strategy,
    patchDiff: patchOutput.patch_diff,
    scout: {
      findings: classificationOutput.findings || [],
      independentDetection: Boolean(classificationOutput.independent_detection),
      matchedKnownCve: Boolean(classificationOutput.matched_known_cve),
      additionalFindings: classificationOutput.additional_findings || []
    },
    adversarial: adversarialResults,
    striker: {
      strategies: patchOutput.strategies || [],
      selectedStrategy: patchOutput.selected_strategy || '',
      reasoning: remediationError ? `Automated patching stopped: ${String(remediationError.message || remediationError)}` : (patchOutput.reasoning || '')
    },
    beforeExploit,
    beforeNormal,
    afterExploit,
    afterNormal,
    confidenceScore,
    eval: evalResults,
    availableTargets: listAvailableTargets().map((item) => ({
      key: item.key,
      packageName: item.packageName,
      cve: item.cve,
      label: `${item.packageName} (${item.cve})`,
      demoButtonLabel: item.demoButtonLabel
    })),
    baseballCard: buildBaseballCard(target, classificationOutput, adversarialResults, beforeExploit, afterNormal, patchOutput, confidenceScore),
    reportPreview: reportMarkdown.split('\n').slice(0, 44).join('\n')
  };
}

async function readJsonOrNull(filePath) {
  try {
    return await readJson(filePath);
  } catch (_) {
    return null;
  }
}
function buildBaseballCard(target, classificationOutput, adversarialResults, beforeExploit, afterNormal, patchOutput, confidenceScore) {
  return [
    { label: 'CVE', value: target.cve, note: 'Advisory or operator-supplied vulnerability identifier under review' },
    { label: 'Severity', value: target.severity, note: 'Current risk estimate derived from advisory context' },
    { label: 'Scout Match', value: classificationOutput.matched_known_cve ? 'Yes' : 'No', note: 'Independent classifier matched the known vulnerability class before advisory analysis' },
    { label: 'Resilience', value: adversarialResults.patch_resilience_score, note: `${adversarialResults.adversarial_tests_run} hostile attempts against the patch` },
    { label: 'Exploit Reproduced', value: beforeExploit.ok ? 'Yes' : 'No', note: beforeExploit.output },
    { label: 'Patch Generated', value: patchOutput.patch_diff ? 'Yes' : 'No', note: 'A minimal target-specific patch diff was produced' },
    { label: 'Tests Passing', value: afterNormal.ok ? 'PASS' : 'Failed', note: 'Expected package behavior preserved after patch' },
    { label: 'Confidence', value: `${confidenceScore} / 100`, note: 'Decision score derived from exploit, regression, and adversarial evidence' }
  ];
}

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  return JSON.parse(raw);
}


