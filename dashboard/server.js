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
const { TARGETS, getTargetConfig } = require('../target_config');

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

    if (url.pathname === '/api/dashboard-data') {
      const targetKey = url.searchParams.get('target') || 'mixin-deep';
      const payload = await buildDashboardData(targetKey);
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
  console.log(`Patchline dashboard running at http://localhost:${PORT}`);
});

function resolveStaticPath(pathname) {
  const normalized = pathname === '/' ? '/index.html' : pathname;
  return path.join(STATIC_DIR, normalized.replace(/^\/+/, ''));
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

async function buildDashboardData(targetKey) {
  const target = getTargetConfig(targetKey);
  await writeDemoArtifacts(target.key);
  const verification = await verifyRemediation({ demo: true, targetKey: target.key });
  const adversarialResults = await runAdversarialTests({ targetKey: target.key });
  const evalResults = await evaluateRun({ targetKey: target.key });

  const [classificationOutput, analyzerOutput, patchOutput, reportMarkdown] = await Promise.all([
    readJson(path.join(ROOT_DIR, 'classification_output.json')),
    readJson(path.join(ROOT_DIR, 'analyzer_output.json')),
    readJson(path.join(ROOT_DIR, 'patch_output.json')),
    fs.readFile(path.join(ROOT_DIR, 'REMEDIATION_REPORT.md'), 'utf8')
  ]);

  const beforeExploit = runExploitTest({ expected: 'vulnerable', targetKey: target.key, modulePath: target.vulnerableDir });
  const beforeNormal = runNormalTests({ targetKey: target.key, modulePath: target.vulnerableDir });
  const afterExploit = runExploitTest({ expected: 'safe', targetKey: target.key, modulePath: path.join(ROOT_DIR, 'patched-package') });
  const afterNormal = runNormalTests({ targetKey: target.key, modulePath: path.join(ROOT_DIR, 'patched-package') });

  const confidenceScore = verification.confidence_score;

  return {
    target: target.key,
    packageName: target.packageName,
    cve: target.cve,
    severity: target.severity,
    affectedRange: target.affectedRange,
    statusBefore: 'VULNERABLE',
    statusAfter: afterExploit.ok ? 'REMEDIATED' : 'UNRESOLVED',
    recommendation: afterExploit.ok && afterNormal.ok ? 'Ready for human review' : 'Needs more analysis',
    recommendationCopy: afterExploit.ok && afterNormal.ok
      ? 'The exploit is blocked, regression tests still pass, and the patch diff is concise enough to review quickly.'
      : 'The fix has not yet cleared the verification bar for a safe human review.',
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
      reasoning: patchOutput.reasoning || ''
    },
    beforeExploit,
    beforeNormal,
    afterExploit,
    afterNormal,
    confidenceScore,
    eval: evalResults,
    availableTargets: Object.values(TARGETS).map((item) => ({
      key: item.key,
      packageName: item.packageName,
      cve: item.cve,
      label: `${item.packageName} (${item.cve})`,
      demoButtonLabel: item.demoButtonLabel
    })),
    baseballCard: [
      { label: 'CVE', value: target.cve, note: 'Known advisory linked to the code path under review' },
      { label: 'Severity', value: target.severity, note: 'Prototype mutation can taint shared object state' },
      { label: 'Scout Match', value: classificationOutput.matched_known_cve ? 'Yes' : 'No', note: 'Independent classifier matched the known vulnerability class before advisory analysis' },
      { label: 'Resilience', value: adversarialResults.patch_resilience_score, note: `${adversarialResults.adversarial_tests_run} hostile attempts against the patch` },
      { label: 'Exploit Reproduced', value: beforeExploit.ok ? 'Yes' : 'No', note: beforeExploit.output },
      { label: 'Patch Generated', value: patchOutput.patch_diff ? 'Yes' : 'No', note: 'Unsafe keys are guarded before mutation' },
      { label: 'Tests Passing', value: afterNormal.ok ? '4 / 4' : 'Failed', note: 'Expected package behavior preserved after patch' },
      { label: 'Confidence', value: `${confidenceScore} / 100`, note: 'Decision score derived from exploit, regression, and adversarial evidence' }
    ],
    reportPreview: reportMarkdown.split('\n').slice(0, 44).join('\n')
  };
}

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  return JSON.parse(raw);
}
