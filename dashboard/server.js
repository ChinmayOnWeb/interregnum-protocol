require('../env_loader');

'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { WebSocketServer } = require('ws');
const { runExploitTest } = require('../exploit_test');
const { runNormalTests } = require('../normal_tests');
const { verifyRemediation } = require('../verifier');
const { evaluateRun } = require('../eval');
const { writeDemoArtifacts } = require('../demo_mode');
const { runAdversarialTests } = require('../adversarial_tester');
const { TARGETS, getTargetConfig, listAvailableTargets } = require('../target_config');
const { buildCustomTarget, readPreparationStatus, updateCurrentCustomTargetSource, writePreparationStatus } = require('../custom_target');
const { generateDynamicHarness } = require('../dynamic_harness');
const { createAuthMiddleware } = require('../auth');
const { insertRun, listRuns, getRun, getRunCount } = require('../db');

let createRemediationPR;
try { createRemediationPR = require('../github_pr').createRemediationPR; } catch (_) { createRemediationPR = null; }

const ROOT_DIR = path.join(__dirname, '..');
const STATIC_DIR = __dirname;
const PORT = Number(process.env.PORT || 4173);
const authMiddleware = createAuthMiddleware();

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

// --- Active WebSocket clients ---
const wsClients = new Set();

function broadcast(message) {
  const payload = typeof message === 'string' ? message : JSON.stringify(message);
  for (const client of wsClients) {
    if (client.readyState === 1) {
      try { client.send(payload); } catch (_) { /* ignore */ }
    }
  }
}

function wsProgress(agent, status, message, extra = {}) {
  broadcast({ type: 'agent_progress', agent, status, message, timestamp: Date.now(), ...extra });
}

// --- Server ---
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    
    // Cross-Origin Isolation for WebContainers
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');

    // Auth check
    const authResult = authMiddleware(req, url);
    if (!authResult.ok) {
      res.writeHead(authResult.status || 401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: authResult.message }));
      return;
    }

    // --- API Routes ---

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

    if (url.pathname === '/api/prepare-status') {
      const status = await readPreparationStatus();
      return sendJson(res, status || {
        status: 'idle', phase: 'idle',
        message: 'No custom target preparation is currently running.',
        progress: 0, target: 'custom'
      });
    }

    if (url.pathname === '/api/dashboard-data') {
      const targetKey = url.searchParams.get('target') || 'mixin-deep';
      const isDemo = targetKey !== 'custom' && Object.prototype.hasOwnProperty.call(TARGETS, targetKey);
      const payload = await buildDashboardData(targetKey, { demo: isDemo });

      // Persist to SQLite
      try {
        insertRun({
          target: payload.target,
          packageName: payload.packageName,
          cve: payload.cve,
          mode: isDemo ? 'demo' : 'live',
          startedAt: new Date().toISOString(),
          finishedAt: new Date().toISOString(),
          status: payload.statusAfter === 'REMEDIATED' ? 'complete' : 'partial',
          confidenceScore: payload.confidenceScore || 0,
          resilienceScore: payload.adversarial ? payload.adversarial.patch_resilience_score : '0%',
          patchQualityScore: payload.eval ? payload.eval.patch_quality_score : 0,
          speedScore: payload.eval ? payload.eval.speed_score : 0,
          fullPayload: payload
        });
      } catch (_) { /* DB insert failure is non-fatal */ }

      broadcast({ type: 'complete', payload });
      return sendJson(res, payload);
    }

    if (url.pathname === '/api/report') {
      return sendFile(res, path.join(ROOT_DIR, 'REMEDIATION_REPORT.md'));
    }

    if (url.pathname === '/api/debate') {
      try {
        const debateRaw = await fs.readFile(path.join(ROOT_DIR, 'debate.jsonl'), 'utf8');
        const lines = debateRaw.split('\\n').filter(Boolean).map(line => {
          try { return JSON.parse(line); } catch(e) { return null; }
        }).filter(Boolean);
        return sendJson(res, { transcript: lines });
      } catch (e) {
        return sendJson(res, { transcript: [] });
      }
    }

    // --- Run History API ---
    if (url.pathname === '/api/runs') {
      const limit = Number(url.searchParams.get('limit') || 50);
      const offset = Number(url.searchParams.get('offset') || 0);
      return sendJson(res, { runs: listRuns({ limit, offset }), total: getRunCount() });
    }

    if (url.pathname.startsWith('/api/runs/')) {
      const runId = url.pathname.replace('/api/runs/', '');
      const run = getRun(runId);
      if (!run) { res.writeHead(404); res.end('Not found'); return; }
      return sendJson(res, run);
    }

    // --- GitHub PR API ---
    if (req.method === 'POST' && url.pathname === '/api/create-pr') {
      if (!createRemediationPR) {
        return sendJson(res, { error: 'GitHub PR module not available' }, 500);
      }
      const body = await readRequestBody(req);
      const parsed = JSON.parse(body || '{}');
      try {
        const result = await createRemediationPR(parsed);
        return sendJson(res, { ok: true, ...result });
      } catch (err) {
        return sendJson(res, { error: err.message }, 400);
      }
    }

    // --- Benchmark API ---
    if (url.pathname === '/api/benchmark') {
      return sendJson(res, { runs: listRuns({ limit: 200 }), total: getRunCount() });
    }

    // --- Static file serving ---
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return sendFile(res, path.join(__dirname, 'index.html'));
    }
    if (url.pathname === '/benchmark') {
      return sendFile(res, path.join(__dirname, 'benchmark.html'));
    }
    if (url.pathname === '/styles.css') {
      res.setHeader('Content-Type', 'text/css');
      return sendFile(res, path.join(__dirname, 'styles.css'));
    }
    if (url.pathname === '/app.js') {
      res.setHeader('Content-Type', 'application/javascript');
      return sendFile(res, path.join(__dirname, 'app.js'));
    }

    const filePath = resolveStaticPath(url.pathname);
    return sendFile(res, filePath);
  } catch (error) {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(error.message);
  }
});

// --- WebSocket upgrade ---
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  if (url.pathname === '/ws') {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wsClients.add(ws);
      ws.on('close', () => wsClients.delete(ws));
      ws.on('error', () => wsClients.delete(ws));
      ws.send(JSON.stringify({ type: 'connected', message: 'WebSocket connected to Interregnum Protocol' }));
    });
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`Patchline dashboard running at http://localhost:${PORT}`);
});

// --- Helpers ---

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

function sendJson(res, payload, statusCode = 200) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload, null, 2));
}

async function updatePreparationProgress(target, phase, progress, message, status = 'running', extra = {}) {
  if (!target || !target.dynamic) return;
  const current = (await readPreparationStatus()) || {};
  await writePreparationStatus({
    ...current, ...extra, status, phase, progress, message,
    target: target.key,
    packageName: extra.packageName || target.packageName || current.packageName || '',
    cve: extra.cve || target.cve || current.cve || ''
  });
  wsProgress(phase, status, message);
}

async function buildDashboardData(targetKey, options = {}) {
  let target = getTargetConfig(targetKey);
  if (options.demo) {
    wsProgress('scout', 'running', `Loading demo artifacts for ${target.packageName}`);
    await writeDemoArtifacts(target.key);
  } else if (target.dynamic) {
    wsProgress('scout', 'running', `Scout is classifying ${target.packageName}`);
    await updatePreparationProgress(target, 'classify', 86, `Scout is classifying ${target.packageName}`);
    const classificationOutput = await require('../classify_vulnerabilities').classifyVulnerabilities({ targetKey: target.key });
    await fs.writeFile(path.join(ROOT_DIR, 'classification_output.json'), `${JSON.stringify(classificationOutput, null, 2)}\n`, 'utf8');
    if (Array.isArray(classificationOutput.findings) && classificationOutput.findings.length > 0) {
      const preferred = classificationOutput.findings.find((finding) => finding.vulnerability_class === target.vulnerableClass) || classificationOutput.findings[0];
      await updateCurrentCustomTargetSource(preferred.file);
      target = getTargetConfig(targetKey);
    }
    wsProgress('harness', 'running', `Generating exploit and regression harness for ${target.packageName}`);
    await updatePreparationProgress(target, 'harness', 90, `Generating exploit and regression harness for ${target.packageName}`);
    await generateDynamicHarness(target.key);
  }

  wsProgress('spotter', 'running', `Analyzing vulnerable code paths in ${target.packageName}`);
  const beforeExploit = runExploitTest({ expected: 'vulnerable', targetKey: target.key, modulePath: target.vulnerableDir });
  const beforeNormal = runNormalTests({ targetKey: target.key, modulePath: target.vulnerableDir });

  let verification, adversarialResults, evalResults, classificationOutput, analyzerOutput, patchOutput;
  let reportMarkdown, afterExploit, afterNormal, confidenceScore;
  let remediationError = null;

  try {
    wsProgress('striker', 'running', `Running remediation pipeline for ${target.packageName}`);
    await updatePreparationProgress(target, 'remediate', 94, `Running remediation pipeline for ${target.packageName}`);
    verification = await verifyRemediation({ demo: Boolean(options.demo), targetKey: target.key });

    wsProgress('adversary', 'running', `Adversarial retesting in progress for ${target.packageName}`);
    await updatePreparationProgress(target, 'adversarial', 97, `Adversarial retesting in progress for ${target.packageName}`);
    adversarialResults = await runAdversarialTests({ targetKey: target.key });

    wsProgress('debrief', 'running', `Scoring patch quality and reliability for ${target.packageName}`);
    await updatePreparationProgress(target, 'eval', 99, `Scoring patch quality and reliability for ${target.packageName}`);
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
    await updatePreparationProgress(target, 'ready', 100, `Remediation results are ready for ${target.packageName}`, 'complete');
    wsProgress('debrief', 'complete', `Protocol completed for ${target.packageName}`);
  } catch (error) {
    remediationError = error;
    classificationOutput = await readJsonOrNull(path.join(ROOT_DIR, 'classification_output.json')) || { findings: [], independent_detection: false, matched_known_cve: false, additional_findings: [] };
    analyzerOutput = await readJsonOrNull(path.join(ROOT_DIR, 'analyzer_output.json')) || { root_cause: 'Analysis completed, but full remediation did not finish for this package.', dangerous_lines: [], patch_strategy: 'Manual review required.' };
    patchOutput = await readJsonOrNull(path.join(ROOT_DIR, 'patch_output.json')) || { patch_diff: '', strategies: [], selected_strategy: '', reasoning: '' };
    reportMarkdown = ['# Remediation Summary', '', 'The package was ingested and analyzed, but the automated remediation stage did not complete successfully.', '', 'Error:', '', String(error && error.message ? error.message : error)].join('\n');
    afterExploit = { ok: false, polluted: false, output: 'Patch generation did not complete.' };
    afterNormal = { ok: false, output: 'Patched normal tests were not run.' };
    adversarialResults = { target: target.key, package_name: target.packageName, cve: target.cve, patch_diff_reviewed: false, attempts: [], adversarial_tests_run: 0, bypasses_found: 0, patch_resilience_score: '0%', verdict: 'NOT RUN', bypasses: [] };
    confidenceScore = 20;
    evalResults = { patch_quality_score: 0, speed_score: 0, patch_quality_breakdown: {}, speed: { total_pipeline_time_seconds: 0, per_agent_step_ms: [] }, reliability_log: { all_succeeded_on_first_try: false, retries_needed: 0, error_log: [String(error && error.message ? error.message : error)], agents: [] } };
    await updatePreparationProgress(target, 'failed', 100, `Automated remediation needs manual review for ${target.packageName}`, 'error', { error: String(error && error.message ? error.message : error) });
    wsProgress('debrief', 'error', `Remediation encountered an issue for ${target.packageName}`);
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
    repoUrl: target.repoUrl || null,
    sourceRelPath: target.sourceRelPath || null,
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
      key: item.key, packageName: item.packageName, cve: item.cve,
      label: `${item.packageName} (${item.cve})`,
      demoButtonLabel: item.demoButtonLabel
    })),
    baseballCard: buildBaseballCard(target, classificationOutput, adversarialResults, beforeExploit, afterNormal, patchOutput, confidenceScore),
    reportPreview: reportMarkdown.split('\n').slice(0, 44).join('\n')
  };
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

async function readJsonOrNull(filePath) {
  try { return await readJson(filePath); } catch (_) { return null; }
}

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  return JSON.parse(raw);
}
