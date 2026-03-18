(async function bootstrap() {
  await loadTarget('mixin-deep');
})().catch((error) => {
  console.error(error);
});

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

async function loadTarget(targetKey) {
  const data = await fetchJson(`/api/dashboard-data?target=${encodeURIComponent(targetKey)}`);
  window.__protocolData = data;
  initializeApp(data);
}

function initializeApp(data) {
  const state = window.__protocolState || { target: data.target, repo: '', cve: '' };
  state.target = data.target;
  window.__protocolState = state;
  window.__protocolData = data;

  bindStaticHandlers(state);
  populateTargetSelect(data.availableTargets, data.target);
  updateDemoChips(data.target);
  syncIntakeMode();
  document.getElementById('repo-input').value = state.repo;
  document.getElementById('cve-input').value = state.cve;
  setText('demo-button-label', data.availableTargets.find((item) => item.key === data.target)?.demoButtonLabel || 'Run Demo');

  renderBaseballStats(data.baseballCard);
  renderMetricsDashboard(data);
  renderEvalSummary(data.eval);
  renderScoutSection(data.scout);
  renderAdversarialSection(data.adversarial);
  renderStrategyMatrix(data.striker);
  renderTextSummary(data);
  populateResults(state, data);
  setResultsView('dashboard');
}

function bindStaticHandlers(state) {
  if (window.__handlersBound) return;

  document.getElementById('target-select').addEventListener('change', async (event) => {
    state.target = event.target.value;
    updateDemoChips(state.target);
    setIntakeMode('custom');
    await loadTarget(state.target);
  });

  document.getElementById('load-demo').addEventListener('click', () => {
    setIntakeMode('demo');
    applyDemoTarget(state, 'mixin-deep');
  });

  document.getElementById('mode-demo').addEventListener('click', () => setIntakeMode('demo'));
  document.getElementById('mode-custom').addEventListener('click', () => setIntakeMode('custom'));

  document.querySelectorAll('[data-demo-target]').forEach((chip) => {
    chip.addEventListener('click', () => {
      setIntakeMode('demo');
      applyDemoTarget(state, chip.getAttribute('data-demo-target') || 'mixin-deep');
    });
  });

  document.getElementById('intake-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const data = window.__protocolData;
    const mode = getIntakeMode();
    state.repo = mode === 'demo' ? (document.getElementById('repo-input').value.trim() || data.packageName) : (document.getElementById('repo-input').value.trim() || data.packageName);
    state.cve = document.getElementById('cve-input').value.trim() || data.cve;
    state.target = document.getElementById('target-select').value;
    startProtocol(state, data);
  });

  document.getElementById('show-dashboard').addEventListener('click', () => setResultsView('dashboard'));
  document.getElementById('show-summary').addEventListener('click', () => setResultsView('summary'));
  window.__handlersBound = true;
}

function populateTargetSelect(targets, selectedKey) {
  const select = document.getElementById('target-select');
  const labels = {
    'mixin-deep': 'npm',
    'set-value': 'npm'
  };
  select.innerHTML = '';
  targets.forEach((target) => {
    const option = document.createElement('option');
    option.value = target.key;
    option.textContent = labels[target.key] || target.packageName;
    option.selected = target.key === selectedKey;
    select.appendChild(option);
  });
}

function applyDemoTarget(state, targetKey) {
  const target = (window.__protocolData.availableTargets || []).find((item) => item.key === targetKey) || window.__protocolData.availableTargets[0];
  if (!target) return;
  document.getElementById('target-select').value = target.key;
  document.getElementById('repo-input').value = target.packageName;
  document.getElementById('cve-input').value = target.cve;
  state.target = target.key;
  state.repo = target.packageName;
  state.cve = target.cve;
  updateDemoChips(target.key);
}

function updateDemoChips(activeTarget) {
  document.querySelectorAll('.demo-chip').forEach((chip) => {
    const target = chip.id === 'load-demo' ? 'mixin-deep' : chip.getAttribute('data-demo-target');
    chip.classList.toggle('is-selected', target === activeTarget);
  });
}

function getIntakeMode() {
  return document.getElementById('mode-custom')?.classList.contains('is-active') ? 'custom' : 'demo';
}

function setIntakeMode(mode) {
  const demoActive = mode !== 'custom';
  document.getElementById('mode-demo')?.classList.toggle('is-active', demoActive);
  document.getElementById('mode-demo')?.setAttribute('aria-pressed', String(demoActive));
  document.getElementById('mode-custom')?.classList.toggle('is-active', !demoActive);
  document.getElementById('mode-custom')?.setAttribute('aria-pressed', String(!demoActive));
  document.getElementById('intake-mode-demo')?.classList.toggle('is-active', demoActive);
  document.getElementById('intake-mode-custom')?.classList.toggle('is-active', !demoActive);
}

function syncIntakeMode() {
  const hasCustomInput = Boolean(document.getElementById('repo-input')?.value || document.getElementById('cve-input')?.value);
  setIntakeMode(hasCustomInput ? 'custom' : 'demo');
}

function startProtocol(state, data) {
  showScreen('screen-live');
  setText('top-status', `Running protocol for ${state.repo}`);
  setText('protocol-target', `${state.repo} - ${state.cve}`);

  const feed = document.getElementById('terminal-stream');
  const artifactPreview = document.getElementById('artifact-preview');
  const artifactTitle = document.getElementById('artifact-title');
  const progressFill = document.getElementById('progress-fill');
  const miniStats = document.getElementById('mini-stats');
  const orb = document.querySelector('.console-orb');

  window.__artifactAnimationToken = 0;
  feed.innerHTML = '';
  artifactPreview.textContent = '';
  artifactPreview.classList.remove('is-visible');
  miniStats.innerHTML = '';
  feed.classList.add('is-running');
  feed.classList.remove('is-complete');
  progressFill.style.width = '0%';
  progressFill.classList.add('is-running');
  progressFill.classList.remove('is-complete');
  if (orb) {
    orb.classList.add('is-running');
    orb.classList.remove('is-complete');
  }

  const steps = buildProtocolSteps(state, data);
  const stageNodes = Array.from(document.querySelectorAll('.live-stage'));
  const pipelineNodes = Array.from(document.querySelectorAll('.pipeline-node'));
  stageNodes.forEach((node, index) => {
    node.dataset.duration = String(Math.round((steps[index]?.delay || 0) / 1000 * 10) / 10);
    node.dataset.agent = steps[index]?.agent || '';
  });
  pipelineNodes.forEach((node, index) => {
    node.dataset.agent = steps[index]?.agent || '';
  });

  let delay = 0;
  steps.forEach((step, index) => {
    setTimeout(() => {
      updateStageNodes(stageNodes, index, pipelineNodes, step.agent);
      setText('live-title', step.title);
      setText('progress-status', step.status);
      progressFill.style.width = `${((index + 1) / steps.length) * 100}%`;
      appendTerminalLine(step.line, step.tone || 'dim', feed);
      artifactTitle.textContent = step.artifactTitle;
      animateArtifactPreview(artifactPreview, step.artifact);
      renderMiniStats(step.miniStats);
      setOrbAgent(step.agent);

      if (index === steps.length - 1) {
        setTimeout(() => {
          feed.classList.remove('is-running');
          feed.classList.add('is-complete');
          progressFill.classList.remove('is-running');
          progressFill.classList.add('is-complete');
          if (orb) {
            orb.classList.remove('is-running');
            orb.classList.add('is-complete');
          }
          populateResults(state, data);
          renderBaseballStats(data.baseballCard);
          renderMetricsDashboard(data);
          renderEvalSummary(data.eval);
          renderScoutSection(data.scout);
          renderAdversarialSection(data.adversarial);
          renderStrategyMatrix(data.striker);
          renderTextSummary(data);
          setResultsView('dashboard');
          showScreen('screen-results');
          setText('top-status', `Protocol completed for ${state.repo}`);
        }, 700);
      }
    }, delay);

    delay += step.delay;
  });
}

function prepareLiveExperience() {
  if (window.__livePrepared) return;
  document.querySelectorAll('.live-stage').forEach((node) => {
    const number = node.querySelector('span');
    const textWrap = node.querySelector('div');
    const title = textWrap ? textWrap.querySelector('strong') : null;
    if (number) number.classList.add('live-stage-number');
    if (textWrap) textWrap.classList.add('live-stage-body');
    if (title && !textWrap.querySelector('.live-stage-title-row')) {
      const row = document.createElement('div');
      row.className = 'live-stage-title-row';
      const titleText = document.createElement('span');
      titleText.className = 'live-stage-title-text';
      titleText.textContent = title.textContent;
      const indicator = document.createElement('span');
      indicator.className = 'live-stage-indicator';
      indicator.setAttribute('aria-hidden', 'true');
      const time = document.createElement('span');
      time.className = 'live-stage-time';
      row.append(titleText, indicator, time);
      title.textContent = '';
      title.appendChild(row);
    }
  });
  window.__livePrepared = true;
}

function buildProtocolSteps(state, data) {
  const selected = data.striker && data.striker.selectedStrategy ? data.striker.selectedStrategy : 'selected strategy';
  const scoutMatch = data.scout && data.scout.matchedKnownCve ? 'matched known vulnerability class' : 'did not match known class';
  const scoutFinding = data.scout && data.scout.findings && data.scout.findings[0]
    ? `${data.scout.findings[0].vulnerability_class} in ${data.scout.findings[0].file}:${data.scout.findings[0].line}`
    : 'No scout findings';
  const exploitLine = data.target === 'set-value'
    ? '[Spotter] Located unsafe path traversal through __proto__ segment'
    : '[Spotter] Located recursive merge path into constructor -> prototype chain';
  const adversarialLine = data.adversarial && data.adversarial.bypasses_found === 0
    ? `[Adversary] ${data.adversarial.adversarial_tests_run} hostile payloads blocked. Verdict: ${data.adversarial.verdict}`
    : `[Adversary] ${data.adversarial.bypasses_found} bypasses found. Re-engage Striker.`;

  return [
    {
      agent: 'scout',
      title: 'Scout is classifying the codebase',
      status: 'Scanning source before advisory analysis',
      line: `[Scout] ${scoutFinding} - ${scoutMatch}`,
      artifactTitle: 'Scout findings',
      artifact: formatScoutPreview(data.scout),
      miniStats: [
        `${data.scout.findings.length} findings classified`,
        data.scout.matchedKnownCve ? 'Independent detection confirmed' : 'No class match yet'
      ],
      delay: 950,
      tone: 'accent'
    },
    {
      agent: 'spotter',
      title: 'Spotter is tracing the dangerous path',
      status: 'Explaining exploitability',
      line: exploitLine,
      artifactTitle: 'Root cause summary',
      artifact: data.rootCause,
      miniStats: ['Dangerous lines identified', `${data.dangerousLines.length} code locations tagged`],
      delay: 1150,
      tone: 'accent'
    },
    {
      agent: 'striker',
      title: 'Striker generated and scored multiple fix strategies',
      status: 'Ranking candidate remediations',
      line: `[Striker] Scored 3 candidate fixes. Selected: ${selected}`,
      artifactTitle: 'Strategy matrix',
      artifact: formatStrategyPreview(data.striker),
      miniStats: ['3 strategies scored', `Winner: ${selected}`],
      delay: 1200,
      tone: 'accent'
    },
    {
      agent: 'validator',
      title: 'Validator is replaying exploit and regression tests',
      status: 'Checking post-patch integrity',
      line: `[Validator] ${data.afterExploit.output} | ${data.afterNormal.ok ? 'Normal tests passing' : 'Normal tests failed'}`,
      artifactTitle: 'Verification output',
      artifact: `${data.beforeExploit.output}

${data.afterExploit.output}

${data.afterNormal.output}`,
      miniStats: ['Exploit replay complete', `Regression status: ${data.afterNormal.ok ? '4 / 4 passed' : 'failed'}`],
      delay: 1300,
      tone: 'accent'
    },
    {
      agent: 'adversary',
      title: 'Adversary is attacking the patch',
      status: 'Looking for bypass payloads',
      line: adversarialLine,
      artifactTitle: 'Adversarial hardening',
      artifact: formatAdversarialPreview(data.adversarial),
      miniStats: [`${data.adversarial.adversarial_tests_run} attacks replayed`, `Resilience ${data.adversarial.patch_resilience_score}`],
      delay: 1150,
      tone: 'accent'
    },
    {
      agent: 'debrief',
      title: 'Debrief package assembled',
      status: 'Preparing operator outputs',
      line: '[Debrief] Dashboard and detailed fix summary are ready.',
      artifactTitle: 'Operator recommendation',
      artifact: `${data.recommendation}

${data.recommendationCopy}`,
      miniStats: [`Confidence ${data.confidenceScore} / 100`, 'Ready for operator review'],
      delay: 900,
      tone: 'accent'
    }
  ];
}

function setOrbAgent(agent) {
  const orb = document.querySelector('.console-orb');
  if (!orb) return;
  orb.dataset.agent = agent || 'idle';
}

function animateArtifactPreview(element, text) {
  const token = (window.__artifactAnimationToken || 0) + 1;
  window.__artifactAnimationToken = token;
  element.textContent = '';
  element.classList.remove('is-visible');
  const finalText = text || '';
  if (!finalText) {
    element.classList.add('is-visible');
    return;
  }

  let index = 0;
  function typeFrame() {
    if (window.__artifactAnimationToken !== token) return;
    index = Math.min(finalText.length, index + 30);
    element.textContent = finalText.slice(0, index);
    if (index < finalText.length) {
      requestAnimationFrame(typeFrame);
    } else {
      element.classList.add('is-visible');
    }
  }

  requestAnimationFrame(typeFrame);
}

function countNumberInNode(node, text) {
  const match = text.match(/\d+(?:\.\d+)?/);
  if (!match) {
    node.textContent = text;
    return;
  }

  const target = Number(match[0]);
  const start = performance.now();
  const duration = 500;
  function frame(now) {
    const progress = Math.min(1, (now - start) / duration);
    const current = target % 1 === 0 ? Math.round(target * progress) : Number((target * progress).toFixed(1));
    node.textContent = text.replace(match[0], String(current));
    if (progress < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function updatePipelineViz(activeIndex) {
  document.querySelectorAll('.pipeline-node').forEach((node, index) => {
    node.classList.remove('is-active', 'is-complete');
    if (index < activeIndex) node.classList.add('is-complete');
    else if (index === activeIndex) node.classList.add('is-active');
  });
}

function formatStepTime(node) {
  const time = node.querySelector('.live-stage-time');
  if (!time) return;
  const duration = Number(node.dataset.duration || 0);
  time.textContent = duration ? `${duration.toFixed(1)}s` : '';
}

function updateStageNodes(nodes, activeIndex, pipelineNodes, activeAgent) {
  nodes.forEach((node, index) => {
    node.classList.remove('is-active', 'is-complete');
    if (index < activeIndex) {
      node.classList.add('is-complete');
      formatStepTime(node);
    } else if (index === activeIndex) {
      node.classList.add('is-active');
      const time = node.querySelector('.live-stage-time');
      if (time) time.textContent = '';
    } else {
      const time = node.querySelector('.live-stage-time');
      if (time) time.textContent = '';
    }
  });
  if (pipelineNodes) updatePipelineViz(activeIndex);
  setOrbAgent(activeAgent);
}

function appendTerminalLine(text, tone, feed) {
  const line = document.createElement('div');
  line.className = `terminal-line ${tone}`;
  line.textContent = text;
  feed.appendChild(line);
  requestAnimationFrame(() => {
    line.classList.add('is-visible');
    feed.scrollTop = feed.scrollHeight;
  });
}

function renderMiniStats(items) {
  const container = document.getElementById('mini-stats');
  container.innerHTML = '';
  items.forEach((item, index) => {
    const row = document.createElement('div');
    row.className = 'mini-stat';
    row.style.animationDelay = `${index * 80}ms`;
    container.appendChild(row);
    countNumberInNode(row, item);
  });
}

function formatStrategyPreview(striker) {
  if (!striker || !Array.isArray(striker.strategies)) return 'No strategy data available.';
  return striker.strategies
    .map((strategy) => `${strategy.selected ? '[SELECTED] ' : ''}${strategy.name} - ${strategy.score}/100`)
    .join('\n');
}

function formatScoutPreview(scout) {
  if (!scout || !Array.isArray(scout.findings) || scout.findings.length === 0) {
    return 'No potential vulnerability classes identified.';
  }
  return scout.findings
    .map((finding) => `${finding.vulnerability_class} | ${finding.file}:${finding.line} | ${finding.severity} | ${finding.confidence}%`)
    .join('\n');
}

function formatAdversarialPreview(adversarial) {
  if (!adversarial || !Array.isArray(adversarial.attempts)) {
    return 'No adversarial attempts recorded.';
  }
  return adversarial.attempts
    .map((attempt) => `${attempt.bypass_name} | ${attempt.result}`)
    .join('\n');
}

function appendTerminalLine(text, tone, feed) {
  const line = document.createElement('div');
  line.className = `terminal-line ${tone}`;
  line.textContent = text;
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
}

function updateStageNodes(nodes, activeIndex) {
  nodes.forEach((node, index) => {
    node.classList.remove('is-active', 'is-complete');
    if (index < activeIndex) node.classList.add('is-complete');
    else if (index === activeIndex) node.classList.add('is-active');
  });
}

function renderMiniStats(items) {
  const container = document.getElementById('mini-stats');
  container.innerHTML = '';
  items.forEach((item) => {
    const row = document.createElement('div');
    row.className = 'mini-stat';
    row.textContent = item;
    container.appendChild(row);
  });
}

function populateResults(state, data) {
  setText('results-chip', `${state.repo} completed`);
  setText('recommendation', data.recommendation);
  setText('recommendation-copy', data.recommendationCopy);
}

function renderBaseballStats(stats) {
  const container = document.getElementById('baseball-stats');
  if (!container) return;
  container.innerHTML = '';
  stats.forEach((stat) => {
    const card = document.createElement('div');
    card.className = 'panel-stat';
    const label = document.createElement('span');
    label.className = 'stat-label';
    label.textContent = stat.label;
    const value = document.createElement('strong');
    value.className = 'stat-number';
    value.textContent = stat.value;
    const note = document.createElement('p');
    note.textContent = stat.note;
    card.append(label, value, note);
    container.appendChild(card);
  });
}

function renderMetricsDashboard(data) {
  renderBigMetrics(data);
  renderRadialConfidence(data.confidenceScore);
  renderPerformanceBars(data);
  renderRiskBars(data);
}

function renderEvalSummary(evalData) {
  if (!evalData) return;
  renderMiniGauge('patch-quality-gauge', 'patch-quality-score', evalData.patch_quality_score, '/100');
  renderMiniGauge('speed-score-gauge', 'speed-score', evalData.speed_score, '/100');
  renderPatchQualityBreakdown(evalData.patch_quality_breakdown);
  renderSpeedSummary(evalData.speed);
  renderReliabilityLog(evalData.reliability_log);
}

function renderAdversarialSection(adversarial) {
  if (!adversarial) return;
  renderMiniGauge('resilience-gauge', 'resilience-score', Number.parseInt(adversarial.patch_resilience_score, 10) || 0, '%');

  const summary = document.getElementById('adversarial-summary');
  if (summary) {
    summary.innerHTML = '';
    [
      { label: 'Verdict', value: adversarial.verdict },
      { label: 'Tests Run', value: String(adversarial.adversarial_tests_run) },
      { label: 'Bypasses Found', value: String(adversarial.bypasses_found) }
    ].forEach((item) => {
      const row = document.createElement('div');
      row.className = 'detail-box compact-box';
      const label = document.createElement('span');
      label.className = 'stat-label';
      label.textContent = item.label;
      const value = document.createElement('strong');
      value.className = 'eval-big-number eval-inline-number';
      value.textContent = item.value;
      row.append(label, value);
      summary.appendChild(row);
    });
  }

  const attempts = document.getElementById('adversarial-attempts');
  if (attempts) {
    attempts.innerHTML = '';
    adversarial.attempts.forEach((attempt) => {
      const card = document.createElement('div');
      card.className = `strategy-card adversarial-card${attempt.result === 'BYPASSED' ? ' is-selected' : ''}`;
      const head = document.createElement('div');
      head.className = 'strategy-head';
      const name = document.createElement('strong');
      name.className = 'strategy-name';
      name.textContent = attempt.bypass_name;
      const result = document.createElement('span');
      result.className = 'strategy-score';
      result.textContent = attempt.result;
      head.append(name, result);
      const payload = document.createElement('p');
      payload.className = 'strategy-approach';
      payload.textContent = attempt.payload;
      card.append(head, payload);
      attempts.appendChild(card);
    });
  }
}

function renderScoutSection(scout) {
  const summaryGrid = document.getElementById('scout-summary-grid');
  const findingsContainer = document.getElementById('scout-findings');
  if (!summaryGrid || !findingsContainer) return;

  summaryGrid.innerHTML = '';
  findingsContainer.innerHTML = '';

  const summaryCards = [
    { label: 'Findings', value: String((scout?.findings || []).length), note: 'Potential vulnerability classes surfaced from source alone' },
    { label: 'Independent Detection', value: scout?.independentDetection ? 'Yes' : 'No', note: 'Scout flagged the known vulnerability class before reading the advisory' },
    { label: 'Matched CVE Class', value: scout?.matchedKnownCve ? 'Yes' : 'No', note: 'Comparison against the known CVE classification' },
    { label: 'Additional Findings', value: String((scout?.additionalFindings || []).length), note: 'Potential issues beyond the known advisory class' }
  ];

  summaryCards.forEach((item) => {
    const card = document.createElement('div');
    card.className = 'detail-box compact-box scout-metric';
    const label = document.createElement('span');
    label.className = 'stat-label';
    label.textContent = item.label;
    const value = document.createElement('strong');
    value.className = 'eval-big-number eval-inline-number';
    value.textContent = item.value;
    const note = document.createElement('p');
    note.className = 'metric-note';
    note.textContent = item.note;
    card.append(label, value, note);
    summaryGrid.appendChild(card);
  });

  (scout?.findings || []).forEach((finding) => {
    const card = document.createElement('div');
    card.className = 'strategy-card scout-card';

    const head = document.createElement('div');
    head.className = 'strategy-head';
    const title = document.createElement('strong');
    title.className = 'strategy-name';
    title.textContent = finding.vulnerability_class;
    const score = document.createElement('span');
    score.className = 'strategy-score';
    score.textContent = `${finding.confidence}%`;
    head.append(title, score);

    const meta = document.createElement('p');
    meta.className = 'strategy-approach';
    meta.textContent = `${finding.file}:${finding.line} · ${finding.severity}`;

    const explanation = document.createElement('p');
    explanation.className = 'panel-copy';
    explanation.textContent = finding.explanation;

    card.append(head, meta, explanation);
    findingsContainer.appendChild(card);
  });
}

function renderStrategyMatrix(striker) {
  setText('strategy-reasoning', striker && striker.reasoning ? striker.reasoning : 'No strategy reasoning available.');
  const container = document.getElementById('strategy-grid');
  if (!container) return;
  container.innerHTML = '';
  (striker && striker.strategies ? striker.strategies : []).forEach((strategy) => {
    const card = document.createElement('article');
    card.className = `strategy-card${strategy.selected ? ' is-selected' : ''}`;

    const head = document.createElement('div');
    head.className = 'strategy-head';
    const title = document.createElement('strong');
    title.className = 'strategy-name';
    title.textContent = strategy.name;
    const score = document.createElement('span');
    score.className = 'strategy-score';
    score.textContent = `${strategy.score}/100`;
    head.append(title, score);

    const approach = document.createElement('p');
    approach.className = 'strategy-approach';
    approach.textContent = strategy.approach;

    const breakdown = document.createElement('div');
    breakdown.className = 'strategy-breakdown';
    ['minimality', 'safety', 'convention_match', 'side_effect_risk'].forEach((key) => {
      const row = document.createElement('div');
      row.className = 'strategy-metric';
      const label = document.createElement('span');
      label.textContent = key.replace(/_/g, ' ');
      const value = document.createElement('strong');
      value.textContent = `${strategy.score_breakdown[key]}/25`;
      row.append(label, value);
      breakdown.appendChild(row);
    });

    card.append(head, approach, breakdown);
    container.appendChild(card);
  });
}

function renderBigMetrics(data) {
  const metrics = [
    { label: 'Confidence', value: `${data.confidenceScore}`, suffix: '/100', note: 'review readiness' },
    { label: 'Resilience', value: data.adversarial.patch_resilience_score, suffix: '', note: 'hostile retest score' },
    { label: 'Scout Findings', value: String(data.scout.findings.length), suffix: '', note: 'independent codebase findings' },
    { label: 'Tests Passing', value: data.afterNormal.ok ? '4' : '0', suffix: '/4', note: 'regression suite' }
  ];

  const container = document.getElementById('big-metrics');
  container.innerHTML = '';
  metrics.forEach((metric) => {
    const card = document.createElement('article');
    card.className = 'metric-card';
    const label = document.createElement('span');
    label.className = 'stat-label';
    label.textContent = metric.label;
    const valueWrap = document.createElement('div');
    valueWrap.className = 'metric-value-wrap';
    const value = document.createElement('strong');
    value.className = 'metric-value';
    value.textContent = metric.value;
    const suffix = document.createElement('span');
    suffix.className = 'metric-suffix';
    suffix.textContent = metric.suffix;
    const note = document.createElement('p');
    note.className = 'metric-note';
    note.textContent = metric.note;
    valueWrap.append(value, suffix);
    card.append(label, valueWrap, note);
    container.appendChild(card);
  });
}

function renderRadialConfidence(score) {
  const radial = document.getElementById('confidence-chart');
  const label = document.getElementById('confidence-big');
  const clamped = Math.max(0, Math.min(100, score));
  if (radial) radial.style.setProperty('--progress', `${clamped}%`);
  if (label) label.textContent = String(clamped);
}

function renderPerformanceBars(data) {
  const exploitValue = data.afterExploit.ok ? 100 : 0;
  const testsValue = data.afterNormal.ok ? 100 : 0;
  const patchValue = data.patchDiff ? 100 : 0;
  setText('exploit-metric', `${exploitValue}%`);
  setText('tests-metric', `${testsValue}%`);
  setText('patch-metric', `${patchValue}%`);
  setBarWidth('exploit-bar', exploitValue);
  setBarWidth('tests-bar', testsValue);
  setBarWidth('patch-bar', patchValue);
}

function renderRiskBars(data) {
  const bars = [
    { label: 'Severity', value: data.severity === 'High' ? 88 : 72, tone: 'high' },
    { label: 'Maintainer risk', value: 72, tone: 'mid' },
    { label: 'Blast radius', value: 81, tone: 'high' },
    { label: 'Patch resilience', value: Number.parseInt(data.adversarial.patch_resilience_score, 10) || 0, tone: 'low' }
  ];
  const container = document.getElementById('risk-bars');
  container.innerHTML = '';
  bars.forEach((bar) => {
    const row = document.createElement('div');
    row.className = 'risk-row';
    const meta = document.createElement('div');
    meta.className = 'risk-meta';
    const label = document.createElement('span');
    label.textContent = bar.label;
    const value = document.createElement('strong');
    value.textContent = `${bar.value}`;
    meta.append(label, value);
    const track = document.createElement('div');
    track.className = 'risk-track';
    const fill = document.createElement('div');
    fill.className = `risk-fill ${bar.tone}`;
    fill.style.width = `${bar.value}%`;
    track.appendChild(fill);
    row.append(meta, track);
    container.appendChild(row);
  });
}

function renderMiniGauge(gaugeId, labelId, value) {
  const gauge = document.getElementById(gaugeId);
  const label = document.getElementById(labelId);
  const clamped = Math.max(0, Math.min(100, Number(value) || 0));
  if (gauge) gauge.style.setProperty('--progress', `${clamped}%`);
  if (label) label.textContent = String(clamped);
}

function renderPatchQualityBreakdown(breakdown) {
  const container = document.getElementById('patch-quality-breakdown');
  if (!container || !breakdown) return;
  const labels = {
    lines_changed: 'Lines changed',
    convention_match: 'Convention match',
    no_new_dependencies: 'No new dependencies',
    vulnerability_fully_blocked: 'Vulnerability blocked',
    no_test_regressions: 'No regressions'
  };
  container.innerHTML = '';
  Object.entries(breakdown).forEach(([key, entry]) => {
    const row = document.createElement('div');
    row.className = 'eval-row';
    const meta = document.createElement('div');
    meta.className = 'eval-row-meta';
    const label = document.createElement('span');
    label.textContent = labels[key] || key;
    const value = document.createElement('strong');
    value.textContent = `${entry.points}/${entry.max_points}`;
    const track = document.createElement('div');
    track.className = 'eval-row-track';
    const fill = document.createElement('div');
    fill.className = 'eval-row-fill';
    fill.style.width = `${Math.round((entry.points / entry.max_points) * 100)}%`;
    meta.append(label, value);
    track.appendChild(fill);
    row.append(meta, track);
    container.appendChild(row);
  });
}

function renderSpeedSummary(speed) {
  if (!speed) return;
  setText('total-pipeline-time', `${Number(speed.total_pipeline_time_seconds || 0).toFixed(2)}s`);
  const container = document.getElementById('speed-step-list');
  if (!container) return;
  container.innerHTML = '';
  (speed.per_agent_step_ms || []).forEach((step) => {
    const card = document.createElement('div');
    card.className = 'detail-box compact-box';
    const label = document.createElement('span');
    label.className = 'stat-label';
    label.textContent = step.agent;
    const value = document.createElement('strong');
    value.className = 'eval-big-number eval-inline-number';
    value.textContent = `${Number(step.duration_seconds || 0).toFixed(2)}s`;
    card.append(label, value);
    container.appendChild(card);
  });
}

function renderReliabilityLog(reliability) {
  if (!reliability) return;
  setText('retries-needed', String(reliability.retries_needed || 0));
  const list = document.getElementById('reliability-list');
  if (list) {
    list.innerHTML = '';
    (reliability.agents || []).forEach((agent) => {
      const row = document.createElement('div');
      row.className = 'detail-box compact-box reliability-row';
      const title = document.createElement('strong');
      title.className = 'eval-inline-number';
      title.textContent = agent.agent;
      const meta = document.createElement('div');
      meta.className = 'reliability-meta';
      meta.textContent = agent.succeeded_on_first_try
        ? `First try • ${Number((agent.duration_ms || 0) / 1000).toFixed(2)}s`
        : `Attempts ${agent.attempts} • ${Number((agent.duration_ms || 0) / 1000).toFixed(2)}s`;
      row.append(title, meta);
      list.appendChild(row);
    });
  }
  const errors = (reliability.error_log || []).length ? reliability.error_log.join('\n') : 'No errors recorded.';
  setText('error-log', errors);
}

function renderTextSummary(data) {
  setText('detail-title', `${data.packageName} fix summary`);
  const body = document.getElementById('detail-body');
  if (!body) return;
  body.innerHTML = '';

  body.append(
    createDetailSection('Decision', [
      `${data.recommendation}. ${data.recommendationCopy}`,
      `Current status: ${data.statusAfter}. Confidence score: ${data.confidenceScore}/100. Patch resilience: ${data.adversarial.patch_resilience_score}.`
    ]),
    createDetailSection('Scout Classification', [
      data.scout.matchedKnownCve
        ? 'Scout independently detected the same vulnerability class as the known advisory before CVE-guided analysis began.'
        : 'Scout did not independently match the known advisory class before CVE-guided analysis.',
      ...data.scout.findings.map((finding) => `${finding.vulnerability_class} at ${finding.file}:${finding.line} (${finding.severity}, ${finding.confidence}% confidence): ${finding.explanation}`)
    ]),
    createDetailSection('Root Cause', [data.rootCause]),
    createDetailSection('Selected Fix Strategy', [
      `${data.striker.selectedStrategy}: ${data.striker.reasoning}`,
      data.patchStrategy
    ]),
    createDetailSection('Adversarial Hardening', [
      `Verdict: ${data.adversarial.verdict}. ${data.adversarial.bypasses_found} bypasses found across ${data.adversarial.adversarial_tests_run} hostile attempts.`,
      ...data.adversarial.attempts.map((attempt) => `${attempt.bypass_name}: ${attempt.result}`)
    ]),
    createDetailSection('Verification', [
      `Before patch: ${data.beforeExploit.output}`,
      `After patch: ${data.afterExploit.output}`,
      data.afterNormal.output
    ]),
    createDetailSection('Patch Diff', [data.patchDiff], true),
    createDetailSection('Report Preview', [data.reportPreview], true)
  );
}

function createDetailSection(title, paragraphs, preformatted = false) {
  const section = document.createElement('section');
  section.className = 'detail-box detail-section';
  const heading = document.createElement('strong');
  heading.className = 'detail-section-title';
  heading.textContent = title;
  section.appendChild(heading);

  paragraphs.filter(Boolean).forEach((text) => {
    const node = document.createElement(preformatted ? 'pre' : 'p');
    if (preformatted) {
      node.className = 'detail-pre';
      node.textContent = text;
    } else {
      node.textContent = text;
    }
    section.appendChild(node);
  });

  return section;
}

function setResultsView(view) {
  const isDashboard = view === 'dashboard';
  const dashboardView = document.getElementById('dashboard-view');
  const summaryView = document.getElementById('summary-view');
  const dashboardButton = document.getElementById('show-dashboard');
  const summaryButton = document.getElementById('show-summary');
  if (dashboardView) dashboardView.classList.toggle('is-active', isDashboard);
  if (summaryView) summaryView.classList.toggle('is-active', !isDashboard);
  if (dashboardButton) {
    dashboardButton.classList.toggle('is-active', isDashboard);
    dashboardButton.setAttribute('aria-pressed', String(isDashboard));
  }
  if (summaryButton) {
    summaryButton.classList.toggle('is-active', !isDashboard);
    summaryButton.setAttribute('aria-pressed', String(!isDashboard));
  }
}

function setBarWidth(id, value) {
  const element = document.getElementById(id);
  if (element) element.style.width = `${value}%`;
}

function showScreen(id) {
  const screens = Array.from(document.querySelectorAll('.screen'));
  const current = screens.find((screen) => screen.classList.contains('active'));
  const next = document.getElementById(id);
  if (!next || current === next) {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    return;
  }

  if (current) {
    current.classList.add('screen-exit');
    window.setTimeout(() => {
      current.classList.remove('active', 'screen-exit');
      next.classList.add('active', 'screen-enter');
      requestAnimationFrame(() => next.classList.add('screen-enter-active'));
      window.setTimeout(() => next.classList.remove('screen-enter', 'screen-enter-active'), 520);
    }, 260);
  } else {
    next.classList.add('active', 'screen-enter');
    requestAnimationFrame(() => next.classList.add('screen-enter-active'));
    window.setTimeout(() => next.classList.remove('screen-enter', 'screen-enter-active'), 520);
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value || '';
}
