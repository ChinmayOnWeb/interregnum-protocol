'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { getTargetConfig, parseTargetFlag } = require('./target_config');

const INTEL_OUTPUT_PATH = path.join(__dirname, 'intel_output.json');
const API_TIMEOUT_MS = Number(process.env.INTEL_API_TIMEOUT_MS || 10000);

const CWE_NAMES = {
  'CWE-20': 'Improper Input Validation',
  'CWE-22': 'Path Traversal',
  'CWE-79': 'Cross-Site Scripting',
  'CWE-89': 'SQL Injection',
  'CWE-94': 'Code Injection',
  'CWE-400': 'Uncontrolled Resource Consumption',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-918': 'Server-Side Request Forgery (SSRF)',
  'CWE-1321': 'Prototype Pollution'
};

function isCveId(value) {
  return /^CVE-\d{4}-\d+$/i.test(String(value || '').trim());
}

function normalizeReference(reference) {
  if (!reference) return null;
  if (typeof reference === 'string') return { url: reference };
  if (typeof reference.url === 'string') return reference;
  return null;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = API_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const bodyText = await response.text();
    if (!response.ok) {
      const error = new Error(`Request failed (${response.status}) for ${url}: ${bodyText.slice(0, 300)}`);
      error.status = response.status;
      throw error;
    }
    return {
      response,
      text: bodyText,
      json: () => (bodyText ? JSON.parse(bodyText) : {})
    };
  } finally {
    clearTimeout(timer);
  }
}

async function tryFetchJson(url, options = {}, timeoutMs = API_TIMEOUT_MS) {
  try {
    const result = await fetchWithTimeout(url, options, timeoutMs);
    return result.json();
  } catch (_) {
    return null;
  }
}

async function tryFetchText(url, options = {}, timeoutMs = API_TIMEOUT_MS) {
  try {
    const result = await fetchWithTimeout(url, options, timeoutMs);
    return result.text;
  } catch (_) {
    return '';
  }
}

function extractSeverity(osv, nvd) {
  const osvSeverity = Array.isArray(osv && osv.severity) ? osv.severity : [];
  for (const entry of osvSeverity) {
    const scoreText = String(entry.score || '');
    const vectorMatch = scoreText.match(/CVSS:[^/]+\/.+$/i);
    const scoreMatch = scoreText.match(/(\d+\.\d+)/);
    if (scoreMatch || vectorMatch) {
      return {
        score: scoreMatch ? Number(scoreMatch[1]) : null,
        vector: vectorMatch ? vectorMatch[0] : scoreText || null
      };
    }
  }

  const metrics = nvd && nvd.metrics ? nvd.metrics : {};
  const candidates = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
  for (const key of candidates) {
    const entries = Array.isArray(metrics[key]) ? metrics[key] : [];
    const primary = entries[0];
    if (!primary || !primary.cvssData) continue;
    return {
      score: Number(primary.cvssData.baseScore) || null,
      vector: primary.cvssData.vectorString || null
    };
  }

  return { score: null, vector: null };
}

function extractAffectedVersions(osv) {
  const affected = Array.isArray(osv && osv.affected) ? osv.affected : [];
  const introduced = [];
  const fixed = [];
  const ecosystems = [];

  for (const item of affected) {
    if (item && item.ecosystem_specific) {
      ecosystems.push(item.ecosystem_specific);
    }

    const ranges = Array.isArray(item && item.ranges) ? item.ranges : [];
    for (const range of ranges) {
      const events = Array.isArray(range && range.events) ? range.events : [];
      for (const event of events) {
        if (event && typeof event.introduced === 'string') introduced.push(event.introduced);
        if (event && typeof event.fixed === 'string') fixed.push(event.fixed);
      }
    }
  }

  return {
    introduced,
    fixed,
    ecosystemSpecific: ecosystems
  };
}

function pickBestVersion(values = []) {
  const filtered = values.filter((value) => typeof value === 'string' && value.trim() !== '' && value !== '0');
  return filtered.length > 0 ? filtered[filtered.length - 1] : '';
}

function buildVulnerableRangeText(target, versions) {
  if (Array.isArray(target.affectedRange) && target.affectedRange.length > 0) {
    return target.affectedRange.join(', ');
  }

  if (typeof target.affectedRange === 'string' && target.affectedRange.trim() !== '') {
    return target.affectedRange;
  }

  if (versions.introduced.length > 0 && versions.fixed.length > 0) {
    return `>= ${versions.introduced[0]}, < ${versions.fixed[versions.fixed.length - 1]}`;
  }

  if (versions.fixed.length > 0) {
    return `< ${versions.fixed[versions.fixed.length - 1]}`;
  }

  if (versions.introduced.length > 0) {
    return `>= ${versions.introduced[0]}`;
  }

  return 'unknown';
}

function extractCwe(osv, nvd) {
  const osvIds = osv && osv.database_specific && Array.isArray(osv.database_specific.cwe_ids)
    ? osv.database_specific.cwe_ids.filter(Boolean)
    : [];
  if (osvIds.length > 0) {
    return {
      cwe: osvIds[0],
      cwe_name: CWE_NAMES[osvIds[0]] || null
    };
  }

  const weaknesses = Array.isArray(nvd && nvd.weaknesses) ? nvd.weaknesses : [];
  for (const weakness of weaknesses) {
    const descriptions = Array.isArray(weakness.description) ? weakness.description : [];
    for (const entry of descriptions) {
      const value = String(entry && entry.value ? entry.value : '');
      const match = value.match(/CWE-\d+/i);
      if (match) {
        const cwe = match[0].toUpperCase();
        return { cwe, cwe_name: CWE_NAMES[cwe] || value };
      }
    }
  }

  return { cwe: null, cwe_name: null };
}

function extractRepoFromUrl(url) {
  try {
    const parsed = new URL(url);
    if (!/github\.com$/i.test(parsed.hostname)) return null;
    const parts = parsed.pathname.replace(/^\/+|\/+$/g, '').split('/');
    if (parts.length < 2) return null;
    return { owner: parts[0], repo: parts[1].replace(/\.git$/i, '') };
  } catch (_) {
    return null;
  }
}

function parseCommitReference(url) {
  try {
    const parsed = new URL(url);
    if (!/github\.com$/i.test(parsed.hostname)) return null;
    const parts = parsed.pathname.replace(/^\/+|\/+$/g, '').split('/');
    const commitIndex = parts.indexOf('commit');
    if (commitIndex !== 2 || parts.length < 4) return null;
    return { owner: parts[0], repo: parts[1], sha: parts[3], url };
  } catch (_) {
    return null;
  }
}

function pickFixReferences(references) {
  const normalized = references.map(normalizeReference).filter(Boolean);
  const commit = normalized.find((reference) => /\/commit\//i.test(reference.url));
  const pull = normalized.find((reference) => /\/pull\//i.test(reference.url));
  const compare = normalized.find((reference) => /\/compare\//i.test(reference.url));
  return { commit, pull, compare };
}

function countChangedLinesFromDiff(diffText) {
  if (!diffText) return 0;
  return diffText
    .split('\n')
    .filter((line) => (line.startsWith('+') || line.startsWith('-')) && !line.startsWith('+++') && !line.startsWith('---'))
    .length;
}

function extractFilesFromGitHubPayload(payload) {
  const files = Array.isArray(payload && payload.files) ? payload.files : [];
  return {
    names: files.map((file) => file.filename).filter(Boolean),
    lineCount: files.reduce((sum, file) => sum + (Number(file.changes) || 0), 0)
  };
}

function firstNvdVuln(payload) {
  const vulns = Array.isArray(payload && payload.vulnerabilities) ? payload.vulnerabilities : [];
  return vulns[0] && vulns[0].cve ? vulns[0].cve : null;
}

async function fetchOsvIntel(target) {
  if (isCveId(target.cve)) {
    const osvById = await tryFetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(target.cve)}`);
    if (osvById) return osvById;
  }

  if (!target.packageName) return null;
  const queryBody = { package: { name: target.packageName, ecosystem: target.ecosystem || 'npm' } };
  if (target.version) queryBody.version = target.version;
  const payload = await tryFetchJson('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(queryBody)
  });

  const vulns = Array.isArray(payload && payload.vulns) ? payload.vulns : [];
  if (isCveId(target.cve)) {
    return vulns.find((entry) => entry.id === target.cve || (Array.isArray(entry.aliases) && entry.aliases.includes(target.cve))) || vulns[0] || null;
  }
  return vulns[0] || null;
}

async function fetchNvdIntel(cve) {
  if (!isCveId(cve)) return null;
  const payload = await tryFetchJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`);
  return firstNvdVuln(payload);
}

async function fetchGitHubCommitDiff(commitRef) {
  if (!commitRef) {
    return {
      fix_commit_url: null,
      fix_diff: '',
      fix_files_changed: [],
      fix_lines_changed: 0,
      notes: ['no known fix commit']
    };
  }

  const apiBase = `https://api.github.com/repos/${commitRef.owner}/${commitRef.repo}/commits/${commitRef.sha}`;
  const payload = await tryFetchJson(apiBase, {
    headers: {
      'User-Agent': 'Project-Praetorian',
      'Accept': 'application/vnd.github+json'
    }
  });
  const diff = await tryFetchText(apiBase, {
    headers: {
      'User-Agent': 'Project-Praetorian',
      'Accept': 'application/vnd.github.v3.diff'
    }
  });

  const fileInfo = extractFilesFromGitHubPayload(payload);
  return {
    fix_commit_url: commitRef.url,
    fix_diff: diff,
    fix_files_changed: fileInfo.names,
    fix_lines_changed: fileInfo.lineCount || countChangedLinesFromDiff(diff),
    notes: diff ? [] : ['fix commit metadata found but diff was unavailable']
  };
}

async function fetchCompareDiff(repoRef, introduced, fixed) {
  if (!repoRef || !introduced || !fixed) {
    return { compare_url: null, compare_diff: '', notes: [] };
  }

  const compareUrl = `https://api.github.com/repos/${repoRef.owner}/${repoRef.repo}/compare/v${introduced}...v${fixed}`;
  const diff = await tryFetchText(compareUrl, {
    headers: {
      'User-Agent': 'Project-Praetorian',
      'Accept': 'application/vnd.github.v3.diff'
    }
  });
  return {
    compare_url: compareUrl,
    compare_diff: diff,
    notes: diff ? [] : ['version comparison diff unavailable']
  };
}

async function gatherVulnerabilityIntel(options = {}) {
  const targetKey = options.targetKey || 'mixin-deep';
  const target = getTargetConfig(targetKey);
  const errors = [];
  const dataSources = [];

  const osv = await fetchOsvIntel(target).catch((error) => {
    errors.push(`osv: ${error.message}`);
    return null;
  });
  if (osv) dataSources.push('osv.dev');

  const nvd = await fetchNvdIntel(target.cve).catch((error) => {
    errors.push(`nvd: ${error.message}`);
    return null;
  });
  if (nvd) dataSources.push('nvd');

  const references = [
    ...(Array.isArray(osv && osv.references) ? osv.references : []),
    ...(Array.isArray(nvd && nvd.references) ? nvd.references : [])
  ].map(normalizeReference).filter(Boolean);

  const fixRefs = pickFixReferences(references);
  const repoRef = parseCommitReference(fixRefs.commit && fixRefs.commit.url)
    || extractRepoFromUrl(target.repoUrl || '')
    || extractRepoFromUrl((fixRefs.pull && fixRefs.pull.url) || '')
    || extractRepoFromUrl((fixRefs.compare && fixRefs.compare.url) || '');

  const commitDiff = await fetchGitHubCommitDiff(parseCommitReference(fixRefs.commit && fixRefs.commit.url)).catch((error) => {
    errors.push(`github-commit: ${error.message}`);
    return {
      fix_commit_url: fixRefs.commit ? fixRefs.commit.url : null,
      fix_diff: '',
      fix_files_changed: [],
      fix_lines_changed: 0,
      notes: ['fix commit lookup failed']
    };
  });
  if (commitDiff.fix_commit_url || commitDiff.fix_diff) dataSources.push('github');

  const versions = extractAffectedVersions(osv);
  const introduced = pickBestVersion(versions.introduced);
  const fixed = pickBestVersion(versions.fixed);
  const compareDiff = await fetchCompareDiff(repoRef, introduced, fixed).catch((error) => {
    errors.push(`github-compare: ${error.message}`);
    return { compare_url: null, compare_diff: '', notes: ['version comparison lookup failed'] };
  });
  if (compareDiff.compare_url && compareDiff.compare_diff && !dataSources.includes('github')) {
    dataSources.push('github');
  }

  const cwe = extractCwe(osv, nvd);
  const severity = extractSeverity(osv, nvd);
  const descriptions = Array.isArray(nvd && nvd.descriptions) ? nvd.descriptions : [];
  const nvdDescription = (descriptions.find((entry) => entry.lang === 'en') || descriptions[0] || {}).value || '';

  const intel = {
    cve: target.cve,
    package: target.packageName,
    summary: (osv && osv.summary) || target.advisorySummary || '',
    details: (osv && osv.details) || target.advisoryDetails || '',
    severity,
    cwe: cwe.cwe,
    cwe_name: cwe.cwe_name,
    vulnerable_versions: buildVulnerableRangeText(target, versions),
    fixed_version: fixed || null,
    fix_commit_url: commitDiff.fix_commit_url,
    fix_pr_url: fixRefs.pull ? fixRefs.pull.url : null,
    compare_url: compareDiff.compare_url,
    fix_diff: commitDiff.fix_diff || '',
    compare_diff: compareDiff.compare_diff || '',
    fix_files_changed: commitDiff.fix_files_changed,
    fix_lines_changed: commitDiff.fix_lines_changed,
    references: references.map((reference) => reference.url),
    nvd_description: nvdDescription,
    osv_ranges: versions,
    osv_ecosystem_specific: versions.ecosystemSpecific,
    data_sources: Array.from(new Set(dataSources)),
    notes: [
      ...commitDiff.notes,
      ...compareDiff.notes
    ],
    errors
  };

  await fs.writeFile(INTEL_OUTPUT_PATH, `${JSON.stringify(intel, null, 2)}\n`, 'utf8');
  return intel;
}

async function readIntelOutput(filePath = INTEL_OUTPUT_PATH) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function main() {
  try {
    const targetKey = parseTargetFlag(process.argv.slice(2));
    const intel = await gatherVulnerabilityIntel({ targetKey });
    console.log(JSON.stringify(intel, null, 2));
  } catch (error) {
    console.error(`Intel gatherer failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  gatherVulnerabilityIntel,
  readIntelOutput,
  INTEL_OUTPUT_PATH
};
