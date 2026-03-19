'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const ROOT_DIR = __dirname;
const DYNAMIC_ROOT = path.join(ROOT_DIR, 'dynamic-target');
const CURRENT_CUSTOM_TARGET_PATH = path.join(ROOT_DIR, 'current_custom_target.json');
const PREP_STATUS_PATH = path.join(ROOT_DIR, 'custom_prepare_status.json');
const PREP_STATUS_TMP_PATH = `${PREP_STATUS_PATH}.tmp`;

async function writePreparationStatus(payload) {
  const current = await readPreparationStatus().catch(() => null);
  const next = {
    startedAt: payload.startedAt || current?.startedAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    status: payload.status || (Number(payload.progress || 0) >= 100 ? 'complete' : 'running'),
    phase: payload.phase || current?.phase || 'idle',
    message: payload.message || current?.message || '',
    progress: Math.max(0, Math.min(100, Number(payload.progress || 0))),
    packageName: payload.packageName || current?.packageName || '',
    cve: payload.cve || current?.cve || '',
    input: payload.input || current?.input || '',
    inputKind: payload.inputKind || current?.inputKind || '',
    target: payload.target || current?.target || 'custom',
    error: payload.error || (payload.status === 'error' ? current?.error || '' : '')
  };
  const serialized = `${JSON.stringify(next, null, 2)}\n`;
  await fsp.writeFile(PREP_STATUS_TMP_PATH, serialized, 'utf8');
  await fsp.rename(PREP_STATUS_TMP_PATH, PREP_STATUS_PATH);
  return next;
}

function extractFirstJsonObject(raw) {
  const text = String(raw || '').trim();
  if (!text) return null;
  if (text.startsWith('{') && text.endsWith('}')) return text;
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < text.length; index += 1) {
    const char = text[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === '\\') {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }
    if (char === '"') {
      inString = true;
      continue;
    }
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        return text.slice(start, index + 1);
      }
    }
  }
  return null;
}

async function readPreparationStatus() {
  try {
    const raw = await fsp.readFile(PREP_STATUS_PATH, 'utf8');
    try {
      return JSON.parse(raw);
    } catch (parseError) {
      const recovered = extractFirstJsonObject(raw);
      if (!recovered) throw parseError;
      return JSON.parse(recovered);
    }
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function clearPreparationStatus() {
  await fsp.rm(PREP_STATUS_PATH, { force: true });
}

function sanitizePackageKey(name) {
  return String(name || 'custom-package').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function parsePackageInput(rawInput) {
  const input = String(rawInput || '').trim();
  if (!input) {
    throw new Error('A package name or package/repository URL is required.');
  }

  if (!/^https?:\/\//i.test(input)) {
    return {
      kind: 'npm',
      packageName: input,
      displayName: input,
      originalInput: input
    };
  }

  const url = new URL(input);
  if (/npmjs\.com$/i.test(url.hostname)) {
    const match = url.pathname.match(/^\/package\/([^?#/]+(?:\/[^?#/]+)?)/i);
    if (!match) {
      throw new Error('Could not parse an npm package name from the provided URL.');
    }

    const packageName = decodeURIComponent(match[1]);
    return {
      kind: 'npm',
      packageName,
      displayName: packageName,
      originalInput: input
    };
  }

  if (/github\.com$/i.test(url.hostname)) {
    const parts = url.pathname.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
    if (parts.length < 2) {
      throw new Error('GitHub repository URLs must look like https://github.com/owner/repo');
    }

    return {
      kind: 'github',
      owner: parts[0],
      repo: parts[1].replace(/\.git$/i, ''),
      displayName: parts.slice(0, 2).join('/'),
      originalInput: input
    };
  }

  throw new Error('Custom ingestion currently supports npm package URLs, bare npm package names, or GitHub repository URLs.');
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Request failed (${response.status}) for ${url}: ${body.slice(0, 300)}`);
  }
  return response.json();
}

async function fetchBuffer(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Download failed (${response.status}) for ${url}: ${body.slice(0, 300)}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

function severityFromCvss(score) {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  if (score > 0) return 'Low';
  return 'Unknown';
}

function extractCvssScore(vuln) {
  if (!vuln || !Array.isArray(vuln.severity)) return 0;
  for (const entry of vuln.severity) {
    const score = String(entry.score || '');
    const match = score.match(/(\d+\.\d+)/);
    if (match) return Number(match[1]);
  }
  return 0;
}

function mapAdvisoryToClass(vuln) {
  const text = `${vuln.summary || ''} ${vuln.details || ''}`.toLowerCase();
  if (text.includes('prototype pollution')) return 'Prototype Pollution';
  if (text.includes('path traversal')) return 'Path Traversal';
  if (
    text.includes('redos') ||
    text.includes('regular expression denial of service') ||
    text.includes('regular expression complexity') ||
    text.includes('(re)dos') ||
    text.includes('resource consumption')
  ) {
    return 'ReDoS (Regular Expression Denial of Service)';
  }
  if (text.includes('command injection')) return 'Command Injection';
  if (text.includes('deserialization')) return 'Insecure Deserialization';
  if (text.includes('sql injection')) return 'SQL Injection';
  if (text.includes('cross-site scripting') || text.includes('xss')) return 'Cross-Site Scripting';
  if (text.includes('ssrf') || text.includes('input validation') || text.includes('redirect')) return 'Insufficient Input Validation';
  return 'Insufficient Input Validation';
}

function buildKeywordList(vulnerabilityClass, advisoryText) {
  const text = String(advisoryText || '').toLowerCase();
  const keywords = new Set();

  if (vulnerabilityClass === 'Prototype Pollution') {
    ['proto', 'constructor', 'prototype', 'merge', 'assign', 'set', 'path', 'deep'].forEach((item) => keywords.add(item));
  } else if (vulnerabilityClass === 'Insufficient Input Validation') {
    ['redirect', 'proxy', 'uri', 'url', 'request', 'follow', 'location', 'protocol', 'host'].forEach((item) => keywords.add(item));
  } else if (vulnerabilityClass === 'Path Traversal') {
    ['path', 'file', 'read', 'write', 'join', 'resolve', 'normalize'].forEach((item) => keywords.add(item));
  }

  text.split(/[^a-z0-9_]+/i).filter((word) => word.length >= 4).forEach((word) => keywords.add(word));
  return Array.from(keywords);
}

function parseGitHubCommitReference(url) {
  try {
    const parsed = new URL(url);
    if (!/github\.com$/i.test(parsed.hostname)) return null;
    const parts = parsed.pathname.replace(/^\/+|\/+$/g, '').split('/');
    if (parts.length < 4 || parts[2] !== 'commit') return null;
    return {
      owner: parts[0],
      repo: parts[1].replace(/\.git$/i, ''),
      sha: parts[3],
      url
    };
  } catch (_) {
    return null;
  }
}

function findFixCommitReference(advisory, repoHint) {
  const references = Array.isArray(advisory && advisory.references) ? advisory.references : [];
  const commitRefs = references
    .map((reference) => parseGitHubCommitReference(reference && reference.url ? reference.url : reference))
    .filter(Boolean);

  if (repoHint) {
    const matching = commitRefs.find((ref) => ref.owner === repoHint.owner && ref.repo === repoHint.repo);
    if (matching) return matching;
  }

  return commitRefs[0] || null;
}

function parseSemver(version) {
  const match = String(version || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  if (!match) return null;
  return match.slice(1).map(Number);
}

function compareSemver(a, b) {
  const parsedA = parseSemver(a);
  const parsedB = parseSemver(b);
  if (!parsedA || !parsedB) return 0;
  for (let index = 0; index < 3; index += 1) {
    if (parsedA[index] > parsedB[index]) return 1;
    if (parsedA[index] < parsedB[index]) return -1;
  }
  return 0;
}

function extractSemverVersionsFromAdvisory(advisory) {
  const affected = Array.isArray(advisory && advisory.affected) ? advisory.affected : [];
  const versions = [];
  const fixedVersions = [];

  for (const item of affected) {
    const itemVersions = Array.isArray(item && item.versions) ? item.versions : [];
    itemVersions.forEach((version) => {
      if (parseSemver(version)) versions.push(version);
    });

    const ranges = Array.isArray(item && item.ranges) ? item.ranges : [];
    for (const range of ranges) {
      const events = Array.isArray(range && range.events) ? range.events : [];
      for (const event of events) {
        if (event && parseSemver(event.fixed)) fixedVersions.push(event.fixed);
      }
    }
  }

  return { versions, fixedVersions };
}

function chooseVulnerableRegistryVersion(registry, advisory, fallbackVersion) {
  const allVersions = Object.keys((registry && registry.versions) || {}).filter((version) => parseSemver(version));
  if (allVersions.length === 0) return fallbackVersion;

  const { versions, fixedVersions } = extractSemverVersionsFromAdvisory(advisory);
  const sorted = allVersions.sort((left, right) => compareSemver(right, left));

  if (versions.length > 0) {
    const vulnerableSet = new Set(versions);
    const matched = sorted.find((version) => vulnerableSet.has(version));
    if (matched) return matched;
  }

  const fixed = fixedVersions.sort((left, right) => compareSemver(right, left))[0];
  if (fixed) {
    const matched = sorted.find((version) => compareSemver(version, fixed) < 0);
    if (matched) return matched;
  }

  return fallbackVersion;
}

async function fetchOsvAdvisoryById(advisoryId) {
  try {
    return await fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(advisoryId)}`);
  } catch (_) {
    return null;
  }
}

async function chooseAdvisory(packageName, version, manualAdvisory) {
  if (manualAdvisory) {
    const directHit = await fetchOsvAdvisoryById(manualAdvisory);
    if (directHit) {
      return directHit;
    }
  }

  if (!packageName) {
    return {
      id: manualAdvisory || 'UNSPECIFIED-ADVISORY',
      aliases: manualAdvisory ? [manualAdvisory] : [],
      summary: manualAdvisory ? `Manual advisory ${manualAdvisory} supplied.` : 'No advisory lookup available for this repository target.',
      details: manualAdvisory
        ? `The operator supplied ${manualAdvisory}. Analyze the codebase and generate the best remediation flow around the supplied repository and any independently discovered risks.`
        : 'Proceed with codebase classification and treat the target as a manually supplied remediation candidate without a fetched advisory.',
      severity: [],
      database_specific: {}
    };
  }

  const result = await fetchJson('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' }, version })
  });

  const vulns = Array.isArray(result.vulns) ? result.vulns : [];
  let selected = null;
  if (manualAdvisory) {
    selected = vulns.find((vuln) => {
      const aliases = Array.isArray(vuln.aliases) ? vuln.aliases : [];
      return vuln.id === manualAdvisory || aliases.includes(manualAdvisory);
    }) || null;
  }

  if (!selected && vulns.length > 0) {
    selected = vulns.slice().sort((a, b) => extractCvssScore(b) - extractCvssScore(a))[0];
  }

  if (!selected) {
    return {
      id: manualAdvisory || 'UNSPECIFIED-ADVISORY',
      aliases: manualAdvisory ? [manualAdvisory] : [],
      summary: manualAdvisory
        ? `Manual advisory ${manualAdvisory} supplied for ${packageName}.`
        : `No OSV advisory was found automatically for ${packageName}@${version}.`,
      details: manualAdvisory
        ? `The operator supplied ${manualAdvisory}. Analyze the codebase and generate the best remediation flow around the supplied package and any independently discovered risks.`
        : 'Proceed with codebase classification and treat the package as a manually supplied remediation target without a fetched advisory.',
      severity: [],
      database_specific: {}
    };
  }

  return selected;
}

async function resolveGitHubVulnerableSnapshot(parsed, advisory, reportStatus) {
  const fixCommit = findFixCommitReference(advisory, parsed);
  if (!fixCommit) return null;

  if (reportStatus) {
    await reportStatus({
      phase: 'snapshot',
      message: `Resolving vulnerable pre-fix snapshot for ${parsed.owner}/${parsed.repo}`,
      progress: 32
    });
  }

  const commitPayload = await fetchJson(`https://api.github.com/repos/${fixCommit.owner}/${fixCommit.repo}/commits/${fixCommit.sha}`, {
    headers: { 'User-Agent': 'Project-Praetorian', 'Accept': 'application/vnd.github+json' }
  });
  const parents = Array.isArray(commitPayload.parents) ? commitPayload.parents : [];
  if (!parents[0] || !parents[0].sha) return null;

  return {
    parentSha: parents[0].sha,
    fixCommitUrl: fixCommit.url,
    artifactUrl: `https://codeload.github.com/${fixCommit.owner}/${fixCommit.repo}/zip/${parents[0].sha}`
  };
}

async function extractTarball(tarballPath, destDir) {
  await fsp.mkdir(destDir, { recursive: true });
  await execFileAsync('tar', ['-xf', tarballPath, '-C', destDir], { windowsHide: true });
}

async function extractZip(zipPath, destDir) {
  await fsp.mkdir(destDir, { recursive: true });
  if (process.platform === 'win32') {
    await execFileAsync('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe', [
      '-NoProfile',
      '-Command',
      `$ProgressPreference='SilentlyContinue'; $InformationPreference='SilentlyContinue'; Expand-Archive -Force -Path '${zipPath.replace(/'/g, "''")}' -DestinationPath '${destDir.replace(/'/g, "''")}'`
    ], { windowsHide: true });
    return;
  }
  await execFileAsync('unzip', ['-o', zipPath, '-d', destDir], { windowsHide: true });
}

async function fileExists(filePath) {
  try {
    await fsp.access(filePath);
    return true;
  } catch (_) {
    return false;
  }
}

async function findCandidateSourceFiles(rootDir) {
  const results = [];

  async function walk(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (/\.(js|cjs|mjs)$/i.test(entry.name)) {
        results.push(fullPath);
      }
    }
  }

  await walk(rootDir);
  return results;
}

async function detectPackageRoot(extractDir) {
  const packagePath = path.join(extractDir, 'package');
  if (await fileExists(packagePath)) return packagePath;

  const entries = await fsp.readdir(extractDir, { withFileTypes: true });
  const dirs = entries.filter((entry) => entry.isDirectory());
  if (dirs.length === 1) return path.join(extractDir, dirs[0].name);
  return extractDir;
}

function scoreSourceFile(filePath, relPath, keywords, packageJson) {
  let score = 0;
  const normalized = relPath.replace(/\\/g, '/').toLowerCase();
  if (packageJson.main && normalized === String(packageJson.main).replace(/\\/g, '/').toLowerCase()) score += 20;
  if (packageJson.module && normalized === String(packageJson.module).replace(/\\/g, '/').toLowerCase()) score += 18;
  if (normalized.endsWith('/index.js') || normalized === 'index.js' || normalized === 'request.js') score += 8;
  if (normalized.includes('/lib/')) score += 5;
  if (normalized.includes('/src/')) score += 4;
  for (const keyword of keywords) {
    if (normalized.includes(keyword)) score += 12;
  }
  score -= normalized.split('/').length;
  score -= filePath.length / 500;
  return score;
}

async function chooseSourceFile(packageDir, packageJson, advisory) {
  const keywords = buildKeywordList(mapAdvisoryToClass(advisory), `${advisory.summary || ''} ${advisory.details || ''}`);
  const candidates = [];
  if (packageJson.main) candidates.push(packageJson.main);
  if (packageJson.module) candidates.push(packageJson.module);
  candidates.push('index.js', 'lib/index.js', 'src/index.js', 'request.js');

  for (const rel of candidates) {
    const fullPath = path.join(packageDir, rel);
    if (await fileExists(fullPath)) {
      return fullPath;
    }
  }

  const files = await findCandidateSourceFiles(packageDir);
  if (files.length === 0) throw new Error('Could not find a JavaScript source file inside the downloaded target.');

  files.sort((a, b) => {
    const relA = path.relative(packageDir, a).replace(/\\/g, '/');
    const relB = path.relative(packageDir, b).replace(/\\/g, '/');
    return scoreSourceFile(a, relB, keywords, packageJson) - scoreSourceFile(b, relA, keywords, packageJson);
  });

  return files[files.length - 1];
}

async function installPackageDependencies(packageDir) {
  if (!(await fileExists(path.join(packageDir, 'package.json')))) return;

  if (process.platform === 'win32') {
    await execFileAsync(
      'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
      ['-NoProfile', '-Command', 'npm.cmd install --silent --omit=dev --ignore-scripts --legacy-peer-deps --no-audit --no-fund'],
      { cwd: packageDir, windowsHide: true }
    );
    return;
  }

  await execFileAsync('npm', ['install', '--silent', '--omit=dev', '--ignore-scripts', '--legacy-peer-deps', '--no-audit', '--no-fund'], {
    cwd: packageDir,
    windowsHide: true
  });
}

async function createWorkspaceFromArchive({ slug, artifactUrl, archiveType, reportStatus }) {
  const workspaceDir = path.join(DYNAMIC_ROOT, slug);
  await fsp.rm(workspaceDir, { recursive: true, force: true });
  await fsp.mkdir(workspaceDir, { recursive: true });

  const archivePath = path.join(workspaceDir, archiveType === 'zip' ? `${slug}.zip` : `${slug}.tgz`);
  const extractDir = path.join(workspaceDir, 'src');
  if (reportStatus) {
    await reportStatus({
      phase: 'download',
      message: `Downloading source archive for ${slug}`,
      progress: 36
    });
  }
  const archive = await fetchBuffer(artifactUrl, {
    headers: { 'User-Agent': 'Project-Praetorian' }
  });
  await fsp.writeFile(archivePath, archive);

  if (reportStatus) {
    await reportStatus({
      phase: 'extract',
      message: `Extracting package archive for ${slug}`,
      progress: 52
    });
  }
  if (archiveType === 'zip') {
    await extractZip(archivePath, extractDir);
  } else {
    await extractTarball(archivePath, extractDir);
  }

  const packageDir = await detectPackageRoot(extractDir);
  if (reportStatus) {
    await reportStatus({
      phase: 'install',
      message: `Installing runtime dependencies for ${slug}`,
      progress: 68
    });
  }
  await installPackageDependencies(packageDir);
  return { workspaceDir, packageDir };
}

async function buildNpmTarget(parsed, manualCve, reportStatus) {
  if (reportStatus) {
    await reportStatus({
      phase: 'metadata',
      message: `Fetching npm package metadata for ${parsed.packageName}`,
      progress: 18,
      packageName: parsed.packageName,
      inputKind: 'npm'
    });
  }
  const registry = await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(parsed.packageName)}`);
  const latestVersion = registry['dist-tags'] && registry['dist-tags'].latest;
  if (!latestVersion) throw new Error(`Could not determine the latest version for ${parsed.packageName}.`);

  if (reportStatus) {
    await reportStatus({
      phase: 'advisory',
      message: `Looking up advisory context for ${parsed.packageName}@${latestVersion}`,
      progress: 28,
      packageName: parsed.packageName
    });
  }
  const advisory = await chooseAdvisory(parsed.packageName, latestVersion, manualCve);
  const selectedVersion = chooseVulnerableRegistryVersion(registry, advisory, latestVersion);
  const versionMeta = registry.versions && registry.versions[selectedVersion];
  if (!versionMeta || !versionMeta.dist || !versionMeta.dist.tarball) {
    throw new Error(`Registry metadata for ${parsed.packageName}@${selectedVersion} is incomplete.`);
  }

  const slug = sanitizePackageKey(`${parsed.packageName}-${selectedVersion}`);
  const { workspaceDir, packageDir } = await createWorkspaceFromArchive({
    slug,
    artifactUrl: versionMeta.dist.tarball,
    archiveType: 'tgz',
    reportStatus
  });

  const packageJsonPath = path.join(packageDir, 'package.json');
  const packageJson = JSON.parse(await fsp.readFile(packageJsonPath, 'utf8'));
  if (reportStatus) {
    await reportStatus({
      phase: 'source',
      message: `Selecting the highest-confidence source file in ${parsed.packageName}`,
      progress: 84,
      packageName: parsed.packageName
    });
  }
  const sourcePath = await chooseSourceFile(packageDir, packageJson, advisory);

  return {
    packageName: parsed.packageName,
    version: selectedVersion,
    workspaceDir,
    packageDir,
    packageJson,
    sourcePath,
    advisory,
    inputKind: 'npm'
  };
}

async function buildGitHubTarget(parsed, manualCve, reportStatus) {
  if (reportStatus) {
    await reportStatus({
      phase: 'metadata',
      message: `Fetching GitHub metadata for ${parsed.owner}/${parsed.repo}`,
      progress: 18,
      packageName: parsed.displayName,
      inputKind: 'github'
    });
  }
  const repoMeta = await fetchJson(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`, {
    headers: { 'User-Agent': 'Project-Praetorian', 'Accept': 'application/vnd.github+json' }
  });
  const defaultBranch = repoMeta.default_branch || 'main';
  const zipUrl = `https://codeload.github.com/${parsed.owner}/${parsed.repo}/zip/refs/heads/${defaultBranch}`;
  const slug = sanitizePackageKey(`${parsed.owner}-${parsed.repo}-${defaultBranch}`);
  const { workspaceDir, packageDir } = await createWorkspaceFromArchive({
    slug,
    artifactUrl: zipUrl,
    archiveType: 'zip',
    reportStatus
  });

  const packageJsonPath = path.join(packageDir, 'package.json');
  const hasPackageJson = await fileExists(packageJsonPath);
  const packageJson = hasPackageJson
    ? JSON.parse(await fsp.readFile(packageJsonPath, 'utf8'))
    : { name: parsed.repo, version: defaultBranch };
  const inferredPackageName = packageJson.name || parsed.repo;
  const inferredVersion = packageJson.version || defaultBranch;
  if (reportStatus) {
    await reportStatus({
      phase: 'advisory',
      message: `Looking up advisory context for ${inferredPackageName}@${inferredVersion}`,
      progress: 28,
      packageName: inferredPackageName
    });
  }
  const advisory = await chooseAdvisory(packageJson.name || '', inferredVersion, manualCve);
  const vulnerableSnapshot = await resolveGitHubVulnerableSnapshot(parsed, advisory, reportStatus).catch(() => null);

  let activeWorkspaceDir = workspaceDir;
  let activePackageDir = packageDir;
  let activePackageJson = packageJson;

  if (vulnerableSnapshot && vulnerableSnapshot.parentSha) {
    const vulnerableSlug = sanitizePackageKey(`${parsed.owner}-${parsed.repo}-${vulnerableSnapshot.parentSha.slice(0, 12)}`);
    const vulnerableWorkspace = await createWorkspaceFromArchive({
      slug: vulnerableSlug,
      artifactUrl: vulnerableSnapshot.artifactUrl,
      archiveType: 'zip',
      reportStatus
    });
    activeWorkspaceDir = vulnerableWorkspace.workspaceDir;
    activePackageDir = vulnerableWorkspace.packageDir;

    const vulnerablePackageJsonPath = path.join(activePackageDir, 'package.json');
    const hasVulnerablePackageJson = await fileExists(vulnerablePackageJsonPath);
    activePackageJson = hasVulnerablePackageJson
      ? JSON.parse(await fsp.readFile(vulnerablePackageJsonPath, 'utf8'))
      : packageJson;
  }

  if (reportStatus) {
    await reportStatus({
      phase: 'source',
      message: `Selecting the highest-confidence source file in ${inferredPackageName}`,
      progress: 84,
      packageName: inferredPackageName
    });
  }
  const sourcePath = await chooseSourceFile(activePackageDir, activePackageJson, advisory);

  return {
    packageName: inferredPackageName,
    version: vulnerableSnapshot && vulnerableSnapshot.parentSha ? vulnerableSnapshot.parentSha : inferredVersion,
    workspaceDir: activeWorkspaceDir,
    packageDir: activePackageDir,
    packageJson: activePackageJson,
    sourcePath,
    advisory,
    inputKind: 'github',
    repoUrl: repoMeta.html_url || parsed.originalInput,
    defaultBranch,
    fixCommitUrl: vulnerableSnapshot && vulnerableSnapshot.fixCommitUrl ? vulnerableSnapshot.fixCommitUrl : null,
    sourceRef: vulnerableSnapshot && vulnerableSnapshot.parentSha ? vulnerableSnapshot.parentSha : defaultBranch
  };
}

async function buildCustomTarget({ input, cve }) {
  const startedAt = new Date().toISOString();
  await clearPreparationStatus();
  const reportStatus = (partial) => writePreparationStatus({
    startedAt,
    input,
    cve: cve || '',
    target: 'custom',
    ...partial
  });

  await reportStatus({
    phase: 'queued',
    message: 'Preparing custom target intake',
    progress: 4
  });

  try {
    const parsed = parsePackageInput(input);
    await reportStatus({
      phase: 'parsed',
      message: `Accepted ${parsed.kind === 'github' ? 'GitHub repository' : 'npm package'} input`,
      progress: 10,
      packageName: parsed.displayName,
      inputKind: parsed.kind
    });
    const built = parsed.kind === 'github'
      ? await buildGitHubTarget(parsed, cve, reportStatus)
      : await buildNpmTarget(parsed, cve, reportStatus);

    const advisoryId = cve || built.advisory.id || (Array.isArray(built.advisory.aliases) && built.advisory.aliases[0]) || 'UNSPECIFIED-ADVISORY';
    const advisoryText = [built.advisory.summary || `Security issue affecting ${built.packageName}.`, '', built.advisory.details || 'No advisory details were returned.'].join('\n');
    const cvePath = path.join(built.workspaceDir, 'advisory.txt');
    await fsp.writeFile(cvePath, `${advisoryText}\n`, 'utf8');

    const target = {
      key: 'custom',
      packageName: built.packageName,
      packageInput: input,
      inputKind: built.inputKind,
      ecosystem: 'npm',
      cve: advisoryId,
      severity: severityFromCvss(extractCvssScore(built.advisory)),
      affectedRange: built.version,
      vulnerableClass: mapAdvisoryToClass(built.advisory),
      vulnerableDir: built.packageDir,
      sourcePath: built.sourcePath,
      sourceRelPath: path.relative(built.packageDir, built.sourcePath).replace(/\\/g, '/'),
      cvePath,
      reportSummary: `\`${advisoryId}\` affects \`${built.packageName}\` around version ${built.version}. This custom target was ingested dynamically from ${built.inputKind} and attached to current advisory context.`,
      demoButtonLabel: 'Custom Package',
      dashboardSummary: `Custom package intake for ${built.packageName}. The Interregnum Protocol fetched the target source, attached advisory context, generated exploit and regression harnesses, and ran the same remediation pipeline used for built-in demos.`,
      dynamic: true,
      workspaceDir: built.workspaceDir,
      version: built.version,
      advisorySummary: built.advisory.summary || '',
      advisoryDetails: built.advisory.details || '',
      repoUrl: built.repoUrl || null,
      sourceRef: built.sourceRef || null,
      fixCommitUrl: built.fixCommitUrl || null
    };

    await reportStatus({
      phase: 'target',
      message: `Finalizing target configuration for ${built.packageName}`,
      progress: 92,
      packageName: built.packageName,
      cve: advisoryId
    });
    await fsp.writeFile(CURRENT_CUSTOM_TARGET_PATH, `${JSON.stringify(target, null, 2)}\n`, 'utf8');
    await reportStatus({
      phase: 'ready',
      message: `Custom target ready: ${built.packageName}`,
      progress: 100,
      status: 'complete',
      packageName: built.packageName,
      cve: advisoryId
    });
    return target;
  } catch (error) {
    await reportStatus({
      phase: 'failed',
      message: String(error && error.message ? error.message : error),
      progress: 100,
      status: 'error',
      error: String(error && error.message ? error.message : error)
    });
    throw error;
  }
}

async function readCurrentCustomTarget() {
  try {
    const raw = await fsp.readFile(CURRENT_CUSTOM_TARGET_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function updateCurrentCustomTargetSource(sourceFile) {
  const current = await readCurrentCustomTarget();
  if (!current) throw new Error('No current custom target is available to update.');
  const absolutePath = path.isAbsolute(sourceFile) ? sourceFile : path.join(ROOT_DIR, sourceFile);
  current.sourcePath = absolutePath;
  current.sourceRelPath = path.relative(current.vulnerableDir, absolutePath).replace(/\\/g, '/');
  await fsp.writeFile(CURRENT_CUSTOM_TARGET_PATH, `${JSON.stringify(current, null, 2)}\n`, 'utf8');
  return current;
}

function readCurrentCustomTargetSync() {
  try {
    return JSON.parse(fs.readFileSync(CURRENT_CUSTOM_TARGET_PATH, 'utf8'));
  } catch (_) {
    return null;
  }
}

module.exports = {
  DYNAMIC_ROOT,
  CURRENT_CUSTOM_TARGET_PATH,
  PREP_STATUS_PATH,
  buildCustomTarget,
  readCurrentCustomTarget,
  readCurrentCustomTargetSync,
  readPreparationStatus,
  writePreparationStatus,
  clearPreparationStatus,
  updateCurrentCustomTargetSource,
  parsePackageInput,
  parseNpmPackageInput(input) {
    const parsed = parsePackageInput(input);
    if (parsed.kind !== 'npm') {
      throw new Error('Input is not an npm package reference.');
    }
    return parsed.packageName;
  }
};
