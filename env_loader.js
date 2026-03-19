'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ENV_PATHS = [
  path.join(__dirname, '.env.local'),
  path.join(__dirname, '.env'),
  path.join(__dirname, 'dashboard', '.env.local'),
  path.join(__dirname, 'dashboard', '.env')
];

function stripWrappingQuotes(value) {
  const trimmed = String(value || '').trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseEnvLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed || trimmed.startsWith('#')) return null;

  const standardMatch = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
  if (standardMatch) {
    return {
      key: standardMatch[1],
      value: stripWrappingQuotes(standardMatch[2])
    };
  }

  const powerShellMatch = trimmed.match(/^\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/i);
  if (powerShellMatch) {
    return {
      key: powerShellMatch[1],
      value: stripWrappingQuotes(powerShellMatch[2])
    };
  }

  return null;
}

function loadLocalEnv() {
  for (const filePath of ENV_PATHS) {
    if (!fs.existsSync(filePath)) continue;
    const raw = fs.readFileSync(filePath, 'utf8');
    for (const line of raw.split(/\r?\n/u)) {
      const parsed = parseEnvLine(line);
      if (!parsed || process.env[parsed.key]) continue;
      process.env[parsed.key] = parsed.value;
    }
  }
}

loadLocalEnv();

module.exports = {
  loadLocalEnv
};
