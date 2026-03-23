#!/usr/bin/env node
'use strict';

require('./env_loader');

const path = require('node:path');
const { parseTargetFlag, parseInputFlag, parseCveFlag } = require('./target_config');

const HELP = `
  interregnum — The Interregnum Protocol CLI

  Usage:
    interregnum scan <target>          Run remediation on a built-in target (mixin-deep, set-value, request)
    interregnum scan --input <url>     Run remediation on a custom npm package or GitHub repo
    interregnum serve                  Start the dashboard server
    interregnum history                Show recent remediation runs
    interregnum help                   Show this help

  Options:
    --target <name>       Built-in target name
    --input <url|name>    Custom npm package name or GitHub repo URL
    --cve <CVE-ID>        Optional CVE identifier
    --demo                Use offline demo mode (no API credits)
    --provider <name>     LLM provider: openai, anthropic, xai (default: openai)
    --port <number>       Dashboard server port (default: 4173)

  Examples:
    interregnum scan --target mixin-deep --demo
    interregnum scan --input lodash --cve CVE-2021-23337
    interregnum scan --input https://github.com/request/request
    interregnum serve --port 3000
    interregnum history
`.trim();

async function runScan(argv) {
  const { main } = require('./run_pipeline');
  if (typeof main === 'function') {
    await main();
  } else {
    // Fallback: the module runs on require
    require('./run_pipeline');
  }
}

async function runServe(argv) {
  const portFlag = argv.indexOf('--port');
  if (portFlag !== -1 && argv[portFlag + 1]) {
    process.env.PORT = argv[portFlag + 1];
  }
  require('./dashboard/server');
}

async function runHistory() {
  try {
    const { listRuns } = require('./db');
    const runs = listRuns({ limit: 20 });
    if (runs.length === 0) {
      console.log('No remediation runs recorded yet.');
      return;
    }
    console.log(`\n  Recent Remediation Runs (${runs.length})\n`);
    console.log('  %-12s %-20s %-18s %-6s %-10s %-8s', 'Run ID', 'Package', 'CVE', 'Score', 'Resilience', 'Status');
    console.log('  ' + '-'.repeat(80));
    for (const run of runs) {
      const shortId = (run.run_id || '').slice(0, 12);
      console.log(
        '  %-12s %-20s %-18s %-6s %-10s %-8s',
        shortId,
        (run.package_name || '').slice(0, 20),
        (run.cve || 'N/A').slice(0, 18),
        run.confidence_score || 0,
        run.resilience_score || '0%',
        run.status || 'unknown'
      );
    }
    console.log();
  } catch (err) {
    console.error('Could not read run history:', err.message);
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0] || 'help';

  switch (command) {
    case 'scan':
      return runScan(argv.slice(1));
    case 'serve':
      return runServe(argv.slice(1));
    case 'history':
      return runHistory();
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP);
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.log(HELP);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
