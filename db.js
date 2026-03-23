'use strict';

const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = path.join(__dirname, 'praetorian.db');

let _db = null;

function getDb() {
  if (_db) return _db;
  try {
    const Database = require('better-sqlite3');
    _db = new Database(DB_PATH);
    _db.pragma('journal_mode = WAL');
    _db.pragma('foreign_keys = ON');
    _db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT UNIQUE NOT NULL,
        target TEXT NOT NULL,
        package_name TEXT NOT NULL,
        cve TEXT,
        mode TEXT DEFAULT 'live',
        started_at TEXT,
        finished_at TEXT,
        duration_ms INTEGER DEFAULT 0,
        status TEXT DEFAULT 'running',
        confidence_score INTEGER DEFAULT 0,
        resilience_score TEXT DEFAULT '0%',
        patch_quality_score INTEGER DEFAULT 0,
        speed_score INTEGER DEFAULT 0,
        full_payload TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_runs_package ON runs(package_name);
      CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at);
    `);
    return _db;
  } catch (err) {
    console.warn('[db] better-sqlite3 not available, run history disabled:', err.message);
    return null;
  }
}

function generateRunId() {
  return `run_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

function insertRun(data) {
  const db = getDb();
  if (!db) return null;
  const runId = data.runId || generateRunId();
  const stmt = db.prepare(`
    INSERT INTO runs (run_id, target, package_name, cve, mode, started_at, finished_at, duration_ms, status, confidence_score, resilience_score, patch_quality_score, speed_score, full_payload)
    VALUES (@run_id, @target, @package_name, @cve, @mode, @started_at, @finished_at, @duration_ms, @status, @confidence_score, @resilience_score, @patch_quality_score, @speed_score, @full_payload)
  `);
  stmt.run({
    run_id: runId,
    target: data.target || 'unknown',
    package_name: data.packageName || data.package_name || 'unknown',
    cve: data.cve || null,
    mode: data.mode || 'live',
    started_at: data.startedAt || data.started_at || new Date().toISOString(),
    finished_at: data.finishedAt || data.finished_at || null,
    duration_ms: data.durationMs || data.duration_ms || 0,
    status: data.status || 'complete',
    confidence_score: data.confidenceScore || data.confidence_score || 0,
    resilience_score: String(data.resilienceScore || data.resilience_score || '0%'),
    patch_quality_score: data.patchQualityScore || data.patch_quality_score || 0,
    speed_score: data.speedScore || data.speed_score || 0,
    full_payload: typeof data.fullPayload === 'string' ? data.fullPayload : JSON.stringify(data.fullPayload || data.full_payload || {})
  });
  return runId;
}

function getRun(runId) {
  const db = getDb();
  if (!db) return null;
  const row = db.prepare('SELECT * FROM runs WHERE run_id = ?').get(runId);
  if (!row) return null;
  return parseRow(row);
}

function listRuns({ limit = 50, offset = 0 } = {}) {
  const db = getDb();
  if (!db) return [];
  const rows = db.prepare('SELECT * FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
  return rows.map(parseRow);
}

function getRunsByPackage(packageName, limit = 20) {
  const db = getDb();
  if (!db) return [];
  const rows = db.prepare('SELECT * FROM runs WHERE package_name = ? ORDER BY created_at DESC LIMIT ?').all(packageName, limit);
  return rows.map(parseRow);
}

function getRunCount() {
  const db = getDb();
  if (!db) return 0;
  const row = db.prepare('SELECT COUNT(*) as count FROM runs').get();
  return row ? row.count : 0;
}

function parseRow(row) {
  let fullPayload = {};
  try {
    fullPayload = JSON.parse(row.full_payload || '{}');
  } catch (_) { /* ignore */ }
  return { ...row, full_payload: fullPayload };
}

module.exports = {
  getDb,
  insertRun,
  getRun,
  listRuns,
  getRunsByPackage,
  getRunCount,
  generateRunId
};
