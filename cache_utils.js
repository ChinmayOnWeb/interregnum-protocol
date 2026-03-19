'use strict';

const fs = require('node:fs/promises');
const crypto = require('node:crypto');

async function readJsonOrNull(filePath) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function safeReadFile(filePath) {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return '';
    }
    throw error;
  }
}

async function createContentSignature(parts) {
  const hash = crypto.createHash('sha1');
  for (const part of parts) {
    hash.update(String(part || ''));
    hash.update('\n---\n');
  }
  return hash.digest('hex');
}

async function readCachedArtifact(filePath, signature) {
  const parsed = await readJsonOrNull(filePath);
  if (!parsed || parsed.signature !== signature) {
    return null;
  }
  return parsed;
}

module.exports = {
  readJsonOrNull,
  safeReadFile,
  createContentSignature,
  readCachedArtifact
};
