#!/usr/bin/env node
/**
 * test_sources.js — Test every source in config/sources.json
 * Reports HTTP status, content size, and pass/fail for each.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

const TIMEOUT_MS = 15000;

function fetchHead(url) {
  return new Promise((resolve) => {
    const client = url.startsWith('https') ? https : http;
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AntiScamBot/1.0 Chrome/120';
    const req = client.get(url, {
      headers: { 'User-Agent': ua, 'Accept': '*/*' }
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        let next = res.headers.location;
        if (next.startsWith('/')) {
          const u = new URL(url);
          next = u.origin + next;
        }
        res.resume();
        return resolve(fetchHead(next));
      }
      let size = 0;
      res.on('data', (chunk) => { size += chunk.length; });
      res.on('end', () => {
        resolve({ status: res.statusCode, size, error: null });
      });
    });
    req.on('error', (err) => {
      resolve({ status: 0, size: 0, error: err.message });
    });
    req.setTimeout(TIMEOUT_MS, () => {
      req.destroy();
      resolve({ status: 0, size: 0, error: 'TIMEOUT' });
    });
  });
}

function getSourceUrl(src) {
  if (typeof src === 'string') return src;
  if (src.type === '165_article_api') return src.list.replace('{page}', '1');
  if (src.type === 'global_scam_merge') return null;
  return src.url || null;
}

function getSourceName(src) {
  if (typeof src === 'string') {
    if (src.startsWith('_')) return null; // section comment
    if (src.startsWith('file://')) return 'LOCAL: ' + src.replace('file://', '');
    try { return new URL(src).hostname; } catch { return src.slice(0, 60); }
  }
  return src.name || src.url || '(unknown)';
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

async function main() {
  const cfgPath = path.resolve(__dirname, 'config', 'sources.json');
  if (!fs.existsSync(cfgPath)) {
    console.error('ERROR: config/sources.json not found');
    process.exit(1);
  }
  const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
  const srcs = cfg.sources || [];

  const results = [];
  let pass = 0, fail = 0, skip = 0;

  console.log('Testing', srcs.length, 'source entries...\n');
  console.log(pad('Source', 45) + pad('Status', 10) + pad('Size', 12) + 'Result');
  console.log('-'.repeat(85));

  for (const src of srcs) {
    const name = getSourceName(src);
    if (!name) { skip++; continue; } // section comment strings

    const url = getSourceUrl(src);

    // Skip global_scam_merge
    if (!url) {
      console.log(pad(name, 45) + pad('--', 10) + pad('--', 12) + 'SKIP (merge)');
      skip++;
      continue;
    }

    // File:// local check
    if (url.startsWith('file://')) {
      const fpath = path.resolve(__dirname, url.replace('file://./', ''));
      const exists = fs.existsSync(fpath);
      const stat = exists ? 'EXISTS' : 'MISSING';
      const sz = exists ? formatBytes(fs.statSync(fpath).size) : '--';
      const verdict = exists ? 'PASS' : 'WARN';
      if (exists) pass++; else fail++;
      console.log(pad(name, 45) + pad(stat, 10) + pad(sz, 12) + verdict);
      results.push({ name, verdict });
      continue;
    }

    // HTTP fetch
    const r = await fetchHead(url);
    let verdict;
    if (r.error) {
      verdict = 'FAIL';
      fail++;
      console.log(pad(name, 45) + pad(r.error, 10) + pad('--', 12) + '\x1b[31mFAIL\x1b[0m (' + r.error + ')');
    } else if (r.status === 200) {
      verdict = 'PASS';
      pass++;
      console.log(pad(name, 45) + pad(String(r.status), 10) + pad(formatBytes(r.size), 12) + '\x1b[32mPASS\x1b[0m');
    } else {
      verdict = 'FAIL';
      fail++;
      console.log(pad(name, 45) + pad(String(r.status), 10) + pad(formatBytes(r.size), 12) + '\x1b[31mFAIL\x1b[0m (HTTP ' + r.status + ')');
    }
    results.push({ name, verdict, status: r.status, size: r.size, error: r.error });
  }

  console.log('-'.repeat(85));
  console.log(`\nSummary: \x1b[32m${pass} PASS\x1b[0m / \x1b[31m${fail} FAIL\x1b[0m / ${skip} SKIP  (${srcs.length} total entries)`);

  if (fail > 0) {
    console.log('\nFailed sources:');
    for (const r of results) {
      if (r.verdict === 'FAIL' || r.verdict === 'WARN') {
        console.log('  - ' + r.name + (r.error ? ' (' + r.error + ')' : '') + (r.status ? ' (HTTP ' + r.status + ')' : ''));
      }
    }
  }
}

function pad(s, len) {
  s = String(s);
  return s.length >= len ? s.slice(0, len - 1) + ' ' : s + ' '.repeat(len - s.length);
}

main().catch(e => { console.error(e); process.exit(1); });
