#!/usr/bin/env node
/**
 * test_background.js — End-to-end smoke test for background.js logic
 * Simulates real user scenarios: Google search, bank login, scam sites, etc.
 * Run: node test_background.js
 */

// ---- Copy logic from background.js (no chrome API dependency) ----

const riskyTokens = ['airdrop','seed-phrase','claim-reward'];
const riskyIfSuspiciousDomain = [
  'login','verify','secure','support','limited',
  'refund','bonus','wallet','gift',
  '客服','驗證','投資','私訊','限時','贈品','錢包','返利','出金','入金','博弈','合約','交易所'
];
const homographMap = {'0':'o','1':'l','3':'e','@':'a','$':'s'};
const famous = ['paypal','apple','google','microsoft','binance','metamask','bankofamerica'];

function normalizeHost(h){ return (h||'').replace(/^www\./,'').toLowerCase(); }

const twoPartTLDs = new Set([
  'com.tw','net.tw','org.tw','edu.tw','gov.tw','idv.tw',
  'com.hk','net.hk','org.hk','edu.hk','gov.hk',
  'com.cn','net.cn','org.cn','gov.cn','edu.cn',
  'co.uk','org.uk','ac.uk','gov.uk',
  'com.au','net.au','org.au','edu.au','gov.au',
  'co.jp','or.jp','ne.jp','ac.jp','go.jp',
  'co.kr','or.kr','ne.kr','ac.kr','go.kr',
  'com.sg','net.sg','org.sg','edu.sg','gov.sg',
  'com.my','net.my','org.my','edu.my','gov.my',
  'com.ph','net.ph','org.ph','edu.ph','gov.ph',
  'co.th','or.th','ac.th','go.th','in.th',
  'com.vn','net.vn','org.vn','edu.vn','gov.vn',
  'co.id','or.id','ac.id','go.id','web.id',
  'com.br','net.br','org.br','edu.br','gov.br',
  'co.in','net.in','org.in','ac.in','gov.in',
  'co.za','org.za','ac.za','gov.za','net.za',
  'co.nz','net.nz','org.nz','ac.nz','govt.nz',
  'com.mx','net.mx','org.mx','edu.mx','gob.mx'
]);
function baseDomain(host){
  const p = (host||'').toLowerCase().split('.');
  if(p.length <= 2) return (host||'').toLowerCase();
  const last2 = p.slice(-2).join('.');
  if(twoPartTLDs.has(last2) && p.length >= 3) return p.slice(-3).join('.');
  return last2;
}

function looksLikeHomograph(h){ const b=(h||'').toLowerCase(); const r=b.split('').map(c=>homographMap[c]||c).join(''); return famous.some(x=>r.includes(x)&&!b.includes(x)); }
function tooDeepSubdomain(h){ return (h||'').split('.').length>=5; }
function isSuspiciousDomain(h){ return /(^|\.)(top|xyz|buzz|click|club|icu|loan|work|gq|ml|tk|cf|ga|cn\.com|pages\.dev|workers\.dev|duckdns\.org|000webhostapp\.com|weebly\.com|blogspot\.com)$/i.test(h||''); }

const searchEngines = new Set(['google.com','google.com.tw','google.co.jp','google.com.hk','google.co.uk','google.com.au','bing.com','yahoo.com','tw.yahoo.com','duckduckgo.com','baidu.com','search.yahoo.com','ecosia.org','yandex.com','naver.com']);
function hasRiskyPath(u, host){
  const b = baseDomain(host);
  const skipSearch = searchEngines.has(host) || searchEngines.has(b);
  let raw = (u.pathname||'') + (skipSearch ? '' : (u.search||''));
  try { raw = decodeURIComponent(raw); } catch {}
  const s = raw.toLowerCase();
  if(riskyTokens.some(k => s.includes(k))) return true;
  if(riskyIfSuspiciousDomain.some(k => s.includes(k)) && isSuspiciousDomain(host)) return true;
  return false;
}
function isShortener(h){ return /(^|\.)((bit\.ly|t\.co|goo\.gl|tinyurl\.com|ow\.ly|is\.gd|cutt\.ly|rebrand\.ly))$/i.test(h||''); }

// Simulate blocklist check with actual data
const fs = require('fs');
const blocklistPath = __dirname + '/data/blocklist.json';
let blocklistSet = new Set();
try {
  const j = JSON.parse(fs.readFileSync(blocklistPath, 'utf8'));
  const domains = j.phishing_domains || j;
  if(Array.isArray(domains)) blocklistSet = new Set(domains.map(s=>String(s).toLowerCase()));
} catch(e) {
  console.warn('[WARN] Could not load blocklist.json, blocklist tests will be skipped');
}

function checkUrl(urlStr){
  try {
    const u = new URL(urlStr);
    const host = normalizeHost(u.host);
    const b = baseDomain(host);
    // Blocklist check
    if(blocklistSet.has(host) || blocklistSet.has(b)){
      return { level:'warn', reasons:['BLACKLIST'] };
    }
    let reasons = [];
    if(looksLikeHomograph(host)) reasons.push('HOMO');
    if(tooDeepSubdomain(host)) reasons.push('DEEP_SUB');
    if(hasRiskyPath(u, host)) reasons.push('RISKY_PATH');
    if(isShortener(host)) reasons.push('SHORT_URL');
    return { level: reasons.length ? 'warn' : 'ok', reasons };
  } catch {
    return { level:'warn', reasons:['BAD_FORMAT'] };
  }
}

// ---- Test Cases ----

const tests = [
  // === SHOULD PASS (not blocked) ===
  // Google search with sensitive keywords
  ['ok', 'https://www.google.com.tw/search?q=詐騙網站', 'Google TW 搜尋「詐騙網站」'],
  ['ok', 'https://www.google.com/search?q=投資理財', 'Google 搜尋「投資理財」'],
  ['ok', 'https://www.google.com/search?q=錢包推薦', 'Google 搜尋「錢包推薦」'],
  ['ok', 'https://www.google.com.tw/search?q=客服電話', 'Google TW 搜尋「客服電話」'],
  ['ok', 'https://www.google.com/search?q=博弈產業分析', 'Google 搜尋「博弈」'],
  ['ok', 'https://www.bing.com/search?q=出金教學', 'Bing 搜尋「出金」'],
  ['ok', 'https://duckduckgo.com/?q=verify+email', 'DDG 搜尋 verify'],
  ['ok', 'https://search.yahoo.com/search?p=wallet+review', 'Yahoo 搜尋 wallet'],

  // Legitimate sites with login/verify/support paths
  ['ok', 'https://www.homeplus.net.tw/cable/member/login-page', 'Homeplus 登入頁'],
  ['ok', 'https://accounts.google.com/v3/signin/identifier', 'Google 登入'],
  ['ok', 'https://www.facebook.com/login/', 'Facebook 登入'],
  ['ok', 'https://appleid.apple.com/account/verify', 'Apple ID 驗證'],
  ['ok', 'https://support.apple.com/zh-tw', 'Apple 客服'],
  ['ok', 'https://bank.com.tw/secure/transfer', '銀行轉帳頁'],
  ['ok', 'https://www.104.com.tw/company/support', '104 客服'],
  ['ok', 'https://shopee.tw/buyer/login', 'Shopee 登入'],
  ['ok', 'https://www.amazon.com/gp/css/order-history/ref=refund', 'Amazon 退款紀錄'],
  ['ok', 'https://crypto.com/exchange/wallet', 'Crypto.com 錢包'],

  // Legitimate sites with Chinese path keywords
  ['ok', 'https://www.cathayholdings.com/investment/投資理財', '國泰投資專區'],
  ['ok', 'https://shopee.tw/search?keyword=錢包', 'Shopee 搜尋錢包'],
  ['ok', 'https://www.104.com.tw/客服中心/', '104 客服中心'],
  ['ok', 'https://www.eslite.com/product/贈品/', '誠品贈品頁'],

  // Major sites should NOT be blocklisted
  ['ok', 'https://www.google.com/', 'Google 首頁'],
  ['ok', 'https://www.facebook.com/', 'Facebook 首頁'],
  ['ok', 'https://www.youtube.com/', 'YouTube 首頁'],
  ['ok', 'https://github.com/', 'GitHub 首頁'],
  ['ok', 'https://www.paypal.com/', 'PayPal 首頁'],
  ['ok', 'https://www.instagram.com/', 'Instagram 首頁'],
  ['ok', 'https://www.amazon.com/', 'Amazon 首頁'],
  ['ok', 'https://www.linkedin.com/', 'LinkedIn 首頁'],
  ['ok', 'https://line.me/', 'LINE 首頁'],
  ['ok', 'https://www.yahoo.com/', 'Yahoo 首頁'],

  // === SHOULD BLOCK ===
  // Suspicious TLD with risky path
  ['warn', 'https://evil-bank.xyz/login', '可疑 TLD + login'],
  ['warn', 'https://free-gift.top/verify-account', '可疑 TLD + verify'],
  ['warn', 'https://scam.pages.dev/support', '可疑 TLD + support'],
  ['warn', 'https://phish.duckdns.org/secure/wallet', '可疑 TLD + secure'],
  ['warn', 'https://fake.000webhostapp.com/投資/', '可疑 TLD + 投資'],
  ['warn', 'https://scam.icu/客服/', '可疑 TLD + 客服'],

  // Always-block tokens (any domain)
  ['warn', 'https://anything.com/free-airdrop', 'airdrop 一律擋'],
  ['warn', 'https://normal.org/enter-seed-phrase', 'seed-phrase 一律擋'],
  ['warn', 'https://legit.io/claim-reward-now', 'claim-reward 一律擋'],

  // Homograph attacks
  ['warn', 'https://paypa1.com/', 'paypal homograph (1→l)'],
  ['warn', 'https://g00gle.com/', 'google homograph (0→o)'],
  ['warn', 'https://micr0soft.com/', 'microsoft homograph'],

  // Deep subdomains
  ['warn', 'https://a.b.c.d.evil.com/', '5-level subdomain'],

  // URL shorteners
  ['warn', 'https://bit.ly/abc123', 'bit.ly 短網址'],
  ['warn', 'https://t.co/xyz', 't.co 短網址'],
  ['warn', 'https://tinyurl.com/test', 'tinyurl 短網址'],
];

// ---- Run Tests ----

let pass = 0, fail = 0;
const failures = [];

for (const [expected, url, desc] of tests) {
  const result = checkUrl(url);
  const got = result.level;
  const ok = got === expected;
  if (ok) {
    pass++;
    console.log(`  \x1b[32m✓\x1b[0m ${desc}`);
  } else {
    fail++;
    console.log(`  \x1b[31m✗\x1b[0m ${desc}  (expected ${expected}, got ${got} [${result.reasons.join(',')}])`);
    failures.push({ desc, url, expected, got, reasons: result.reasons });
  }
}

console.log(`\n${'='.repeat(60)}`);
console.log(`Results: \x1b[32m${pass} PASS\x1b[0m / \x1b[31m${fail} FAIL\x1b[0m  (${tests.length} total)`);

if (failures.length) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  ${f.desc}`);
    console.log(`    URL: ${f.url}`);
    console.log(`    Expected: ${f.expected}, Got: ${f.got} [${f.reasons.join(', ')}]`);
  }
}

process.exit(fail > 0 ? 1 : 0);
