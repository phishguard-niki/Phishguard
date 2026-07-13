// background.js (v0.5.1)
const APP_VERSION = '0.5.1';

// --- v0.5.0: shards fetched on-demand from GitHub blocklist-data repo ---
// (Was bundled in data/blocklist-shards/, but 60MB+ exceeds Chrome Web Store
// practical limits and would make daily blocklist refresh dependent on extension
// re-publish.) Now mirrors the on-demand pattern from openclaw-skill/lib/check_url.py.
const GITHUB_SHARDS_BASE = 'https://raw.githubusercontent.com/phishguard-niki/blocklist-data/main';
const SHARD_TTL_MS = 60 * 60 * 1000;  // 1 hour fresh; stale-while-error fallback
const SHARDS_CACHE_NAME = 'phishguard-shards-v1';

// --- Fix #1: risky tokens split into always-flag vs suspicious-domain-only ---
// Always flag — these almost exclusively appear in scam contexts
const riskyTokens = ['airdrop','seed-phrase','claim-reward'];
// Only flag when domain TLD is suspicious
const riskyIfSuspiciousDomain = [
  'login','verify','secure','support','limited',
  'refund','bonus','wallet','gift',
  '客服','驗證','投資','私訊','限時','贈品','錢包','返利','出金','入金','博弈','合約','交易所'
];

const homographMap = {'0':'o','1':'l','3':'e','@':'a','$':'s'};
// Cyrillic confusable characters (used in IDN homograph attacks)
const cyrillicMap = {'\u0430':'a','\u0435':'e','\u043e':'o','\u0440':'p','\u0441':'c','\u0443':'y','\u0445':'x','\u0456':'i'};
const famous = ['paypal','apple','google','microsoft','binance','metamask','bankofamerica'];

function normalizeHost(h){ return (h||'').replace(/^www\./,'').toLowerCase(); }

// --- Fix #3: baseDomain handles ccTLDs (.com.tw, .co.uk, etc.) ---
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
function hasCyrillicConfusable(h){ return (h||'').split('').some(c => c in cyrillicMap); }
function isIPAddress(h){ return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h||''); }
function isTooLongDomain(h){ return (h||'').length > 50; }
function tooDeepSubdomain(h){ return (h||'').split('.').length>=5; }
function isSuspiciousDomain(h){ return /(^|\.)(top|xyz|buzz|click|club|icu|loan|work|gq|ml|tk|cf|ga|cn\.com|pages\.dev|workers\.dev|duckdns\.org|000webhostapp\.com|weebly\.com|blogspot\.com)$/i.test(h||''); }
const searchEngines = new Set(['google.com','google.com.tw','google.co.jp','google.com.hk','google.co.uk','google.com.au','bing.com','yahoo.com','tw.yahoo.com','duckduckgo.com','baidu.com','search.yahoo.com','ecosia.org','yandex.com','naver.com']);
function hasRiskyPath(u, host){
  // Skip query string for search engines — user's search terms are not risky signals
  const b = baseDomain(host);
  const skipSearch = searchEngines.has(host) || searchEngines.has(b);
  // Decode URI so Chinese characters like %E6%8A%95%E8%B3%87 → 投資 can be matched
  let raw = (u.pathname||'') + (skipSearch ? '' : (u.search||''));
  try { raw = decodeURIComponent(raw); } catch {}
  const s = raw.toLowerCase();
  if(riskyTokens.some(k => s.includes(k))) return true;
  if(riskyIfSuspiciousDomain.some(k => s.includes(k)) && isSuspiciousDomain(host)) return true;
  return false;
}
function isShortener(h){ return /(^|\.)((bit\.ly|t\.co|goo\.gl|tinyurl\.com|ow\.ly|is\.gd|cutt\.ly|rebrand\.ly))$/i.test(h||''); }
async function getSettings(){ return new Promise(r=>chrome.storage.local.get({ asg_lang:null, asg_scanImages:true, asg_warnShortUrl:true, asg_showBanner:true, asg_interstitial:'C', asg_customBlocklist:[] }, r)); }

// --- v0.5.0: per-shard lazy load, GitHub on-demand + Cache API L2 + stale fallback ---
// Layer 1: in-memory Map (lives for the duration of the service worker)
// Layer 2: Cache API (persists across SW restarts, no quota issue like chrome.storage)
// Layer 3: stale-cache fallback if GitHub fetch fails (offline / rate-limited)
let shardIndex = null;
const shardCache = {};

async function _fetchJsonCached(url, ttlMs){
  const cache = await caches.open(SHARDS_CACHE_NAME);
  const cached = await cache.match(url);
  if(cached){
    const cachedAt = parseInt(cached.headers.get('x-pg-cached-at') || '0', 10);
    if(Date.now() - cachedAt < ttlMs){
      return cached.json();
    }
  }
  try{
    const resp = await fetch(url, { cache: 'no-store' });
    if(!resp.ok) throw new Error('HTTP ' + resp.status);
    const text = await resp.text();
    // Store with our own timestamp header so we can manage TTL ourselves
    const cacheable = new Response(text, {
      headers: {
        'content-type': 'application/json',
        'x-pg-cached-at': String(Date.now())
      }
    });
    await cache.put(url, cacheable);
    return JSON.parse(text);
  }catch(e){
    if(cached){
      console.warn('[ASG] Fetch failed, falling back to stale cache for', url, e?.message);
      return cached.json();
    }
    throw e;
  }
}

async function loadShardIndex(){
  if(shardIndex) return shardIndex;
  try{
    shardIndex = await _fetchJsonCached(GITHUB_SHARDS_BASE + '/index.json', SHARD_TTL_MS);
  }catch(e){
    console.warn('[ASG] shard index unavailable:', e?.message);
    shardIndex = {};
  }
  return shardIndex;
}

async function loadShard(letter){
  if(shardCache[letter]) return shardCache[letter];
  const idx = await loadShardIndex();
  const file = idx[letter];
  if(!file){ shardCache[letter] = new Set(); return shardCache[letter]; }
  try{
    const obj = await _fetchJsonCached(GITHUB_SHARDS_BASE + '/' + file, SHARD_TTL_MS);
    const domains = Array.isArray(obj.domains) ? obj.domains : (Array.isArray(obj) ? obj : []);
    shardCache[letter] = new Set(domains.map(s => String(s).toLowerCase()));
  }catch(e){
    console.warn('[ASG] shard ' + letter + ' unavailable:', e?.message);
    shardCache[letter] = new Set();
  }
  return shardCache[letter];
}

function shardKey(domain){
  const c = (domain||'')[0];
  return (c >= 'a' && c <= 'z') ? c : 'other';
}

// --- Blocklist whitelist: legit domains that may appear in phishing feeds ---
const _blocklistWhitelist = new Set([
  'crypto.com','coinbase.com','binance.com','kraken.com',
  'blockchain.com','ledger.com','trezor.io','trust.com',
  'google.com','facebook.com','youtube.com','instagram.com',
  'twitter.com','x.com','apple.com','microsoft.com',
  'amazon.com','github.com','linkedin.com','netflix.com',
  'yahoo.com','bing.com','wikipedia.org','line.me',
  'shopee.tw','pchome.com.tw','paypal.com',
  // Taiwan financial / brokerage / news sites (often false-positive flagged)
  'moneydj.com','cnyes.com','histock.tw','wantgoo.com',
  'moneylink.com.tw','sinotrade.com.tw','esunsec.com.tw',
  'fubon.com','yuanta.com.tw','cathaysec.com.tw',
  'ctbcsec.com','kgieworld.com','capital.com.tw'
]);

async function isInBuiltinBlocklist(host, base){
  if(_blocklistWhitelist.has(host) || _blocklistWhitelist.has(base)) return false;
  const keys = new Set([shardKey(host), shardKey(base)]);
  for(const k of keys){
    const shard = await loadShard(k);
    if(shard.has(host) || shard.has(base)) return true;
  }
  return false;
}

// --- Google Safe Browsing API: real-time phishing detection ---
const _sbCache = new Map(); // domain → { timestamp, threat }
const SB_CACHE_TTL = 3600000;      // 1 hour for threats
const SB_SAFE_CACHE_TTL = 86400000; // 24 hours for safe results
const SB_TIMEOUT = 500;             // 500ms max wait
const SB_DAILY_LIMIT = 10000;
const _sbSkipDomains = new Set([
  'google.com','google.com.tw','facebook.com','youtube.com','instagram.com',
  'twitter.com','x.com','apple.com','microsoft.com','amazon.com','github.com',
  'linkedin.com','netflix.com','yahoo.com','bing.com','wikipedia.org',
  'line.me','shopee.tw','pchome.com.tw','gov.tw','edu.tw'
]);

async function _sbGetDailyCount(){
  return new Promise(r => chrome.storage.local.get(['_sb_date','_sb_count'], d => {
    const today = new Date().toISOString().slice(0,10);
    if(d._sb_date === today) r(d._sb_count || 0);
    else { chrome.storage.local.set({_sb_date: today, _sb_count: 0}); r(0); }
  }));
}
async function _sbIncrementCount(){
  const count = await _sbGetDailyCount();
  chrome.storage.local.set({_sb_count: count + 1});
}

async function checkGoogleSafeBrowsing(urlStr){
  try{
    const u = new URL(urlStr);
    const host = normalizeHost(u.host);
    const b = baseDomain(host);

    // Skip well-known safe domains
    if(_sbSkipDomains.has(host) || _sbSkipDomains.has(b)) return null;

    // Check cache
    const cached = _sbCache.get(host);
    if(cached && Date.now() - cached.timestamp < (cached.threat ? SB_CACHE_TTL : SB_SAFE_CACHE_TTL)){
      return cached.threat;
    }

    // Check daily quota
    const count = await _sbGetDailyCount();
    if(count >= SB_DAILY_LIMIT){
      console.debug('[SB] Daily quota reached, skipping API call');
      return null;
    }

    // Try Lookup API if user has API key
    const cfg = await new Promise(r => chrome.storage.local.get({asg_sb_apikey: ''}, r));
    const apiKey = cfg.asg_sb_apikey;

    if(apiKey){
      // Google Safe Browsing Lookup API v4
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), SB_TIMEOUT);
      try{
        const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          signal: controller.signal,
          body: JSON.stringify({
            client: { clientId: 'phishguard', clientVersion: APP_VERSION },
            threatInfo: {
              threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: urlStr }]
            }
          })
        });
        clearTimeout(timer);
        await _sbIncrementCount();
        const data = await resp.json();
        const threat = (data.matches && data.matches.length > 0) ? data.matches[0].threatType : null;
        _sbCache.set(host, { timestamp: Date.now(), threat });
        return threat;
      }catch(e){
        clearTimeout(timer);
        console.debug('[SB] Lookup API error:', e?.message);
        return null;
      }
    }

    // No API key: Safe Browsing requires an API key for threat lookups.
    // Without one, we rely on blocklist + heuristic detection only.
    return null;
  }catch{
    return null;
  }
}

async function checkUrlRiskWithLists(urlStr){
  const cfg = await getSettings();
  const custom = new Set((cfg.asg_customBlocklist||[]).map(s=>String(s).toLowerCase()));
  try{
    const u = new URL(urlStr);
    const host = normalizeHost(u.host);
    const b = baseDomain(host);
    if(custom.has(host) || custom.has(b) || await isInBuiltinBlocklist(host, b)){
      return { level:'warn', reasonKeys:['BLACKLIST'], suggestionKey:'URL_SUGGESTION', fromList:true };
    }
    // Run heuristics + Safe Browsing API in parallel
    let level='ok', reasonKeys=[];
    if(looksLikeHomograph(host)){ reasonKeys.push('HOMO'); level='warn'; }
    if(hasCyrillicConfusable(host)){ reasonKeys.push('CYRILLIC'); level='warn'; }
    if(tooDeepSubdomain(host)){ reasonKeys.push('DEEP_SUB'); level='warn'; }
    if(isIPAddress(host)){ reasonKeys.push('IP_ADDR'); level='warn'; }
    if(isTooLongDomain(host)){ reasonKeys.push('LONG_DOMAIN'); level='warn'; }
    if(hasRiskyPath(u, host)){ reasonKeys.push('RISKY_PATH'); level='warn'; }
    if(cfg.asg_warnShortUrl && isShortener(host)){ reasonKeys.push('SHORT_URL'); level='warn'; }

    // Google Safe Browsing real-time check (non-blocking)
    try{
      const sbThreat = await checkGoogleSafeBrowsing(urlStr);
      if(sbThreat){
        reasonKeys.push('SAFE_BROWSING');
        level = 'warn';
        console.log(`[SB] Threat detected: ${sbThreat} for ${host}`);
      }
    }catch{}

    return { level, reasonKeys, suggestionKey:'URL_SUGGESTION', fromList:false, fromRealTime: reasonKeys.includes('SAFE_BROWSING') };
  }catch{
    return { level:'warn', reasonKeys:['BAD_FORMAT'], suggestionKey:'URL_SUGGESTION', fromList:false };
  }
}

// --- Fix: debounce scanTab to prevent race conditions from multiple listeners ---
const _scanPending = new Map();

async function scanTab(tabId, url){
  // Debounce: if same tab scanned within 500ms, skip
  const now = Date.now();
  const last = _scanPending.get(tabId);
  if(last && now - last < 500) return;
  _scanPending.set(tabId, now);

  const cfg = await getSettings();
  const payload = await checkUrlRiskWithLists(url);
  if(payload.level === 'ok') return;
  try{
    await chrome.scripting.executeScript({ target:{tabId, allFrames:true}, files:['content/overlay.js']});
    await chrome.scripting.insertCSS({ target:{tabId, allFrames:true}, files:['ui/overlay.css']});
    await chrome.scripting.executeScript({ target:{tabId, allFrames:false}, func:(p)=>{ window.__ASG_showWarning&&window.__ASG_showWarning(p); }, args:[payload] });
    const lang = (cfg.asg_lang || ((navigator.language||'').toLowerCase().startsWith('zh')?'zh-TW':'en'));
    if(cfg.asg_interstitial==='C'){
      await chrome.scripting.executeScript({ target:{tabId, allFrames:true}, files:['content/interstitial.js']});
      await chrome.scripting.insertCSS({ target:{tabId, allFrames:true}, files:['ui/interstitial.css']});
      const iSource = payload.fromList ? 'list' : (payload.fromRealTime ? 'realtime' : 'heuristic');
      await chrome.scripting.executeScript({ target:{tabId, allFrames:false}, func:(l,s)=>{ window.__ASG_showInterstitial&&window.__ASG_showInterstitial({ lang:l, source:s }); }, args:[lang, iSource] });
    }else if(cfg.asg_showBanner){
      await chrome.scripting.executeScript({ target:{tabId, allFrames:true}, files:['content/banner.js']});
      await chrome.scripting.insertCSS({ target:{tabId, allFrames:true}, files:['ui/banner.css']});
      await chrome.scripting.executeScript({ target:{tabId, allFrames:false}, func:(l)=>{ window.__ASG_showBanner&&window.__ASG_showBanner({ lang:l }); }, args:[lang] });
    }
  }catch(e){
    // --- Fix: fallback — inject via tabs API if chrome.scripting fails (Safari compat) ---
    console.warn('scripting.executeScript failed, trying tabs.executeScript fallback:', e?.message);
    try{
      if(typeof chrome.tabs?.executeScript === 'function'){
        chrome.tabs.executeScript(tabId, { file:'content/overlay.js', allFrames:true });
        chrome.tabs.insertCSS(tabId, { file:'ui/overlay.css', allFrames:true });
      }
    }catch(e2){ console.debug('Fallback also failed:', e2?.message); }
  }
}

// --- Fix: ensure background activates on Safari startup ---
chrome.runtime.onInstalled?.addListener(()=>{ console.log('[ASG] Extension installed/updated'); });
chrome.runtime.onStartup?.addListener(()=>{ console.log('[ASG] Browser started'); });

chrome.webNavigation.onCommitted.addListener((d)=>{ if(d.frameId===0) scanTab(d.tabId, d.url); });
chrome.webNavigation.onHistoryStateUpdated.addListener((d)=>{ if(d.frameId===0) scanTab(d.tabId, d.url); });
chrome.webNavigation.onCompleted.addListener(async (d)=>{ if(d.frameId!==0) return; try{ const tab=await chrome.tabs.get(d.tabId); if(tab&&tab.url) scanTab(d.tabId, tab.url); }catch{} });
