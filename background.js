// background.js (v0.4.3)

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

// --- Fix #4: lazy shard loading (was loading entire 47MB JSON) ---
// --- Fix #5: fix blocklist JSON parsing (object not array) ---
let shardIndex = null;
const shardCache = {};

async function loadShardIndex(){
  if(shardIndex) return shardIndex;
  try{
    const resp = await fetch(chrome.runtime.getURL('data/blocklist-shards/index.json'));
    shardIndex = await resp.json();
  }catch{
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
    const resp = await fetch(chrome.runtime.getURL('data/blocklist-shards/' + file));
    const obj = await resp.json();
    const domains = Array.isArray(obj.domains) ? obj.domains : (Array.isArray(obj) ? obj : []);
    shardCache[letter] = new Set(domains.map(s => String(s).toLowerCase()));
  }catch{
    shardCache[letter] = new Set();
  }
  return shardCache[letter];
}

function shardKey(domain){
  const c = (domain||'')[0];
  return (c >= 'a' && c <= 'z') ? c : 'other';
}

async function isInBuiltinBlocklist(host, base){
  const keys = new Set([shardKey(host), shardKey(base)]);
  for(const k of keys){
    const shard = await loadShard(k);
    if(shard.has(host) || shard.has(base)) return true;
  }
  return false;
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
    let level='ok', reasonKeys=[];
    if(looksLikeHomograph(host)){ reasonKeys.push('HOMO'); level='warn'; }
    if(tooDeepSubdomain(host)){ reasonKeys.push('DEEP_SUB'); level='warn'; }
    if(hasRiskyPath(u, host)){ reasonKeys.push('RISKY_PATH'); level='warn'; }
    if(cfg.asg_warnShortUrl && isShortener(host)){ reasonKeys.push('SHORT_URL'); level='warn'; }
    return { level, reasonKeys, suggestionKey:'URL_SUGGESTION', fromList:false };
  }catch{
    return { level:'warn', reasonKeys:['BAD_FORMAT'], suggestionKey:'URL_SUGGESTION', fromList:false };
  }
}

async function scanTab(tabId, url){
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
      await chrome.scripting.executeScript({ target:{tabId, allFrames:false}, func:(l,fl)=>{ window.__ASG_showInterstitial&&window.__ASG_showInterstitial({ lang:l, source: fl?'list':'heuristic' }); }, args:[lang, !!payload.fromList] });
    }else if(cfg.asg_showBanner){
      await chrome.scripting.executeScript({ target:{tabId, allFrames:true}, files:['content/banner.js']});
      await chrome.scripting.insertCSS({ target:{tabId, allFrames:true}, files:['ui/banner.css']});
      await chrome.scripting.executeScript({ target:{tabId, allFrames:false}, func:(l)=>{ window.__ASG_showBanner&&window.__ASG_showBanner({ lang:l }); }, args:[lang] });
    }
  }catch(e){ console.debug('Inject failed:', e?.message); }
}

chrome.webNavigation.onCommitted.addListener((d)=>{ if(d.frameId===0) scanTab(d.tabId, d.url); });
chrome.webNavigation.onHistoryStateUpdated.addListener((d)=>{ if(d.frameId===0) scanTab(d.tabId, d.url); });
chrome.webNavigation.onCompleted.addListener(async (d)=>{ if(d.frameId!==0) return; try{ const tab=await chrome.tabs.get(d.tabId); if(tab&&tab.url) scanTab(d.tabId, tab.url); }catch{} });
