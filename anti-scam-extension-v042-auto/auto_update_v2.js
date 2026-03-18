#!/usr/bin/env node
/**
 * anti-scam-extension-v042-auto / auto_update_v2.js (CJS)
 * - Taiwan 165: CSV + Article API (list + detail/content HTML parsing)
 * - China: CAC / Police HTML
 * - International: OpenPhish / URLhaus / Phishing.Database
 * - Global Scam: multi feeds (text/json) + merged de-dup feed
 * - UA + Retry + per-source stats + shards
 */
const fs = require('fs');
const path = require('path');
const https= require('https');
const http = require('http');

function parseArgs(){
  const a=process.argv.slice(2), o={};
  for(let i=0;i<a.length;i++){
    const k=a[i];
    if(k==='--sources') o.sources=a[++i];
    else if(k==='--out') o.out=a[++i];
    else if(k==='--keywords') o.keywords=a[++i];
    else if(k==='--urlhaus_only_online') o.urlhausOnlyOnline=true;
    else if(k==='--phishstats_min_score') o.phishstatsMinScore=parseFloat(a[++i]);
    else if(k==='--shards_dir') o.shardsDir=a[++i];
    else if(k==='--shards') o.shards=parseInt(a[++i],10);
  }
  if(!o.sources) throw new Error('Missing --sources');
  if(!o.out) throw new Error('Missing --out');
  if(!o.shards) o.shards=27;
  if(isNaN(o.phishstatsMinScore)) o.phishstatsMinScore=0;
  return o;
}

function fetchUrl(url, tryCount=1, uaLabel=''){
  return new Promise((resolve,reject)=>{
    const client = url.startsWith('https')? https : http;
    const headers = {
      'User-Agent': uaLabel || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AntiScamBot/1.0 Chrome/120 Safari/537.36',
      'Accept': '*/*',
      'Accept-Language': 'zh-TW,zh;q=0.9,en;q=0.8'
    };
    const req = client.get(url, { headers }, (res)=>{
      if(res.statusCode>=300 && res.statusCode<400 && res.headers.location){
        let next = res.headers.location;
        if(next && next.startsWith('/')){
          const u = new URL(url);
          next = u.origin + next;
        }
        return resolve(fetchUrl(next, tryCount, uaLabel));
      }
      if(res.statusCode!==200){
        if((res.statusCode===403 || res.statusCode===429 || res.statusCode>=500) && tryCount<3){
          const delay=1000*tryCount;
          return setTimeout(()=>resolve(fetchUrl(url, tryCount+1, uaLabel)), delay);
        }
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      let data=''; res.setEncoding('utf8');
      res.on('data',(d)=>data+=d); res.on('end',()=>resolve(data));
    });
    req.on('error',(err)=>{
      if(tryCount<3){ const delay=1000*tryCount; return setTimeout(()=>resolve(fetchUrl(url, tryCount+1, uaLabel)), delay);} 
      reject(err);
    });
    req.setTimeout(30000, ()=> req.destroy(new Error('TIMEOUT')));
  });
}
function readLocal(p){ const f=p.startsWith('file://')? p.replace('file://','') : p; return fs.readFileSync(f,'utf8'); }
function pickUA(label){ if(label && label.startsWith('CN_')) return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15'; if(label && label.startsWith('TW_')) return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AntiScamBot/1.0 Chrome/120 Safari/537.36'; if(label && label.startsWith('GLOBAL_')) return 'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0'; return ''; }
function normalizeHost(input){ try{ const v=String(input||'').trim(); if(!v) return ''; const urlLike=/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)? v : `http://${v}`; const u=new URL(urlLike); let h=(u.hostname||'').toLowerCase(); if(h.startsWith('www.')) h=h.slice(4); return h; }catch{ return String(input||'').trim().toLowerCase().replace(/^www\./,''); }}
function uniqueSorted(arr){ return Array.from(new Set(arr.filter(Boolean))).sort(); }
function shardByFirstLetter(hosts){ const b={}; for(let i=0;i<26;i++) b[String.fromCharCode(97+i)]=[]; b.other=[]; for(const h of hosts){ const c=(h[0]||'').toLowerCase(); b[(c>='a'&&c<='z')?c:'other'].push(h);} return b; }
function extractTokensFromCSV(csv){ const t=csv.replace(/\r/g,'\n'); const lines=t.split('\n').filter(l=>l.trim()!==''); if(!lines.length) return {header:[], rows:[]}; const header=lines[0].split(',').map(h=>h.trim().toLowerCase()); const rows=lines.slice(1).map(l=>l.split(',')); return {header,rows}; }
function parsePhishStats(csv, minScore=0){ const { header, rows } = extractTokensFromCSV(csv); const urlIdx=header.findIndex(h=>h.includes('url')); const scoreIdx=header.findIndex(h=>h.includes('score')); const out=[]; for(const r of rows){ const url=(r[urlIdx]||'').trim(); const scoreRaw=(r[scoreIdx]||'').trim(); const sc=parseFloat(scoreRaw.replace(/[^0-9.]/g,'')); if(url && !isNaN(sc) && sc>=minScore) out.push(normalizeHost(url)); } return out; }
function parseURLhausCSV(csv, onlyOnline=false){ const lines=csv.replace(/\r/g,'\n').split('\n'); const out=[]; for(const line of lines){ if(!line || line.startsWith('#')) continue; const parts=line.split(','); if(parts.length<4) continue; const url=parts[2]; const status=String(parts[3]||'').toLowerCase(); if(onlyOnline && status.includes('offline')) continue; out.push(normalizeHost(url)); } return out; }
function parseTW165CSV(csv){ const { header, rows } = extractTokensFromCSV(csv); const urlCols=header.map((h,i)=>({h,i})).filter(x=>x.h.includes('url')); const out=[]; for(const r of rows){ for(const col of urlCols){ const cell=(r[col.i]||'').trim(); if(!cell) continue; const tokens=cell.split(/[;\s]+/); for(const t of tokens) out.push(normalizeHost(t)); } } return out; }
function parseHTMLtoHosts(html){ const re=/\bhttps?:\/\/[^\s"'<>]+/gim; const seen=new Set(), out=[]; let m; while((m=re.exec(html))!==null){ const h=normalizeHost(m[0]); if(h && !seen.has(h)){ seen.add(h); out.push(h); } } return out; }
function extractFromText(text){ const lines=text.replace(/\r/g,'\n').split('\n').map(s=>s.trim()).filter(Boolean); const tokens=[]; const urlLike=/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)?([\w.-]+)\.[a-zA-Z]{2,}(?:\/[^\s]*)?/g; for(const line of lines){ const m=line.match(urlLike); if(m) tokens.push(...m);} return (tokens.length?tokens:lines).map(normalizeHost); }
async function fetchTW165ArticleIDs(listUrl, label){ const ids=new Set(); for(let p=1;p<=5;p++){ const url=listUrl.replace('{page}', String(p)); try{ const txt=await fetchUrl(url,1,pickUA(label)); const j=JSON.parse(txt); const items=Array.isArray(j?.list)? j.list : (Array.isArray(j?.data)? j.data : []); if(!items.length) break; for(const it of items){ const id = it?.id || it?.articleId || it?.ID; if(id) ids.add(String(id)); } }catch(e){ break; } } return Array.from(ids); }
async function fetchTW165ArticleDetail(detailUrlTmpl, id, label){ const url=detailUrlTmpl.replace('{id}', id); const txt=await fetchUrl(url,1,pickUA(label)); const j=JSON.parse(txt); const content=j?.content || j?.data?.content || ''; return parseHTMLtoHosts(String(content)); }
function saveMergedGlobalScam(cacheFile, hostArrays){ try{ fs.mkdirSync(path.dirname(cacheFile), { recursive:true }); const merged=uniqueSorted(hostArrays.flat().filter(Boolean)); fs.writeFileSync(cacheFile, merged.join('\n'), 'utf8'); console.log(`[OK] GLOBAL_SCAM_MERGED: ${merged.length} hosts -> ${cacheFile}`); return merged; }catch(e){ console.warn(`[WARN] merge write fail: ${e.message}`); return []; }}

async function main(){ const opts=parseArgs(); const cfg=JSON.parse(fs.readFileSync(opts.sources,'utf8')); const srcs=Array.isArray(cfg.sources)? cfg.sources : []; const collected=[]; const push=(label,hosts)=>{ collected.push({label,hosts}); console.log(`[OK] ${label}: ${hosts.length} hosts`); }; const globalScamBuckets=[]; for(const src of srcs){ try{ if(typeof src==='string'){ const content=src.startsWith('http')? await fetchUrl(src,1,pickUA('')) : readLocal(src); let hosts=[]; if(/phishstats\.info\/.+\.csv/i.test(src)) hosts=parsePhishStats(content, opts.phishstatsMinScore); else if(/urlhaus\.abuse\.ch\/downloads\/csv\//i.test(src)) hosts=parseURLhausCSV(content, !!opts.urlhausOnlyOnline); else{ try{ const j=JSON.parse(content); if(Array.isArray(j)) hosts=j.map(normalizeHost); else if(Array.isArray(j.phishing_domains)) hosts=j.phishing_domains.map(normalizeHost); else if(Array.isArray(j.blocked)) hosts=j.blocked.map(normalizeHost); else if(Array.isArray(j.urls)) hosts=j.urls.map(normalizeHost); else hosts=extractFromText(content);}catch{ if(content.includes(',')){ const {rows}=extractTokensFromCSV(content); hosts=rows.map(r=>normalizeHost(r[0]||'')).filter(Boolean);} else hosts=extractFromText(content);} } push(src,hosts); } else if(typeof src==='object' && src){ const label=src.name||src.url; let hosts=[]; if(src.type==='csv'){ const content=src.url.startsWith('http')? await fetchUrl(src.url,1,pickUA(label)) : readLocal(src.url); hosts=parseTW165CSV(content); } else if(src.type==='html'){ const content=src.url.startsWith('http')? await fetchUrl(src.url,1,pickUA(label)) : readLocal(src.url); hosts=parseHTMLtoHosts(content); } else if(src.type==='text'){ const content=src.url.startsWith('http')? await fetchUrl(src.url,1,pickUA(label)) : readLocal(src.url); hosts=extractFromText(content); } else if(src.type==='json'){ const content=src.url.startsWith('http')? await fetchUrl(src.url,1,pickUA(label)) : readLocal(src.url); try{ const j=JSON.parse(content); if(Array.isArray(j)) hosts=j.map(normalizeHost); else if(Array.isArray(j.domains)) hosts=j.domains.map(normalizeHost); else if(Array.isArray(j.blocklist)) hosts=j.blocklist.map(normalizeHost); else if(Array.isArray(j.data)) hosts=j.data.map(x=>normalizeHost(x.domain||x.url||x)); else hosts=extractFromText(content);}catch{ hosts=extractFromText(content);} } else if(src.type==='165_article_api'){ const listUrlTmpl=src.list; const detailUrlTmpl=src.detail; const ids=await fetchTW165ArticleIDs(listUrlTmpl, label); let all=[]; for(const id of ids){ try{ const one=await fetchTW165ArticleDetail(detailUrlTmpl, id, label); all=all.concat(one); }catch(e){} } hosts = all.filter(h=> h && !h.endsWith('.gov.tw') && !h.endsWith('.edu.tw') && !h.endsWith('.npa.gov.tw')); } else if(src.type==='global_scam_merge'){ globalScamBuckets.push('__MERGE__'+(src.cache ? src.cache : 'cache/global-scam-merged.txt'));
          continue; } else { console.warn(`[WARN] Unknown source type: ${src.type}`); }
        if((label||'').startsWith('TW_165')){
          hosts = hosts.filter(h=> h && !h.endsWith('.gov.tw') && !h.endsWith('.edu.tw') && !h.endsWith('.npa.gov.tw'));
        }
        if((label||'').startsWith('GLOBAL_SCAM_')){
          globalScamBuckets.push(hosts);
        }
        push(label,hosts);
      }
    }catch(e){ console.warn(`[WARN] Failed source ${typeof src==='string'? src : (src.name||src.url)}: ${e.message}`); }
  }
  if(globalScamBuckets.length){ const cacheEntry=globalScamBuckets.find(x=> (typeof x==='string') && x.startsWith('__MERGE__')); if(cacheEntry){ const cacheFile=cacheEntry.replace('__MERGE__',''); const arrays=globalScamBuckets.filter(x=>Array.isArray(x)); const merged=saveMergedGlobalScam(cacheFile, arrays); if(merged.length) collected.push({label:'GLOBAL_SCAM_MERGED', hosts: merged}); } }
  // Whitelist: major legitimate domains that phishing feeds sometimes include as targets (not attackers)
  const whitelist = new Set([
    'google.com','google.com.tw','google.co.jp','google.com.hk','google.co.uk','google.com.au',
    'facebook.com','instagram.com','twitter.com','x.com','youtube.com','tiktok.com',
    'apple.com','microsoft.com','amazon.com','netflix.com',
    'linkedin.com','github.com','paypal.com','ebay.com',
    'yahoo.com','bing.com','duckduckgo.com','baidu.com',
    'line.me','telegram.org','whatsapp.com','discord.com',
    'shopee.tw','shopee.com','pchome.com.tw','momo.com','ruten.com.tw','books.com.tw',
    '104.com.tw','1111.com.tw','yes123.com.tw',
    'rakuten.co.jp','mercari.com','amazon.co.jp',
    'gov.tw','npa.gov.tw','moi.gov.tw',
    'dropbox.com','onedrive.com','icloud.com',
    'chase.com','wellsfargo.com','bankofamerica.com',
    'wise.com','stripe.com','square.com',
    'binance.com','coinbase.com','kraken.com',
    'cloudflare.com','amazonaws.com','azure.com',
    'reddit.com','stackoverflow.com','wikipedia.org'
  ]);
  function isWhitelisted(h){
    if(whitelist.has(h)) return true;
    // Also whitelist subdomains: accounts.google.com → google.com is whitelisted
    const parts = h.split('.');
    for(let i=1; i<parts.length; i++){
      if(whitelist.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  }
  const mergedHosts = uniqueSorted(collected.flatMap(c=>c.hosts).filter(h => h && !isWhitelisted(h)));
  let keywords=['reset-password','verify-account','bank-login','otp','one-time','2fa','登入驗證','重設密碼','身分驗證'];
  if(opts.keywords && fs.existsSync(opts.keywords)){ const add=fs.readFileSync(opts.keywords,'utf8').split(/\r?\n/).map(s=>s.trim()).filter(Boolean); keywords=uniqueSorted(keywords.concat(add)); }
  const outObj={ version:new Date().toISOString().slice(0,10), updated_at:new Date().toISOString(), expires:new Date(Date.now()+1000*60*60*24*30).toISOString().slice(0,10), sources:srcs, phishing_domains: mergedHosts, wildcards:[], regex:[], keywords };
  const outDir=path.dirname(path.resolve(opts.out)); fs.mkdirSync(outDir,{recursive:true}); fs.writeFileSync(path.resolve(opts.out), JSON.stringify(outObj,null,2),'utf8');
  console.log(`\n[DONE] Wrote blocklist to: ${path.resolve(opts.out)} (domains=${mergedHosts.length})`);
  if(opts.shardsDir){ const dir=path.resolve(opts.shardsDir); fs.mkdirSync(dir,{recursive:true}); const buckets=shardByFirstLetter(mergedHosts); const index={}; for(const [label,arr] of Object.entries(buckets)){ const p=path.join(dir,`shard-${label}.json`); fs.writeFileSync(p, JSON.stringify({label,domains:arr},null,0),'utf8'); index[label]=path.basename(p);} fs.writeFileSync(path.join(dir,'index.json'), JSON.stringify(index,null,2),'utf8'); console.log(`[DONE] Wrote shards to: ${dir}`);} }

main().catch(e=>{ console.error(e); process.exit(1); });
