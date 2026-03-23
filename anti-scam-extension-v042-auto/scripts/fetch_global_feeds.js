#!/usr/bin/env node
/**
 * scripts/fetch_global_feeds.js
 *  - Fetch FCA / ASIC / SFC public pages and extract suspicious/scam domains
 *  - Save into config/global/*.json|.txt for the auto_update pipeline
 *  - No APIs/keys required; HTML scraping with UA + Retry
 */
const fs = require('fs');
const path = require('path');
const https = require('https');

function get(url){
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AntiScamFetcher/1.0 Chrome/120 Safari/537.36';
  return new Promise((resolve,reject)=>{
    const req = https.get(url,{headers:{'User-Agent':ua,'Accept-Language':'en,zh-TW;q=0.9'}},(res)=>{
      if(res.statusCode>=300 && res.statusCode<400 && res.headers.location){
        let next = res.headers.location; if(next.startsWith('/')){ const u=new URL(url); next=u.origin+next; }
        return resolve(get(next));
      }
      if(res.statusCode!==200){ return reject(new Error('HTTP '+res.statusCode+' '+url)); }
      let data=''; res.setEncoding('utf8'); res.on('data',d=>data+=d); res.on('end',()=>resolve(data));
    });
    req.on('error',reject); req.setTimeout(30000,()=>req.destroy(new Error('TIMEOUT')));
  });
}
function normalizeHost(v){
  try{ const s=String(v||'').trim(); if(!s) return ''; const u=new URL(/^https?:\/\//i.test(s)?s:'http://'+s); let h=(u.hostname||'').toLowerCase(); if(h.startsWith('www.')) h=h.slice(4); return h; }catch{return String(v||'').trim().toLowerCase().replace(/^www\./,'');}
}
function extractHostsFromHTML(html){
  const re=/\bhttps?:\/\/[^\s"'<>]+/gim; const out=new Set(); let m;
  while((m=re.exec(html))!==null){ const h=normalizeHost(m[0]); if(h) out.add(h); }
  return Array.from(out);
}
function filterOut(list, excludes){
  const ex = new Set(excludes);
  return Array.from(new Set(list.filter(h=>h && !Array.from(ex).some(s=> h===s || h.endsWith('.'+s))))).sort();
}
async function run(){
  const base = path.resolve(__dirname,'..');
  const outDir = path.join(base,'config','global');
  fs.mkdirSync(outDir,{recursive:true});

  // 1) FCA Warning List page (HTML)
  try{
    const fcaURL = 'https://www.fca.org.uk/consumers/warning-list-unauthorised-firms';
    const html = await get(fcaURL);
    let hosts = extractHostsFromHTML(html);
    hosts = filterOut(hosts,[
      'fca.org.uk','www.fca.org.uk','facebook.com','twitter.com','linkedin.com',
      'youtube.com','google.com','googletagmanager.com','doubleclick.net'
    ]);
    const fcaObj = { source: fcaURL, fetched_at: new Date().toISOString(), domains: hosts };
    fs.writeFileSync(path.join(outDir,'fca-scam.json'), JSON.stringify(fcaObj,null,2),'utf8');
    console.log('[OK] FCA domains:', hosts.length);
  }catch(e){ console.warn('[WARN] FCA fetch failed:', e.message); }

  // 2) ASIC Investor Alert List (HTML)
  try{
    const asicURL = 'https://moneysmart.gov.au/check-and-report-scams/investor-alert-list';
    const html = await get(asicURL);
    let hosts = extractHostsFromHTML(html);
    hosts = filterOut(hosts,[
      'moneysmart.gov.au','asic.gov.au','facebook.com','twitter.com','linkedin.com',
      'youtube.com','google.com','googletagmanager.com','doubleclick.net'
    ]);
    const asicObj = { source: asicURL, fetched_at: new Date().toISOString(), domains: hosts };
    fs.writeFileSync(path.join(outDir,'asic-scam.json'), JSON.stringify(asicObj,null,2),'utf8');
    console.log('[OK] ASIC domains:', hosts.length);
  }catch(e){ console.warn('[WARN] ASIC fetch failed:', e.message); }

  // 3) SFC (HK) 警示名單（中文頁面）
  try{
    const sfcURL = 'https://www.sfc.hk/TC/Alert_List';
    const html = await get(sfcURL);
    let hosts = extractHostsFromHTML(html);
    hosts = filterOut(hosts,[
      'sfc.hk','www.sfc.hk','facebook.com','twitter.com','linkedin.com',
      'youtube.com','google.com','googletagmanager.com','doubleclick.net'
    ]);
    const sfcObj = { source: sfcURL, fetched_at: new Date().toISOString(), domains: hosts };
    fs.writeFileSync(path.join(outDir,'sfc-scam.json'), JSON.stringify(sfcObj,null,2),'utf8');
    console.log('[OK] SFC domains:', hosts.length);
  }catch(e){ console.warn('[WARN] SFC fetch failed:', e.message); }

  console.log('\n[INFO] Global feeds fetched. You can now run auto_update_v2.js');
}

run().catch(e=>{ console.error(e); process.exit(1); });
