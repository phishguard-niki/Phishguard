// content/overlay.js
(() => {
  if (window.__ASG_installed) return; window.__ASG_installed = true;
  const dict = {
    'zh-TW': { title_warn:'⚠️ 風險警告', title_bad:'⛔ 高風險警告', reasons:{
      BLACKLIST:'此網站已列入疑似詐騙清單（165/自訂清單）。', HOMO:'域名疑似同形字混淆（仿冒品牌）。', DEEP_SUB:'子網域結構異常地深，常用於偽裝。', RISKY_PATH:'網址路徑/參數含高風險關鍵字。', SHORT_URL:'短網址可能隱藏實際目的地，請先展開。', BAD_FORMAT:'不是有效的網址格式。', EXTREME_RATIO:'圖片長寬比極端，疑為裁切或拼接。', LOW_RES:'解析度過低，可能多次轉存或壓縮。', NON_HTTPS:'圖片非 HTTPS 來源。', NO_SIZE:'圖片無法讀取尺寸。' }, suggestion:{ URL_SUGGESTION:'請確認是否為官方來源；避免在此頁輸入個資或金流資訊。', IMG_SUGGESTION:'不明來源圖片請勿輕信其內文或連結。' }, actions:{ back:'返回/離開', keep:'仍要繼續', lang:'EN' }, hotline:'需要協助？撥打 165 反詐騙專線或造訪 165 全民防騙網' },
    'en': { title_warn:'⚠️ Risk Warning', title_bad:'⛔ High-Risk Warning', reasons:{
      BLACKLIST:'This site appears on a suspected scam list (165/custom).', HOMO:'Domain may use look‑alike characters (brand impersonation).', DEEP_SUB:'Unusually deep subdomain structure, often used to disguise.', RISKY_PATH:'URL path/parameters contain high‑risk keywords.', SHORT_URL:'Short URL may hide real destination. Expand first.', BAD_FORMAT:'Invalid URL format.', EXTREME_RATIO:'Extreme aspect ratio; possibly cropped or stitched.', LOW_RES:'Very low resolution; likely multiple re-saves/compressions.', NON_HTTPS:'Image is not served over HTTPS.', NO_SIZE:'Failed to read image dimensions.' }, suggestion:{ URL_SUGGESTION:'Verify official source; avoid entering personal or payment info.', IMG_SUGGESTION:'Avoid trusting or forwarding images from unknown sources.' }, actions:{ back:'Back/Leave', keep:'Continue anyway', lang:'繁中' }, hotline:'Need help? Call 165 Anti‑Fraud Hotline (TW) or visit the 165 Anti‑Fraud Network' }
  };
  function readSettings(){ return new Promise(r=> chrome.storage?.local.get({ asg_lang:null }, r)); }
  let lang='en'; if ((navigator.language||'').toLowerCase().startsWith('zh')) lang='zh-TW';
  readSettings().then(({asg_lang})=>{ if (asg_lang) lang=asg_lang; });
  function t(ns,key){ const d=dict[lang]||dict['en']; if(ns==='title')return key==='bad'?d.title_bad:d.title_warn; if(ns==='reasons')return d.reasons[key]||key; if(ns==='suggestion')return d.suggestion[key]||''; if(ns==='actions')return d.actions[key]||key; if(ns==='hotline')return d.hotline; return key; }
  function toggleLang(){ lang=(lang==='zh-TW')?'en':'zh-TW'; chrome.storage?.local.set({ asg_lang:lang }); const p=window.__ASG_lastPayload; if(p) render(p); }
  function ensureCss(){ const href = chrome.runtime.getURL('ui/overlay.css'); if (!document.querySelector(`link[href="${href}"]`)) { const link=document.createElement('link'); link.rel='stylesheet'; link.href=href; document.documentElement.appendChild(link);} }
  function buildHtml({ level='warn', reasonKeys=[], suggestionKey='' }){
    const title=t('title', level==='bad'?'bad':'warn');
    const reasons=(reasonKeys&&reasonKeys.length)? reasonKeys.map(k=>`<li>${t('reasons',k)}</li>`).join(''):'';
    const suggestion=suggestionKey?`<p class="asg-suggestion"><b>${(lang==='zh-TW'?'建議':'Suggestion')}：</b>${t('suggestion',suggestionKey)}</p>`:'';
    const hotlineLink=(lang==='zh-TW')?`<a href="https://165.npa.gov.tw/" target="_blank" rel="noopener">165 全民防騙網</a>`:`<a href="https://165.npa.gov.tw/" target="_blank" rel="noopener">165 Anti-Fraud Network</a>`;
    return `<div class="asg-modal"><div class="asg-head"><h3>${title}</h3><button id="asg-lang" class="asg-lang">${t('actions','lang')}</button></div><ul class="asg-reasons">${reasons}</ul>${suggestion}<div class="asg-actions"><button id="asg-back">${t('actions','back')}</button><button id="asg-keep">${t('actions','keep')}</button></div><div class="asg-hotline"><small>📞 ${t('hotline')}：${hotlineLink}</small></div></div>`; }
  function render(payload){ ensureCss(); const existed=document.getElementById('asg-overlay'); if(existed)existed.remove(); const wrap=document.createElement('div'); wrap.id='asg-overlay'; wrap.innerHTML=buildHtml(payload); wrap.querySelector('#asg-back').onclick=()=>history.back(); wrap.querySelector('#asg-keep').onclick=()=>wrap.remove(); wrap.querySelector('#asg-lang').onclick=()=>toggleLang(); document.documentElement.appendChild(wrap);} 
  window.__ASG_showWarning=(payload)=>{ window.__ASG_lastPayload=payload; render(payload); };
})();
