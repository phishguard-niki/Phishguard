// content/interstitial.js (強度 C：全畫面確認頁)
(() => {
  if (window.__ASG_interstitial_installed) return; window.__ASG_interstitial_installed = true;
  const href = chrome.runtime.getURL('ui/interstitial.css');
  if (!document.querySelector(`link[href="${href}"]`)) { const l=document.createElement('link'); l.rel='stylesheet'; l.href=href; document.documentElement.appendChild(l);} 
  const dict = {
    'zh-TW': { title:'請確認：此網站風險極高', btn:'我已了解風險，仍要繼續', note:'資訊僅供提醒，請勿在此頁輸入個資/金流。需要協助可撥打 165 或造訪 165 全民防騙網。', sourceH:'偵測來源：啟發式', sourceL:'偵測來源：黑名單' },
    'en':    { title:'Please Confirm: High‑Risk Website', btn:'I understand the risk. Continue anyway', note:'This is a warning only. Do not enter personal/payment info. Need help? Call 165 or visit the 165 Anti‑Fraud Network.', sourceH:'Detection: Heuristic', sourceL:'Detection: Blocklist' }
  };
  function render({ lang='zh-TW', source='heuristic' }={}){
    const d = dict[lang] || dict['en'];
    const existed = document.getElementById('asg-interstitial'); if (existed) existed.remove();
    const w = document.createElement('div'); w.id='asg-interstitial';
    const sourceText = (source==='list')? d.sourceL : d.sourceH;
    w.innerHTML = `<div class="asg-i-card"><h2>${d.title}</h2><p class="asg-i-source">${sourceText}</p><p class="asg-i-note">${d.note} <a href="https://165.npa.gov.tw/" target="_blank" rel="noopener">165</a></p><div class="asg-i-actions"><button id="asg-i-continue">${d.btn}</button></div></div>`;
    w.querySelector('#asg-i-continue').onclick = () => w.remove();
    document.documentElement.appendChild(w);
  }
  window.__ASG_showInterstitial = (opts)=>render(opts||{});
})();
