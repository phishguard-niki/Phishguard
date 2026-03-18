// options.js (v0.4.2)
(function(){
  const $ = (s)=>document.querySelector(s);
  const langEl = $('#lang');
  const scanEl = $('#scanImages');
  const shortEl = $('#warnShort');
  const bannerEl = $('#showBanner');
  const interEl = $('#interstitial');
  const listEl = $('#customList');

  function load(){
    chrome.storage.local.get({ asg_lang:null, asg_scanImages:true, asg_warnShortUrl:true, asg_showBanner:true, asg_interstitial:'C', asg_customBlocklist:[] }, (cfg)=>{
      langEl.value = cfg.asg_lang || 'auto';
      scanEl.checked = !!cfg.asg_scanImages;
      shortEl.checked = !!cfg.asg_warnShortUrl;
      bannerEl.checked = !!cfg.asg_showBanner;
      interEl.value = cfg.asg_interstitial || 'C';
      listEl.value = (cfg.asg_customBlocklist||[]).join('\n');
    });
  }

  function save(){
    const v = langEl.value;
    const raw = listEl.value || '';
    const list = raw.split(/\n+/).map(s=>s.trim()).filter(Boolean);
    chrome.storage.local.set({
      asg_lang: v==='auto'? null : v,
      asg_scanImages: scanEl.checked,
      asg_warnShortUrl: shortEl.checked,
      asg_showBanner: bannerEl.checked,
      asg_interstitial: interEl.value,
      asg_customBlocklist: list
    }, ()=>{
      const btn = document.getElementById('save');
      btn.textContent = '已儲存 Saved';
      setTimeout(()=> btn.textContent = '儲存 / Save', 1200);
    });
  }

  document.getElementById('save').addEventListener('click', save);
  load();
})();
