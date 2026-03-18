// content/banner.js
(() => {
  if (window.__ASG_banner_installed) return; window.__ASG_banner_installed = true;
  const href = chrome.runtime.getURL('ui/banner.css');
  if (!document.querySelector(`link[href="${href}"]`)) { const l=document.createElement('link'); l.rel='stylesheet'; l.href=href; document.documentElement.appendChild(l);} 
  function i18n(lang){ const zh={ main:'可能是詐騙', sub:'請先向官方或 165 反詐騙專線查證' }; const en={ main:'POTENTIAL SCAM', sub:'Verify with the official source or 165 Anti‑Fraud Hotline' }; return (lang==='zh-TW')?zh:en; }
  function render({ lang='zh-TW', showSub=true }={}){ const txt=i18n(lang); const existed=document.getElementById('asg-banner'); if(existed)existed.remove(); const wrap=document.createElement('div'); wrap.id='asg-banner'; wrap.innerHTML=`<div class="asg-badge">${txt.main}${showSub?`<span class="asg-sub">${txt.sub}</span>`:''}</div><div class="asg-close" title="${lang==='zh-TW'?'關閉':'Close'}">×</div><div class="asg-handle" title="${lang==='zh-TW'?'拖曳':'Drag'}">↘</div>`; wrap.querySelector('.asg-close').onclick=()=>wrap.remove(); const handle=wrap.querySelector('.asg-handle'); const st={drag:false,dx:0,dy:0}; handle.addEventListener('pointerdown',e=>{st.drag=true;const r=wrap.getBoundingClientRect();st.dx=e.clientX-r.left;st.dy=e.clientY-r.top;handle.setPointerCapture(e.pointerId);}); handle.addEventListener('pointermove',e=>{ if(!st.drag) return; const x=e.clientX-st.dx, y=e.clientY-st.dy; wrap.style.left=`${x}px`; wrap.style.top=`${y}px`; wrap.style.transform='rotate(-15deg)'; wrap.style.translate='0'; }); handle.addEventListener('pointerup',()=>st.drag=false); document.documentElement.appendChild(wrap);} 
  window.__ASG_showBanner=(opts)=>render(opts||{});
})();
