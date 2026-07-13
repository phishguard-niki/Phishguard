// content/imageScanner.js (v0.5.1)
// Fix: previous version fired 'LOW_RES' warning for any image < 200x200 natural,
// which false-positived on every avatar/icon/emoji across Threads/Twitter/Facebook.
// New rules — only warn when an image is clearly problematic:
//   1. Skip images that aren't displayed at a significant size (< 300px in either dimension)
//   2. Skip data: / blob: (inline UI assets)
//   3. Warn on non-HTTPS remote images (mixed-content risk)
//   4. Warn only if a LARGE displayed image is served at a much smaller native
//      resolution — the "compressed re-share of a scam screenshot" pattern
//   5. Warn on extreme aspect ratio (> 5:1) for large images only
(function(){
  function getCfg(){
    return new Promise(resolve =>
      chrome.storage.local.get({ asg_scanImages: true }, resolve)
    );
  }

  function heuristics(img){
    const keys = [];
    let level = 'ok';

    const nw = img.naturalWidth, nh = img.naturalHeight;
    const dw = img.clientWidth, dh = img.clientHeight;
    const src = (img.currentSrc || img.src || '').trim();

    // Skip: not displayed prominently (avatars, icons, emoji, hidden imgs)
    if (dw < 300 || dh < 300) return { level: 'ok' };

    // Skip: inline UI assets
    if (src.startsWith('data:') || src.startsWith('blob:')) return { level: 'ok' };

    // Non-HTTPS remote image on an HTTPS page is worth flagging
    if (src && !/^https:/i.test(src)) {
      keys.push('NON_HTTPS');
      level = 'warn';
    }

    if (nw > 0 && nh > 0) {
      // Extreme aspect ratio — only for large displayed images (already gated above)
      const ratio = Math.max(nw, nh) / Math.min(nw, nh);
      if (ratio > 5) {
        keys.push('EXTREME_RATIO');
        level = 'warn';
      }

      // "Upscaled low-res" pattern — displayed large but natural resolution tiny.
      // Common for re-shared / re-compressed scam screenshots.
      // Require BOTH: large displayed (already ≥300) AND tiny natural (<150 either axis).
      if (nw < 150 || nh < 150) {
        keys.push('LOW_RES');
        level = 'warn';
      }
    }

    return { level, reasonKeys: keys, suggestionKey: 'IMG_SUGGESTION' };
  }

  function show(p){
    const ensure = () => new Promise(res => {
      if (window.__ASG_showWarning) return res();
      const s = document.createElement('script');
      s.src = chrome.runtime.getURL('content/overlay.js');
      s.onload = res;
      document.documentElement.appendChild(s);
    });
    ensure().then(() => window.__ASG_showWarning && window.__ASG_showWarning(p));
  }

  function scanOne(img){
    try {
      const r = heuristics(img);
      if (r.level !== 'ok') show(r);
    } catch {}
  }

  function scanNodeForImages(root){
    try {
      if (root && root.tagName === 'IMG') {
        if (root.complete) scanOne(root);
        else root.addEventListener('load', () => scanOne(root), { once: true });
      }
      if (root && typeof root.querySelectorAll === 'function') {
        Array.from(root.querySelectorAll('img')).forEach(im => {
          if (im.complete) scanOne(im);
          else im.addEventListener('load', () => scanOne(im), { once: true });
        });
      }
    } catch {}
  }

  function init(){
    getCfg().then(({ asg_scanImages }) => {
      if (!asg_scanImages) return;
      Array.from(document.images || []).forEach(im => {
        if (im.complete) scanOne(im);
        else im.addEventListener('load', () => scanOne(im), { once: true });
      });
      const mo = new MutationObserver(muts => {
        for (const m of muts) {
          if (m.addedNodes && m.addedNodes.length) {
            Array.from(m.addedNodes).forEach(n => scanNodeForImages(n));
          }
        }
      });
      mo.observe(document.documentElement, { childList: true, subtree: true });
    });
  }

  init();
})();
