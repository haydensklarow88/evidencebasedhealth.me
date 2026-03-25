/**
 * Evidence-Based Health — shared cookie consent banner.
 * Uses the same localStorage key ('cookieConsent') as index.html
 * so consent is respected site-wide.
 *
 * Fires any callbacks registered in window.EBH_CONSENT_CALLBACKS
 * once marketing consent is granted.
 */
(function () {
  'use strict';

  var KEY = 'cookieConsent';
  var stored = localStorage.getItem(KEY);

  /* Expose read-only consent state for tag scripts */
  window.EBH_CONSENT = {
    analytics : stored === 'all',
    marketing : stored === 'all',
    answered  : stored !== null
  };

  if (stored !== null) return; /* Already answered — don't show banner */

  /* ── Styles ────────────────────────────────────────────────────────────── */
  var css = document.createElement('style');
  css.id  = 'ebh-cb-style';
  css.textContent = [
    '#ebh-cb{',
      'position:fixed;bottom:0;left:0;right:0;z-index:9999;',
      'background:#0f1a14;',
      'border-top:2px solid #1a5c3a;',
      'padding:1.2rem 2rem;',
    '}',
    '#ebh-cb-inner{',
      'max-width:1280px;margin:0 auto;',
      'display:flex;align-items:center;gap:2rem;flex-wrap:wrap;',
    '}',
    '#ebh-cb-text{',
      "font-family:'DM Sans',system-ui,sans-serif;",
      'font-size:.82rem;font-weight:300;line-height:1.6;',
      'color:rgba(247,245,240,.75);flex:1;min-width:200px;',
    '}',
    '#ebh-cb-text a{color:#c2d9cb;text-underline-offset:2px;}',
    '#ebh-cb-actions{display:flex;gap:.8rem;flex-shrink:0;}',
    '#ebh-cb button{',
      "font-family:'DM Sans',system-ui,sans-serif;",
      'font-size:.78rem;font-weight:500;letter-spacing:.05em;',
      'padding:.5rem 1.1rem;border-radius:2px;border:1px solid;cursor:pointer;',
      'transition:background .2s,color .2s;',
    '}',
    '#ebh-cb-reject{',
      'background:transparent;',
      'color:rgba(247,245,240,.65);',
      'border-color:rgba(255,255,255,.2);',
    '}',
    '#ebh-cb-reject:hover{background:rgba(255,255,255,.08);color:#fff;}',
    '#ebh-cb-accept{',
      'background:#1a5c3a;color:#fff;border-color:#1a5c3a;',
    '}',
    '#ebh-cb-accept:hover{background:#2d7a52;}',
    '@media(max-width:600px){',
      '#ebh-cb-inner{flex-direction:column;align-items:flex-start;gap:1rem;}',
      '#ebh-cb-actions{width:100%;}',
      '#ebh-cb button{flex:1;}',
    '}'
  ].join('');

  /* ── Markup ────────────────────────────────────────────────────────────── */
  var bar    = document.createElement('div');
  bar.id     = 'ebh-cb';
  bar.setAttribute('role', 'dialog');
  bar.setAttribute('aria-label', 'Cookie consent');
  bar.setAttribute('aria-live', 'polite');

  var inner  = document.createElement('div');
  inner.id   = 'ebh-cb-inner';

  var text   = document.createElement('p');
  text.id    = 'ebh-cb-text';
  text.innerHTML =
    'We use essential cookies to keep the site working. With your permission, we\u2019d ' +
    'also like to use analytics and marketing cookies to understand traffic and show ' +
    'relevant content. <a href="/privacy.html">Learn more</a>.';

  var actions = document.createElement('div');
  actions.id  = 'ebh-cb-actions';

  var btnReject = document.createElement('button');
  btnReject.id  = 'ebh-cb-reject';
  btnReject.textContent = 'Essential only';

  var btnAccept = document.createElement('button');
  btnAccept.id  = 'ebh-cb-accept';
  btnAccept.textContent = 'Accept all';

  actions.appendChild(btnReject);
  actions.appendChild(btnAccept);
  inner.appendChild(text);
  inner.appendChild(actions);
  bar.appendChild(inner);

  /* ── Consent logic ─────────────────────────────────────────────────────── */
  function setConsent(level) {
    localStorage.setItem(KEY, level);
    window.EBH_CONSENT.analytics = level === 'all';
    window.EBH_CONSENT.marketing = level === 'all';
    window.EBH_CONSENT.answered  = true;
    remove();
    if (level === 'all' && Array.isArray(window.EBH_CONSENT_CALLBACKS)) {
      window.EBH_CONSENT_CALLBACKS.forEach(function (fn) {
        try { fn(); } catch (e) { /* ignore */ }
      });
    }
  }

  function remove() {
    if (bar.parentNode)    bar.parentNode.removeChild(bar);
    if (css.parentNode)    css.parentNode.removeChild(css);
  }

  btnAccept.addEventListener('click', function () { setConsent('all'); });
  btnReject.addEventListener('click', function () { setConsent('essential'); });

  /* ── Mount when DOM is ready ───────────────────────────────────────────── */
  function mount() {
    document.head.appendChild(css);
    document.body.appendChild(bar);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
}());
