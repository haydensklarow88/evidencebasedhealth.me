// js/i18n.js — Evidence-Based Health · Language Translation Engine
// Translates page content via POST /translate (OpenAI), caches in localStorage.
// Language preference synced to user profile when logged in.

(function () {
  'use strict';

  var API        = 'https://lvsofp8c9g.execute-api.us-east-1.amazonaws.com/prod';
  var LANG_KEY   = 'ebh_language';
  var TOKEN_KEY  = 'ebh-profile-jwt';
  var CACHE_VER  = 'v1';
  var CACHE_TTL  = 7 * 24 * 3600000; // 7 days

  // ── Language list ───────────────────────────────────────────────────────
  var LANGUAGES = [
    { code: 'en',    name: 'English',                  native: 'English',             dir: 'ltr' },
    { code: 'es',    name: 'Spanish',                  native: 'Español',             dir: 'ltr' },
    { code: 'fr',    name: 'French',                   native: 'Français',            dir: 'ltr' },
    { code: 'de',    name: 'German',                   native: 'Deutsch',             dir: 'ltr' },
    { code: 'it',    name: 'Italian',                  native: 'Italiano',            dir: 'ltr' },
    { code: 'pt',    name: 'Portuguese',               native: 'Português',           dir: 'ltr' },
    { code: 'nl',    name: 'Dutch',                    native: 'Nederlands',          dir: 'ltr' },
    { code: 'pl',    name: 'Polish',                   native: 'Polski',              dir: 'ltr' },
    { code: 'ru',    name: 'Russian',                  native: 'Русский',             dir: 'ltr' },
    { code: 'uk',    name: 'Ukrainian',                native: 'Українська',          dir: 'ltr' },
    { code: 'zh',    name: 'Chinese (Simplified)',      native: '中文（简体）',          dir: 'ltr' },
    { code: 'zh-TW', name: 'Chinese (Traditional)',    native: '中文（繁體）',          dir: 'ltr' },
    { code: 'ja',    name: 'Japanese',                 native: '日本語',               dir: 'ltr' },
    { code: 'ko',    name: 'Korean',                   native: '한국어',               dir: 'ltr' },
    { code: 'ar',    name: 'Arabic',                   native: 'العربية',             dir: 'rtl' },
    { code: 'he',    name: 'Hebrew',                   native: 'עברית',               dir: 'rtl' },
    { code: 'fa',    name: 'Persian (Farsi)',           native: 'فارسی',               dir: 'rtl' },
    { code: 'ur',    name: 'Urdu',                     native: 'اردو',                dir: 'rtl' },
    { code: 'hi',    name: 'Hindi',                    native: 'हिंदी',               dir: 'ltr' },
    { code: 'bn',    name: 'Bengali',                  native: 'বাংলা',               dir: 'ltr' },
    { code: 'pa',    name: 'Punjabi',                  native: 'ਪੰਜਾਬੀ',              dir: 'ltr' },
    { code: 'gu',    name: 'Gujarati',                 native: 'ગુજરાતી',             dir: 'ltr' },
    { code: 'mr',    name: 'Marathi',                  native: 'मराठी',               dir: 'ltr' },
    { code: 'ta',    name: 'Tamil',                    native: 'தமிழ்',               dir: 'ltr' },
    { code: 'te',    name: 'Telugu',                   native: 'తెలుగు',              dir: 'ltr' },
    { code: 'kn',    name: 'Kannada',                  native: 'ಕನ್ನಡ',               dir: 'ltr' },
    { code: 'ml',    name: 'Malayalam',                native: 'മലയാളം',              dir: 'ltr' },
    { code: 'ne',    name: 'Nepali',                   native: 'नेपाली',              dir: 'ltr' },
    { code: 'si',    name: 'Sinhala',                  native: 'සිංහල',               dir: 'ltr' },
    { code: 'vi',    name: 'Vietnamese',               native: 'Tiếng Việt',          dir: 'ltr' },
    { code: 'th',    name: 'Thai',                     native: 'ภาษาไทย',             dir: 'ltr' },
    { code: 'id',    name: 'Indonesian',               native: 'Bahasa Indonesia',    dir: 'ltr' },
    { code: 'ms',    name: 'Malay',                    native: 'Bahasa Melayu',       dir: 'ltr' },
    { code: 'tl',    name: 'Filipino (Tagalog)',       native: 'Filipino',            dir: 'ltr' },
    { code: 'jv',    name: 'Javanese',                 native: 'Basa Jawa',           dir: 'ltr' },
    { code: 'my',    name: 'Burmese',                  native: 'မြန်မာဘာသာ',          dir: 'ltr' },
    { code: 'km',    name: 'Khmer',                    native: 'ខ្មែរ',               dir: 'ltr' },
    { code: 'lo',    name: 'Lao',                      native: 'ລາວ',                 dir: 'ltr' },
    { code: 'mn',    name: 'Mongolian',                native: 'Монгол',              dir: 'ltr' },
    { code: 'ka',    name: 'Georgian',                 native: 'ქართული',             dir: 'ltr' },
    { code: 'am',    name: 'Amharic',                  native: 'አማርኛ',               dir: 'ltr' },
    { code: 'sw',    name: 'Swahili',                  native: 'Kiswahili',           dir: 'ltr' },
    { code: 'yo',    name: 'Yoruba',                   native: 'Yorùbá',              dir: 'ltr' },
    { code: 'ig',    name: 'Igbo',                     native: 'Igbo',                dir: 'ltr' },
    { code: 'ha',    name: 'Hausa',                    native: 'Hausa',               dir: 'ltr' },
    { code: 'so',    name: 'Somali',                   native: 'Soomaali',            dir: 'ltr' },
    { code: 'zu',    name: 'Zulu',                     native: 'isiZulu',             dir: 'ltr' },
    { code: 'af',    name: 'Afrikaans',                native: 'Afrikaans',           dir: 'ltr' },
    { code: 'ht',    name: 'Haitian Creole',           native: 'Kreyòl ayisyen',      dir: 'ltr' },
    { code: 'tr',    name: 'Turkish',                  native: 'Türkçe',              dir: 'ltr' },
    { code: 'az',    name: 'Azerbaijani',              native: 'Azərbaycanca',        dir: 'ltr' },
    { code: 'kk',    name: 'Kazakh',                   native: 'Қазақша',             dir: 'ltr' },
    { code: 'uz',    name: 'Uzbek',                    native: "O'zbek",              dir: 'ltr' },
    { code: 'hy',    name: 'Armenian',                 native: 'Հայերեն',             dir: 'ltr' },
    { code: 'el',    name: 'Greek',                    native: 'Ελληνικά',            dir: 'ltr' },
    { code: 'ro',    name: 'Romanian',                 native: 'Română',              dir: 'ltr' },
    { code: 'hu',    name: 'Hungarian',                native: 'Magyar',              dir: 'ltr' },
    { code: 'cs',    name: 'Czech',                    native: 'Čeština',             dir: 'ltr' },
    { code: 'sk',    name: 'Slovak',                   native: 'Slovenčina',          dir: 'ltr' },
    { code: 'sl',    name: 'Slovenian',                native: 'Slovenščina',         dir: 'ltr' },
    { code: 'hr',    name: 'Croatian',                 native: 'Hrvatski',            dir: 'ltr' },
    { code: 'bs',    name: 'Bosnian',                  native: 'Bosanski',            dir: 'ltr' },
    { code: 'sr',    name: 'Serbian',                  native: 'Српски',              dir: 'ltr' },
    { code: 'bg',    name: 'Bulgarian',                native: 'Български',           dir: 'ltr' },
    { code: 'mk',    name: 'Macedonian',               native: 'Македонски',          dir: 'ltr' },
    { code: 'sq',    name: 'Albanian',                 native: 'Shqip',               dir: 'ltr' },
    { code: 'lt',    name: 'Lithuanian',               native: 'Lietuvių',            dir: 'ltr' },
    { code: 'lv',    name: 'Latvian',                  native: 'Latviešu',            dir: 'ltr' },
    { code: 'et',    name: 'Estonian',                 native: 'Eesti',               dir: 'ltr' },
    { code: 'fi',    name: 'Finnish',                  native: 'Suomi',               dir: 'ltr' },
    { code: 'sv',    name: 'Swedish',                  native: 'Svenska',             dir: 'ltr' },
    { code: 'no',    name: 'Norwegian',                native: 'Norsk',               dir: 'ltr' },
    { code: 'da',    name: 'Danish',                   native: 'Dansk',               dir: 'ltr' },
    { code: 'is',    name: 'Icelandic',                native: 'Íslenska',            dir: 'ltr' },
    { code: 'ga',    name: 'Irish',                    native: 'Gaeilge',             dir: 'ltr' },
    { code: 'cy',    name: 'Welsh',                    native: 'Cymraeg',             dir: 'ltr' },
  ];

  // ── Cache ─────────────────────────────────────────────────────────────────
  function cacheKey(langCode) {
    var page = location.pathname.replace(/^.*\//, '').replace(/\.html$/, '') || 'index';
    return 'ebh_i18n_' + CACHE_VER + '_' + langCode + '_' + page;
  }
  function getCache(langCode) {
    try {
      var raw = localStorage.getItem(cacheKey(langCode));
      if (!raw) return null;
      var obj = JSON.parse(raw);
      if (Date.now() - obj.ts > CACHE_TTL) { localStorage.removeItem(cacheKey(langCode)); return null; }
      return obj.map;
    } catch (e) { return null; }
  }
  function setCache(langCode, map) {
    try { localStorage.setItem(cacheKey(langCode), JSON.stringify({ ts: Date.now(), map: map })); } catch (e) {}
  }

  // ── DOM element collection ────────────────────────────────────────────────
  var BLOCK_TAGS = ['DIV','P','H1','H2','H3','H4','H5','H6','UL','OL','LI','TABLE','TBODY','TR','FORM','SECTION','ARTICLE','ASIDE','HEADER','FOOTER','NAV','MAIN','BLOCKQUOTE'];

  function hasBlockChild(el) {
    for (var i = 0; i < el.children.length; i++) {
      if (BLOCK_TAGS.indexOf(el.children[i].tagName) !== -1) return true;
    }
    return false;
  }

  function hasInputChild(el) {
    return !!el.querySelector('input, select, textarea');
  }

  function collectElements() {
    var selectors = [
      'nav .nav-logo', 'nav .nav-link',
      '.page-hero .page-label', '.page-hero h1', '.page-hero p',
      '.edu-notice p',
      'main h1', 'main h2', 'main h3', 'main h4',
      'main p', 'main li', 'main label',
      'main button', 'main .page-label', 'main .field-label',
      'main .intro', 'main .cred-text', 'main .reason-text',
      'main .section-sub', 'main .section-heading',
      'main .optin-sub', 'main .auth-sub',
      'main .featured-label', 'main .featured-title',
      'main .featured-preview', 'main .featured-read',
      'main .highlight-box p', 'main .quote-box p',
      'main .cta-p', 'main .references p',
      'main .references-label',
      'footer'
    ];
    var seen = [];
    var elements = [];
    selectors.forEach(function (sel) {
      try {
        document.querySelectorAll(sel).forEach(function (el) {
          if (seen.indexOf(el) !== -1) return;
          if (el.closest('[data-no-translate]')) return;
          if (hasBlockChild(el)) return;
          var text = (el.innerText || '').trim();
          if (!text || text.length < 2) return;
          // Skip pure numbers, symbols, emails, URLs
          if (/^[\d\s.,%-]+$/.test(text)) return;
          if (/^https?:\/\//.test(text)) return;
          seen.push(el);
          elements.push(el);
        });
      } catch (e) {}
    });
    return elements;
  }

  // ── Current page slug ────────────────────────────────────────────────────
  function pageSlug() {
    return location.pathname.replace(/^.*\//, '').replace(/\.html$/, '') || 'index';
  }

  // ── Load pre-built translation map from DynamoDB via GET /translations ───
  function loadPrebuilt(langCode) {
    return fetch(API + '/translations?lang=' + encodeURIComponent(langCode) + '&page=' + encodeURIComponent(pageSlug()))
      .then(function (res) {
        if (!res.ok) return null;
        return res.json();
      }).then(function (data) {
        return (data && data.map) ? data.map : null;
      }).catch(function () { return null; });
  }

  // ── Translation API call (fallback for strings not in pre-built map) ──────
  function translateTexts(texts, langCode, langName) {
    return fetch(API + '/translate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ texts: texts, targetLang: langCode, langName: langName, page: pageSlug() }),
    }).then(function (res) {
      if (!res.ok) throw new Error('Translation API ' + res.status);
      return res.json();
    }).then(function (data) {
      return data.translations;
    });
  }

  // ── Apply / restore translations ──────────────────────────────────────────
  function applyTranslations(elements, originalTexts, map) {
    for (var i = 0; i < elements.length; i++) {
      var el = elements[i];
      var orig = originalTexts[i];
      var translated = map[orig];
      if (translated && translated !== orig) {
        if (!el.dataset.origContent) el.dataset.origContent = el.innerHTML;
        if (hasInputChild(el)) {
          // Modify text nodes in-place so input/checkbox elements and their
          // event listeners are preserved intact.
          var textSet = false;
          var nodes = el.childNodes;
          for (var n = 0; n < nodes.length; n++) {
            var node = nodes[n];
            if (node.nodeType === 3 && node.textContent.trim()) {
              if (!textSet) {
                var ws = node.textContent.match(/^\s*/)[0];
                node.textContent = ws + translated;
                textSet = true;
              } else {
                node.textContent = ''; // clear extra text (from inline-element labels)
              }
            } else if (node.nodeType === 1 &&
                       node.tagName !== 'INPUT' && node.tagName !== 'SELECT' && node.tagName !== 'TEXTAREA') {
              // Hide inline elements like <strong> whose text is now in the translation
              node.style.display = 'none';
            }
          }
        } else {
          el.innerText = translated;
        }
      }
    }
  }

  function restorePage() {
    document.querySelectorAll('[data-orig-content]').forEach(function (el) {
      el.innerHTML = el.dataset.origContent;
      delete el.dataset.origContent;
    });
    document.documentElement.dir = 'ltr';
    document.documentElement.lang = 'en';
  }

  // ── Translate page ────────────────────────────────────────────────────────
  function translatePage(langCode) {
    if (langCode === 'en') { restorePage(); return Promise.resolve(); }
    var lang = LANGUAGES.filter(function (l) { return l.code === langCode; })[0];
    if (!lang) return Promise.resolve();

    var elements = collectElements();
    var originalTexts = elements.map(function (el) { return (el.innerText || '').trim(); });

    // Check localStorage cache first
    var localCache = getCache(langCode) || {};

    // Try loading pre-built map from DynamoDB (instant for pre-translated langs)
    return loadPrebuilt(langCode).then(function (prebuilt) {
      // Merge pre-built into local cache; pre-built is authoritative
      var cache = Object.assign({}, localCache, prebuilt || {});

      var missing = [];
      for (var i = 0; i < originalTexts.length; i++) {
        if (!cache[originalTexts[i]]) missing.push(originalTexts[i]);
      }

      var fetchPromise;
      if (missing.length > 0) {
        // Fallback: translate remaining strings via API (auto-writes to DynamoDB)
        var BATCH = 15;
        var batches = [];
        for (var b = 0; b < missing.length; b += BATCH) {
          batches.push(missing.slice(b, b + BATCH));
        }
        fetchPromise = batches.reduce(function (p, batch) {
          return p.then(function () {
            return translateTexts(batch, langCode, lang.name).then(function (translated) {
              for (var j = 0; j < batch.length; j++) {
                cache[batch[j]] = (translated && translated[j]) ? translated[j] : batch[j];
              }
            });
          });
        }, Promise.resolve()).then(function () {
          setCache(langCode, cache);
        });
      } else {
        // All strings found in pre-built map — save to local cache and done
        setCache(langCode, cache);
        fetchPromise = Promise.resolve();
      }

      return fetchPromise.then(function () {
        applyTranslations(elements, originalTexts, cache);
        document.documentElement.dir = lang.dir || 'ltr';
        document.documentElement.lang = langCode;
      });
    });
  }

  // ── Language preference persistence ──────────────────────────────────────
  function getSavedLang() {
    try { return localStorage.getItem(LANG_KEY) || 'en'; } catch (e) { return 'en'; }
  }
  function saveLangLocal(code) {
    try { localStorage.setItem(LANG_KEY, code); } catch (e) {}
  }
  function saveLangProfile(code) {
    var token;
    try { token = localStorage.getItem(TOKEN_KEY); } catch (e) {}
    if (!token) return;
    fetch(API + '/profile-language', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ language: code }),
    }).catch(function () {});
  }

  // ── Language picker UI ────────────────────────────────────────────────────
  function injectStyles() {
    var style = document.createElement('style');
    style.textContent = [
      '#i18n-btn{display:flex;align-items:center;gap:0.4rem;padding:0.28rem 0.6rem;border-radius:20px;',
      'border:1px solid var(--paper-warm,#ede9e1);background:transparent;cursor:pointer;',
      'font-family:var(--sans,system-ui,sans-serif);font-size:0.7rem;color:var(--ink-light,#5c6e65);',
      'transition:border-color .15s,color .15s;white-space:nowrap;line-height:1}',
      '#i18n-btn:hover{border-color:var(--accent,#1a5c3a);color:var(--accent,#1a5c3a)}',
      '#i18n-btn svg{flex-shrink:0}',
      '#i18n-overlay{display:none;position:fixed;inset:0;z-index:9000;',
      'background:rgba(15,26,20,.45);backdrop-filter:blur(2px)}',
      '#i18n-overlay.open{display:flex;align-items:flex-start;justify-content:flex-end;padding:64px 1.2rem 0}',
      '#i18n-modal{background:#fff;border-radius:8px;width:300px;max-height:460px;',
      'display:flex;flex-direction:column;overflow:hidden;',
      'box-shadow:0 12px 40px rgba(15,26,20,.22)}',
      '#i18n-modal-head{padding:.85rem 1rem .5rem;border-bottom:1px solid var(--paper-warm,#ede9e1)}',
      '#i18n-modal-head p{font-size:.65rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;',
      'color:var(--ink-faint,#9aada3);margin:0 0 .55rem}',
      '#i18n-search{width:100%;padding:.45rem .65rem;border:1px solid var(--paper-warm,#ede9e1);',
      'border-radius:6px;font-family:var(--sans,system-ui,sans-serif);font-size:.85rem;outline:none;',
      'color:var(--ink,#0f1a14);box-sizing:border-box}',
      '#i18n-search:focus{border-color:var(--accent,#1a5c3a)}',
      '#i18n-list{overflow-y:auto;flex:1;padding:.3rem 0}',
      '.i18n-item{display:flex;align-items:center;gap:.6rem;padding:.5rem 1rem;cursor:pointer;',
      'font-size:.85rem;color:var(--ink,#0f1a14);transition:background .1s}',
      '.i18n-item:hover{background:var(--paper,#f7f5f0)}',
      '.i18n-item.active{background:var(--accent-light,#e8f2ec);color:var(--accent,#1a5c3a);font-weight:500}',
      '.i18n-native{font-size:.75rem;color:var(--ink-faint,#9aada3);margin-left:auto}',
      '#i18n-toast{display:none;position:fixed;bottom:1.4rem;left:50%;transform:translateX(-50%);',
      'background:var(--accent,#1a5c3a);color:#fff;border-radius:20px;',
      'padding:.5rem 1.3rem;font-size:.8rem;font-family:var(--sans,system-ui);z-index:9999;',
      'box-shadow:0 4px 16px rgba(15,26,20,.25);pointer-events:none}',
      '@media(max-width:600px){',
      '#i18n-overlay.open{padding:56px 0 0;align-items:flex-end;justify-content:stretch}',
      '#i18n-modal{width:100%;max-height:60vh;border-bottom-left-radius:0;border-bottom-right-radius:0}}',
      /* Nav layout: desktop — keep globe at far right after nav-links */
      '@media(min-width:601px){nav{justify-content:flex-start!important}',
      'nav .nav-links{margin-left:auto}',
      '#i18n-btn{margin-left:1.5rem}}',
      /* Nav layout: mobile — globe on same row as logo, nav-links below */
      '@media(max-width:600px){.nav-logo{flex:1!important}',
      '#i18n-btn{flex-shrink:0;align-self:center}}',
    ].join('');
    document.head.appendChild(style);
  }

  function renderList(langs, activeCode) {
    var list = document.getElementById('i18n-list');
    if (!list) return;
    list.innerHTML = langs.map(function (l) {
      var active = l.code === activeCode ? ' active' : '';
      return '<div class="i18n-item' + active + '" role="option" aria-selected="' + (l.code === activeCode) + '" data-code="' + l.code + '" tabindex="0"><span>' + l.name + '</span><span class="i18n-native">' + l.native + '</span></div>';
    }).join('');
    list.querySelectorAll('.i18n-item').forEach(function (item) {
      item.addEventListener('click', function () { selectLang(item.dataset.code); });
      item.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') selectLang(item.dataset.code); });
    });
  }

  function buildPickerUI() {
    if (document.getElementById('i18n-btn')) return;
    injectStyles();

    var savedCode = getSavedLang();
    var savedLang = LANGUAGES.filter(function (l) { return l.code === savedCode; })[0] || LANGUAGES[0];

    // Globe button — appended to nav (sibling of .nav-logo and .nav-links)
    var btn = document.createElement('button');
    btn.id = 'i18n-btn';
    btn.setAttribute('aria-label', 'Select language');
    btn.setAttribute('title', 'Select language');
    btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg><span id="i18n-label">' + (savedCode === 'en' ? 'Language' : savedLang.native) + '</span>';
    var navEl = document.querySelector('nav');
    if (navEl) navEl.appendChild(btn);

    // Overlay + modal
    var overlay = document.createElement('div');
    overlay.id = 'i18n-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Select language');
    overlay.innerHTML = '<div id="i18n-modal"><div id="i18n-modal-head"><p>Select language</p><input id="i18n-search" type="search" placeholder="Search…" autocomplete="off" spellcheck="false"></div><div id="i18n-list" role="listbox"></div></div>';
    document.body.appendChild(overlay);

    // Toast
    var toast = document.createElement('div');
    toast.id = 'i18n-toast';
    toast.textContent = 'Translating…';
    document.body.appendChild(toast);

    renderList(LANGUAGES, savedCode);

    btn.addEventListener('click', function () { overlay.classList.add('open'); document.getElementById('i18n-search').focus(); });
    overlay.addEventListener('click', function (e) { if (e.target === overlay) overlay.classList.remove('open'); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') overlay.classList.remove('open'); });

    var searchEl = document.getElementById('i18n-search');
    searchEl.addEventListener('input', function () {
      var q = searchEl.value.toLowerCase();
      var filtered = q ? LANGUAGES.filter(function (l) {
        return l.name.toLowerCase().indexOf(q) !== -1 || l.native.toLowerCase().indexOf(q) !== -1 || l.code.indexOf(q) !== -1;
      }) : LANGUAGES;
      renderList(filtered, getSavedLang());
    });
  }

  function selectLang(code) {
    var overlay = document.getElementById('i18n-overlay');
    if (overlay) overlay.classList.remove('open');

    saveLangLocal(code);

    var lang = LANGUAGES.filter(function (l) { return l.code === code; })[0];
    var label = document.getElementById('i18n-label');
    if (label) label.textContent = code === 'en' ? 'Language' : (lang ? lang.native : code);

    renderList(LANGUAGES, code);

    // Update prominent selector label if present
    var promLabel = document.getElementById('i18n-prom-label');
    if (promLabel) promLabel.textContent = lang ? lang.native : code;

    if (code === 'en') {
      restorePage();
      saveLangProfile(code);
      return;
    }

    var toast = document.getElementById('i18n-toast');
    if (toast) { toast.textContent = 'Translating\u2026'; toast.style.display = 'block'; }

    translatePage(code).then(function () {
      saveLangProfile(code);
      if (toast) toast.style.display = 'none';
    }).catch(function (err) {
      console.error('i18n translate error:', err);
      if (toast) { toast.textContent = 'Translation unavailable'; }
      setTimeout(function () {
        if (toast) { toast.style.display = 'none'; toast.textContent = 'Translating\u2026'; }
      }, 3000);
    });
  }

  // ── Init ──────────────────────────────────────────────────────────────────
  function init() {
    buildPickerUI();
    var saved = getSavedLang();
    if (saved && saved !== 'en') {
      var toast = document.getElementById('i18n-toast');
      if (toast) toast.style.display = 'block';
      translatePage(saved).catch(function () {}).then(function () {
        if (toast) toast.style.display = 'none';
      });
    }
  }

  // Run immediately if DOM is ready (script at end of body), else wait
  if (document.body && document.readyState !== 'loading') {
    init();
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }

  // Public API
  window.ebhI18n = {
    select: selectLang,
    getSaved: getSavedLang,
    languages: LANGUAGES,
    retranslate: function () {
      var code = getSavedLang();
      if (code === 'en') return;
      restorePage();
      var toast = document.getElementById('i18n-toast');
      if (toast) { toast.textContent = 'Translating\u2026'; toast.style.display = 'block'; }
      translatePage(code).then(function () {
        if (toast) toast.style.display = 'none';
      }).catch(function (err) {
        console.error('i18n retranslate error:', err);
        if (toast) { toast.textContent = 'Translation unavailable'; setTimeout(function () { if (toast) { toast.style.display = 'none'; toast.textContent = 'Translating\u2026'; } }, 3000); }
      });
    },
  };

}());
