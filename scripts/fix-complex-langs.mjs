/**
 * fix-complex-langs.mjs
 * Re-seeds languages that fail with the full batch size (lo, am, hy + any others)
 * due to "Unterminated string in JSON" (response too long for complex scripts).
 *
 * Uses BATCH_SIZE=15 and max_tokens=16384 for robustness.
 * Safe to re-run — uses merge writes (preserves existing entries).
 *
 * Usage:
 *   node scripts/fix-complex-langs.mjs
 *   node scripts/fix-complex-langs.mjs --langs lo,am,hy --pages index,prevention-roadmap
 */

import { readFileSync } from 'fs';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';

const OPENAI_API_KEY     = process.env.OPENAI_API_KEY;
const TRANSLATIONS_TABLE = process.env.TRANSLATIONS_TABLE || 'EBHTranslations';
const REGION             = 'us-east-1';
const CONCURRENCY        = 1;   // lower concurrency — these calls are heavier
const BATCH_SIZE         = 5;   // small batches to avoid response truncation for complex scripts

if (!OPENAI_API_KEY) { console.error('Set OPENAI_API_KEY env var'); process.exit(1); }

const dynamo = new DynamoDBClient({ region: REGION });

// Parse CLI args: --langs lo,am,hy  --pages index,about
const args = process.argv.slice(2);
function getArg(name) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : null;
}

const ALL_LANG_DEFS = [
  { code: 'es',    name: 'Spanish' },
  { code: 'fr',    name: 'French' },
  { code: 'de',    name: 'German' },
  { code: 'it',    name: 'Italian' },
  { code: 'pt',    name: 'Portuguese' },
  { code: 'nl',    name: 'Dutch' },
  { code: 'pl',    name: 'Polish' },
  { code: 'ru',    name: 'Russian' },
  { code: 'uk',    name: 'Ukrainian' },
  { code: 'zh',    name: 'Chinese (Simplified)' },
  { code: 'zh-TW', name: 'Chinese (Traditional)' },
  { code: 'ja',    name: 'Japanese' },
  { code: 'ko',    name: 'Korean' },
  { code: 'ar',    name: 'Arabic' },
  { code: 'he',    name: 'Hebrew' },
  { code: 'fa',    name: 'Persian (Farsi)' },
  { code: 'ur',    name: 'Urdu' },
  { code: 'hi',    name: 'Hindi' },
  { code: 'bn',    name: 'Bengali' },
  { code: 'pa',    name: 'Punjabi' },
  { code: 'gu',    name: 'Gujarati' },
  { code: 'mr',    name: 'Marathi' },
  { code: 'ta',    name: 'Tamil' },
  { code: 'te',    name: 'Telugu' },
  { code: 'kn',    name: 'Kannada' },
  { code: 'ml',    name: 'Malayalam' },
  { code: 'ne',    name: 'Nepali' },
  { code: 'si',    name: 'Sinhala' },
  { code: 'vi',    name: 'Vietnamese' },
  { code: 'th',    name: 'Thai' },
  { code: 'id',    name: 'Indonesian' },
  { code: 'ms',    name: 'Malay' },
  { code: 'tl',    name: 'Filipino (Tagalog)' },
  { code: 'jv',    name: 'Javanese' },
  { code: 'my',    name: 'Burmese' },
  { code: 'km',    name: 'Khmer' },
  { code: 'lo',    name: 'Lao' },
  { code: 'mn',    name: 'Mongolian' },
  { code: 'ka',    name: 'Georgian' },
  { code: 'am',    name: 'Amharic' },
  { code: 'sw',    name: 'Swahili' },
  { code: 'yo',    name: 'Yoruba' },
  { code: 'ig',    name: 'Igbo' },
  { code: 'ha',    name: 'Hausa' },
  { code: 'so',    name: 'Somali' },
  { code: 'zu',    name: 'Zulu' },
  { code: 'af',    name: 'Afrikaans' },
  { code: 'ht',    name: 'Haitian Creole' },
  { code: 'tr',    name: 'Turkish' },
  { code: 'az',    name: 'Azerbaijani' },
  { code: 'kk',    name: 'Kazakh' },
  { code: 'uz',    name: 'Uzbek' },
  { code: 'hy',    name: 'Armenian' },
  { code: 'el',    name: 'Greek' },
  { code: 'ro',    name: 'Romanian' },
  { code: 'hu',    name: 'Hungarian' },
  { code: 'cs',    name: 'Czech' },
  { code: 'sk',    name: 'Slovak' },
  { code: 'sl',    name: 'Slovenian' },
  { code: 'hr',    name: 'Croatian' },
  { code: 'bs',    name: 'Bosnian' },
  { code: 'sr',    name: 'Serbian' },
  { code: 'bg',    name: 'Bulgarian' },
  { code: 'mk',    name: 'Macedonian' },
  { code: 'sq',    name: 'Albanian' },
  { code: 'lt',    name: 'Lithuanian' },
  { code: 'lv',    name: 'Latvian' },
  { code: 'et',    name: 'Estonian' },
  { code: 'fi',    name: 'Finnish' },
  { code: 'sv',    name: 'Swedish' },
  { code: 'no',    name: 'Norwegian' },
  { code: 'da',    name: 'Danish' },
  { code: 'is',    name: 'Icelandic' },
  { code: 'ga',    name: 'Irish' },
  { code: 'cy',    name: 'Welsh' },
];

const ALL_PAGES = [
  { slug: 'index',              file: 'index.html' },
  { slug: 'about',              file: 'about.html' },
  { slug: 'newsletter',         file: 'newsletter.html' },
  { slug: 'prevention-roadmap', file: 'prevention-roadmap.html' },
  { slug: 'my-roadmap',         file: 'my-roadmap.html' },
  // disclaimer, privacy, thanks are admin/legal pages — not translated
];

// Default: only the three consistently-failing complex-script languages
const DEFAULT_LANGS = ['lo', 'am', 'hy'];

const langFilter  = getArg('langs')  ? getArg('langs').split(',').map(s => s.trim())  : DEFAULT_LANGS;
const pageFilter  = getArg('pages')  ? getArg('pages').split(',').map(s => s.trim())  : null;

const LANGUAGES = ALL_LANG_DEFS.filter(l => langFilter.includes(l.code));
const PAGES     = pageFilter ? ALL_PAGES.filter(p => pageFilter.includes(p.slug)) : ALL_PAGES;

// ── Shared helpers (same as pretranslate.mjs) ────────────────────────────────
function stripHtml(str) {
  return str
    .replace(/<[^>]+>/g, ' ')
    .replace(/&rsquo;/g, "'").replace(/&lsquo;/g, "'")
    .replace(/&rdquo;/g, '"').replace(/&ldquo;/g, '"')
    .replace(/&mdash;/g, '—').replace(/&ndash;/g, '–')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&hellip;/g, '…').replace(/&rarr;/g, '→')
    .replace(/&#8209;/g, '‑').replace(/&#10003;/g, '✓')
    .replace(/&[a-z]+;/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

function extractStringsFromHtml(html) {
  const seen = new Set();
  const result = [];

  function add(t) {
    const clean = t.trim();
    if (!clean || clean.length < 2) return;
    if (/^[\d\s.,\-+%()]+$/.test(clean)) return;
    if (/^https?:\/\//.test(clean)) return;
    if (seen.has(clean)) return;
    seen.add(clean);
    result.push(clean);
  }

  for (const m of html.matchAll(/<a[^>]+class="[^"]*nav[^"]*"[^>]*>([\s\S]*?)<\/a>/gi))
    add(stripHtml(m[1]));
  for (const m of html.matchAll(/<div[^>]+class="[^"]*page-label[^"]*"[^>]*>([\s\S]*?)<\/div>/gi))
    add(stripHtml(m[1]));
  for (const m of html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi))
    add(stripHtml(m[1]));
  for (const m of html.matchAll(/<p[^>]+class="[^"]*hero-sub[^"]*"[^>]*>([\s\S]*?)<\/p>/gi))
    add(stripHtml(m[1]));
  for (const m of html.matchAll(/<h[234][^>]*>([\s\S]*?)<\/h[234]>/gi))
    add(stripHtml(m[1]));

  const noScript = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '');
  for (const m of noScript.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi))
    add(stripHtml(m[1]));
  for (const m of noScript.matchAll(/<li[^>]*>([\s\S]*?)<\/li>/gi))
    add(stripHtml(m[1]));
  for (const m of noScript.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/gi))
    add(stripHtml(m[1]));
  for (const m of noScript.matchAll(/<label[^>]*>([\s\S]*?)<\/label>/gi)) {
    const textOnly = m[1].replace(/<input[^>]*\/?>/gi, '').replace(/<[^>]+>/g, ' ');
    add(stripHtml(textOnly));
  }
  for (const m of noScript.matchAll(/<footer[^>]*>([\s\S]*?)<\/footer>/gi))
    for (const pm of m[1].matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi))
      add(stripHtml(pm[1]));
  for (const cls of ['field-hint', 'q-sub', 'results-disclaimer', 'hero-sub', 'optin-sub',
                      'edu-notice', 'info-section', 'references', 'cred-text', 'reason-text']) {
    const re = new RegExp(`class="[^"]*${cls}[^"]*"[^>]*>([\\s\\S]*?)<\\/(?:p|div|span)>`, 'gi');
    for (const m of noScript.matchAll(re))
      add(stripHtml(m[1]));
  }

  return result;
}

function extractJsStrings(html) {
  const seen = new Set();
  const result = [];

  function add(t) {
    const clean = t.replace(/\\u2019/g,"'").replace(/\\u2013/g,'–').replace(/\\u2014/g,'—')
                   .replace(/\\n/g,' ').replace(/\\'/g,"'").replace(/\\"/g,'"')
                   .replace(/&rsquo;/g,"'").replace(/&mdash;/g,'—').replace(/&ndash;/g,'–')
                   .replace(/&hellip;/g,'…').replace(/&rarr;/g,'→').replace(/&nbsp;/g,' ')
                   .replace(/&amp;/g,'&')
                   .replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();
    if (!clean || clean.length < 3) return;
    if (/^[\d\s.,\-+%()]+$/.test(clean)) return;
    if (/^https?:\/\//.test(clean)) return;
    if (seen.has(clean)) return;
    seen.add(clean);
    result.push(clean);
  }

  for (const m of html.matchAll(/title:\s*[`']([^`']+)[`']/g)) add(m[1]);
  for (const m of html.matchAll(/label:\s*[`']([^`']+)[`']/g)) add(m[1]);
  for (const m of html.matchAll(/body:\s*`([\s\S]*?)`\s*,/g)) {
    const cleaned = m[1].replace(/\$\{[^}]+\}/g, '…');
    add(cleaned);
  }
  for (const m of html.matchAll(/'([^']{8,}[?.!])'/g)) add(m[1]);
  for (const m of html.matchAll(/`([^`]{8,}[?.!])`/g)) {
    const s = m[1].replace(/\$\{[^}]+\}/g, '…');
    add(s);
  }
  for (const m of html.matchAll(/textContent\s*=\s*['`]([^'`]+)['`]/g)) add(m[1]);
  for (const m of html.matchAll(/\.textContent\s*=\s*['`]([^'`]+)['`]/g)) add(m[1]);

  return result;
}

// ── OpenAI call with explicit max_tokens ─────────────────────────────────────
async function translateBatch(texts, langCode, langName) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      temperature: 0.1,
      max_tokens: 16384,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content: 'You are a professional medical translator. Return ONLY valid JSON: { "translations": ["...", ...] }. Preserve any HTML tags exactly as-is. Translate accurately and naturally.',
        },
        {
          role: 'user',
          content: `Translate each text from English to ${langName}. Return JSON with a "translations" array in the same order.\n\nTexts:\n${JSON.stringify(texts)}`,
        },
      ],
    }),
  });
  if (!res.ok) throw new Error(`OpenAI ${res.status}: ${await res.text()}`);
  const data = await res.json();
  const content = data.choices?.[0]?.message?.content || '{}';
  const parsed = JSON.parse(content);
  const arr = Array.isArray(parsed) ? parsed
    : Array.isArray(parsed.translations) ? parsed.translations
    : Object.values(parsed).find(v => Array.isArray(v)) || [];
  if (arr.length !== texts.length) throw new Error(`Length mismatch: sent ${texts.length}, got ${arr.length}`);
  return arr;
}

async function translateAllStrings(strings, langCode, langName) {
  const map = {};
  for (let i = 0; i < strings.length; i += BATCH_SIZE) {
    const batch = strings.slice(i, i + BATCH_SIZE);
    let attempts = 0;
    while (attempts < 3) {
      try {
        const translated = await translateBatch(batch, langCode, langName);
        for (let j = 0; j < batch.length; j++) {
          if (translated[j]) map[batch[j]] = translated[j];
        }
        process.stdout.write('.');
        break;
      } catch (e) {
        attempts++;
        if (attempts >= 3) {
          console.error(`\n  ✗ batch ${i}–${i + batch.length} failed after 3 attempts: ${e.message}`);
          break;
        }
        process.stdout.write(`↻`);
        await new Promise(r => setTimeout(r, 2000 * attempts));
      }
    }
  }
  return map;
}

async function saveToDb(page, lang, map) {
  let existing = {};
  try {
    const item = await dynamo.send(new GetItemCommand({
      TableName: TRANSLATIONS_TABLE,
      Key: { page: { S: page }, lang: { S: lang } },
    }));
    if (item.Item?.map?.S) existing = JSON.parse(item.Item.map.S);
  } catch {}
  const merged = { ...existing, ...map };
  await dynamo.send(new UpdateItemCommand({
    TableName: TRANSLATIONS_TABLE,
    Key: { page: { S: page }, lang: { S: lang } },
    UpdateExpression: 'SET #m = :m, updatedAt = :u',
    ExpressionAttributeNames:  { '#m': 'map' },
    ExpressionAttributeValues: {
      ':m': { S: JSON.stringify(merged) },
      ':u': { S: new Date().toISOString() },
    },
  }));
}

async function pool(items, fn, concurrency) {
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
}

const BASE_DIR = new URL('..', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1');

async function main() {
  console.log('🔧 EBH complex-language fix script');
  console.log(`   Langs: ${LANGUAGES.map(l => l.code).join(', ')}`);
  console.log(`   Pages: ${PAGES.map(p => p.slug).join(', ')}`);
  console.log(`   Batch size: ${BATCH_SIZE} | max_tokens: 16384\n`);

  for (const { slug, file } of PAGES) {
    let html;
    try { html = readFileSync(`${BASE_DIR}/${file}`, 'utf8'); }
    catch (e) { console.warn(`  ⚠ Cannot read ${file}: ${e.message}`); continue; }

    const htmlStrings = extractStringsFromHtml(html);
    const jsStrings   = slug === 'prevention-roadmap' ? extractJsStrings(html) : [];
    const allStrings  = [...new Set([...htmlStrings, ...jsStrings])];
    console.log(`📄 ${slug}: ${allStrings.length} strings`);

    await pool(LANGUAGES, async (lang) => {
      process.stdout.write(`  → ${lang.code.padEnd(5)} `);
      try {
        const map = await translateAllStrings(allStrings, lang.code, lang.name);
        await saveToDb(slug, lang.code, map);
        process.stdout.write(` ✓ (${Object.keys(map).length})\n`);
      } catch (e) {
        process.stdout.write(` ✗ ${e.message}\n`);
      }
    }, CONCURRENCY);
  }

  console.log('\n✅ Done.');
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
