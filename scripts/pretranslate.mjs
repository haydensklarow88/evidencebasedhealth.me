/**
 * pretranslate.mjs
 * Pre-translates all HTML pages into all 80 languages and stores in DynamoDB.
 * Run once: node scripts/pretranslate.mjs
 * Re-run after content changes.
 */

import { readFileSync } from 'fs';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';

const OPENAI_API_KEY   = process.env.OPENAI_API_KEY;
const TRANSLATIONS_TABLE = process.env.TRANSLATIONS_TABLE || 'EBHTranslations';
const REGION           = 'us-east-1';
const CONCURRENCY      = 5;   // languages in parallel
const BATCH_SIZE       = 40;  // strings per OpenAI call (no API GW limit here)

if (!OPENAI_API_KEY) { console.error('Set OPENAI_API_KEY env var'); process.exit(1); }

const dynamo = new DynamoDBClient({ region: REGION });

// ── Language list (must match i18n.js) ─────────────────────────────────────
const LANGUAGES = [
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

// ── Pages to translate (slug → html file path) ──────────────────────────────
const PAGES = [
  { slug: 'index',              file: 'index.html' },
  { slug: 'about',              file: 'about.html' },
  { slug: 'newsletter',         file: 'newsletter.html' },
  { slug: 'prevention-roadmap', file: 'prevention-roadmap.html' },
  { slug: 'my-roadmap',         file: 'my-roadmap.html' },
  { slug: 'disclaimer',         file: 'disclaimer.html' },
  { slug: 'privacy',            file: 'privacy.html' },
  { slug: 'thanks',             file: 'thanks.html' },
];

// ── HTML text extraction ─────────────────────────────────────────────────────
// Strip all HTML tags and decode common entities from a string.
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

// Extract inner text from a tag match, strip HTML.
function extractTagContent(html, tagPattern) {
  const texts = [];
  const re = new RegExp(tagPattern, 'gis');
  let m;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1] || m[0];
    const text = stripHtml(raw).trim();
    if (text && text.length >= 2 && !/^[\d\s.,\-+%()]+$/.test(text) && !/^https?:\/\//.test(text)) {
      texts.push(text);
    }
  }
  return texts;
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

  // Nav logo / nav links
  for (const m of html.matchAll(/<a[^>]+class="[^"]*nav[^"]*"[^>]*>([\s\S]*?)<\/a>/gi))
    add(stripHtml(m[1]));

  // Page label
  for (const m of html.matchAll(/<div[^>]+class="[^"]*page-label[^"]*"[^>]*>([\s\S]*?)<\/div>/gi))
    add(stripHtml(m[1]));

  // Hero heading & sub
  for (const m of html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi))
    add(stripHtml(m[1]));
  for (const m of html.matchAll(/<p[^>]+class="[^"]*hero-sub[^"]*"[^>]*>([\s\S]*?)<\/p>/gi))
    add(stripHtml(m[1]));

  // All h2, h3, h4
  for (const m of html.matchAll(/<h[234][^>]*>([\s\S]*?)<\/h[234]>/gi))
    add(stripHtml(m[1]));

  // All <p> not inside <script> / <style>
  const noScript = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '');
  for (const m of noScript.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi))
    add(stripHtml(m[1]));

  // List items
  for (const m of noScript.matchAll(/<li[^>]*>([\s\S]*?)<\/li>/gi))
    add(stripHtml(m[1]));

  // Buttons (not inside nav pill script)
  for (const m of noScript.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/gi))
    add(stripHtml(m[1]));

  // Labels with text nodes (skip pure-input labels)
  for (const m of noScript.matchAll(/<label[^>]*>([\s\S]*?)<\/label>/gi)) {
    const inner = m[1];
    // Only extract the text node part (after stripping input tags)
    const textOnly = inner.replace(/<input[^>]*\/?>/gi, '').replace(/<[^>]+>/g, ' ');
    add(stripHtml(textOnly));
  }

  // Footer text
  for (const m of noScript.matchAll(/<footer[^>]*>([\s\S]*?)<\/footer>/gi))
    for (const pm of m[1].matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi))
      add(stripHtml(pm[1]));

  // field-hint, field-label, q-sub, results-summary placeholder, section-heading, optin-sub etc.
  for (const cls of ['field-hint', 'q-sub', 'results-disclaimer', 'hero-sub', 'optin-sub',
                      'edu-notice', 'info-section', 'references', 'cred-text', 'reason-text']) {
    const re = new RegExp(`class="[^"]*${cls}[^"]*"[^>]*>([\\s\\S]*?)<\\/(?:p|div|span)>`, 'gi');
    for (const m of noScript.matchAll(re))
      add(stripHtml(m[1]));
  }

  return result;
}

// ── Extract JS result-card strings from prevention-roadmap.html ─────────────
// These are the dynamic strings rendered after form submit.
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

  // Extract title: '...' and title: `...` patterns
  for (const m of html.matchAll(/title:\s*[`']([^`']+)[`']/g)) add(m[1]);
  // Extract label: '...' patterns
  for (const m of html.matchAll(/label:\s*[`']([^`']+)[`']/g)) add(m[1]);
  // Extract body template literal content (strip JS interpolation)
  for (const m of html.matchAll(/body:\s*`([\s\S]*?)`\s*,/g)) {
    const cleaned = m[1].replace(/\$\{[^}]+\}/g, '…');
    add(cleaned);
  }
  // Extract ask strings
  for (const m of html.matchAll(/'([^']{8,}[?.!])'/g)) add(m[1]);
  for (const m of html.matchAll(/`([^`]{8,}[?.!])`/g)) {
    const s = m[1].replace(/\$\{[^}]+\}/g, '…');
    add(s);
  }
  // button/message text
  for (const m of html.matchAll(/textContent\s*=\s*['`]([^'`]+)['`]/g)) add(m[1]);
  for (const m of html.matchAll(/\.textContent\s*=\s*['`]([^'`]+)['`]/g)) add(m[1]);

  return result;
}

// ── OpenAI translation ───────────────────────────────────────────────────────
async function translateBatch(texts, langCode, langName) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      temperature: 0.1,
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
        break;
      } catch (e) {
        attempts++;
        if (attempts >= 3) { console.error(`  ✗ batch failed after 3 attempts: ${e.message}`); break; }
        console.warn(`  ↻ retry ${attempts}/3 for lang=${langCode} batch ${i}–${i + batch.length}`);
        await new Promise(r => setTimeout(r, 2000 * attempts));
      }
    }
  }
  return map;
}

// ── DynamoDB write ───────────────────────────────────────────────────────────
async function saveToDb(page, lang, map) {
  // Load existing, merge, save
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

// ── Pool helper (run N tasks in parallel with concurrency limit) ─────────────
async function pool(items, fn, concurrency) {
  const results = [];
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return results;
}

// ── Main ─────────────────────────────────────────────────────────────────────
const BASE_DIR = new URL('..', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1');

async function processPage(pageSlug, htmlFile) {
  console.log(`\n📄 Page: ${pageSlug}`);
  let html;
  try {
    html = readFileSync(`${BASE_DIR}/${htmlFile}`, 'utf8');
  } catch (e) {
    console.warn(`  ⚠ Cannot read ${htmlFile}: ${e.message}`);
    return;
  }

  const htmlStrings = extractStringsFromHtml(html);
  const jsStrings   = pageSlug === 'prevention-roadmap' ? extractJsStrings(html) : [];
  const allStrings  = [...new Set([...htmlStrings, ...jsStrings])];
  console.log(`  ${allStrings.length} unique strings (${htmlStrings.length} HTML + ${jsStrings.length} JS)`);

  if (allStrings.length === 0) { console.log('  ⚠ No strings found, skipping'); return; }

  await pool(LANGUAGES, async (lang) => {
    process.stdout.write(`  → ${lang.code.padEnd(6)}`);
    try {
      const map = await translateAllStrings(allStrings, lang.code, lang.name);
      await saveToDb(pageSlug, lang.code, map);
      process.stdout.write(` ✓ (${Object.keys(map).length} strings)\n`);
    } catch (e) {
      process.stdout.write(` ✗ ${e.message}\n`);
    }
  }, CONCURRENCY);
}

async function main() {
  console.log('🌍 EBH Pre-translation seed script');
  console.log(`   Table: ${TRANSLATIONS_TABLE} | Region: ${REGION}`);
  console.log(`   Languages: ${LANGUAGES.length} | Pages: ${PAGES.length}\n`);

  for (const { slug, file } of PAGES) {
    await processPage(slug, file);
  }

  console.log('\n✅ Done. All translations stored in DynamoDB.');
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
