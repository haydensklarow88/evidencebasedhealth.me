import { createHmac, timingSafeEqual, randomUUID, pbkdf2Sync, randomBytes } from 'crypto';
import {
  DynamoDBClient,
  PutItemCommand,
  ScanCommand,
  UpdateItemCommand,
  DeleteItemCommand,
  GetItemCommand,
} from '@aws-sdk/client-dynamodb';
import {
  SESv2Client,
  SendEmailCommand,
} from '@aws-sdk/client-sesv2';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { PinpointSMSVoiceV2Client, SendTextMessageCommand } from '@aws-sdk/client-pinpoint-sms-voice-v2';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const {
  ADMIN_PASSWORD, JWT_SECRET,
  FB_ACCESS_TOKEN, FB_AD_ACCOUNT_ID, FB_PAGE_ID,
  META_ACCESS_TOKEN,
  SITE_ORIGIN, CLIENTS_TABLE = 'AdClients',
  SUBSCRIBERS_TABLE = 'EBHSubscribers',
  VIOLATIONS_TABLE  = 'EBHPolicyViolations',
  NL_DRAFTS_TABLE   = 'EBHNewsletterDrafts',
  AUTOPILOT_TABLE   = 'EBHAutopilotConfig',
  POSTS_TABLE       = 'EBHPosts',
  PROFILES_TABLE      = 'EBHProfiles',
  PREVENTION_TABLE    = 'PreventionProfiles',
  TRANSLATIONS_TABLE  = 'EBHTranslations',
  MEDIA_BUCKET        = 'ebh-media-uploads',
  GOOGLE_ADS_DEVELOPER_TOKEN, GOOGLE_DEVELOPER_TOKEN,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
  GOOGLE_REFRESH_TOKEN,
  GOOGLE_ADS_CUSTOMER_ID, GOOGLE_CUSTOMER_ID,
  GOOGLE_ADS_MCC_ID, GOOGLE_MCC_ID,
  PERPLEXITY_API_KEY, OPENAI_API_KEY,
  SES_FROM_EMAIL = 'newsletter@evidencebasedhealth.me',
  SES_REPLY_TO   = 'hayden@evidencebasedhealth.me',
} = process.env;

const s3 = new S3Client({ region: 'us-east-1' });
const smsV2 = new PinpointSMSVoiceV2Client({ region: 'us-east-1' });

// Normalise Google Ads env var names â€” support both GOOGLE_ADS_* and GOOGLE_* variants
const _devToken    = GOOGLE_ADS_DEVELOPER_TOKEN || GOOGLE_DEVELOPER_TOKEN;
const _customerId  = GOOGLE_ADS_CUSTOMER_ID     || GOOGLE_CUSTOMER_ID;
const _mccId       = GOOGLE_ADS_MCC_ID          || GOOGLE_MCC_ID;

// â”€â”€â”€ LegitScript / FTC Compliance Policy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Disclaimer appended to all AI-generated ad variants
const COMPLIANCE_DISCLAIMER = 'Educational content only â€” not medical advice. Talk with your clinician before starting or changing any treatment.';

// Commercial-intent patterns â€” ALWAYS blocked in ad copy regardless of certification
const RX_COMMERCIAL_PATTERNS = [
  /\b(buy|order|get|purchase|access|obtain)\s+(semaglutide|tirzepatide|ozempic|wegovy|mounjaro|rybelsus|saxenda|peptide|testosterone|trt)\b/i,
  /no\s+prescription\s+(needed|required|necessary)/i,
  /guaranteed?\s+(weight\s+loss|results?|fat\s*loss|to\s+lose)/i,
  /melt\s+(fat|weight)|lose\s+\d+\s*(lbs?|pounds?|kg)\s+in\s+\d+/i,
  /online\s+pharmacy|we\s+(prescribe|dispense)|home\s+delivery.*prescription/i,
  /without\s+(seeing\s+)?a\s+doctor/i,
  /instant\s+(access|approval|prescription)/i,
];

// Drug BRAND names â€” blocked in ad copy for uncertified clients
const RX_BRAND_NAMES = ['ozempic','wegovy','mounjaro','rybelsus','saxenda','victoza','trulicity','zepbound','byetta'];

// Generic drug names â€” allowed ONLY with explicit educational framing for uncertified clients
const RX_GENERIC_NAMES = ['semaglutide','tirzepatide','liraglutide','dulaglutide','exenatide','bpc-157','tb-500','ipamorelin','cjc-1295','sermorelin'];

// Educational context qualifiers â€” presence alongside a generic name makes it acceptable
const EDU_QUALIFIER_RE = /\b(how|what|why|does|about|explain(s|ed)?|science|research|stud(y|ies)|mechanism|education(al)?|guide|overview|basics?|understanding|evidence.based)\b/i;

/**
 * Check ad copy text (or array of texts) for compliance violations.
 * @param {string|string[]} texts       - headlines, descriptions, or keywords to scan
 * @param {boolean}         isCertified - true only if client holds active LegitScript Rx certification
 * @returns {{ pass: boolean, violations: string[] }}
 */
function policyCheck(texts, isCertified = false) {
  const arr        = Array.isArray(texts) ? texts : [texts];
  const flat       = arr.join(' ');
  const lower      = flat.toLowerCase();
  const violations = [];

  // 1. Always-blocked commercial Rx intent patterns
  for (const pat of RX_COMMERCIAL_PATTERNS) {
    if (pat.test(flat)) violations.push(`Prohibited commercial Rx pattern: "${pat.source}"`);
  }

  if (!isCertified) {
    // 2. Drug brand names in ad copy â€” blocked for uncertified clients
    for (const name of RX_BRAND_NAMES) {
      if (lower.includes(name)) {
        violations.push(`Brand name "${name}" in ad copy requires LegitScript Rx certification`);
      }
    }
    // 3. Generic drug names â€” only permitted with an educational qualifier in the same text
    for (const name of RX_GENERIC_NAMES) {
      const escaped = name.replace(/-/g, '[- ]?');
      const nameRe  = new RegExp(`\\b${escaped}\\b`, 'i');
      if (nameRe.test(flat) && !EDU_QUALIFIER_RE.test(flat)) {
        violations.push(`Generic name "${name}" without educational framing requires LegitScript Rx certification`);
      }
    }
  }

  return { pass: violations.length === 0, violations };
}
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Persist a single policy violation event for future learning.
 * Fire-and-forget â€” failures must never break campaign creation.
 */
async function logViolation({ platform, type, text, policyName, policyDescription, isExemptible, wasExempted, clientId }) {
  if (!VIOLATIONS_TABLE || !text) return;
  try {
    await dynamo.send(new PutItemCommand({
      TableName: VIOLATIONS_TABLE,
      Item: {
        violationId:       { S: randomUUID() },
        platform:          { S: platform || 'google' },
        type:              { S: type || 'unknown' },
        text:              { S: String(text).slice(0, 500) },
        policyName:        { S: policyName || 'UNKNOWN' },
        policyDescription: { S: policyDescription || '' },
        isExemptible:      { BOOL: !!isExemptible },
        wasExempted:       { BOOL: !!wasExempted },
        clientId:          { S: clientId || '' },
        createdAt:         { S: new Date().toISOString() },
      },
    }));
  } catch { /* never surface logging errors */ }
}

/**
 * Fetch all stored policy violation records, optionally filtered by platform.
 */
async function getViolationHistory(platform) {
  if (!VIOLATIONS_TABLE) return [];
  try {
    const params = { TableName: VIOLATIONS_TABLE };
    if (platform) {
      params.FilterExpression = '#p = :p';
      params.ExpressionAttributeNames  = { '#p': 'platform' };
      params.ExpressionAttributeValues = { ':p': { S: platform } };
    }
    const { Items } = await dynamo.send(new ScanCommand(params));
    return (Items || []).map(item => ({
      violationId:       item.violationId?.S || '',
      platform:          item.platform?.S    || 'google',
      type:              item.type?.S        || '',
      text:              item.text?.S        || '',
      policyName:        item.policyName?.S  || '',
      policyDescription: item.policyDescription?.S || '',
      isExemptible:      item.isExemptible?.BOOL   || false,
      wasExempted:       item.wasExempted?.BOOL     || false,
      clientId:          item.clientId?.S    || '',
      createdAt:         item.createdAt?.S   || '',
    }));
  } catch { return []; }
}

const ses = new SESv2Client({ region: process.env.AWS_REGION || 'us-east-1' });

const FB_VER  = 'v20.0';
const FB_BASE = `https://graph.facebook.com/${FB_VER}`;
const GADS_VER  = 'v20';
const GADS_BASE = `https://googleads.googleapis.com/${GADS_VER}`;
const dynamo  = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });

const CORS = {
  'Access-Control-Allow-Origin':  SITE_ORIGIN || 'https://evidencebasedhealth.me',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
};

function safeEq(a, b) {
  const h = s => createHmac('sha256', 'ebh_cmp').update(String(s)).digest();
  return timingSafeEqual(h(a), h(b));
}

function signJWT(payload) {
  const enc = x => Buffer.from(JSON.stringify(x)).toString('base64url');
  const hdr = enc({ alg: 'HS256', typ: 'JWT' });
  const bdy = enc(payload);
  const sig = createHmac('sha256', JWT_SECRET).update(`${hdr}.${bdy}`).digest('base64url');
  return `${hdr}.${bdy}.${sig}`;
}

function verifyJWT(token) {
  try {
    const [hdr, bdy, sig] = (token || '').split('.');
    if (!hdr || !bdy || !sig) return null;
    const expected = createHmac('sha256', JWT_SECRET).update(`${hdr}.${bdy}`).digest('base64url');
    const sBuf = Buffer.from(sig, 'base64url');
    const eBuf = Buffer.from(expected, 'base64url');
    if (sBuf.length !== eBuf.length || !timingSafeEqual(sBuf, eBuf)) return null;
    const payload = JSON.parse(Buffer.from(bdy, 'base64url').toString());
    return payload.exp >= Math.floor(Date.now() / 1000) ? payload : null;
  } catch { return null; }
}

function resp(status, body, extra = {}) {
  return { statusCode: status, headers: { ...CORS, 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(body) };
}

// â”€â”€ Profile auth helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// PBKDF2-HMAC-SHA512 with 210,000 iterations (OWASP 2024 minimum for SHA-512)
function hashPassword(password, salt) {
  return pbkdf2Sync(password, salt, 210000, 64, 'sha512').toString('hex');
}
function newSalt() { return randomBytes(32).toString('hex'); }
function checkPassword(input, storedHash, storedSalt) {
  const computed = Buffer.from(hashPassword(input, storedSalt), 'hex');
  const stored   = Buffer.from(storedHash, 'hex');
  return computed.length === stored.length && timingSafeEqual(computed, stored);
}
function signProfileJWT(email) {
  return signJWT({ sub: email, role: 'profile', exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 });
}
function verifyProfileJWT(authHeader) {
  const tok = (authHeader || '').replace(/^Bearer\s+/i, '');
  const p = verifyJWT(tok);
  return p?.role === 'profile' ? p : null;
}

async function refreshGToken(refreshTok) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: refreshTok,
    }).toString(),
  });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error_description || 'Google token refresh failed');
  return data.access_token;
}

async function gAds(method, path, body, customerId, mccId, accessToken, devToken) {
  const url = `${GADS_BASE}/customers/${customerId}${path}`;
  const headers = {
    'Authorization': `Bearer ${accessToken}`,
    'developer-token': devToken || _devToken,
    'Content-Type': 'application/json',
  };
  if (mccId) headers['login-customer-id'] = String(mccId);
  const res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json();
  if (!res.ok) {
    const allErrors = data.error?.details?.flatMap(d => d.errors || []) || [];
    const firstError = allErrors[0] || {};
    let msg = firstError.message || data.error?.message || JSON.stringify(data);
    // Collect policy violation info across ALL errors
    const violationKeys = [];
    let allExemptible = allErrors.length > 0;
    for (const e of allErrors) {
      const pd = e.details?.policyViolationDetails;
      if (pd) {
        msg += ` [Policy: ${pd.externalPolicyName || pd.externalPolicyDescription || 'policy violation'}${pd.isExemptible ? ' \u2014 exemptible' : ' \u2014 NOT exemptible'}]`;
        if (!pd.isExemptible) allExemptible = false;
        // pd.key is the object {policyName, violatingText} needed for exemptPolicyViolationKeys
        if (pd.key && pd.isExemptible) violationKeys.push(pd.key);
      } else {
        allExemptible = false;
      }
    }
    const err = new Error(`Google Ads API: ${msg}`);
    err.violationKeys  = violationKeys;
    err.allExemptible  = allExemptible && violationKeys.length > 0;
    throw err;
  }
  return data;
}

async function fb(method, path, data, token = FB_ACCESS_TOKEN) {
  const url  = new URL(`${FB_BASE}${path}`);
  const opts = { method, headers: {} };
  if (method === 'GET') {
    url.searchParams.set('access_token', token);
    if (data) for (const [k, v] of Object.entries(data)) url.searchParams.set(k, String(v));
  } else {
    url.searchParams.set('access_token', token);
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(data);
  }
  const res  = await fetch(url.toString(), opts);
  const json = await res.json();
  if (!res.ok || json.error) throw new Error(json.error?.message || `FB API error ${res.status}`);
  return json;
}

function fromDynamo(item) {
  return {
    clientId:            item.clientId.S,
    name:                item.name?.S  || '',
    color:               item.color?.S || '#1a5c3a',
    notes:               item.notes?.S || '',
    platforms:           JSON.parse(item.platformsJson?.S || '{}'),
    isCertifiedForRxAds: item.isCertifiedForRxAds?.BOOL || false,
    createdAt:           item.createdAt?.S || '',
    updatedAt:           item.updatedAt?.S || '',
  };
}

async function getClient(clientId) {
  const { Items } = await dynamo.send(new ScanCommand({
    TableName: CLIENTS_TABLE,
    FilterExpression: 'clientId = :id',
    ExpressionAttributeValues: { ':id': { S: clientId } },
  }));
  return Items?.[0] ? fromDynamo(Items[0]) : null;
}

async function resolveGoogleCreds(clientId) {
  let devToken   = _devToken;
  let refreshTok = GOOGLE_REFRESH_TOKEN;
  let customerId = (_customerId || '').replace(/-/g, '');
  let mccId      = (_mccId || '').replace(/-/g, '');
  if (clientId) {
    const client = await getClient(clientId);
    const g = client?.platforms?.google;
    if (g?.customerId)      customerId = g.customerId.replace(/-/g, '');
    if (g?.developerToken)  devToken   = g.developerToken;
    if (g?.loginCustomerId) mccId      = g.loginCustomerId.replace(/-/g, '');
    if (g?.refreshToken)    refreshTok = g.refreshToken;
  }
  return { devToken, refreshTok, customerId, mccId };
}

export const handler = async (event) => {
  const method  = event.requestContext?.http?.method || '';
  const rawPath = event.rawPath || '';
  if (method === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch {}

  /* ── CARB LOG PROXY ENDPOINTS — public, no auth required ─────────────────
     These proxy USDA FDC and OpenAI so the client never sees API keys.     */

  /* GET /barcode-lookup?code={barcode} — resolve barcode to product + nutrition */
  if (rawPath.endsWith('/barcode-lookup') && method === 'GET') {
    const code = (event.queryStringParameters?.code || '').trim();
    if (!code) return resp(400, { error: 'code is required' });

    // Helper: extract nutrition from a BarcodeFinder foods[] entry
    const extractBFNutrition = (food) => {
      if (!food) return null;
      const carbs = food.total_carbohydrate?.value ?? null;
      const fiber = food.dietary_fiber?.value ?? null;
      const servingG = food.serving_weight_grams ?? null;
      if (carbs !== null && carbs > 0 && servingG) {
        return {
          serving_grams: servingG,
          serving_description: food.serving_qty && food.serving_unit
            ? `${food.serving_qty} ${food.serving_unit}`
            : `${Math.round(servingG)}g`,
          carbs_g: carbs,
          fiber_g: fiber ?? 0,
        };
      }
      return null;
    };

    // Step 1: Try BarcodeFinder
    let bfTitle = null, bfBrand = null, bfNutrition = null;
    try {
      const BARCODEFINDER_API_KEY = process.env.BARCODEFINDER_API_KEY;
      const bfHeaders = BARCODEFINDER_API_KEY ? { 'X-API-Key': BARCODEFINDER_API_KEY } : {};
      const bfRes = await fetch(`https://barcodefinder.info/v1/product/${encodeURIComponent(code)}`, { headers: bfHeaders, signal: AbortSignal.timeout(5000) });
      if (bfRes.ok) {
        const bfData = await bfRes.json();
        const p = bfData.product;
        if (p && p.title) {
          bfTitle = p.title;
          bfBrand = p.brand || null;
          const food0 = Array.isArray(p.foods) && p.foods.length ? p.foods[0] : null;
          bfNutrition = extractBFNutrition(food0);
        }
      }
    } catch {}

    // If BarcodeFinder had a good product + nutrition, return it
    if (bfTitle && bfNutrition) {
      return resp(200, { found: true, title: bfTitle, brand: bfBrand, nutrition: bfNutrition });
    }

    // Step 2: Use Perplexity to resolve barcode → product name + nutrition
    // (runs when BarcodeFinder is down OR returned 0 carbs)
    if (PERPLEXITY_API_KEY) {
      try {
        const ppRes = await fetch('https://api.perplexity.ai/chat/completions', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: 'sonar',
            messages: [
              { role: 'system', content: 'You are a barcode and nutrition lookup tool. Return ONLY valid JSON, no markdown, no code blocks.' },
              { role: 'user', content: `Look up barcode ${code}. Return ONLY this JSON (no other text):\n{"found":true,"product_name":"exact name","brand":"brand name","serving_description":"e.g. 5 crackers","serving_grams":15,"carbs_g":11,"fiber_g":0}\nIf you cannot identify the product or find its nutrition with confidence, return: {"found":false}` },
            ],
            max_tokens: 200,
          }),
          signal: AbortSignal.timeout(8000),
        });
        if (ppRes.ok) {
          const ppData = await ppRes.json();
          const raw = ppData.choices?.[0]?.message?.content || '{"found":false}';
          const cleaned = raw.replace(/```(?:json)?\s*/gi, '').replace(/```\s*/g, '').trim();
          const parsed = JSON.parse(cleaned);
          if (parsed.found && parsed.product_name && parsed.serving_grams > 0 && parsed.carbs_g > 0) {
            return resp(200, {
              found: true,
              title: parsed.product_name,
              brand: parsed.brand || bfBrand || null,
              nutrition: {
                serving_grams: parsed.serving_grams,
                serving_description: parsed.serving_description || `${Math.round(parsed.serving_grams)}g`,
                carbs_g: parsed.carbs_g,
                fiber_g: parsed.fiber_g ?? 0,
              },
            });
          }
          // Perplexity found product name but no nutrition — pass name through for USDA search
          if (parsed.found && parsed.product_name) {
            return resp(200, { found: true, title: parsed.product_name, brand: parsed.brand || bfBrand || null, nutrition: null });
          }
        }
      } catch {}
    }

    // Step 3: BarcodeFinder had product name but no nutrition — return name for USDA fallback
    if (bfTitle) {
      return resp(200, { found: true, title: bfTitle, brand: bfBrand, nutrition: null });
    }

    return resp(200, { found: false });
  }

  /* GET /fdc-search?q=oatmeal&n=8 */
  if (rawPath.endsWith('/fdc-search') && method === 'GET') {
    const FDC_API_KEY = process.env.FDC_API_KEY;
    if (!FDC_API_KEY) return resp(503, { error: 'Food database not configured.' });
    const q    = event.queryStringParameters?.q || '';
    const n    = Math.min(20, parseInt(event.queryStringParameters?.n || '8', 10));
    if (!q || q.trim().length < 2) return resp(400, { error: 'q is required' });
    const url  = `https://api.nal.usda.gov/fdc/v1/foods/search?api_key=${FDC_API_KEY}&query=${encodeURIComponent(q.trim())}&pageSize=${n}&dataType=Foundation,SR%20Legacy,Branded`;
    const r    = await fetch(url);
    const data = await r.json();
    if (!r.ok) return resp(502, { error: 'USDA FDC error: ' + (data.error || r.status) });
    return resp(200, data);
  }

  /* GET /fdc-food/:fdcId */
  if (rawPath.match(/\/fdc-food\/\d+$/) && method === 'GET') {
    const FDC_API_KEY = process.env.FDC_API_KEY;
    if (!FDC_API_KEY) return resp(503, { error: 'Food database not configured.' });
    const fdcId = rawPath.split('/').pop();
    const url   = `https://api.nal.usda.gov/fdc/v1/food/${fdcId}?api_key=${FDC_API_KEY}&nutrients=1005,1079`;
    const r     = await fetch(url);
    const data  = await r.json();
    if (!r.ok) return resp(502, { error: 'USDA FDC error: ' + (data.error || r.status) });
    return resp(200, data);
  }

  /* POST /perplexity-nutrition  { query: "2 slices of Costco pizza" } */
  if (rawPath.endsWith('/perplexity-nutrition') && method === 'POST') {
    if (!PERPLEXITY_API_KEY) return resp(503, { error: 'Nutrition search not configured.' });
    const { query } = body;
    if (!query || !query.trim()) return resp(400, { error: 'query is required' });
    const ppNutRes = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'sonar',
        messages: [
          { role: 'system', content: 'You are a nutrition data lookup tool. Search the web for exact nutrition facts for the food described. Return ONLY valid JSON with no markdown formatting, no code blocks, no explanation.' },
          { role: 'user', content: `Find the nutrition facts for: "${query.trim().slice(0, 300)}"\n\nReturn ONLY this JSON (no other text, no markdown): {"found": true, "food_name": "exact product name", "serving_description": "e.g. 1 slice", "serving_grams": 107, "carbs_g": 36, "fiber_g": 2, "source": "source website domain"}\n\nOnly return found:true if you found specific carb numbers with confidence. Otherwise return: {"found": false}` },
        ],
        max_tokens: 300,
      }),
    });
    if (!ppNutRes.ok) return resp(502, { error: 'Search error: ' + ppNutRes.status });
    const ppNutData = await ppNutRes.json();
    const raw = ppNutData.choices?.[0]?.message?.content || '{"found":false}';
    const cleaned = raw.replace(/```(?:json)?\s*/gi, '').replace(/```\s*/g, '').trim();
    try { return resp(200, JSON.parse(cleaned)); }
    catch { return resp(200, { found: false }); }
  }

  /* POST /ai-chat-nutrition { messages: [{role, content}] }
     Multi-turn chat: asks clarifying questions, then returns ready JSON with items. */
  if (rawPath.endsWith('/ai-chat-nutrition') && method === 'POST') {
    if (!OPENAI_API_KEY) return resp(503, { error: 'AI not configured.' });
    const { messages } = body;
    if (!Array.isArray(messages) || !messages.length) return resp(400, { error: 'messages required' });
    // Sanitize messages
    const safeMsgs = messages.slice(-12).map(m => ({
      role: m.role === 'user' ? 'user' : 'assistant',
      content: String(m.content || '').slice(0, 600),
    }));
    const systemPrompt = `You are a friendly nutrition logging assistant. People rely on this for accurate carb tracking — accuracy matters greatly for their health.

Your behavior:
1. If the user's food description is ambiguous (unclear brand, restaurant vs homemade, or vague portion), ask ONE short clarifying question in plain conversational English.
2. Once you have enough detail to identify the food and portion accurately, respond ONLY with this exact JSON structure (no other text, no markdown, no code fences):
{"type":"ready","meal":"lunch","items":[{"search_query":"brand + specific food type","quantity_grams":number,"description":"human-readable e.g. 2 slices Costco Food Court cheese pizza"}]}

CRITICAL JSON rules:
- "type" field MUST always be the literal string "ready" (never a meal name).
- "meal" field must be exactly one of: breakfast, lunch, dinner, snacks.
- Do not wrap JSON in markdown code blocks.
- If food is clearly specified (brand + portion + type known), skip questions and go straight to JSON.
- Ask at most 2 clarifying questions across the whole conversation.
- search_query must be specific enough for a nutrition database (include brand, exact product, preparation method).
- quantity_grams is your best estimate of the total grams consumed.
- Infer meal from time context; default to "lunch" if unclear.
- Keep questions short (one sentence, no bullets or formatting).`;
    const oRes = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
      body: JSON.stringify({ model: 'gpt-4o-mini', max_tokens: 800, messages: [{ role: 'system', content: systemPrompt }, ...safeMsgs] }),
    });
    if (!oRes.ok) { const e = await oRes.json(); return resp(502, { error: e.error?.message || 'OpenAI error' }); }
    const oData = await oRes.json();
    const content = (oData.choices?.[0]?.message?.content || '').trim();
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[0]);
        const MEAL_NAMES = ['breakfast', 'lunch', 'dinner', 'snacks'];
        // Normalize: GPT sometimes puts the meal name in "type" instead of "ready"
        if (MEAL_NAMES.includes(parsed.type)) {
          parsed.meal = parsed.meal || parsed.type;
          parsed.type = 'ready';
        }
        // Normalize: if no type but has items array, treat as ready
        if (!parsed.type && Array.isArray(parsed.items)) {
          parsed.type = 'ready';
          if (!parsed.meal) parsed.meal = 'lunch';
        }
        return resp(200, parsed);
      } catch {}
    }
    return resp(200, { type: 'question', text: content });
  }

  /* POST /ai-parse-food  { text: "I had a cup of oatmeal..." } */
  if (rawPath.endsWith('/ai-parse-food') && method === 'POST') {
    if (!OPENAI_API_KEY) return resp(503, { error: 'AI parsing not configured.' });
    const { text } = body;
    if (!text || !text.trim()) return resp(400, { error: 'text is required' });
    const oRes = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
      body: JSON.stringify({
        model: 'gpt-4o-mini', max_tokens: 600,
        response_format: { type: 'json_object' },
        messages: [{
          role: 'system',
          content: `You are a nutrition parsing assistant. Extract each distinct food item and return JSON:
{"meal":"breakfast"|"lunch"|"dinner"|"snacks","items":[{"search_query":"string","quantity_grams":number,"description":"human readable"}]}

Rules for search_query:
- Must match what you'd find in the USDA FoodData Central database
- Include brand name AND specific food type (e.g. "Chick-fil-A lemonade" not just "lemonade")
- Be specific: "greek yogurt plain" not "yogurt", "brown rice cooked" not "rice"
- For branded items keep the brand + product (e.g. "Starbucks oat milk latte")
- description should be the human-readable portion label (e.g. "1 cup of Chick-fil-A lemonade")

Estimate grams from described portions. Infer meal from context (morning→breakfast, midday→lunch, evening→dinner). Default to "breakfast". Return ONLY valid JSON.`,
        }, { role: 'user', content: text.trim().slice(0, 1000) }],
      }),
    });
    if (!oRes.ok) { const e = await oRes.json(); return resp(502, { error: e.error?.message || 'OpenAI error' }); }
    const oData = await oRes.json();
    try {
      const parsed = JSON.parse(oData.choices[0].message.content);
      return resp(200, parsed);
    } catch {
      return resp(502, { error: 'Could not parse AI response' });
    }
  }

  /* POST /roadmap — public, no auth required */
  if (rawPath.endsWith('/roadmap') && method === 'POST') {
    const { yearOfBirth, sexAtBirth, organs = [], riskFlags = [] } = body;
    const yob = parseInt(yearOfBirth, 10);
    const age = new Date().getFullYear() - yob;
    if (isNaN(age) || age < 18 || age > 120)
      return resp(400, { error: 'Valid yearOfBirth required' });
    if (!PERPLEXITY_API_KEY)
      return resp(503, { error: 'AI research not configured' });

    const organMap = { colon: 'colon', cervix: 'cervix', prostate: 'prostate', breasts: 'breasts/chest tissue' };
    const riskMap  = {
      'crc-family':   'first-degree relative with colorectal cancer or advanced polyps before age 60',
      'crc-polyps':   'personal history of colon polyps',
      'cervix-hpv':   'history of abnormal Pap/HPV or cervical dysplasia',
      'breast-family':'first-degree relative with breast cancer',
      'brca':         'known BRCA1/BRCA2 gene variant',
    };
    const sexLabel  = { male: 'male', female: 'female', intersex: 'intersex/biological variation', 'prefer-not': 'unspecified' }[sexAtBirth] || 'unspecified';
    const organList = organs.map(o => organMap[o] || o).join(', ') || 'not specified';
    const riskList  = riskFlags.map(r => riskMap[r] || r).join('; ') || 'none';

    const prompt = `A ${age}-year-old person (sex assigned at birth: ${sexLabel}) with the following anatomy: ${organList}. Known risk factors: ${riskList}.\n\nBased on current US cancer screening and prevention guidelines (USPSTF, ACS, ACOG, ACR, AUA), what cancer screenings are recommended for this person?\n\nFor each applicable screening:\n1. Name the screening test\n2. State the specific guideline recommendation (USPSTF grade if applicable)\n3. Recommended starting age and frequency\n4. Note any changes based on their risk factors\n5. Cite the specific guideline source with URL\n\nInclude screenings currently due, coming up in the next 5 years, and any high-risk pathway recommendations.`;

    const ppRes = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'sonar-pro',
        messages: [
          { role: 'system', content: 'You are a preventive medicine reference tool. Provide accurate, evidence-based cancer screening recommendations based only on published guidelines from USPSTF, ACS, ACOG, ACR, AUA, or equivalent major US medical societies. Always cite specific guideline sources. This is educational information only, not medical advice.' },
          { role: 'user', content: prompt },
        ],
        max_tokens: 1500,
      }),
    });
    if (!ppRes.ok) {
      const e = await ppRes.json().catch(() => ({}));
      return resp(502, { error: 'Research API error', detail: String(e.error?.message || ppRes.status) });
    }
    const ppData = await ppRes.json();
    return resp(200, {
      content:   ppData.choices?.[0]?.message?.content || '',
      citations: ppData.citations || [],
    });
  }

  /* POST /admin-auth */
  if (rawPath.endsWith('/admin-auth') && method === 'POST') {
    if (!body.password || !safeEq(body.password, ADMIN_PASSWORD))
      return resp(401, { error: 'Invalid password' });
    const token = signJWT({ sub: 'admin', exp: Math.floor(Date.now() / 1000) + 604800 }); // 7 days
    return resp(200, { token });
  }

  /* Auth guard â€” skips public & profile-JWT-protected routes */
  const _publicRoute =
    rawPath.endsWith('/profile-register') ||
    rawPath.endsWith('/profile-login') ||
    rawPath.endsWith('/profile') ||
    rawPath.endsWith('/profile-change-password') ||
    rawPath.endsWith('/profile-language') ||
    rawPath.endsWith('/translate') ||
    rawPath.endsWith('/translations') ||
    rawPath.endsWith('/prevention-profile') ||
    (rawPath.endsWith('/subscribe') && method === 'POST') ||
    (rawPath.endsWith('/unsubscribe') && method === 'GET') ||
    (rawPath.endsWith('/post') && method === 'GET') ||
    (rawPath.endsWith('/list-posts') && method === 'GET');
  const bearer = (event.headers?.authorization || event.headers?.Authorization || '').replace(/^Bearer\s+/i, '');
  if (!_publicRoute && !verifyJWT(bearer)) return resp(401, { error: 'Unauthorized' });

  /* GET /clients */
  if (rawPath.endsWith('/clients') && method === 'GET') {
    const result  = await dynamo.send(new ScanCommand({ TableName: CLIENTS_TABLE }));
    const clients = (result.Items || []).map(fromDynamo);
    clients.sort((a, b) => a.name.localeCompare(b.name));
    return resp(200, clients);
  }

  /* POST /clients */
  if (rawPath.endsWith('/clients') && method === 'POST') {
    const { name, color, notes, platforms, isCertifiedForRxAds = false } = body;
    if (!name?.trim()) return resp(400, { error: 'name is required' });
    const clientId = randomUUID();
    const now = new Date().toISOString();
    await dynamo.send(new PutItemCommand({
      TableName: CLIENTS_TABLE,
      Item: {
        clientId:            { S: clientId },
        name:                { S: name.trim() },
        color:               { S: color || '#1a5c3a' },
        notes:               { S: notes || '' },
        platformsJson:       { S: JSON.stringify(platforms || {}) },
        isCertifiedForRxAds: { BOOL: !!isCertifiedForRxAds },
        createdAt:           { S: now },
        updatedAt:           { S: now },
      },
    }));
    return resp(200, { clientId, name: name.trim(), color: color || '#1a5c3a', notes: notes || '', platforms: platforms || {}, isCertifiedForRxAds: !!isCertifiedForRxAds, createdAt: now });
  }

  /* PUT /clients */
  if (rawPath.endsWith('/clients') && method === 'PUT') {
    const { clientId, name, color, notes, platforms, isCertifiedForRxAds = false } = body;
    if (!clientId) return resp(400, { error: 'clientId is required' });
    const now = new Date().toISOString();
    await dynamo.send(new UpdateItemCommand({
      TableName: CLIENTS_TABLE,
      Key: { clientId: { S: clientId } },
      UpdateExpression: 'SET #n = :name, color = :color, notes = :notes, platformsJson = :pj, isCertifiedForRxAds = :cert, updatedAt = :ua',
      ExpressionAttributeNames: { '#n': 'name' },
      ExpressionAttributeValues: {
        ':name':  { S: name?.trim() || '' },
        ':color': { S: color || '#1a5c3a' },
        ':notes': { S: notes || '' },
        ':pj':    { S: JSON.stringify(platforms || {}) },
        ':cert':  { BOOL: !!isCertifiedForRxAds },
        ':ua':    { S: now },
      },
    }));
    return resp(200, { success: true });
  }

  /* DELETE /clients */
  if (rawPath.endsWith('/clients') && method === 'DELETE') {
    const clientId = body.clientId || event.queryStringParameters?.clientId;
    if (!clientId) return resp(400, { error: 'clientId is required' });
    await dynamo.send(new DeleteItemCommand({
      TableName: CLIENTS_TABLE,
      Key: { clientId: { S: clientId } },
    }));
    return resp(200, { success: true });
  }

  /* GET /policy-violations â€” return learned violation history */
  if (rawPath.endsWith('/policy-violations') && method === 'GET') {
    const violations = await getViolationHistory();
    return resp(200, violations.sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  }

  /* DELETE /policy-violations â€” remove a false positive */
  if (rawPath.endsWith('/policy-violations') && method === 'DELETE') {
    const { violationId } = body;
    if (!violationId) return resp(400, { error: 'violationId required' });
    await dynamo.send(new DeleteItemCommand({
      TableName: VIOLATIONS_TABLE,
      Key: { violationId: { S: violationId } },
    }));
    return resp(200, { success: true });
  }

  /* GET /meta-interests */
  if (rawPath.endsWith('/meta-interests') && method === 'GET') {
    const q        = (event.queryStringParameters?.q || '').trim();
    const clientId = event.queryStringParameters?.clientId;
    let fbToken = META_ACCESS_TOKEN || FB_ACCESS_TOKEN;
    if (clientId) {
      const client = await getClient(clientId);
      if (client?.platforms?.meta?.accessToken) fbToken = client.platforms.meta.accessToken;
    }
    if (!q) return resp(200, []);
    const results = await fb('GET', '/search', { type: 'adinterest', q, limit: 10 }, fbToken);
    return resp(200, results.data || []);
  }

  /* POST /create-meta-ad */
  if (rawPath.endsWith('/create-meta-ad') && method === 'POST') {
    const {
      clientId, campaignName, objective = 'OUTCOME_TRAFFIC',
      dailyBudget, ageMin = 35, ageMax = 65, countries = ['US'],
      interests = [], primaryText, headline, description,
      destinationUrl = 'https://evidencebasedhealth.me', imageUrl,
    } = body;

    if (!campaignName?.trim() || !dailyBudget || !primaryText?.trim() || !headline?.trim())
      return resp(400, { error: 'campaignName, dailyBudget, primaryText, and headline are required' });

    let fbToken = META_ACCESS_TOKEN || FB_ACCESS_TOKEN;
    let actId   = FB_AD_ACCOUNT_ID;
    let pageId  = FB_PAGE_ID;

    if (clientId) {
      const client = await getClient(clientId);
      const m = client?.platforms?.meta;
      if (m?.accessToken) fbToken = m.accessToken;
      if (m?.adAccountId) actId   = m.adAccountId.startsWith('act_') ? m.adAccountId : `act_${m.adAccountId}`;
      if (m?.pageId)      pageId  = m.pageId;
    }

    if (!fbToken || fbToken === 'PLACEHOLDER')
      return resp(503, { error: 'Meta credentials not configured for this client. Add them in the Clients tab.' });

    const campaign = await fb('POST', `/${actId}/campaigns`, {
      name: campaignName.trim(), objective, status: 'PAUSED', special_ad_categories: [],
    }, fbToken);

    const adset = await fb('POST', `/${actId}/adsets`, {
      name:              `${campaignName} ï¿½ Ad Set`,
      campaign_id:       campaign.id,
      daily_budget:      Math.round(Number(dailyBudget) * 100),
      billing_event:     'IMPRESSIONS',
      optimization_goal: objective === 'OUTCOME_LEADS' ? 'LEAD_GENERATION' : 'LINK_CLICKS',
      bid_strategy:      'LOWEST_COST_WITHOUT_CAP',
      targeting: {
        age_min: Number(ageMin), age_max: Number(ageMax),
        geo_locations: { countries },
        ...(interests.length > 0 && { flexible_spec: [{ interests }] }),
      },
      status: 'PAUSED', destination_type: 'WEBSITE',
    }, fbToken);

    const creative = await fb('POST', `/${actId}/adcreatives`, {
      name: `${campaignName} ï¿½ Creative`,
      object_story_spec: {
        page_id: pageId,
        link_data: {
          link: destinationUrl, message: primaryText.trim(), name: headline.trim(),
          call_to_action: { type: 'SIGN_UP', value: { link: destinationUrl } },
          ...(description?.trim() && { description: description.trim() }),
          ...(imageUrl?.trim()    && { picture: imageUrl.trim() }),
        },
      },
    }, fbToken);

    const ad = await fb('POST', `/${actId}/ads`, {
      name: `${campaignName} ï¿½ Ad`, adset_id: adset.id,
      creative: { creative_id: creative.id }, status: 'PAUSED',
    }, fbToken);

    return resp(200, {
      success: true, campaign_id: campaign.id, adset_id: adset.id,
      creative_id: creative.id, ad_id: ad.id,
      review_url: `https://www.facebook.com/adsmanager/manage/campaigns?act=${actId.replace('act_', '')}`,
    });
  }

  /* GET /google-insights â€” top search terms + best RSA assets from existing campaigns */
  if (rawPath.endsWith('/google-insights') && method === 'GET') {
    const clientId = event.queryStringParameters?.clientId;
    let devToken   = _devToken;
    let refreshTok = GOOGLE_REFRESH_TOKEN;
    let customerId = (_customerId || '').replace(/-/g, '');
    let mccId      = (_mccId || '').replace(/-/g, '');

    if (clientId) {
      const client = await getClient(clientId);
      const g = client?.platforms?.google;
      if (g?.customerId)      customerId = g.customerId.replace(/-/g, '');
      if (g?.developerToken)  devToken   = g.developerToken;
      if (g?.loginCustomerId) mccId      = g.loginCustomerId.replace(/-/g, '');
      if (g?.refreshToken)    refreshTok = g.refreshToken;
    }
    if (!devToken || !refreshTok || !customerId)
      return resp(503, { error: 'Google Ads credentials not configured.' });

    const accessToken = await refreshGToken(refreshTok);

    // 1. Top search terms (last 90 days, >0 clicks, ordered by CTR)
    const stRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT search_term_view.search_term, metrics.clicks, metrics.ctr, metrics.conversions
              FROM search_term_view
              WHERE segments.date DURING LAST_90_DAYS
                AND metrics.clicks > 0
              ORDER BY metrics.ctr DESC
              LIMIT 25`,
    }, customerId, mccId, accessToken, devToken);
    const searchTerms = (stRes.flatMap ? stRes : [stRes])
      .flatMap(r => r.results || [])
      .map(r => ({
        term:        r.searchTermView?.searchTerm || '',
        clicks:      Number(r.metrics?.clicks || 0),
        ctr:         Number(r.metrics?.ctr || 0),
        conversions: Number(r.metrics?.conversions || 0),
      }))
      .filter(r => r.term);

    // 2. Best + Good RSA asset performance
    const assetRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT ad_group_ad_asset_view.field_type, ad_group_ad_asset_view.performance_label,
                     asset.text_asset.text
              FROM ad_group_ad_asset_view
              WHERE ad_group_ad_asset_view.performance_label IN ('BEST','GOOD')
                AND asset.type = 'TEXT'
              ORDER BY ad_group_ad_asset_view.performance_label ASC
              LIMIT 50`,
    }, customerId, mccId, accessToken, devToken);
    const assetRows = (assetRes.flatMap ? assetRes : [assetRes])
      .flatMap(r => r.results || []);
    const topHeadlines    = [...new Set(
      assetRows.filter(r => r.adGroupAdAssetView?.fieldType === 'HEADLINE')
               .map(r => r.asset?.textAsset?.text).filter(Boolean)
    )].slice(0, 15);
    const topDescriptions = [...new Set(
      assetRows.filter(r => r.adGroupAdAssetView?.fieldType === 'DESCRIPTION')
               .map(r => r.asset?.textAsset?.text).filter(Boolean)
    )].slice(0, 4);

    // 3. Top keywords by CTR
    const kwRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT ad_group_criterion.keyword.text, metrics.clicks, metrics.ctr, metrics.conversions
              FROM keyword_view
              WHERE segments.date DURING LAST_90_DAYS
                AND metrics.clicks > 0
                AND ad_group_criterion.status != 'REMOVED'
              ORDER BY metrics.ctr DESC
              LIMIT 20`,
    }, customerId, mccId, accessToken, devToken);
    const topKeywords = [...new Set(
      (kwRes.flatMap ? kwRes : [kwRes])
        .flatMap(r => r.results || [])
        .map(r => r.adGroupCriterion?.keyword?.text).filter(Boolean)
    )];

    return resp(200, {
      searchTerms,
      topHeadlines,
      topDescriptions,
      topKeywords,
      hasData: searchTerms.length > 0 || topHeadlines.length > 0 || topKeywords.length > 0,
    });
  }

  /* POST /create-google-campaign */
  if (rawPath.endsWith('/create-google-campaign') && method === 'POST') {
    const {
      clientId, campaignName = 'New Campaign', dailyBudget,
      adGroups = [],        // [{name, keywords, headlines}]
      descriptions = [],    // shared across all groups
      keywords = [], headlines = [], // legacy single-group fallback
      finalUrl = 'https://evidencebasedhealth.me',
      locationTargeting,
      biddingStrategy = 'clicks',  // 'clicks' | 'conversions'
      searchPartners  = false,
    } = body;

    // Normalise: accept both multi-group and legacy single-group payloads
    const groups = adGroups.length > 0
      ? adGroups
      : [{ name: 'Ad Group 1', keywords, headlines }];

    if (!campaignName || !dailyBudget)
      return resp(400, { error: 'Provide campaignName and dailyBudget' });
    if (descriptions.length < 2)
      return resp(400, { error: 'Provide at least 2 shared descriptions' });
    for (const g of groups) {
      if (!g.headlines || g.headlines.length < 3)
        return resp(400, { error: `Ad group "${g.name}" needs at least 3 headlines` });
    }

    const { devToken, refreshTok, customerId, mccId } = await resolveGoogleCreds(clientId);
    if (!devToken || !refreshTok || !customerId)
      return resp(503, { error: 'Google Ads credentials not configured. Add them in the Clients tab or set defaults.' });

    // Compliance check on all keywords and headlines before submission
    const isCertifiedForRxAds = clientId ? ((await getClient(clientId))?.isCertifiedForRxAds || false) : false;
    const policyWarnings = [];
    for (const g of groups) {
      const kwCheck = policyCheck(g.keywords || [], isCertifiedForRxAds);
      if (!kwCheck.pass) policyWarnings.push(...kwCheck.violations.map(v => `[${g.name} keywords] ${v}`));
      const hlCheck = policyCheck(g.headlines || [], isCertifiedForRxAds);
      if (!hlCheck.pass) policyWarnings.push(...hlCheck.violations.map(v => `[${g.name} headlines] ${v}`));
    }
    const descCheck = policyCheck(descriptions, isCertifiedForRxAds);
    if (!descCheck.pass) policyWarnings.push(...descCheck.violations.map(v => `[descriptions] ${v}`));
    // Hard-block only commercial Rx patterns; warn on drug names so user can review
    const hardViolations = policyWarnings.filter(w => w.includes('Prohibited commercial'));
    if (hardViolations.length > 0)
      return resp(400, { error: 'Campaign blocked: prohibited commercial Rx language detected.', violations: hardViolations });

    const accessToken = await refreshGToken(refreshTok);

    // Load violation history to pre-filter previously hard-rejected content
    // "hard-rejected" = non-exemptible violations (wasExempted=false, isExemptible=false)
    const violationHistory = await getViolationHistory('google');
    const hardBlockedSet = new Set(
      violationHistory
        .filter(v => !v.isExemptible && !v.wasExempted)
        .map(v => v.text.toLowerCase().trim())
    );

    // 1. Budget
    const budgetRes = await gAds('POST', '/campaignBudgets:mutate', {
      operations: [{ create: {
        name: `${campaignName} Budget ${Date.now()}`,
        amountMicros: String(Math.round(Number(dailyBudget) * 1_000_000)),
        deliveryMethod: 'STANDARD', explicitlyShared: false,
      }}],
    }, customerId, mccId, accessToken, devToken);
    const budgetRN = budgetRes.results[0].resourceName;

    // 2. Campaign â€” bidding strategy and search partners are configurable
    // Note: Google Ads API calls "Maximize Clicks" â†’ targetSpend at the campaign level
    // Always append a short timestamp to prevent duplicate-name errors on retries
    const finalCampaignName = `${campaignName} ${Date.now()}`;
    const biddingField = biddingStrategy === 'conversions'
      ? { maximizeConversions: {} }
      : { targetSpend: {} };

    const campaignRes = await gAds('POST', '/campaigns:mutate', {
      operations: [{ create: {
        name: finalCampaignName,
        advertisingChannelType: 'SEARCH',
        status: 'PAUSED',
        campaignBudget: budgetRN,
        ...biddingField,
        containsEuPoliticalAdvertising: 'DOES_NOT_CONTAIN_EU_POLITICAL_ADVERTISING',
        networkSettings: {
          targetGoogleSearch: true,
          targetSearchNetwork: searchPartners === true,
          targetContentNetwork: false,
        },
      }}],
    }, customerId, mccId, accessToken, devToken);
    const campaignRN = campaignRes.results[0].resourceName;
    const campaignId = campaignRN.split('/').pop();

    // 3. Add campaign-level negative keywords (healthcare education standard set)
    // These block commercial/transactional intent queries not appropriate for an education brand
    const CAMPAIGN_NEGATIVES = [
      // Purchase / commercial intent
      'buy','purchase','order','cheap','discount','coupon','promo','deal','free trial',
      'cost','price','how much','afford',
      // Prescription / pharmacy
      'prescription','prescribe','Rx','pharmacy','drug store','compounding','compound pharmacy',
      'online pharmacy','mail order pharmacy',
      // Brand drug names (catch misspellings too)
      'ozempic','wegovy','mounjaro','rybelsus','saxenda','victoza','trulicity','zepbound',
      // Direct clinical / emergency â€” not our service
      'emergency','urgent care','near me','clinic near','doctor near','symptoms',
      'side effects','overdose','withdrawal',
      // Job seekers
      'jobs','careers','salary','internship','hiring',
    ];
    await gAds('POST', '/campaignCriteria:mutate', {
      operations: CAMPAIGN_NEGATIVES.map(kw => ({ create: {
        campaign: campaignRN,
        negative: true,
        keyword: { text: kw, matchType: 'BROAD' },
      }})),
    }, customerId, mccId, accessToken, devToken);

    // 4â€“6. Create each ad group with its RSA and keywords
    const createdGroups = [];
    for (const group of groups) {
      const agRes = await gAds('POST', '/adGroups:mutate', {
        operations: [{ create: {
          name: group.name,
          campaign: campaignRN,
          status: 'ENABLED',
          type: 'SEARCH_STANDARD',
          cpcBidMicros: '1000000',
        }}],
      }, customerId, mccId, accessToken, devToken);
      const agRN = agRes.results[0].resourceName;
      const agId = agRN.split('/').pop();

      // RSA: group headlines + shared descriptions
      // Two-pass: attempt normal creation, then auto-exempt if Google flags exemptible health policy
      let adPolicyWarning = null;
      const adOp = {
        adGroup: agRN,
        status: 'PAUSED',
        ad: {
          responsiveSearchAd: {
            headlines:    group.headlines.slice(0, 15).map(t => ({ text: t })),
            descriptions: descriptions.slice(0, 4).map(t => ({ text: t })),
          },
          finalUrls: [finalUrl],
        },
      };
      try {
        await gAds('POST', '/adGroupAds:mutate', { operations: [{ create: adOp }] },
          customerId, mccId, accessToken, devToken);
      } catch (adErr) {
        if (adErr.allExemptible && adErr.violationKeys?.length > 0) {
          // All violations are exemptible â€” retry with violation keys acknowledged
          try {
            await gAds('POST', '/adGroupAds:mutate',
              { operations: [{ create: adOp, exemptPolicyViolationKeys: adErr.violationKeys }] },
              customerId, mccId, accessToken, devToken);
            // Log exempted texts so UI can surface them
            for (const key of adErr.violationKeys) {
              logViolation({ platform:'google', type:'headline', text: key.violatingText || '', policyName: key.policyName || '', isExemptible: true, wasExempted: true, clientId });
            }
          } catch (retryErr) {
            adPolicyWarning = retryErr.message;
            policyWarnings.push(`[${group.name} ad] ${retryErr.message}`);
            for (const key of (retryErr.violationKeys?.length ? retryErr.violationKeys : adErr.violationKeys)) {
              logViolation({ platform:'google', type:'headline', text: key.violatingText || '', policyName: key.policyName || '', isExemptible: false, wasExempted: false, clientId });
            }
          }
        } else {
          // Non-exemptible â€” log and warn but don't abort campaign
          adPolicyWarning = adErr.message;
          policyWarnings.push(`[${group.name} ad] ${adErr.message}`);
          for (const key of (adErr.violationKeys || [])) {
            logViolation({ platform:'google', type:'headline', text: key.violatingText || '', policyName: key.policyName || '', isExemptible: false, wasExempted: false, clientId });
          }
        }
      }

      // Keywords for this group â€” pre-filter hard-blocked terms, then two-pass health policy exemption
      if (group.keywords?.length > 0) {
        const allKws = group.keywords.slice(0, 20);
        // Skip any terms previously hard-rejected by Google (non-exemptible)
        const filteredKws = allKws.filter(kw => {
          if (hardBlockedSet.has(kw.toLowerCase().trim())) {
            policyWarnings.push(`[${group.name}] Keyword "${kw}" skipped â€” previously hard-rejected by Google policy`);
            return false;
          }
          return true;
        });

        if (filteredKws.length > 0) {
          const kwOps = filteredKws.map(kw => ({ create: {
            adGroup: agRN,
            status: 'ENABLED',
            keyword: { text: kw, matchType: 'BROAD' },
          }}));
          try {
            await gAds('POST', '/adGroupCriteria:mutate', { operations: kwOps },
              customerId, mccId, accessToken, devToken);
          } catch (kwErr) {
            if (kwErr.allExemptible && kwErr.violationKeys?.length > 0) {
              // Retry with health policy exemption keys
              const kwOpsExempt = kwOps.map(op => ({ ...op, exemptPolicyViolationKeys: kwErr.violationKeys }));
              try {
                await gAds('POST', '/adGroupCriteria:mutate', { operations: kwOpsExempt },
                  customerId, mccId, accessToken, devToken);
                // Log each exempted term â€” wasExempted=true means it works but needs acknowledged
                for (const key of kwErr.violationKeys) {
                  logViolation({ platform:'google', type:'keyword', text: key.violatingText || '', policyName: key.policyName || '', isExemptible: true, wasExempted: true, clientId });
                }
              } catch (kwRetryErr) {
                policyWarnings.push(`[${group.name} keywords] ${kwRetryErr.message}`);
                // Log as hard-rejected â€” avoid next time
                for (const key of (kwRetryErr.violationKeys?.length ? kwRetryErr.violationKeys : kwErr.violationKeys)) {
                  logViolation({ platform:'google', type:'keyword', text: key.violatingText || '', policyName: key.policyName || '', isExemptible: false, wasExempted: false, clientId });
                }
              }
            } else {
              policyWarnings.push(`[${group.name} keywords] ${kwErr.message}`);
              for (const key of (kwErr.violationKeys || [])) {
                logViolation({ platform:'google', type:'keyword', text: key.violatingText || '', policyName: key.policyName || '', isExemptible: false, wasExempted: false, clientId });
              }
            }
          }
        }
      }

      createdGroups.push({ name: group.name, id: agId, keywords: group.keywords || [], headlines: group.headlines, adWarning: adPolicyWarning || undefined });
    }

    // 6. Location targeting
    // Always apply at least US targeting; never leave a campaign wordlwide by default
    {
      const locOps = [];

      if (!locationTargeting || locationTargeting.type === 'national') {
        // Default: United States only (geo constant 2840)
        locOps.push({ create: {
          campaign: campaignRN,
          location: { geoTargetConstant: 'geoTargetConstants/2840' },
        }});
      }

      if (locationTargeting?.type === 'states' && locationTargeting.states?.length > 0) {
        for (const stateId of locationTargeting.states) {
          locOps.push({ create: {
            campaign: campaignRN,
            location: { geoTargetConstant: `geoTargetConstants/${stateId}` },
          }});
        }
      } else if (locationTargeting?.type === 'zip' && locationTargeting.zipCodes?.length > 0) {
        // Look up zip code geo target constant IDs via GAQL
        const zipQuoted = locationTargeting.zipCodes.slice(0, 50).map(z => `'${z}'`).join(',');
        const zipRes = await gAds('POST', '/googleAds:searchStream', {
          query: `SELECT geo_target_constant.id, geo_target_constant.resource_name
                  FROM geo_target_constant
                  WHERE geo_target_constant.country_code = 'US'
                    AND geo_target_constant.target_type = 'Postal Code'
                    AND geo_target_constant.name IN (${zipQuoted})`,
        }, customerId, mccId, accessToken, devToken);
        const zipRows = (Array.isArray(zipRes) ? zipRes : [zipRes]).flatMap(r => r.results || []);
        for (const row of zipRows) {
          const rn = row.geoTargetConstant?.resourceName;
          if (rn) locOps.push({ create: {
            campaign: campaignRN,
            location: { geoTargetConstant: rn },
          }});
        }
      } else if (locationTargeting?.type === 'radius' && locationTargeting.lat != null && locationTargeting.lng != null) {
        locOps.push({ create: {
          campaign: campaignRN,
          proximity: {
            geoPoint: {
              longitudeInMicroDegrees: Math.round(locationTargeting.lng * 1_000_000),
              latitudeInMicroDegrees:  Math.round(locationTargeting.lat * 1_000_000),
            },
            radius:      locationTargeting.radiusMiles || 25,
            radiusUnits: 'MILES',
          },
        }});
      }

      if (locOps.length > 0) {
        await gAds('POST', '/campaignCriteria:mutate', { operations: locOps },
          customerId, mccId, accessToken, devToken);
      }
    }

    const cidDisplay = customerId.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3');
    return resp(200, {
      success: true, campaignId, campaignName: finalCampaignName,
      adGroups: createdGroups,
      biddingStrategy,
      searchPartners,
      customer_id: cidDisplay,
      review_url: `https://ads.google.com/aw/campaigns?campaignId=${campaignId}`,
      ...(policyWarnings.length > 0 && { complianceWarnings: [...new Set(policyWarnings)] }),
    });
  }

  /* GET /list-google-campaigns */
  if (rawPath.endsWith('/list-google-campaigns') && method === 'GET') {
    const clientId = event.queryStringParameters?.clientId;
    const { devToken, refreshTok, customerId, mccId } = await resolveGoogleCreds(clientId);
    if (!devToken || !refreshTok || !customerId)
      return resp(503, { error: 'Google Ads credentials not configured.' });
    const accessToken = await refreshGToken(refreshTok);
    const res = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT campaign.id, campaign.name, campaign.status,
                     campaign.advertising_channel_type, campaign_budget.amount_micros
              FROM campaign
              WHERE campaign.status IN ('ENABLED','PAUSED')
              ORDER BY campaign.name ASC`,
    }, customerId, mccId, accessToken, devToken);
    const rows = (Array.isArray(res) ? res : [res]).flatMap(r => r.results || []);
    const campaigns = rows.map(r => ({
      id:           r.campaign?.id,
      name:         r.campaign?.name,
      status:       r.campaign?.status,
      channelType:  r.campaign?.advertisingChannelType,
      dailyBudget:  r.campaignBudget?.amountMicros
        ? (Number(r.campaignBudget.amountMicros) / 1_000_000).toFixed(2) : null,
    }));
    return resp(200, { campaigns });
  }

  /* GET /list-campaign-ads â€” ad groups, keywords, RSA headlines for one campaign */
  if (rawPath.endsWith('/list-campaign-ads') && method === 'GET') {
    const { clientId, campaignId } = event.queryStringParameters || {};
    if (!campaignId) return resp(400, { error: 'Provide campaignId' });
    const { devToken, refreshTok, customerId, mccId } = await resolveGoogleCreds(clientId);
    if (!devToken || !refreshTok || !customerId)
      return resp(503, { error: 'Google Ads credentials not configured.' });
    const accessToken = await refreshGToken(refreshTok);

    // Ad groups
    const agRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT ad_group.id, ad_group.name, ad_group.status
              FROM ad_group
              WHERE campaign.id = ${campaignId}
                AND ad_group.status != 'REMOVED'`,
    }, customerId, mccId, accessToken, devToken);
    const adGroups = (Array.isArray(agRes) ? agRes : [agRes])
      .flatMap(r => r.results || [])
      .map(r => ({ id: r.adGroup?.id, name: r.adGroup?.name, status: r.adGroup?.status }));

    // Keywords for the campaign
    const kwRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT ad_group_criterion.keyword.text, ad_group_criterion.keyword.match_type,
                     ad_group_criterion.status, ad_group.name
              FROM ad_group_criterion
              WHERE campaign.id = ${campaignId}
                AND ad_group_criterion.type = 'KEYWORD'
                AND ad_group_criterion.status != 'REMOVED'`,
    }, customerId, mccId, accessToken, devToken);
    const keywords = (Array.isArray(kwRes) ? kwRes : [kwRes])
      .flatMap(r => r.results || [])
      .map(r => ({
        text:       r.adGroupCriterion?.keyword?.text,
        matchType:  r.adGroupCriterion?.keyword?.matchType,
        status:     r.adGroupCriterion?.status,
        adGroup:    r.adGroup?.name,
      }));

    // RSA headlines + descriptions
    const adRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT ad_group_ad.ad.responsive_search_ad.headlines,
                     ad_group_ad.ad.responsive_search_ad.descriptions,
                     ad_group_ad.status, ad_group.name
              FROM ad_group_ad
              WHERE campaign.id = ${campaignId}
                AND ad_group_ad.status != 'REMOVED'`,
    }, customerId, mccId, accessToken, devToken);
    const ads = (Array.isArray(adRes) ? adRes : [adRes])
      .flatMap(r => r.results || [])
      .map(r => ({
        status:       r.adGroupAd?.status,
        adGroup:      r.adGroup?.name,
        headlines:    (r.adGroupAd?.ad?.responsiveSearchAd?.headlines || []).map(h => h.text),
        descriptions: (r.adGroupAd?.ad?.responsiveSearchAd?.descriptions || []).map(d => d.text),
      }));

    return resp(200, { adGroups, keywords, ads });
  }

  /* POST /toggle-google-campaign */
  if (rawPath.endsWith('/toggle-google-campaign') && method === 'POST') {
    const { clientId, campaignId, action } = body;
    if (!campaignId || !['ENABLED', 'PAUSED'].includes(action))
      return resp(400, { error: 'Provide campaignId and action (ENABLED or PAUSED)' });
    const { devToken, refreshTok, customerId, mccId } = await resolveGoogleCreds(clientId);
    if (!devToken || !refreshTok || !customerId)
      return resp(503, { error: 'Google Ads credentials not configured.' });
    const accessToken = await refreshGToken(refreshTok);
    await gAds('POST', '/campaigns:mutate', {
      operations: [{ update: {
        resourceName: `customers/${customerId}/campaigns/${campaignId}`,
        status: action,
      }, updateMask: 'status' }],
    }, customerId, mccId, accessToken, devToken);
    return resp(200, { success: true, campaignId, status: action });
  }

  /* POST /delete-google-campaign */
  if (rawPath.endsWith('/delete-google-campaign') && method === 'POST') {
    const { clientId, campaignId } = body;
    if (!campaignId) return resp(400, { error: 'Provide campaignId' });
    const { devToken, refreshTok, customerId, mccId } = await resolveGoogleCreds(clientId);
    if (!devToken || !refreshTok || !customerId)
      return resp(503, { error: 'Google Ads credentials not configured.' });
    const accessToken = await refreshGToken(refreshTok);
    await gAds('POST', '/campaigns:mutate', {
      operations: [{ remove: `customers/${customerId}/campaigns/${campaignId}` }],
    }, customerId, mccId, accessToken, devToken);
    return resp(200, { success: true, campaignId });
  }

  /* GET /ga4-report â€” site analytics from Google Analytics Data API */
  if (rawPath.endsWith('/ga4-report') && method === 'GET') {
    const clientId = event.queryStringParameters?.clientId;
    const { refreshTok } = await resolveGoogleCreds(clientId);
    if (!refreshTok) return resp(503, { error: 'Google credentials not configured.' });

    const propertyId = process.env.GOOGLE_GA4_PROPERTY_ID;
    if (!propertyId) return resp(503, { error: 'GOOGLE_GA4_PROPERTY_ID not set on Lambda.' });

    // Refresh token â€” GA4 uses same Google OAuth but analytics scope
    const tokRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshTok,
        grant_type:    'refresh_token',
      }),
    });
    const tokData = await tokRes.json();
    const access_token = tokData.access_token;
    if (!access_token) return resp(502, { error: `Could not refresh GA4 access token: ${tokData.error_description || tokData.error || 'unknown'}` });

    const ga4Fetch = async (dimensions, metrics) => {
      const r = await fetch(
        `https://analyticsdata.googleapis.com/v1beta/properties/${propertyId}:runReport`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dateRanges: [{ startDate: '30daysAgo', endDate: 'today' }],
            dimensions: dimensions.map(n => ({ name: n })),
            metrics:    metrics.map(n => ({ name: n })),
            limit: 20,
          }),
        },
      );
      return r.json();
    };

    const [trafficRes, cityRes, demoRes] = await Promise.all([
      ga4Fetch(['sessionSourceMedium'], ['sessions', 'users', 'newUsers']),
      ga4Fetch(['city', 'region'],      ['sessions', 'users']),
      ga4Fetch(['userAgeBracket'],      ['sessions', 'users']),
    ]);

    const parseRows = res =>
      (res.rows || []).map(row => ({
        dims:    (row.dimensionValues || []).map(d => d.value),
        metrics: (row.metricValues    || []).map(m => m.value),
      }));

    const totalsRes = await ga4Fetch(['date'], ['sessions', 'users', 'newUsers', 'bounceRate']);
    const totals = (totalsRes.rows || []).reduce(
      (acc, row) => {
        acc.sessions  += Number(row.metricValues[0].value);
        acc.users     += Number(row.metricValues[1].value);
        acc.newUsers  += Number(row.metricValues[2].value);
        return acc;
      },
      { sessions: 0, users: 0, newUsers: 0 },
    );

    return resp(200, {
      totals,
      traffic: parseRows(trafficRes),
      cities:  parseRows(cityRes),
      ages:    parseRows(demoRes),
    });
  }

  /* POST /generate-google-brief (kept for backward compat) */
  if (rawPath.endsWith('/generate-google-brief') && method === 'POST') {
    return resp(301, { error: 'Use /create-google-campaign for live campaign creation.' });
  }

  /* POST /suggest-audience â€” AI suggests a target audience description from free-form topic + objective */
  if (rawPath.endsWith('/suggest-audience') && method === 'POST') {
    const { topic, objective } = body;
    if (!topic || !objective)
      return resp(400, { error: 'topic and objective are required' });
    if (!PERPLEXITY_API_KEY)
      return resp(503, { error: 'AI not configured' });

    const ppRes = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'sonar-pro',
        messages: [
          { role: 'system', content: 'You are a digital marketing strategist specialising in health and wellness audiences. Output ONLY plain text, no JSON, no markdown, no bullet points.' },
          { role: 'user', content: `Write a single concise target audience description (1 sentence, max 180 characters) for a health ad campaign.\nTopic: ${topic}\nObjective: ${objective}\n\nDescribe the audience in terms of age range, mindset, and current behaviour â€” similar to: "Adults 30â€“65 curious about GLP-1 / semaglutide who are researching weight-loss options but haven't visited our education page yet"` },
        ],
        max_tokens: 120,
        temperature: 0.4,
      }),
    });
    if (!ppRes.ok) return resp(502, { error: 'AI API error' });
    const ppData = await ppRes.json();
    const suggestion = (ppData.choices?.[0]?.message?.content || '').trim().replace(/^"|"$/g, '');
    return resp(200, { audience: suggestion });
  }

  /* POST /generate-ad-copy â€” AI creates 5 education-first ad variants */
  if (rawPath.endsWith('/generate-ad-copy') && method === 'POST') {
    const { clientId, platform = 'Meta', offer, objective, audience, brand = 'Evidence-Based Health', extra = '' } = body;
    if (!offer || !objective || !audience)
      return resp(400, { error: 'offer, objective, and audience are required' });
    if (!PERPLEXITY_API_KEY)
      return resp(503, { error: 'AI not configured â€” set PERPLEXITY_API_KEY in Lambda env vars.' });

    // Look up client certification status
    let isCertifiedForRxAds = false;
    if (clientId) {
      const client = await getClient(clientId);
      isCertifiedForRxAds = client?.isCertifiedForRxAds || false;
    }

    const isGoogle = platform === 'Google';
    const googleInstructions = isGoogle ? `
For each variant provide exactly these JSON fields:
- headline (max 30 characters)
- headline2 (max 30 characters)
- headline3 (max 30 characters)
- description (max 90 characters â€” this is Description 1)
- description2 (max 90 characters â€” this is Description 2)
- cta (short call-to-action phrase, max 15 chars, e.g. "Start Free Today")
- imageConcept (short visual idea)

Strictly enforce character limits. Count carefully.` : `
For each variant provide exactly these JSON fields:
- headline (max 40 characters)
- primaryText (max 125 characters â€” the main ad body)
- cta (call-to-action line, max 30 chars)
- imageConcept (short description of an image concept)

Strictly enforce character limits. Count carefully.`;

    // Compliance context injected into the prompt
    const complianceBlock = isCertifiedForRxAds
      ? `COMPLIANCE STATUS: This client holds active LegitScript Rx certification.
- Drug brand names (Ozempic, Wegovy, Mounjaro, etc.) and generic names (semaglutide, tirzepatide, etc.) may appear in copy when contextually appropriate.
- Still avoid guarantee language ("lose X lbs", "guaranteed results"), "no prescription needed", or any direct-to-consumer pharmacy framing.
- Always maintain evidence-based, professional tone.`
      : `COMPLIANCE STATUS: This client is NOT LegitScript certified. STRICTLY ENFORCE ALL rules below:
- NEVER use drug brand names in any field: no Ozempic, Wegovy, Mounjaro, Rybelsus, Saxenda, Victoza, Trulicity, Zepbound.
- NEVER use drug generic names as selling points: no semaglutide, tirzepatide, liraglutide in headlines or CTAs.
  Generic names are ONLY acceptable in descriptions if accompanied by an explicit educational qualifier (e.g. "how semaglutide works", "semaglutide research explained").
- NEVER imply prescription access, delivery, or dispensing: no "get it online", "no Rx needed", "home delivery".
- NEVER use guarantee language: no "lose X lbs", "guaranteed results", "melt fat".
- Frame ALL copy as education, research news, or lifestyle guidance.
- Use category terms instead: "GLP-1 therapies", "metabolic medications", "weight management options".
- Every variant MUST communicate that the content is educational and that a clinician should be consulted.`;

    const prompt = `You are a performance marketer writing compliant health and wellness ads for the brand "${brand}".

Platform: ${platform}
Offer/topic: ${offer}
Campaign objective: ${objective}
Target audience: ${audience}
${extra ? `Additional context: ${extra}` : ''}

${complianceBlock}

Write 5 distinct ad variants. Every variant MUST also follow these universal rules:
1. Education-first tone: evidence-based, clear, warm, non-scary.
2. Use problem/solution or curiosity angles â€” e.g. "Most people don't know X" or "A PA explains Y".
3. No direct "buy prescription online" language under any circumstances.
4. Each variant must include a "disclaimer" field with this exact text: "${COMPLIANCE_DISCLAIMER}"
${googleInstructions}

Return ONLY a valid JSON array of 5 objects, no markdown, no explanation. Example structure:
[{"headline":"...","primaryText":"...","cta":"...","imageConcept":"...","disclaimer":"..."},...]`;

    const ppRes = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'sonar-pro',
        messages: [
          { role: 'system', content: `You are an expert health ad copywriter who strictly follows FTC and LegitScript compliance rules. Output ONLY valid JSON arrays, no markdown, no commentary.` },
          { role: 'user', content: prompt },
        ],
        max_tokens: 1800,
      }),
    });
    if (!ppRes.ok) {
      const e = await ppRes.json().catch(() => ({}));
      return resp(502, { error: 'AI API error', detail: String(e.error?.message || ppRes.status) });
    }
    const ppData = await ppRes.json();
    const rawContent = ppData.choices?.[0]?.message?.content || '[]';
    let variants;
    try {
      const cleaned = rawContent.replace(/^```[a-z]*\n?/i, '').replace(/```$/,'').trim();
      variants = JSON.parse(cleaned);
    } catch {
      return resp(502, { error: 'AI returned malformed JSON', raw: rawContent.slice(0, 500) });
    }

    if (!Array.isArray(variants)) variants = [];
    variants = variants.slice(0, 5);

    // Server-side policy check on all generated copy
    const complianceWarnings = [];
    for (const v of variants) {
      const textFields = [v.headline, v.headline2, v.headline3, v.description, v.description2, v.primaryText, v.cta].filter(Boolean);
      const check = policyCheck(textFields, isCertifiedForRxAds);
      if (!check.pass) complianceWarnings.push(...check.violations);
      // Always ensure disclaimer is present
      v.disclaimer = COMPLIANCE_DISCLAIMER;
    }

    return resp(200, {
      variants,
      compliance: {
        certified: isCertifiedForRxAds,
        warnings:  [...new Set(complianceWarnings)],
      },
    });
  }

  /* POST /meta-audiences â€” create standard website custom audiences in Meta */
  if (rawPath.endsWith('/meta-audiences') && method === 'POST') {
    const { clientId } = body;
    let fbToken = process.env.META_ACCESS_TOKEN || FB_ACCESS_TOKEN;
    let actId   = FB_AD_ACCOUNT_ID;
    if (clientId) {
      const client = await getClient(clientId);
      const m = client?.platforms?.meta;
      if (m?.accessToken) fbToken = m.accessToken;
      if (m?.adAccountId) actId   = m.adAccountId.startsWith('act_') ? m.adAccountId : `act_${m.adAccountId}`;
    }
    if (!fbToken) return resp(503, { error: 'Meta credentials not configured.' });

    const audienceDefs = [
      {
        name: 'EBH â€” All Website Visitors (180d)',
        rule: {
          inclusions: { operator: 'or', rules: [{
            event_sources: [{ id: actId.replace('act_',''), type: 'pixel' }],
            retention_seconds: 180 * 86400,
            filter: { operator: 'and', filters: [{ field: 'event', operator: 'i_contains', value: 'PageView' }] },
          }]},
        },
      },
      {
        name: 'EBH â€” GLP-1 / Peptide / TRT Visitors (90d)',
        rule: {
          inclusions: { operator: 'or', rules: [{
            event_sources: [{ id: actId.replace('act_',''), type: 'pixel' }],
            retention_seconds: 90 * 86400,
            filter: { operator: 'and', filters: [{ field: 'event', operator: 'i_contains', value: 'ViewContent' }] },
          }]},
        },
      },
      {
        name: 'EBH â€” Engaged Visitors 45s+ (60d)',
        rule: {
          inclusions: { operator: 'or', rules: [{
            event_sources: [{ id: actId.replace('act_',''), type: 'pixel' }],
            retention_seconds: 60 * 86400,
            filter: { operator: 'and', filters: [{ field: 'event', operator: 'i_contains', value: 'EngagedVisitor' }] },
          }]},
        },
      },
      {
        name: 'EBH â€” Leads / Subscribers (180d)',
        rule: {
          inclusions: { operator: 'or', rules: [{
            event_sources: [{ id: actId.replace('act_',''), type: 'pixel' }],
            retention_seconds: 180 * 86400,
            filter: { operator: 'and', filters: [{ field: 'event', operator: 'i_contains', value: 'Lead' }] },
          }]},
        },
      },
    ];

    const created = [];
    const errors  = [];
    for (const def of audienceDefs) {
      try {
        const res = await fb('POST', `/${actId}/customaudiences`, {
          name:              def.name,
          subtype:           'WEBSITE',
          rule:              JSON.stringify(def.rule),
          retention_days:    180,
          prefill:           true,
        }, fbToken);
        created.push({ name: def.name, id: res.id });
      } catch (ex) {
        errors.push(`${def.name}: ${ex.message}`);
      }
    }
    return resp(errors.length === audienceDefs.length ? 502 : 200, {
      audiences: created,
      errors: errors.length ? errors : undefined,
    });
  }

  /* GET /setup-conversion â€” create (or retrieve) a "Newsletter Signup" conversion action */
  if (rawPath.endsWith('/setup-conversion') && method === 'GET') {
    const clientId = event.queryStringParameters?.clientId;
    const { devToken, refreshTok, customerId, mccId } = await resolveGoogleCreds(clientId);
    if (!devToken || !refreshTok || !customerId)
      return resp(503, { error: 'Google Ads credentials not configured.' });
    const accessToken = await refreshGToken(refreshTok);

    // Search for existing newsletter signup conversion action
    const searchRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT conversion_action.id, conversion_action.name,
                     conversion_action.tag_snippets, conversion_action.status,
                     conversion_action.type
              FROM conversion_action
              WHERE conversion_action.status != 'REMOVED'`,
    }, customerId, mccId, accessToken, devToken);

    const rows = (Array.isArray(searchRes) ? searchRes : [searchRes]).flatMap(r => r.results || []);
    const existing = rows.find(r =>
      r.conversionAction?.name?.toLowerCase().includes('newsletter') ||
      r.conversionAction?.name?.toLowerCase().includes('subscribe')
    );

    if (existing) {
      // Extract conversion label from tag_snippets
      const snippets = existing.conversionAction?.tagSnippets || [];
      const webSnip  = snippets.find(s => s.type === 'WEBPAGE' || s.type === 'WEBPAGE_ONCLICK');
      const labelMatch = (webSnip?.eventSnippet || '').match(/send_to.*?AW-\d+\/([A-Za-z0-9_-]+)/);
      const convLabel = labelMatch?.[1] || null;
      return resp(200, {
        status: 'existing',
        id:     existing.conversionAction?.id,
        name:   existing.conversionAction?.name,
        label:  convLabel,
        conversionId: customerId,
        adsAccountId: `AW-18001526983`,
      });
    }

    // Create a new "Newsletter Signup" conversion action
    const createRes = await gAds('POST', '/conversionActions:mutate', {
      operations: [{ create: {
        name:                   'Newsletter Signup',
        category:               'SIGNUP',
        type:                   'WEBPAGE',
        status:                 'ENABLED',
        primaryForGoal:         true,
        countingType:           'ONE_PER_CLICK',
        valueSettings: {
          defaultValue:         1.0,
          alwaysUseDefaultValue: true,
        },
        attributionModelSettings: {
          attributionModel: 'GOOGLE_ADS_LAST_CLICK',
        },
      }}],
    }, customerId, mccId, accessToken, devToken);
    const newConvRN = createRes.results?.[0]?.resourceName;
    const newConvId = newConvRN?.split('/').pop();

    // Fetch the tag snippet for the new action to get the label
    const fetchRes = await gAds('POST', '/googleAds:searchStream', {
      query: `SELECT conversion_action.id, conversion_action.name, conversion_action.tag_snippets
              FROM conversion_action
              WHERE conversion_action.resource_name = '${newConvRN}'`,
    }, customerId, mccId, accessToken, devToken);
    const fetchRows = (Array.isArray(fetchRes) ? fetchRes : [fetchRes]).flatMap(r => r.results || []);
    const newSnippets = fetchRows[0]?.conversionAction?.tagSnippets || [];
    const newWebSnip  = newSnippets.find(s => s.type === 'WEBPAGE' || s.type === 'WEBPAGE_ONCLICK');
    const newLabelMatch = (newWebSnip?.eventSnippet || '').match(/send_to.*?AW-\d+\/([A-Za-z0-9_-]+)/);
    const newLabel = newLabelMatch?.[1] || null;

    return resp(200, {
      status: 'created',
      id:     newConvId,
      name:   'Newsletter Signup',
      label:  newLabel,
      adsAccountId: `AW-18001526983`,
    });
  }

  /* POST /weekly-summary â€” pull Google Ads + Meta perf data and AI-analyze it */
  if (rawPath.endsWith('/weekly-summary') && method === 'POST') {
    const { clientId } = body;
    const { devToken, refreshTok, customerId, mccId } = await resolveGoogleCreds(clientId);

    let metaToken = process.env.META_ACCESS_TOKEN || FB_ACCESS_TOKEN;
    let metaActId = FB_AD_ACCOUNT_ID;
    if (clientId) {
      const client = await getClient(clientId);
      const m = client?.platforms?.meta;
      if (m?.accessToken) metaToken = m.accessToken;
      if (m?.adAccountId) metaActId = m.adAccountId.startsWith('act_') ? m.adAccountId : `act_${m.adAccountId}`;
    }

    const perfBlocks = [];

    // Google Ads: last 7 days â€” ad sets (ad groups) by cost/conv, top creatives by CTR
    if (devToken && refreshTok && customerId && customerId !== 'None') {
      try {
        const accessToken = await refreshGToken(refreshTok);
        const [agRes, adRes] = await Promise.all([
          gAds('POST', '/googleAds:searchStream', {
            query: `SELECT ad_group.name, metrics.clicks, metrics.impressions, metrics.ctr,
                           metrics.conversions, metrics.cost_micros
                    FROM ad_group
                    WHERE segments.date DURING LAST_7_DAYS
                      AND metrics.impressions > 0
                    ORDER BY metrics.conversions DESC
                    LIMIT 10`,
          }, customerId, mccId, accessToken, devToken),
          gAds('POST', '/googleAds:searchStream', {
            query: `SELECT ad_group_ad.ad.responsive_search_ad.headlines,
                           metrics.clicks, metrics.impressions, metrics.ctr, metrics.conversions
                    FROM ad_group_ad
                    WHERE segments.date DURING LAST_7_DAYS
                      AND metrics.impressions > 0
                    ORDER BY metrics.ctr DESC
                    LIMIT 10`,
          }, customerId, mccId, accessToken, devToken),
        ]);
        const adGroups = (Array.isArray(agRes) ? agRes : [agRes]).flatMap(r => r.results || []).map(r => ({
          name:        r.adGroup?.name,
          clicks:      Number(r.metrics?.clicks || 0),
          ctr:         ((Number(r.metrics?.ctr || 0)) * 100).toFixed(2) + '%',
          conv:        Number(r.metrics?.conversions || 0),
          cost:        '$' + (Number(r.metrics?.costMicros || 0) / 1e6).toFixed(2),
        }));
        const topAds = (Array.isArray(adRes) ? adRes : [adRes]).flatMap(r => r.results || []).map(r => ({
          headline: (r.adGroupAd?.ad?.responsiveSearchAd?.headlines || [{ text: 'â€”' }])[0].text,
          ctr:      ((Number(r.metrics?.ctr || 0)) * 100).toFixed(2) + '%',
          conv:     Number(r.metrics?.conversions || 0),
        }));
        if (adGroups.length || topAds.length) {
          perfBlocks.push(`=== Google Ads â€” Last 7 Days ===\nAd Groups:\n${adGroups.map(a=>`${a.name}: ${a.clicks} clicks, CTR ${a.ctr}, ${a.conv} conv, cost ${a.cost}`).join('\n')}\nTop Creatives by CTR:\n${topAds.map(a=>`"${a.headline}": CTR ${a.ctr}, ${a.conv} conv`).join('\n')}`);
        }
      } catch (ex) {
        perfBlocks.push(`Google Ads data unavailable: ${ex.message}`);
      }
    }

    // Meta: last 7 days â€” ad sets by spend/leads, ads by CTR
    if (metaToken && metaActId) {
      try {
        const [adsetData, adsData] = await Promise.all([
          fb('GET', `/${metaActId}/adsets`, {
            fields: 'name,insights.date_preset(last_7d){impressions,clicks,ctr,spend,actions}',
            limit: 10,
          }, metaToken),
          fb('GET', `/${metaActId}/ads`, {
            fields: 'name,insights.date_preset(last_7d){impressions,clicks,ctr,spend,actions}',
            limit: 10,
          }, metaToken),
        ]);
        const parseInsights = (item) => {
          const ins = item.insights?.data?.[0] || {};
          const leads = (ins.actions || []).find(a => a.action_type === 'lead')?.value || 0;
          return { name: item.name, imp: ins.impressions || 0, clicks: ins.clicks || 0, ctr: parseFloat(ins.ctr || 0).toFixed(2) + '%', spend: '$' + parseFloat(ins.spend || 0).toFixed(2), leads };
        };
        const adsets = (adsetData.data || []).map(parseInsights).filter(a => Number(a.imp) > 0);
        const ads    = (adsData.data   || []).map(parseInsights).filter(a => Number(a.imp) > 0);
        if (adsets.length || ads.length) {
          perfBlocks.push(`=== Meta Ads â€” Last 7 Days ===\nAd Sets:\n${adsets.map(a=>`${a.name}: ${a.clicks} clicks, CTR ${a.ctr}, ${a.leads} leads, spend ${a.spend}`).join('\n')}\nAds by CTR:\n${ads.map(a=>`${a.name}: CTR ${a.ctr}, ${a.leads} leads, spend ${a.spend}`).join('\n')}`);
        }
      } catch (ex) {
        perfBlocks.push(`Meta data unavailable: ${ex.message}`);
      }
    }

    if (!perfBlocks.length)
      return resp(200, { summary: 'No performance data available yet. Run campaigns for at least a week to generate insights.', topAudiences: [], topCreatives: [], suggestions: [] });

    if (!PERPLEXITY_API_KEY)
      return resp(200, { rawData: perfBlocks.join('\n\n'), summary: 'AI analysis unavailable â€” set PERPLEXITY_API_KEY.', topAudiences: [], topCreatives: [], suggestions: [] });

    const aiPrompt = `Here is last week's ad performance data:\n\n${perfBlocks.join('\n\n')}\n\nAnalyze and return a valid JSON object with exactly these fields:
{
  "topAudiences": [{ "name": "...", "stat": "..." }],  // top 3 audiences/ad sets by conversion rate or cost/lead
  "topCreatives": [{ "name": "...", "stat": "..." }],  // top 5 creatives/ads by CTR or conversion rate
  "suggestions": ["...", "...", "..."],                 // exactly 3 concrete, actionable suggestions for: (a) budget allocation, (b) audiences, (c) new creative angles
  "summary": "2-3 sentence plain-English executive summary of the week"
}
Return ONLY valid JSON, no markdown, no commentary.`;

    const aiRes = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'sonar-pro',
        messages: [
          { role: 'system', content: 'You are a performance marketing analyst. Output only valid JSON, no markdown.' },
          { role: 'user', content: aiPrompt },
        ],
        max_tokens: 800,
      }),
    });
    const aiData  = await aiRes.json();
    const rawText = aiData.choices?.[0]?.message?.content || '{}';
    let parsed;
    try {
      const cleaned = rawText.replace(/^```[a-z]*\n?/i, '').replace(/```$/,'').trim();
      parsed = JSON.parse(cleaned);
    } catch {
      parsed = { summary: rawText.slice(0, 600), topAudiences: [], topCreatives: [], suggestions: [] };
    }
    return resp(200, {
      topAudiences: parsed.topAudiences || [],
      topCreatives: parsed.topCreatives || [],
      suggestions:  parsed.suggestions  || [],
      summary:      parsed.summary      || '',
    });
  }

  /* POST /launch-meta-campaign â€” create full campaign â†’ adset â†’ creative â†’ ad (PAUSED) */
  if (rawPath.endsWith('/launch-meta-campaign') && method === 'POST') {
    const {
      clientId,
      campaignName,
      type = 'cold',
      objective = 'OUTCOME_TRAFFIC',
      dailyBudget = 20,
      destinationUrl = 'https://evidencebasedhealth.me',
      ageMin = 25, ageMax = 65,
      countries = ['US'],
      audienceIds = [],
      excludeAudienceIds = [],
      primaryText, headline, description, imageUrl,
      ctaType = 'LEARN_MORE',
    } = body;

    if (!campaignName?.trim() || !primaryText?.trim() || !headline?.trim())
      return resp(400, { error: 'campaignName, primaryText, and headline are required' });

    let fbToken = META_ACCESS_TOKEN || FB_ACCESS_TOKEN;
    let actId   = FB_AD_ACCOUNT_ID;
    let pageId  = FB_PAGE_ID;

    if (clientId) {
      const client = await getClient(clientId);
      const m = client?.platforms?.meta;
      if (m?.accessToken) fbToken = m.accessToken;
      if (m?.adAccountId) actId = m.adAccountId.startsWith('act_') ? m.adAccountId : `act_${m.adAccountId}`;
      if (m?.pageId)      pageId = m.pageId;
    }

    if (!fbToken || fbToken === 'PLACEHOLDER')
      return resp(503, { error: 'Meta credentials not configured for this client.' });

    const countryList = Array.isArray(countries) ? countries : [countries];

    const targeting = {
      age_min: Number(ageMin),
      age_max: Number(ageMax),
      geo_locations: { countries: countryList },
    };
    if (audienceIds.length > 0)
      targeting.custom_audiences = audienceIds.map(id => ({ id: String(id) }));
    if (excludeAudienceIds.length > 0)
      targeting.excluded_custom_audiences = excludeAudienceIds.map(id => ({ id: String(id) }));

    const optGoal = objective === 'OUTCOME_LEADS'      ? 'LEAD_GENERATION'  :
                    objective === 'OUTCOME_ENGAGEMENT' ? 'POST_ENGAGEMENT'  : 'LINK_CLICKS';

    const campaign = await fb('POST', `/${actId}/campaigns`, {
      name: campaignName.trim(),
      objective,
      status: 'PAUSED',
      special_ad_categories: [],
    }, fbToken);

    const adset = await fb('POST', `/${actId}/adsets`, {
      name:              `${campaignName.trim()} â€” Ad Set`,
      campaign_id:       campaign.id,
      daily_budget:      Math.round(Number(dailyBudget) * 100),
      billing_event:     'IMPRESSIONS',
      optimization_goal: optGoal,
      bid_strategy:      'LOWEST_COST_WITHOUT_CAP',
      targeting,
      status:            'PAUSED',
      destination_type:  'WEBSITE',
    }, fbToken);

    const creative = await fb('POST', `/${actId}/adcreatives`, {
      name: `${campaignName.trim()} â€” Creative`,
      object_story_spec: {
        page_id: pageId,
        link_data: {
          link:             destinationUrl,
          message:          primaryText.trim(),
          name:             headline.trim(),
          call_to_action:   { type: ctaType, value: { link: destinationUrl } },
          ...(description?.trim() && { description: description.trim() }),
          ...(imageUrl?.trim()    && { picture: imageUrl.trim() }),
        },
      },
    }, fbToken);

    const ad = await fb('POST', `/${actId}/ads`, {
      name:      `${campaignName.trim()} â€” Ad`,
      adset_id:  adset.id,
      creative:  { creative_id: creative.id },
      status:    'PAUSED',
    }, fbToken);

    return resp(200, {
      campaignId:   campaign.id,
      adsetId:      adset.id,
      creativeId:   creative.id,
      adId:         ad.id,
      campaignName: campaignName.trim(),
      previewUrl:   `https://www.facebook.com/adsmanager/manage/campaigns?act=${actId.replace('act_', '')}`,
    });
  }

  /* â”€â”€ PROFILE ROUTES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

  /* POST /profile-register â€” PUBLIC â€” create password-protected profile */
  if (rawPath.endsWith('/profile-register') && method === 'POST') {
    const {
      email, password,
      yearOfBirth, sexAtBirth = '', orientation = '',
      organs = [], riskFlags = [],
      emailConsent = false, smsConsent = false, phone = '',
    } = body;

    const addr = (email || '').trim().toLowerCase();
    if (!addr || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr))
      return resp(400, { error: 'Valid email address is required.' });
    if (!password || password.length < 8)
      return resp(400, { error: 'Password must be at least 8 characters.' });

    const yob = parseInt(yearOfBirth, 10);
    if (isNaN(yob) || yob < 1900 || yob > new Date().getFullYear() - 18)
      return resp(400, { error: 'Invalid year of birth.' });

    const salt = newSalt();
    const hash = hashPassword(password, salt);
    const now  = new Date().toISOString();

    try {
      await dynamo.send(new PutItemCommand({
        TableName: PROFILES_TABLE,
        Item: {
          email:        { S: addr },
          passwordHash: { S: hash },
          passwordSalt: { S: salt },
          yearOfBirth:  { N: String(yob) },
          sexAtBirth:   { S: sexAtBirth },
          orientation:  { S: orientation },
          organs:       { SS: organs.length ? organs : ['none'] },
          riskFlags:    { SS: riskFlags.length ? riskFlags : ['none'] },
          emailConsent: { BOOL: !!emailConsent },
          smsConsent:   { BOOL: !!smsConsent },
          phone:        { S: (phone || '').trim() || 'none' },
          createdAt:    { S: now },
          updatedAt:    { S: now },
          lastLoginAt:  { S: now },
        },
        ConditionExpression: 'attribute_not_exists(email)',
      }));
    } catch (err) {
      if (err.name === 'ConditionalCheckFailedException')
        return resp(409, { error: 'An account with that email already exists.' });
      throw err;
    }

    // Welcome confirmation email
    await ses.send(new SendEmailCommand({
      FromEmailAddress: SES_FROM_EMAIL,
      ReplyToAddresses: [SES_REPLY_TO],
      Destination: { ToAddresses: [addr] },
      Content: { Simple: {
        Subject: { Data: 'Your prevention roadmap profile is ready â€” Evidence-Based Health', Charset: 'UTF-8' },
        Body: {
          Text: { Data: `Your prevention roadmap profile has been created.\n\nLog in anytime to review your personalized screening timeline:\nhttps://evidencebasedhealth.me/my-roadmap.html\n\nWhat we store: email address, year of birth, and your anonymous health profile (organ selections and risk flags). No name, no full date of birth, no medical records.\n\nTo delete your account at any time, log in and choose "Delete my account" from your profile.\n\nEvidence-Based Health â€” Educational content only`, Charset: 'UTF-8' },
          Html: { Data: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f7f5f0;font-family:'Helvetica Neue',Arial,sans-serif"><table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5f0;padding:32px 16px"><tr><td align="center"><table width="100%" cellpadding="0" cellspacing="0" style="max-width:580px;background:#fff;border-radius:8px;overflow:hidden"><tr><td style="background:#1a5c3a;padding:24px 32px"><p style="margin:0;font-size:11px;font-style:italic;color:rgba(255,255,255,0.7)">Evidence-Based Health</p><h1 style="margin:8px 0 0;font-size:20px;color:#fff;font-weight:700;line-height:1.3">Your prevention roadmap profile is ready</h1></td></tr><tr><td style="padding:28px 32px;color:#2d3d35;font-size:15px;line-height:1.65"><p style="margin:0 0 16px">Your account has been created. Log in anytime to view your personalized screening timeline and upcoming reminders.</p><p style="margin:0 0 24px"><a href="https://evidencebasedhealth.me/my-roadmap.html" style="background:#1a5c3a;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">View my roadmap &rarr;</a></p><p style="margin:24px 0 0;font-size:13px;color:#666;border-top:1px solid #e8e4dc;padding-top:16px"><strong>What we store:</strong> Email address, year of birth, and your anonymous screening profile (organ selections + risk flags). No name. No full date of birth. No medical records.</p><p style="margin:12px 0 0;font-size:12px;color:#999">Evidence-Based Health &middot; Educational content only &middot; Not medical advice</p></td></tr></table></td></tr></table></body></html>`, Charset: 'UTF-8' },
        },
      }},
    })).catch(err => console.error('Profile welcome email failed:', err));

    return resp(201, { token: signProfileJWT(addr) });
  }

  /* POST /profile-login â€” PUBLIC â€” authenticate and return JWT */
  if (rawPath.endsWith('/profile-login') && method === 'POST') {
    const { email, password } = body;
    const addr = (email || '').trim().toLowerCase();
    if (!addr || !password) return resp(400, { error: 'Email and password are required.' });

    const res = await dynamo.send(new GetItemCommand({
      TableName: PROFILES_TABLE, Key: { email: { S: addr } },
    }));
    const item = res.Item;
    // Always run password check to prevent timing-based email enumeration
    const dummyHash = '0'.repeat(128);
    const dummySalt = '0'.repeat(64);
    const valid = item
      ? checkPassword(password, item.passwordHash.S, item.passwordSalt.S)
      : (checkPassword(password, dummyHash, dummySalt) && false); // always false
    if (!valid) return resp(401, { error: 'Invalid email or password.' });

    await dynamo.send(new UpdateItemCommand({
      TableName: PROFILES_TABLE,
      Key: { email: { S: addr } },
      UpdateExpression: 'SET lastLoginAt = :t',
      ExpressionAttributeValues: { ':t': { S: new Date().toISOString() } },
    })).catch(() => {});

    return resp(200, { token: signProfileJWT(addr) });
  }

  /* GET /profile â€” AUTH â€” return profile (no password fields) */
  if (rawPath.endsWith('/profile') && method === 'GET') {
    const auth = verifyProfileJWT(event.headers?.authorization || event.headers?.Authorization);
    if (!auth) return resp(401, { error: 'Authentication required.' });

    const res = await dynamo.send(new GetItemCommand({
      TableName: PROFILES_TABLE, Key: { email: { S: auth.sub } },
    }));
    if (!res.Item) return resp(404, { error: 'Profile not found.' });
    const i = res.Item;

    return resp(200, {
      email:        i.email.S,
      yearOfBirth:  Number(i.yearOfBirth.N),
      sexAtBirth:   i.sexAtBirth?.S   || '',
      orientation:  i.orientation?.S  || '',
      organs:       (i.organs?.SS     || []).filter(x => x !== 'none'),
      riskFlags:    (i.riskFlags?.SS  || []).filter(x => x !== 'none'),
      emailConsent: i.emailConsent?.BOOL ?? false,
      smsConsent:   i.smsConsent?.BOOL   ?? false,
      phone:        i.phone?.S && i.phone.S !== 'none' ? i.phone.S : '',
      language:     i.language?.S || 'en',
      createdAt:    i.createdAt?.S    || '',
      lastLoginAt:  i.lastLoginAt?.S  || '',
    });
  }

  /* PUT /profile â€” AUTH â€” update profile data */
  if (rawPath.endsWith('/profile') && method === 'PUT') {
    const auth = verifyProfileJWT(event.headers?.authorization || event.headers?.Authorization);
    if (!auth) return resp(401, { error: 'Authentication required.' });

    const { yearOfBirth, sexAtBirth = '', orientation = '', organs = [], riskFlags = [], emailConsent = false, smsConsent = false, phone = '' } = body;
    const yob = parseInt(yearOfBirth, 10);
    if (isNaN(yob) || yob < 1900 || yob > new Date().getFullYear() - 18)
      return resp(400, { error: 'Invalid year of birth.' });

    const profileUpdatedAt = new Date().toISOString();
    await dynamo.send(new UpdateItemCommand({
      TableName: PROFILES_TABLE,
      Key: { email: { S: auth.sub } },
      UpdateExpression: 'SET yearOfBirth = :yob, sexAtBirth = :sex, orientation = :ori, organs = :org, riskFlags = :rf, emailConsent = :ec, smsConsent = :sc, phone = :ph, updatedAt = :ua',
      ExpressionAttributeValues: {
        ':yob': { N: String(yob) },
        ':sex': { S: sexAtBirth },
        ':ori': { S: orientation },
        ':org': { SS: organs.length ? organs : ['none'] },
        ':rf':  { SS: riskFlags.length ? riskFlags : ['none'] },
        ':ec':  { BOOL: !!emailConsent },
        ':sc':  { BOOL: !!smsConsent },
        ':ph':  { S: (phone || '').trim() || 'none' },
        ':ua':  { S: profileUpdatedAt },
      },
    }));

    // Sync to PreventionProfiles (reminder table) if entry exists
    await dynamo.send(new UpdateItemCommand({
      TableName: PREVENTION_TABLE,
      Key: { email: { S: auth.sub } },
      UpdateExpression: 'SET yearOfBirth = :yob, organs = :org, riskFlags = :rf, emailConsent = :ec, smsConsent = :sc, phone = :ph, updatedAt = :ua',
      ConditionExpression: 'attribute_exists(email)',
      ExpressionAttributeValues: {
        ':yob': { N: String(yob) },
        ':org': { L: organs.map(o => ({ S: o })) },
        ':rf':  { L: riskFlags.map(r => ({ S: r })) },
        ':ec':  { BOOL: !!emailConsent },
        ':sc':  { BOOL: !!smsConsent },
        ':ph':  { S: (phone || '').trim() || 'none' },
        ':ua':  { S: profileUpdatedAt },
      },
    })).catch(() => {}); // silently skip if no prevention profile exists yet

    return resp(200, { success: true });
  }

  /* DELETE /profile â€” AUTH â€” permanently delete account */
  if (rawPath.endsWith('/profile') && method === 'DELETE') {
    const auth = verifyProfileJWT(event.headers?.authorization || event.headers?.Authorization);
    if (!auth) return resp(401, { error: 'Authentication required.' });

    // Delete from both auth table and prevention profiles (so reminders stop immediately)
    await Promise.all([
      dynamo.send(new DeleteItemCommand({
        TableName: PROFILES_TABLE, Key: { email: { S: auth.sub } },
      })),
      dynamo.send(new DeleteItemCommand({
        TableName: PREVENTION_TABLE, Key: { email: { S: auth.sub } },
      })).catch(() => {}),
    ]);
    return resp(200, { success: true, deleted: true });
  }

  /* POST /profile-change-password â€” AUTH â€” update password */
  if (rawPath.endsWith('/profile-change-password') && method === 'POST') {
    const auth = verifyProfileJWT(event.headers?.authorization || event.headers?.Authorization);
    if (!auth) return resp(401, { error: 'Authentication required.' });

    const { currentPassword, newPassword } = body;
    if (!currentPassword || !newPassword) return resp(400, { error: 'currentPassword and newPassword required.' });
    if (newPassword.length < 10) return resp(400, { error: 'New password must be at least 10 characters.' });

    const existing = await dynamo.send(new GetItemCommand({
      TableName: PROFILES_TABLE, Key: { email: { S: auth.sub } },
    }));
    if (!existing.Item) return resp(404, { error: 'Profile not found.' });

    const storedHash = existing.Item.passwordHash?.S;
    const storedSalt = existing.Item.passwordSalt?.S;
    if (!checkPassword(currentPassword, storedHash, storedSalt)) {
      return resp(401, { error: 'Current password is incorrect.' });
    }

    const newSaltVal = newSalt();
    const newHash    = hashPassword(newPassword, newSaltVal);
    await dynamo.send(new UpdateItemCommand({
      TableName: PROFILES_TABLE,
      Key: { email: { S: auth.sub } },
      UpdateExpression: 'SET passwordHash = :h, passwordSalt = :s, updatedAt = :u',
      ExpressionAttributeValues: {
        ':h': { S: newHash },
        ':s': { S: newSaltVal },
        ':u': { S: new Date().toISOString() },
      },
    }));
    return resp(200, { success: true });
  }

  /* â”€â”€ PREVENTION PROFILE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

  /* POST /prevention-profile â€” PUBLIC â€” save prevention roadmap opt-in */
  if (rawPath.endsWith('/prevention-profile') && method === 'POST') {
    const {
      email, phone = null,
      yearOfBirth, sexAtBirth = '',
      orientation = '',
      organs = [], riskFlags = [],
      emailConsent = false, smsConsent = false, remarketingConsent = false,
      sourcePath = '/prevention-roadmap',
    } = body;

    const addr = (email || '').trim().toLowerCase();
    if (!addr || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr))
      return resp(400, { error: 'Valid email address is required.' });

    const yob = parseInt(yearOfBirth, 10);
    if (isNaN(yob) || yob < 1900 || yob > new Date().getFullYear() - 18)
      return resp(400, { error: 'Invalid year of birth.' });

    const now   = new Date().toISOString();
    const token = randomUUID();

    // Upsert prevention profile into EBHSubscribers
    const profileItem = {
      email:               { S: addr },
      displayName:         { S: addr },
      source:              { S: sourcePath || '/prevention-roadmap' },
      status:              { S: emailConsent ? 'active' : 'profile-only' },
      unsubToken:          { S: token },
      subscribedAt:        { S: now },
      updatedAt:           { S: now },
      yearOfBirth:         { N: String(yob) },
      sexAtBirth:          { S: sexAtBirth },
      orientation:         { S: orientation },
      organs:              { SS: organs.length ? organs : ['none'] },
      riskFlags:           { SS: riskFlags.length ? riskFlags : ['none'] },
      phone:               { S: (phone || '').trim() || 'none' },
      emailConsent:        { BOOL: !!emailConsent },
      smsConsent:          { BOOL: !!smsConsent },
      remarketingConsent:  { BOOL: !!remarketingConsent },
    };

    await dynamo.send(new PutItemCommand({
      TableName: SUBSCRIBERS_TABLE,
      Item: profileItem,
      ConditionExpression: 'attribute_not_exists(email)',
    })).catch(async () => {
      // Already exists â€” update prevention profile fields but preserve subscribedAt
      await dynamo.send(new UpdateItemCommand({
        TableName: SUBSCRIBERS_TABLE,
        Key: { email: { S: addr } },
        UpdateExpression: [
          'SET #st = :st, updatedAt = :ua, yearOfBirth = :yob,',
          'sexAtBirth = :sex, orientation = :ori, organs = :org, riskFlags = :rf,',
          'phone = :ph, emailConsent = :ec, smsConsent = :sc, remarketingConsent = :rc',
        ].join(' '),
        ExpressionAttributeNames:  { '#st': 'status' },
        ExpressionAttributeValues: {
          ':st':  { S: emailConsent ? 'active' : 'profile-only' },
          ':ua':  { S: now },
          ':yob': { N: String(yob) },
          ':sex': { S: sexAtBirth },
          ':ori': { S: orientation },
          ':org': { SS: organs.length ? organs : ['none'] },
          ':rf':  { SS: riskFlags.length ? riskFlags : ['none'] },
          ':ph':  { S: (phone || '').trim() || 'none' },
          ':ec':  { BOOL: !!emailConsent },
          ':sc':  { BOOL: !!smsConsent },
          ':rc':  { BOOL: !!remarketingConsent },
        },
      }));
    });

    // Send confirmation email if consent given
    if (emailConsent) {
      const age = new Date().getFullYear() - yob;
      const organLabels = { colon: 'colon', cervix: 'cervix', prostate: 'prostate', breasts: 'breast tissue' };
      const organStr = organs.map(o => organLabels[o] || o).join(', ') || 'none specified';
      const unsubUrl = `https://lvsofp8c9g.execute-api.us-east-1.amazonaws.com/prod/unsubscribe?token=${encodeURIComponent(token)}`;

      const confirmHtml = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your prevention profile is saved</title></head>
<body style="margin:0;padding:0;background:#f7f5f0;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5f0;padding:32px 16px">
<tr><td align="center"><table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:8px;overflow:hidden">
  <tr><td style="background:#1a5c3a;padding:24px 36px">
    <p style="margin:0;font-family:Georgia,serif;font-size:11px;font-style:italic;color:rgba(255,255,255,0.7);letter-spacing:0.05em">Evidence-Based Health</p>
    <h1 style="margin:8px 0 0;font-family:Georgia,serif;font-size:22px;font-weight:700;color:#ffffff;line-height:1.3">Your prevention profile is saved</h1>
  </td></tr>
  <tr><td style="padding:32px 36px;color:#2d3d35;font-size:15px;line-height:1.65">
    <p>&#10003;&nbsp; We've saved your prevention roadmap profile. Here's what we have on file:</p>
    <table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:16px 0;font-size:14px">
      <tr><td style="padding:8px 0;border-bottom:1px solid #e8e4dc;color:#666;width:40%">Approx. age</td><td style="padding:8px 0;border-bottom:1px solid #e8e4dc;font-weight:600">${age}</td></tr>
      <tr><td style="padding:8px 0;border-bottom:1px solid #e8e4dc;color:#666">Anatomy selected</td><td style="padding:8px 0;border-bottom:1px solid #e8e4dc;font-weight:600">${organStr}</td></tr>
      <tr><td style="padding:8px 0;color:#666">Risk factors noted</td><td style="padding:8px 0;font-weight:600">${riskFlags.length ? riskFlags.length + ' on file' : 'None'}</td></tr>
    </table>
    <p>We'll send you a simple reminder when a key screening age is approaching based on your profile. No spam&mdash;occasional, evidence-based nudges only.</p>
    <p style="margin-top:24px"><a href="https://evidencebasedhealth.me/prevention-roadmap.html" style="background:#1a5c3a;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">View your roadmap again &rarr;</a></p>
    <p style="margin-top:32px;font-size:12px;color:#999">You're receiving this because you opted in at evidencebasedhealth.me. <a href="${unsubUrl}" style="color:#999">Unsubscribe</a>.</p>
  </td></tr>
</table></td></tr></table>
</body></html>`;

      await ses.send(new SendEmailCommand({
        FromEmailAddress: SES_FROM_EMAIL,
        ReplyToAddresses: [SES_REPLY_TO],
        Destination: { ToAddresses: [addr] },
        Content: { Simple: {
          Subject: { Data: 'Your prevention profile is saved â€” Evidence-Based Health', Charset: 'UTF-8' },
          Body: {
            Text: { Data: `Your prevention profile is saved.\n\nApprox. age: ${age}\nAnatomy: ${organStr}\nRisk factors: ${riskFlags.length || 0} on file\n\nWe'll send reminders as screening ages approach.\n\nView your roadmap: https://evidencebasedhealth.me/prevention-roadmap.html\n\nUnsubscribe: ${unsubUrl}`, Charset: 'UTF-8' },
            Html: { Data: confirmHtml, Charset: 'UTF-8' },
          },
        }},
      })).catch(err => console.error('Prevention profile confirmation email failed:', err));
    }

    return resp(200, { success: true });
  }

  /* â”€â”€ NEWSLETTER ROUTES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

  /* POST /subscribe â€” PUBLIC (no auth) â€” capture email from site forms */
  if (rawPath.endsWith('/subscribe') && method === 'POST') {
    const { email, name = '', source = 'website' } = body;
    const addr = (email || '').trim().toLowerCase();
    if (!addr || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr))
      return resp(400, { error: 'Valid email address is required.' });

    // Upsert â€” idempotent re-subscribe
    const now = new Date().toISOString();
    const token = randomUUID();            // unsubscribe token
    await dynamo.send(new PutItemCommand({
      TableName: SUBSCRIBERS_TABLE,
      Item: {
        email:           { S: addr },
        displayName:     { S: name.slice(0, 80) },
        source:          { S: source },
        status:          { S: 'active' },
        unsubToken:      { S: token },
        subscribedAt:    { S: now },
        updatedAt:       { S: now },
      },
      ConditionExpression: 'attribute_not_exists(email) OR #st <> :active',
      ExpressionAttributeNames:  { '#st': 'status' },
      ExpressionAttributeValues: { ':active': { S: 'active' } },
    })).catch(async () => {
      // Already exists and active â€” just update timestamp
      await dynamo.send(new UpdateItemCommand({
        TableName: SUBSCRIBERS_TABLE,
        Key: { email: { S: addr } },
        UpdateExpression: 'SET #st = :active, updatedAt = :ua',
        ExpressionAttributeNames:  { '#st': 'status' },
        ExpressionAttributeValues: { ':active': { S: 'active' }, ':ua': { S: now } },
      }));
    });

    return resp(200, { success: true, message: 'Subscribed successfully.' });
  }

  /* GET /subscribers â€” admin â€” list all */
  if (rawPath.endsWith('/subscribers') && method === 'GET') {
    const result = await dynamo.send(new ScanCommand({ TableName: SUBSCRIBERS_TABLE }));
    const subs = (result.Items || []).map(i => ({
      email:        i.email?.S,
      displayName:  i.displayName?.S || '',
      source:       i.source?.S || 'website',
      status:       i.status?.S || 'active',
      subscribedAt: i.subscribedAt?.S || '',
    }));
    subs.sort((a, b) => (b.subscribedAt || '').localeCompare(a.subscribedAt || ''));
    return resp(200, { subscribers: subs, total: subs.length, active: subs.filter(s => s.status === 'active').length });
  }

  /* DELETE /subscriber â€” admin â€” unsubscribe by email */
  if (rawPath.endsWith('/subscriber') && method === 'DELETE') {
    const email = (body.email || '').trim().toLowerCase();
    if (!email) return resp(400, { error: 'email required' });
    await dynamo.send(new UpdateItemCommand({
      TableName: SUBSCRIBERS_TABLE,
      Key: { email: { S: email } },
      UpdateExpression: 'SET #st = :unsub, updatedAt = :ua',
      ExpressionAttributeNames:  { '#st': 'status' },
      ExpressionAttributeValues: { ':unsub': { S: 'unsubscribed' }, ':ua': { S: new Date().toISOString() } },
    }));
    return resp(200, { success: true });
  }

  /* GET /unsubscribe?token=xxx â€” PUBLIC â€” one-click unsubscribe link in emails */
  if (rawPath.endsWith('/unsubscribe') && method === 'GET') {
    const token = event.queryStringParameters?.token || '';
    if (!token) return { statusCode: 400, headers: CORS, body: 'Missing token.' };
    const result = await dynamo.send(new ScanCommand({
      TableName: SUBSCRIBERS_TABLE,
      FilterExpression: 'unsubToken = :t',
      ExpressionAttributeValues: { ':t': { S: token } },
    }));
    const item = result.Items?.[0];
    if (!item) return { statusCode: 404, headers: CORS, body: 'Token not found.' };
    await dynamo.send(new UpdateItemCommand({
      TableName: SUBSCRIBERS_TABLE,
      Key: { email: item.email },
      UpdateExpression: 'SET #st = :unsub, updatedAt = :ua',
      ExpressionAttributeNames:  { '#st': 'status' },
      ExpressionAttributeValues: { ':unsub': { S: 'unsubscribed' }, ':ua': { S: new Date().toISOString() } },
    }));
    return {
      statusCode: 200,
      headers: { ...CORS, 'Content-Type': 'text/html' },
      body: '<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:4rem;color:#333"><h2>âœ“ Unsubscribed</h2><p>You have been removed from the Evidence-Based Health newsletter. <a href="https://evidencebasedhealth.me">Return to site</a></p></body></html>',
    };
  }

  /* POST /generate-post â€” admin â€” AI generates a newsletter post */
  if (rawPath.endsWith('/generate-post') && method === 'POST') {
    const {
      topic,           // free-text prompt from admin
      pillar = 'evidence-based health',
      tone   = 'educational, warm, no hype',
      length = 'medium',  // short | medium | long
      extraContext = '',
    } = body;
    if (!topic?.trim()) return resp(400, { error: 'topic is required' });
    if (!PERPLEXITY_API_KEY) return resp(503, { error: 'PERPLEXITY_API_KEY not set.' });

    const wordTarget = length === 'short' ? '250â€“350' : length === 'long' ? '600â€“800' : '400â€“550';

    // Step 1 â€” Perplexity: ground the topic with real current research + trending angles
    const researchPrompt = `Search for the latest research, clinical news, and engagement trends related to: "${topic}" in the context of ${pillar}.

IMPORTANT SOURCE RULES â€” you MUST follow these strictly:
- Only cite sources from US government sites (.gov): PubMed/NCBI, CDC, NIH, USPSTF, FDA, CMS, AHRQ, NLM
OR from peer-reviewed medical journals including (but not limited to):
  General: NEJM, JAMA, The Lancet, BMJ, Annals of Internal Medicine, Nature Medicine, PLOS Medicine, PLOS One, BMJ Medicine, Mayo Clinic Proceedings
  Surgery: Annals of Surgery, JAMA Surgery, Journal of the American College of Surgeons, British Journal of Surgery, World Journal of Surgery
  Cardiology: Journal of the American College of Cardiology, Circulation, European Heart Journal
  Oncology: CA: A Cancer Journal for Clinicians, Journal of Clinical Oncology, The Lancet Oncology, JAMA Oncology
  GI: Gastroenterology, Gut, American Journal of Gastroenterology
  Pediatrics: Pediatrics, JAMA Pediatrics, The Journal of Pediatrics
  Primary care: Annals of Family Medicine, BJGP, Family Medicine
  Any PubMed-indexed peer-reviewed journal
- ONLY cite studies or guidelines where at least one author holds an MD or DO degree. Do NOT cite works authored solely by economists, policy analysts, statisticians, or non-clinician researchers.
- Do NOT cite: blogs, news aggregators, non-peer-reviewed sources, health policy reports (e.g. OECD Health at a Glance, Commonwealth Fund reports, WHO policy briefs), industry white papers, or preprints without peer review.

Return:
1. 2â€“3 most interesting, recent factual findings or statistics with exact citations (journal name, year, DOI or PubMed ID if available, at least one MD/DO author confirmed)
2. What question or angle is currently getting the most engagement on this clinical topic?
3. A surprising or counterintuitive finding that would hook a clinically-literate adult reader
4. Any recent guideline changes or new studies from the past 12â€“24 months with citations`;

    const ppRes = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'sonar-pro',
        messages: [
          { role: 'system', content: 'You are a medical research assistant. Provide accurate, cited health information for newsletter content research.' },
          { role: 'user',   content: researchPrompt },
        ],
        max_tokens: 800,
      }),
    });
    const ppData  = await ppRes.json();
    const research = ppData.choices?.[0]?.message?.content || '';
    const citations = ppData.citations || [];

    // Step 2 â€” Write the post (OpenAI if available, else Perplexity)
    // Build slug from topic for the public post URL
    const slug = topic.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
    const postUrl = `https://evidencebasedhealth.me/post.html?slug=${encodeURIComponent(slug)}`;

    const writePrompt = `You are writing a weekly health newsletter for "Evidence-Based Health" â€” a newsletter founded by a National PA of the Year. The tone is: ${tone}. No fearmongering, no supplement upsells, no direct prescription language.

Core pillar: ${pillar}
Topic this week: ${topic}
${extraContext ? `Additional context: ${extraContext}` : ''}

CITATION RULES â€” strictly enforced:
- Only cite peer-reviewed medical journals (PubMed-indexed) or US government sources (.gov: CDC, NIH, USPSTF, FDA, AHRQ).
- Only cite studies or guidelines where at least one author holds an MD or DO degree.
- Do NOT cite: OECD reports, Commonwealth Fund, WHO policy briefs, health economics reports, non-peer-reviewed sources, blogs, news aggregators, or any source without a clinician author.
- Every inline citation must include: Author surname(s), Journal, Year. Format as superscript <sup>[N]</sup> in the body and as a numbered <li> in the References section.

Research grounding (use these facts, verify each meets citation rules above before using):
${research}

Write a newsletter post of ${wordTarget} words. Structure:
1. **Subject line** (one line â€” curiosity-driven, click-worthy, max 60 chars)
2. **Preview text** (one line â€” 80â€“90 chars, complements the subject line)
3. **Body** (this is the EMAIL body only) â€” opening hook (1 sentence), core content (cite sources inline as superscript <sup>[1]</sup> style), one key takeaway box styled exactly as: <div style="background:#f0f7f3;border-left:4px solid #1a5c3a;border-radius:6px;padding:16px 20px;margin:24px 0"><strong style="color:#1a5c3a;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em">Key Takeaway</strong><p style="margin:8px 0 0;font-size:15px;color:#2d3d35;line-height:1.65">[takeaway text here]</p></div>, then a CTA link: <p style="margin:24px 0 0"><a href="${postUrl}" style="color:#1a5c3a;font-weight:600">Read the full evidence brief â†’</a></p>
4. **fullPostHtml** â€” THIS IS A COMPLETELY SEPARATE, STANDALONE WEB ARTICLE. It must be 600â€“900 words. It is published at ${postUrl} and is NOT an email â€” do NOT include any "Read the full evidence brief" link, do NOT include any email CTA, do NOT include any link back to the post URL. Write it as a self-contained article: an engaging headline (<h2>), introduction paragraph, 3â€“4 substantive sections each with an <h3> subheading, expanded explanation of the research, all inline citations as numbered superscripts <sup>[1]</sup>, one key takeaway box using the same styling as above, and a References section at the bottom as an <h3>References</h3> followed by an <ol> with each citation as a <li> containing journal name, year, and DOI/PubMed link where available. The fullPostHtml must be LONGER and MORE DETAILED than bodyHtml.
5. **3 social post captions** (Twitter/X, LinkedIn, Instagram) for the same topic

Return valid JSON with exactly these fields:
{
  "subjectLine": "...",
  "previewText": "...",
  "bodyHtml": "...",        // email body â€” clean HTML, no <html>/<body> wrapper
  "bodyText": "...",        // plain text email fallback
  "fullPostHtml": "...",   // full web article with references, no <html>/<body> wrapper
  "socialX": "...",
  "socialLinkedIn": "...",
  "socialInstagram": "...",
  "slug": "${slug}"
}
Return ONLY valid JSON, no markdown fences.`;

    let post;
    if (OPENAI_API_KEY) {
      const oaRes = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'gpt-4o',
          messages: [
            { role: 'system', content: 'You are an expert health writer. Only cite peer-reviewed medical journals (PubMed-indexed) or US .gov sources. Only use references with at least one MD or DO author. Never cite OECD, policy reports, or non-peer-reviewed sources. Return only valid JSON, no markdown.' },
            { role: 'user',   content: writePrompt },
          ],
          response_format: { type: 'json_object' },
          max_tokens: 3500,
        }),
      });
      const oaData = await oaRes.json();
      const raw = oaData.choices?.[0]?.message?.content || '{}';
      try { post = JSON.parse(raw); } catch { post = {}; }
    } else {
      // Fallback: use Perplexity for writing too
      const ppwRes = await fetch('https://api.perplexity.ai/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${PERPLEXITY_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'sonar-pro',
          messages: [
            { role: 'system', content: 'You are an expert health writer. Only cite peer-reviewed medical journals (PubMed-indexed) or US .gov sources. Only use references with at least one MD or DO author. Never cite OECD, policy reports, or non-peer-reviewed sources. Return only valid JSON, no markdown fences.' },
            { role: 'user',   content: writePrompt },
          ],
          max_tokens: 3500,
        }),
      });
      const ppwData = await ppwRes.json();
      const raw = (ppwData.choices?.[0]?.message?.content || '{}').replace(/^```[a-z]*\n?/i,'').replace(/```$/,'').trim();
      try { post = JSON.parse(raw); } catch { post = { bodyText: raw, subjectLine: topic, previewText: '', bodyHtml: `<p>${raw.replace(/\n/g,'</p><p>')}</p>`, fullPostHtml: '', socialX: '', socialLinkedIn: '', socialInstagram: '', slug }; }
    }

    return resp(200, { ...post, slug, citations, research: research.slice(0, 1200) });
  }

  /* POST /publish-post â€” admin â€” save a generated post to the public posts table */
  if (rawPath.endsWith('/publish-post') && method === 'POST') {
    const { slug: pSlug, subjectLine, bodyHtml, fullPostHtml, previewText = '', imageUrl = '', citations: pCites = [] } = body;
    if (!pSlug || !subjectLine || !fullPostHtml) return resp(400, { error: 'slug, subjectLine, and fullPostHtml are required' });
    const now = new Date().toISOString();
    await dynamo.send(new PutItemCommand({
      TableName: POSTS_TABLE,
      Item: {
        slug:         { S: pSlug },
        subjectLine:  { S: subjectLine },
        previewText:  { S: previewText },
        bodyHtml:     { S: bodyHtml || '' },
        fullPostHtml: { S: fullPostHtml },
        imageUrl:     { S: imageUrl },
        citations:    { S: JSON.stringify(pCites) },
        publishedAt:  { S: now },
        updatedAt:    { S: now },
      },
    }));
    return resp(200, { published: true, url: `https://evidencebasedhealth.me/post.html?slug=${encodeURIComponent(pSlug)}` });
  }

  /* GET /post â€” public â€” fetch a single post by ?slug= */
  if (rawPath.endsWith('/post') && method === 'GET') {
    const qSlug = (event.queryStringParameters?.slug || '').trim();
    if (!qSlug) return resp(400, { error: 'slug query param required' });
    const res = await dynamo.send(new GetItemCommand({ TableName: POSTS_TABLE, Key: { slug: { S: qSlug } } }));
    if (!res.Item) return resp(404, { error: 'Post not found' });
    const i = res.Item;
    return resp(200, {
      slug:         i.slug?.S,
      subjectLine:  i.subjectLine?.S,
      previewText:  i.previewText?.S,
      fullPostHtml: i.fullPostHtml?.S,
      imageUrl:     i.imageUrl?.S,
      citations:    JSON.parse(i.citations?.S || '[]'),
      publishedAt:  i.publishedAt?.S,
    });
  }

  /* GET /list-posts â€” admin â€” list all published posts */
  if (rawPath.endsWith('/list-posts') && method === 'GET') {
    const scanRes = await dynamo.send(new ScanCommand({ TableName: POSTS_TABLE, ProjectionExpression: 'slug, subjectLine, previewText, imageUrl, publishedAt, updatedAt' }));
    const posts = (scanRes.Items || []).map(i => ({
      slug:        i.slug?.S,
      subjectLine: i.subjectLine?.S,
      previewText: i.previewText?.S,
      imageUrl:    i.imageUrl?.S,
      publishedAt: i.publishedAt?.S,
      updatedAt:   i.updatedAt?.S,
    })).sort((a, b) => (b.publishedAt || '').localeCompare(a.publishedAt || ''));
    return resp(200, { posts });
  }

  /* PUT /update-post â€” admin â€” update an existing post (or create one manually) */
  if (rawPath.endsWith('/update-post') && method === 'PUT') {
    const { slug: uSlug, subjectLine: uSubject, previewText: uPreview = '', fullPostHtml: uFullHtml, imageUrl: uImg = '', citations: uCites = [] } = body;
    if (!uSlug || !uSubject || !uFullHtml) return resp(400, { error: 'slug, subjectLine, and fullPostHtml are required' });
    const now = new Date().toISOString();
    // Preserve publishedAt if it already exists, else set now
    const existing = await dynamo.send(new GetItemCommand({ TableName: POSTS_TABLE, Key: { slug: { S: uSlug } } }));
    const publishedAt = existing.Item?.publishedAt?.S || now;
    await dynamo.send(new PutItemCommand({
      TableName: POSTS_TABLE,
      Item: {
        slug:         { S: uSlug },
        subjectLine:  { S: uSubject },
        previewText:  { S: uPreview },
        fullPostHtml: { S: uFullHtml },
        imageUrl:     { S: uImg },
        citations:    { S: JSON.stringify(uCites) },
        publishedAt:  { S: publishedAt },
        updatedAt:    { S: now },
      },
    }));
    return resp(200, { updated: true, url: `https://evidencebasedhealth.me/post.html?slug=${encodeURIComponent(uSlug)}` });
  }

  /* DELETE /delete-post â€” admin â€” delete a post by slug */
  if (rawPath.endsWith('/delete-post') && method === 'DELETE') {
    const dSlug = (event.queryStringParameters?.slug || body?.slug || '').trim();
    if (!dSlug) return resp(400, { error: 'slug required' });
    await dynamo.send(new DeleteItemCommand({ TableName: POSTS_TABLE, Key: { slug: { S: dSlug } } }));
    return resp(200, { deleted: true });
  }

  /* POST /send-newsletter â€” admin â€” send generated post to all active subscribers */
  if (rawPath.endsWith('/send-newsletter') && method === 'POST') {
    const { subjectLine, bodyHtml, bodyText, previewText = '', imageUrl = '', testOnly = false, testEmail = '' } = body;
    if (!subjectLine?.trim() || !bodyHtml?.trim())
      return resp(400, { error: 'subjectLine and bodyHtml are required' });

    // Build full branded email HTML
    const fullHtml = (email, unsubToken) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${subjectLine}</title></head>
<body style="margin:0;padding:0;background:#f7f5f0;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5f0;padding:32px 16px">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:10px;overflow:hidden;border:1px solid #e8e5df">
      <!-- Header -->
      <tr><td style="background:#1a5c3a;padding:24px 36px">
        <p style="margin:0;font-family:Georgia,serif;font-size:11px;font-style:italic;color:rgba(255,255,255,0.7);letter-spacing:0.05em">Evidence-Based Health</p>
        <h1 style="margin:8px 0 0;font-family:Georgia,serif;font-size:22px;font-weight:700;color:#ffffff;line-height:1.3">${subjectLine}</h1>
        ${previewText ? `<p style="margin:8px 0 0;font-size:13px;color:rgba(255,255,255,0.8)">${previewText}</p>` : ''}
      </td></tr>
      ${imageUrl ? `<tr><td style="padding:0;line-height:0"><img src="${imageUrl}" alt="" style="width:100%;max-height:320px;object-fit:cover;display:block;border:none"></td></tr>` : ""}
      <!-- Body -->
      <tr><td style="padding:32px 36px;font-size:15px;line-height:1.75;color:#2d3d35">
        ${bodyHtml}
      </td></tr>
      <!-- CTA -->
      <tr><td style="padding:0 36px 32px;text-align:center">
        <a href="https://evidencebasedhealth.me" style="display:inline-block;background:#1a5c3a;color:#ffffff;text-decoration:none;padding:12px 28px;border-radius:6px;font-size:14px;font-weight:600">Read on EvidenceBasedHealth.me â†’</a>
      </td></tr>
      <!-- Footer -->
      <tr><td style="background:#f7f5f0;border-top:1px solid #e8e5df;padding:20px 36px;text-align:center">
        <p style="margin:0;font-size:11px;color:#9aada3;line-height:1.7">
          You're receiving this because you subscribed at evidencebasedhealth.me.<br>
          <a href="https://lvsofp8c9g.execute-api.us-east-1.amazonaws.com/prod/unsubscribe?token=${unsubToken}" style="color:#9aada3">Unsubscribe</a>
          &nbsp;Â·&nbsp; Evidence-Based Health &nbsp;Â·&nbsp; Not medical advice
        </p>
      </td></tr>
    </table>
  </td></tr>
</table></body></html>`;

    if (testOnly) {
      // Send only to testEmail
      const addr = (testEmail || '').trim();
      if (!addr) return resp(400, { error: 'testEmail required for testOnly mode' });
      await ses.send(new SendEmailCommand({
        FromEmailAddress: SES_FROM_EMAIL,
        ReplyToAddresses: [SES_REPLY_TO],
        Destination: { ToAddresses: [addr] },
        Content: { Simple: {
          Subject: { Data: `[TEST] ${subjectLine}`, Charset: 'UTF-8' },
          Body: {
            Text: { Data: bodyText || subjectLine, Charset: 'UTF-8' },
            Html: { Data: fullHtml(addr, 'test-token'), Charset: 'UTF-8' },
          },
        }},
      }));
      return resp(200, { success: true, sent: 1, mode: 'test' });
    }

    // Full send â€” load all active subscribers
    const result = await dynamo.send(new ScanCommand({
      TableName: SUBSCRIBERS_TABLE,
      FilterExpression: '#st = :active',
      ExpressionAttributeNames:  { '#st': 'status' },
      ExpressionAttributeValues: { ':active': { S: 'active' } },
    }));
    const subscribers = result.Items || [];
    if (!subscribers.length) return resp(200, { success: true, sent: 0, message: 'No active subscribers.' });

    let sent = 0, errCount = 0;
    for (const sub of subscribers) {
      try {
        const email     = sub.email?.S;
        const unsubTok  = sub.unsubToken?.S || 'no-token';
        await ses.send(new SendEmailCommand({
          FromEmailAddress: SES_FROM_EMAIL,
          ReplyToAddresses: [SES_REPLY_TO],
          Destination: { ToAddresses: [email] },
          Content: { Simple: {
            Subject: { Data: subjectLine, Charset: 'UTF-8' },
            Body: {
              Text: { Data: bodyText || subjectLine, Charset: 'UTF-8' },
              Html: { Data: fullHtml(email, unsubTok), Charset: 'UTF-8' },
            },
          }},
        }));
        sent++;
        // SES rate-limit guard â€” 14 sends/sec is SES sandbox limit
        if (sent % 10 === 0) await new Promise(r => setTimeout(r, 800));
      } catch { errCount++; }
    }

    return resp(200, { success: true, sent, errors: errCount, total: subscribers.length });
  }

  /* POST /presigned-upload â€” return a presigned S3 PUT URL for direct browser upload */
  if (rawPath.endsWith('/presigned-upload') && method === 'POST') {
    const { fileName, contentType } = body;
    if (!fileName || !contentType) return resp(400, { error: 'fileName and contentType required' });
    // Sanitise file name
    const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const key = `uploads/${Date.now()}_${safeName}`;
    const cmd = new PutObjectCommand({
      Bucket: MEDIA_BUCKET,
      Key: key,
      ContentType: contentType,
    });
    const uploadUrl = await getSignedUrl(s3, cmd, { expiresIn: 300 });
    const fileUrl = `https://${MEDIA_BUCKET}.s3.amazonaws.com/${key}`;
    return resp(200, { uploadUrl, fileUrl });
  }

  /* POST /nl-draft â€” save or update a newsletter draft / scheduled post */
  if (rawPath.endsWith('/nl-draft') && method === 'POST') {
    const draftId = body.draftId || randomUUID();
    const now = new Date().toISOString();
    const item = {
      draftId:         { S: draftId },
      subjectLine:     { S: body.subjectLine    || '(no subject)' },
      bodyHtml:        { S: body.body           || '' },
      fullPostHtml:    { S: body.fullPostHtml   || '' },
      previewText:     { S: body.previewText    || '' },
      socialX:         { S: body.socialX        || '' },
      socialLinkedIn:  { S: body.socialLinkedIn || '' },
      socialInstagram: { S: body.socialInstagram|| '' },
      slug:            { S: body.slug           || '' },
      citations:       { S: JSON.stringify(body.citations || []) },
      imageUrl:        { S: body.imageUrl       || '' },
      status:          { S: body.status         || 'draft' },
      createdAt:       { S: body.createdAt      || now },
      updatedAt:       { S: now },
    };
    if (body.scheduledAt) item.scheduledAt = { S: body.scheduledAt };
    await dynamo.send(new PutItemCommand({ TableName: NL_DRAFTS_TABLE, Item: item }));
    return resp(200, { draftId });
  }

  /* GET /nl-drafts â€” list all newsletter drafts */
  if (rawPath.endsWith('/nl-drafts') && method === 'GET') {
    const res = await dynamo.send(new ScanCommand({ TableName: NL_DRAFTS_TABLE }));
    const items = (res.Items || []).map(i => ({
      draftId:         i.draftId?.S,
      subjectLine:     i.subjectLine?.S,
      bodyHtml:        i.bodyHtml?.S,
      fullPostHtml:    i.fullPostHtml?.S,
      previewText:     i.previewText?.S,
      socialX:         i.socialX?.S,
      socialLinkedIn:  i.socialLinkedIn?.S,
      socialInstagram: i.socialInstagram?.S,
      slug:            i.slug?.S,
      citations:       JSON.parse(i.citations?.S || '[]'),
      status:          i.status?.S,
      createdAt:       i.createdAt?.S,
      scheduledAt:     i.scheduledAt?.S,
      imageUrl:        i.imageUrl?.S,
    })).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return resp(200, items);
  }

  /* DELETE /nl-draft â€” delete a draft */
  if (rawPath.endsWith('/nl-draft') && method === 'DELETE') {
    const { draftId } = body;
    if (!draftId) return resp(400, { error: 'draftId required' });
    await dynamo.send(new DeleteItemCommand({ TableName: NL_DRAFTS_TABLE, Key: { draftId: { S: draftId } } }));
    return resp(200, { deleted: draftId });
  }

  /* POST /nl-autopilot â€” save autopilot configuration */
  if (rawPath.endsWith('/nl-autopilot') && method === 'POST') {
    await dynamo.send(new PutItemCommand({
      TableName: AUTOPILOT_TABLE,
      Item: {
        configId: { S: 'default' },
        topic:    { S: body.topic    || '' },
        pillar:   { S: body.pillar   || '' },
        day:      { S: body.day      || 'Wednesday' },
        time:     { S: body.time     || '09:00' },
        tone:     { S: body.tone     || 'educational, warm, no hype' },
        enabled:  { BOOL: body.enabled !== false },
        updatedAt:{ S: new Date().toISOString() },
      },
    }));
    return resp(200, { saved: true });
  }

  /* GET /nl-autopilot â€” retrieve autopilot configuration */
  if (rawPath.endsWith('/nl-autopilot') && method === 'GET') {
    const res = await dynamo.send(new GetItemCommand({ TableName: AUTOPILOT_TABLE, Key: { configId: { S: 'default' } } }));
    if (!res.Item) return resp(200, {});
    const i = res.Item;
    return resp(200, {
      topic:   i.topic?.S   || '',
      pillar:  i.pillar?.S  || '',
      day:     i.day?.S     || 'Wednesday',
      time:    i.time?.S    || '09:00',
      tone:    i.tone?.S    || 'educational, warm, no hype',
      enabled: i.enabled?.BOOL ?? true,
    });
  }

  /* GET /translations â€” PUBLIC â€” fetch pre-built translation map for a page+lang */
  if (rawPath.endsWith('/translations') && method === 'GET') {
    const qs     = event.queryStringParameters || {};
    const lang   = qs.lang   || '';
    const page   = qs.page   || '';
    if (!lang || !page) return resp(400, { error: 'lang and page required' });
    if (!/^[a-zA-Z]{2,8}(-[a-zA-Z]{2,8})?$/.test(lang)) return resp(400, { error: 'invalid lang' });

    try {
      const item = await dynamo.send(new GetItemCommand({
        TableName: TRANSLATIONS_TABLE,
        Key: { page: { S: page }, lang: { S: lang } },
      }));
      if (!item.Item) return resp(404, { error: 'not found' });
      const map = JSON.parse(item.Item.map.S);
      return resp(200, { map });
    } catch (e) {
      console.error('GET /translations error:', e);
      return resp(500, { error: 'internal error' });
    }
  }

  /* POST /translate â€” PUBLIC â€” translate texts via OpenAI, write-through to DynamoDB */
  if (rawPath.endsWith('/translate') && method === 'POST') {
    const { texts, targetLang, langName, page } = body;

    if (!texts || !Array.isArray(texts) || texts.length === 0)
      return resp(400, { error: 'texts array required' });
    if (!targetLang || typeof targetLang !== 'string' || !/^[a-zA-Z]{2,8}(-[a-zA-Z]{2,8})?$/.test(targetLang))
      return resp(400, { error: 'valid targetLang required' });
    if (texts.length > 60)
      return resp(400, { error: 'max 60 texts per request' });
    const totalChars = texts.reduce((s, t) => s + String(t).length, 0);
    if (totalChars > 20000)
      return resp(400, { error: 'total text too large' });

    if (!OPENAI_API_KEY) return resp(503, { error: 'Translation not available' });

    const cleanTexts = texts.map(t => String(t).trim());
    const targetLabel = langName || targetLang;

    const oaRes = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        temperature: 0.1,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: 'You are a professional medical translator. Return ONLY valid JSON in the format: { "translations": ["...", "..."] }. Preserve any HTML tags exactly as-is. Translate text content accurately and naturally.',
          },
          {
            role: 'user',
            content: `Translate each text from English to ${targetLabel}. Return JSON with a "translations" array in the same order.\n\nTexts:\n${JSON.stringify(cleanTexts)}`,
          },
        ],
      }),
    });

    if (!oaRes.ok) {
      const err = await oaRes.json().catch(() => ({}));
      console.error('OpenAI /translate error:', err);
      return resp(502, { error: 'Translation service unavailable' });
    }

    const oaData = await oaRes.json();
    const content = oaData.choices?.[0]?.message?.content || '{}';
    try {
      const parsed = JSON.parse(content);
      const translations = Array.isArray(parsed) ? parsed
        : Array.isArray(parsed.translations) ? parsed.translations
        : Object.values(parsed).find(v => Array.isArray(v)) || [];
      if (translations.length === 0) throw new Error('Empty translations array');

      // Write-through cache: if page slug provided, merge into DynamoDB
      if (page && typeof page === 'string' && /^[a-z0-9-]+$/.test(page) && TRANSLATIONS_TABLE) {
        try {
          // Load existing map, merge, save back
          const existing = await dynamo.send(new GetItemCommand({
            TableName: TRANSLATIONS_TABLE,
            Key: { page: { S: page }, lang: { S: targetLang } },
          }));
          const existingMap = existing.Item ? JSON.parse(existing.Item.map.S) : {};
          for (let i = 0; i < cleanTexts.length; i++) {
            if (translations[i]) existingMap[cleanTexts[i]] = translations[i];
          }
          await dynamo.send(new UpdateItemCommand({
            TableName: TRANSLATIONS_TABLE,
            Key: { page: { S: page }, lang: { S: targetLang } },
            UpdateExpression: 'SET #m = :m, updatedAt = :u',
            ExpressionAttributeNames:  { '#m': 'map' },
            ExpressionAttributeValues: {
              ':m': { S: JSON.stringify(existingMap) },
              ':u': { S: new Date().toISOString() },
            },
          }));
        } catch (cacheErr) {
          console.error('Translation cache write error:', cacheErr);
          // Non-fatal â€” still return the translations
        }
      }

      return resp(200, { translations });
    } catch (e) {
      console.error('OpenAI /translate parse error:', content, e.message);
      return resp(502, { error: 'Translation format error' });
    }
  }

  /* POST /profile-language â€” AUTH (profile JWT) â€” save language preference */
  if (rawPath.endsWith('/profile-language') && method === 'POST') {
    const auth = verifyProfileJWT(event.headers?.authorization || event.headers?.Authorization);
    if (!auth) return resp(401, { error: 'Authentication required.' });

    const { language } = body;
    if (!language || typeof language !== 'string' || !/^[a-zA-Z]{2,8}(-[a-zA-Z]{2,8})?$/.test(language))
      return resp(400, { error: 'Valid language code required.' });

    await dynamo.send(new UpdateItemCommand({
      TableName: PROFILES_TABLE,
      Key: { email: { S: auth.sub } },
      UpdateExpression: 'SET #lang = :l, updatedAt = :ua',
      ExpressionAttributeNames:  { '#lang': 'language' },
      ExpressionAttributeValues: { ':l': { S: language }, ':ua': { S: new Date().toISOString() } },
    }));

    return resp(200, { success: true });
  }

  /* POST /admin/test-reminder — send a test reminder email+SMS for any email/profile */
  if (rawPath.endsWith('/admin/test-reminder') && method === 'POST') {

    const { email, yob: bodyYob, organs: bodyOrgans = [], riskFlags: bodyRiskFlags = [], phone: bodyPhone } = body;
    if (!email) return resp(400, { error: 'email required.' });

    // Look up existing prevention profile to auto-fill fields
    const profileItem = await dynamo.send(new GetItemCommand({
      TableName: PREVENTION_TABLE, Key: { email: { S: email } },
    })).then(r => r.Item || null).catch(() => null);

    const yob       = bodyYob       || (profileItem?.yearOfBirth?.N ? parseInt(profileItem.yearOfBirth.N, 10) : null);
    const organs    = bodyOrgans.length    ? bodyOrgans    : (profileItem?.organs?.L?.map(o => o.S) || []);
    const riskFlags = bodyRiskFlags.length ? bodyRiskFlags : (profileItem?.riskFlags?.L?.map(r => r.S) || []);
    const phone     = bodyPhone || profileItem?.phone?.S || null;

    if (!yob) return resp(400, { error: 'email and yob required (yob not found in profile).' });

    const SES_FROM_REMINDER = process.env.SES_FROM_EMAIL || 'newsletter@evidencebasedhealth.me';
    const SMS_ORIG_ID = 'pool-7ad57f44d3464b40a2fd4e695b7daf01';
    const SITE = process.env.SITE_ORIGIN || 'https://evidencebasedhealth.me';
    const age  = new Date().getFullYear() - parseInt(yob, 10);

    // Inline reminder logic (mirrors reminderHandler)
    function buildTestReminders(age, organs, riskFlags) {
      const rs = [];
      // Colorectal
      if (organs.includes('colon')) {
        const lynchRisk = riskFlags.includes('lynch-syndrome');
        const highRisk  = !lynchRisk && (riskFlags.includes('crc-family') || riskFlags.includes('crc-polyps'));
        const startAge  = lynchRisk ? 25 : highRisk ? 40 : 45;
        if ((lynchRisk && age >= 20 && age <= 76) || (age >= startAge - 2 && age <= 76)) {
          rs.push({ topic: 'colorectal', emailSubject: 'TEST: colorectal cancer screening reminder — Evidence-Based Health',
            emailBody: '<p><strong>[TEST]</strong> This is a test reminder for colorectal cancer screening. In production, full clinical detail is included.</p>',
            smsBody: '[TEST] Prevention reminder: colorectal cancer screening. evidencebasedhealth.me' });
        }
      }
      // Cervical
      if (organs.includes('cervix') && age >= 21 && age <= 65) {
        rs.push({ topic: 'cervical', emailSubject: 'TEST: cervical cancer screening reminder — Evidence-Based Health',
          emailBody: '<p><strong>[TEST]</strong> This is a test reminder for cervical cancer screening.</p>',
          smsBody: '[TEST] Prevention reminder: cervical cancer screening. evidencebasedhealth.me' });
      }
      // Breast
      if (organs.includes('breast') && age >= 38 && age <= 75) {
        rs.push({ topic: 'breast', emailSubject: 'TEST: breast cancer screening reminder — Evidence-Based Health',
          emailBody: '<p><strong>[TEST]</strong> This is a test reminder for breast cancer (mammography) screening.</p>',
          smsBody: '[TEST] Prevention reminder: breast cancer screening (mammography). evidencebasedhealth.me' });
      }
      // Prostate
      if (organs.includes('prostate') && age >= 40 && age <= 71) {
        rs.push({ topic: 'prostate', emailSubject: 'TEST: prostate cancer screening discussion reminder — Evidence-Based Health',
          emailBody: '<p><strong>[TEST]</strong> This is a test reminder for prostate cancer (PSA) screening discussion.</p>',
          smsBody: '[TEST] Prevention reminder: discuss prostate (PSA) screening with your clinician. evidencebasedhealth.me' });
      }
      // Always include one generic if no organ-specific ones fired
      if (rs.length === 0) {
        rs.push({ topic: 'generic', emailSubject: 'TEST: prevention reminder — Evidence-Based Health',
          emailBody: '<p><strong>[TEST]</strong> This is a generic test reminder. Add organs/riskFlags to see organ-specific reminders.</p>',
          smsBody: '[TEST] Prevention reminder test from evidencebasedhealth.me' });
      }
      return rs;
    }

    function wrapTestEmail(subject, bodyHtml, yob) {
      const age = new Date().getFullYear() - yob;
      return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="font-family:'DM Sans',system-ui,sans-serif;background:#f7f5f0;margin:0;padding:0">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5f0;padding:40px 20px">
<tr><td align="center"><table width="100%" style="max-width:560px;background:#fff;border:1px solid #ede9e1;border-radius:4px;overflow:hidden">
<tr><td style="background:#b45309;height:4px;font-size:0;line-height:0">&nbsp;</td></tr>
<tr><td style="padding:28px 36px 20px">
<p style="font-size:0.72rem;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;color:#b45309;margin:0 0 8px">⚠ TEST EMAIL — NOT SENT TO REAL USER</p>
<h1 style="font-family:Georgia,serif;font-size:1.3rem;color:#0f1a14;margin:0 0 16px;line-height:1.3">${subject.replace(' — Evidence-Based Health','')}</h1>
<div style="font-size:0.93rem;color:#2d3d35;line-height:1.75;margin-bottom:20px">${bodyHtml}</div>
<p style="font-size:0.82rem;color:#888;font-style:italic">Birth year: ${yob} | Age: ~${age} | This email tests the reminder delivery pipeline.</p>
<a href="${SITE}/my-roadmap.html" style="display:inline-block;background:#1a5c3a;color:#fff;padding:10px 20px;border-radius:2px;text-decoration:none;font-size:0.85rem;font-weight:500;margin-top:16px">View my roadmap &rarr;</a>
</td></tr>
<tr><td style="padding:16px 36px;background:#f7f5f0;border-top:1px solid #ede9e1;font-size:0.75rem;color:#9aada3">
Test email — not medical advice — sent by EBH admin test tool
</td></tr>
</table></td></tr></table></body></html>`;
    }

    const reminders = buildTestReminders(age, organs, riskFlags);
    const results = [];

    for (const r of reminders) {
      const result = { topic: r.topic, email: null, sms: null };
      // Send email
      try {
        await ses.send(new SendEmailCommand({
          FromEmailAddress: SES_FROM_REMINDER,
          Destination: { ToAddresses: [email] },
          Content: { Simple: {
            Subject: { Data: r.emailSubject, Charset: 'UTF-8' },
            Body: {
              Html: { Data: wrapTestEmail(r.emailSubject, r.emailBody, parseInt(yob, 10)), Charset: 'UTF-8' },
              Text: { Data: r.emailSubject + '\n\n' + r.smsBody + '\n\nNot medical advice. — ' + SITE, Charset: 'UTF-8' },
            },
          }},
        }));
        result.email = 'sent';
      } catch (err) {
        result.email = 'error: ' + err.message;
      }
      // Send SMS if phone provided
      if (phone) {
        try {
          await smsV2.send(new SendTextMessageCommand({
            DestinationPhoneNumber: phone,
            OriginationIdentity:    SMS_ORIG_ID,
            MessageBody:            r.smsBody.replace(/evidencebasedhealth\.me\s*$/, `evidencebasedhealth.me/my-roadmap.html`),
            MessageType:            'TRANSACTIONAL',
          }));
          result.sms = 'sent';
        } catch (err) {
          result.sms = 'error: ' + err.message;
        }
      } else {
        result.sms = 'skipped (no phone provided)';
      }
      results.push(result);
    }
    return resp(200, { tested: true, email, yob, age, profileFound: !!profileItem, phone: phone || null, reminders: results });
  }

  return resp(404, { error: 'Not found' });
};

