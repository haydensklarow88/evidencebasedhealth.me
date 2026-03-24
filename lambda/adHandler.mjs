import { createHmac, timingSafeEqual } from 'crypto';

const {
  ADMIN_PASSWORD,
  JWT_SECRET,
  FB_ACCESS_TOKEN,
  FB_AD_ACCOUNT_ID,  // e.g. act_123456789
  FB_PAGE_ID,
  SITE_ORIGIN,
} = process.env;

const FB_VER  = 'v20.0';
const FB_BASE = `https://graph.facebook.com/${FB_VER}`;

const CORS = {
  'Access-Control-Allow-Origin':  SITE_ORIGIN || 'https://evidencebasedhealth.me',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
};

/* ── Crypto helpers ──────────────────────────────────────────────── */

/** Timing-safe string comparison via HMAC digest (normalises length) */
function safeEq(a, b) {
  const h = (s) => createHmac('sha256', 'ebh_cmp').update(String(s)).digest();
  return timingSafeEqual(h(a), h(b));
}

function signJWT(payload) {
  const enc = (x) => Buffer.from(JSON.stringify(x)).toString('base64url');
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
    const sBuf = Buffer.from(sig,      'base64url');
    const eBuf = Buffer.from(expected, 'base64url');
    if (sBuf.length !== eBuf.length || !timingSafeEqual(sBuf, eBuf)) return null;
    const payload = JSON.parse(Buffer.from(bdy, 'base64url').toString());
    return payload.exp >= Math.floor(Date.now() / 1000) ? payload : null;
  } catch { return null; }
}

/* ── Response helper ─────────────────────────────────────────────── */
function resp(status, body, extra = {}) {
  return {
    statusCode: status,
    headers: { ...CORS, 'Content-Type': 'application/json', ...extra },
    body: JSON.stringify(body),
  };
}

/* ── Meta Graph API helper ───────────────────────────────────────── */
async function fb(method, path, data) {
  const url  = new URL(`${FB_BASE}${path}`);
  const opts = { method, headers: {} };

  if (method === 'GET') {
    url.searchParams.set('access_token', FB_ACCESS_TOKEN);
    if (data) for (const [k, v] of Object.entries(data)) url.searchParams.set(k, String(v));
  } else {
    url.searchParams.set('access_token', FB_ACCESS_TOKEN);
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(data);
  }

  const res  = await fetch(url.toString(), opts);
  const json = await res.json();
  if (!res.ok || json.error) throw new Error(json.error?.message || `FB API error ${res.status}`);
  return json;
}

/* ── Lambda handler ──────────────────────────────────────────────── */
export const handler = async (event) => {
  const method  = event.requestContext?.http?.method || '';
  const rawPath = event.rawPath || '';

  if (method === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch {}

  /* ───────────────────────────────────── POST /admin-auth */
  if (rawPath.endsWith('/admin-auth') && method === 'POST') {
    if (!body.password || !safeEq(body.password, ADMIN_PASSWORD)) {
      return resp(401, { error: 'Invalid password' });
    }
    const token = signJWT({ sub: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 });
    return resp(200, { token });
  }

  /* ── Auth guard (all routes below require valid JWT) ───── */
  const bearer = (event.headers?.authorization || event.headers?.Authorization || '')
    .replace(/^Bearer\s+/i, '');
  if (!verifyJWT(bearer)) return resp(401, { error: 'Unauthorized' });

  /* ─────────────────────────────── GET /meta-interests?q= */
  if (rawPath.endsWith('/meta-interests') && method === 'GET') {
    const q = (event.queryStringParameters?.q || '').trim();
    if (!q) return resp(200, []);
    const results = await fb('GET', '/search', { type: 'adinterest', q, limit: 10 });
    return resp(200, results.data || []);
  }

  /* ─────────────────────────────── POST /create-meta-ad  */
  if (rawPath.endsWith('/create-meta-ad') && method === 'POST') {
    const {
      campaignName,
      objective    = 'OUTCOME_TRAFFIC',
      dailyBudget,
      ageMin       = 35,
      ageMax       = 65,
      countries    = ['US'],
      interests    = [],
      primaryText,
      headline,
      description,
      destinationUrl = 'https://evidencebasedhealth.me',
      imageUrl,
    } = body;

    if (!campaignName?.trim() || !dailyBudget || !primaryText?.trim() || !headline?.trim()) {
      return resp(400, { error: 'campaignName, dailyBudget, primaryText, and headline are required' });
    }
    if (!FB_ACCESS_TOKEN || FB_ACCESS_TOKEN === 'PLACEHOLDER') {
      return resp(503, { error: 'Meta API credentials not configured. Set FB_ACCESS_TOKEN, FB_AD_ACCOUNT_ID, and FB_PAGE_ID in Lambda environment variables.' });
    }

    // 1. Campaign
    const campaign = await fb('POST', `/${FB_AD_ACCOUNT_ID}/campaigns`, {
      name:                   campaignName.trim(),
      objective,
      status:                 'PAUSED',
      special_ad_categories:  [],
    });

    // 2. Ad Set
    const targeting = {
      age_min:       Number(ageMin),
      age_max:       Number(ageMax),
      geo_locations: { countries },
      ...(interests.length > 0 && { flexible_spec: [{ interests }] }),
    };
    const adset = await fb('POST', `/${FB_AD_ACCOUNT_ID}/adsets`, {
      name:              `${campaignName} — Ad Set`,
      campaign_id:       campaign.id,
      daily_budget:      Math.round(Number(dailyBudget) * 100),  // cents
      billing_event:     'IMPRESSIONS',
      optimization_goal: objective === 'OUTCOME_LEADS' ? 'LEAD_GENERATION' : 'LINK_CLICKS',
      bid_strategy:      'LOWEST_COST_WITHOUT_CAP',
      targeting,
      status:            'PAUSED',
      destination_type:  'WEBSITE',
    });

    // 3. Ad Creative
    const creative = await fb('POST', `/${FB_AD_ACCOUNT_ID}/adcreatives`, {
      name: `${campaignName} — Creative`,
      object_story_spec: {
        page_id:   FB_PAGE_ID,
        link_data: {
          link:           destinationUrl,
          message:        primaryText.trim(),
          name:           headline.trim(),
          call_to_action: { type: 'SIGN_UP', value: { link: destinationUrl } },
          ...(description?.trim() && { description: description.trim() }),
          ...(imageUrl?.trim()    && { picture:     imageUrl.trim() }),
        },
      },
    });

    // 4. Ad
    const ad = await fb('POST', `/${FB_AD_ACCOUNT_ID}/ads`, {
      name:     `${campaignName} — Ad`,
      adset_id: adset.id,
      creative: { creative_id: creative.id },
      status:   'PAUSED',
    });

    return resp(200, {
      success:     true,
      campaign_id: campaign.id,
      adset_id:    adset.id,
      creative_id: creative.id,
      ad_id:       ad.id,
      review_url:  `https://www.facebook.com/adsmanager/manage/campaigns?act=${FB_AD_ACCOUNT_ID.replace('act_', '')}`,
    });
  }

  /* ──────────────────────── POST /generate-google-brief  */
  if (rawPath.endsWith('/generate-google-brief') && method === 'POST') {
    const {
      campaignName = 'EBH Newsletter',
      dailyBudget,
      keywords     = [],
      headlines    = [],
      descriptions = [],
      finalUrl     = 'https://evidencebasedhealth.me',
    } = body;

    if (!campaignName || !dailyBudget || headlines.length < 3 || descriptions.length < 2) {
      return resp(400, { error: 'Provide campaignName, dailyBudget, at least 3 headlines, and 2 descriptions' });
    }

    return resp(200, {
      brief: {
        platform:    'Google Ads',
        generatedAt: new Date().toISOString(),
        campaign: {
          name:             campaignName,
          type:             'Search',
          network:          'Google Search Network',
          dailyBudget:      `$${dailyBudget}/day`,
          biddingStrategy:  'Maximize Conversions',
        },
        adGroup: {
          name:     `${campaignName} – Ad Group 1`,
          keywords: keywords.map(k => ({ keyword: k, matchType: 'Broad match' })),
        },
        responsiveSearchAd: {
          finalUrl,
          displayPath:  'evidencebasedhealth.me/brief',
          headlines:    headlines.slice(0, 15),
          descriptions: descriptions.slice(0, 4),
        },
        setupInstructions: [
          'Sign in to ads.google.com',
          'Click + New Campaign → Goal: Leads → Type: Search',
          `Set daily budget: $${dailyBudget}`,
          'Bidding: Maximize Conversions',
          'Create Ad Group and paste keywords (one per line)',
          'Create Responsive Search Ad and paste headlines + descriptions',
          `Set Final URL: ${finalUrl}`,
        ],
      },
    });
  }

  return resp(404, { error: 'Not found' });
};
