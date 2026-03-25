import { createHmac, timingSafeEqual, randomUUID } from 'crypto';
import {
  DynamoDBClient,
  PutItemCommand,
  ScanCommand,
  UpdateItemCommand,
  DeleteItemCommand,
} from '@aws-sdk/client-dynamodb';

const {
  ADMIN_PASSWORD, JWT_SECRET,
  FB_ACCESS_TOKEN, FB_AD_ACCOUNT_ID, FB_PAGE_ID,
  SITE_ORIGIN, CLIENTS_TABLE = 'AdClients',
} = process.env;

const FB_VER  = 'v20.0';
const FB_BASE = `https://graph.facebook.com/${FB_VER}`;
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
    clientId:  item.clientId.S,
    name:      item.name?.S  || '',
    color:     item.color?.S || '#1a5c3a',
    notes:     item.notes?.S || '',
    platforms: JSON.parse(item.platformsJson?.S || '{}'),
    createdAt: item.createdAt?.S || '',
    updatedAt: item.updatedAt?.S || '',
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

export const handler = async (event) => {
  const method  = event.requestContext?.http?.method || '';
  const rawPath = event.rawPath || '';
  if (method === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch {}

  /* POST /admin-auth */
  if (rawPath.endsWith('/admin-auth') && method === 'POST') {
    if (!body.password || !safeEq(body.password, ADMIN_PASSWORD))
      return resp(401, { error: 'Invalid password' });
    const token = signJWT({ sub: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 });
    return resp(200, { token });
  }

  /* Auth guard */
  const bearer = (event.headers?.authorization || event.headers?.Authorization || '').replace(/^Bearer\s+/i, '');
  if (!verifyJWT(bearer)) return resp(401, { error: 'Unauthorized' });

  /* GET /clients */
  if (rawPath.endsWith('/clients') && method === 'GET') {
    const result  = await dynamo.send(new ScanCommand({ TableName: CLIENTS_TABLE }));
    const clients = (result.Items || []).map(fromDynamo);
    clients.sort((a, b) => a.name.localeCompare(b.name));
    return resp(200, clients);
  }

  /* POST /clients */
  if (rawPath.endsWith('/clients') && method === 'POST') {
    const { name, color, notes, platforms } = body;
    if (!name?.trim()) return resp(400, { error: 'name is required' });
    const clientId = randomUUID();
    const now = new Date().toISOString();
    await dynamo.send(new PutItemCommand({
      TableName: CLIENTS_TABLE,
      Item: {
        clientId:      { S: clientId },
        name:          { S: name.trim() },
        color:         { S: color || '#1a5c3a' },
        notes:         { S: notes || '' },
        platformsJson: { S: JSON.stringify(platforms || {}) },
        createdAt:     { S: now },
        updatedAt:     { S: now },
      },
    }));
    return resp(200, { clientId, name: name.trim(), color: color || '#1a5c3a', notes: notes || '', platforms: platforms || {}, createdAt: now });
  }

  /* PUT /clients */
  if (rawPath.endsWith('/clients') && method === 'PUT') {
    const { clientId, name, color, notes, platforms } = body;
    if (!clientId) return resp(400, { error: 'clientId is required' });
    const now = new Date().toISOString();
    await dynamo.send(new UpdateItemCommand({
      TableName: CLIENTS_TABLE,
      Key: { clientId: { S: clientId } },
      UpdateExpression: 'SET #n = :name, color = :color, notes = :notes, platformsJson = :pj, updatedAt = :ua',
      ExpressionAttributeNames: { '#n': 'name' },
      ExpressionAttributeValues: {
        ':name':  { S: name?.trim() || '' },
        ':color': { S: color || '#1a5c3a' },
        ':notes': { S: notes || '' },
        ':pj':    { S: JSON.stringify(platforms || {}) },
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

  /* GET /meta-interests */
  if (rawPath.endsWith('/meta-interests') && method === 'GET') {
    const q        = (event.queryStringParameters?.q || '').trim();
    const clientId = event.queryStringParameters?.clientId;
    let fbToken = FB_ACCESS_TOKEN;
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

    let fbToken = FB_ACCESS_TOKEN;
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
      name:              `${campaignName} — Ad Set`,
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
      name: `${campaignName} — Creative`,
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
      name: `${campaignName} — Ad`, adset_id: adset.id,
      creative: { creative_id: creative.id }, status: 'PAUSED',
    }, fbToken);

    return resp(200, {
      success: true, campaign_id: campaign.id, adset_id: adset.id,
      creative_id: creative.id, ad_id: ad.id,
      review_url: `https://www.facebook.com/adsmanager/manage/campaigns?act=${actId.replace('act_', '')}`,
    });
  }

  /* POST /generate-google-brief */
  if (rawPath.endsWith('/generate-google-brief') && method === 'POST') {
    const { campaignName = 'Newsletter', dailyBudget, keywords = [], headlines = [], descriptions = [], finalUrl = 'https://evidencebasedhealth.me', clientId } = body;

    if (!campaignName || !dailyBudget || headlines.length < 3 || descriptions.length < 2)
      return resp(400, { error: 'Provide campaignName, dailyBudget, at least 3 headlines, and 2 descriptions' });

    let clientName = null;
    if (clientId) {
      const client = await getClient(clientId);
      clientName = client?.name;
    }

    let displayPath;
    try { displayPath = new URL(finalUrl).hostname; } catch { displayPath = finalUrl; }

    return resp(200, {
      brief: {
        platform:    'Google Ads',
        generatedAt: new Date().toISOString(),
        ...(clientName && { client: clientName }),
        campaign: { name: campaignName, type: 'Search', network: 'Google Search Network', dailyBudget: `$${dailyBudget}/day`, biddingStrategy: 'Maximize Conversions' },
        adGroup:  { name: `${campaignName} – Ad Group 1`, keywords: keywords.map(k => ({ keyword: k, matchType: 'Broad match' })) },
        responsiveSearchAd: { finalUrl, displayPath, headlines: headlines.slice(0, 15), descriptions: descriptions.slice(0, 4) },
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
