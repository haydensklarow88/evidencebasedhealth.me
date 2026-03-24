// lambda/preventionHandler.mjs
//
// POST /prevention-profile
//
// Stores a prevention profile in PreventionProfiles DynamoDB table,
// sends a welcome email via SES, and optionally sends a welcome SMS.
//
// Required env vars (same Lambda execution role as subscribeHandler):
//   PREVENTION_TABLE     — DynamoDB table name (default: PreventionProfiles)
//   SES_FROM             — verified SES sender (hello@evidencebasedhealth.me)
//   SITE_ORIGIN          — https://evidencebasedhealth.me
//   SMS_ENABLED          — "true" to send SMS
//   SMS_ORIGINATION_ID   — phone-aa451571172f48d2b48072b3b0a0d5b2
//
// IAM permissions needed (same role — add to existing policy):
//   dynamodb:PutItem      on PreventionProfiles
//   ses:SendEmail         (already granted)
//   sms-voice:SendTextMessage (already granted)

import { DynamoDBClient, PutItemCommand }                          from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand }                             from '@aws-sdk/client-ses';
import { PinpointSMSVoiceV2Client, SendTextMessageCommand }        from '@aws-sdk/client-pinpoint-sms-voice-v2';

const db    = new DynamoDBClient({});
const ses   = new SESClient({});
const smsV2 = new PinpointSMSVoiceV2Client({});

const TABLE          = process.env.PREVENTION_TABLE     || 'PreventionProfiles';
const FROM           = process.env.SES_FROM             || 'hello@evidencebasedhealth.me';
const ORIGIN         = process.env.SITE_ORIGIN          || 'https://evidencebasedhealth.me';
const SMS_ORIGINATION_ID = process.env.SMS_ORIGINATION_ID || 'phone-aa451571172f48d2b48072b3b0a0d5b2';
const SMS_ENABLED    = process.env.SMS_ENABLED === 'true';

const EMAIL_RE = /^[^\s@"'<>]+@[^\s@"'<>]+\.[^\s@"'<>]{2,}$/;
const PHONE_RE = /^\+[1-9]\d{7,14}$/;

const CORS = {
  'Access-Control-Allow-Origin':  ORIGIN,
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Content-Type':                 'application/json',
};

export async function handler(event) {
  if (event.requestContext?.http?.method === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const {
    email,
    phone,
    yearOfBirth,
    sexAtBirth,
    organs        = [],
    riskFlags     = [],
    emailConsent  = false,
    smsConsent    = false,
    remarketingConsent = false,
    sourcePath    = '/prevention-roadmap',
    userAgent     = '',
  } = body;

  // ── Validation ──────────────────────────────────────────────────────────
  if (!email || !EMAIL_RE.test(email)) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Invalid email' }) };
  }
  if (!emailConsent) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Email consent required' }) };
  }
  const yob = parseInt(yearOfBirth, 10);
  if (isNaN(yob) || yob < 1920 || yob > new Date().getFullYear() - 18) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Invalid year of birth' }) };
  }
  const cleanPhone = phone && PHONE_RE.test(phone.replace(/\s/g, '')) ? phone.replace(/\s/g, '') : null;

  const now = new Date().toISOString();
  const ip  = event.requestContext?.http?.sourceIp || 'unknown';

  // ── DynamoDB upsert ──────────────────────────────────────────────────────
  await db.send(new PutItemCommand({
    TableName: TABLE,
    Item: {
      email:               { S: email.toLowerCase() },
      phone:               cleanPhone ? { S: cleanPhone } : { NULL: true },
      yearOfBirth:         { N: String(yob) },
      sexAtBirth:          { S: sexAtBirth || 'unknown' },
      organs:              { L: organs.map(o => ({ S: o })) },
      riskFlags:           { L: riskFlags.map(r => ({ S: r })) },
      emailConsent:        { BOOL: emailConsent },
      smsConsent:          { BOOL: !!(smsConsent && cleanPhone) },
      remarketingConsent:  { BOOL: !!remarketingConsent },
      sourcePath:          { S: sourcePath },
      ipAddress:           { S: ip },
      userAgent:           { S: userAgent.slice(0, 500) },
      createdAt:           { S: now },
      updatedAt:           { S: now },
    },
    // Allow upsert — overwrites if re-submitting same email
  }));

  // ── Welcome email ────────────────────────────────────────────────────────
  const organList = organs.length
    ? organs.map(o => o.charAt(0).toUpperCase() + o.slice(1)).join(', ')
    : 'Not specified';

  const emailHtml = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:'DM Sans',system-ui,sans-serif;background:#f7f5f0;margin:0;padding:0">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5f0;padding:40px 20px">
  <tr><td align="center">
    <table width="100%" style="max-width:560px;background:#fff;border:1px solid #ede9e1;border-radius:4px;overflow:hidden">
      <tr><td style="background:linear-gradient(90deg,#1a5c3a,#2d7a52);height:4px;font-size:0;line-height:0">&nbsp;</td></tr>
      <tr><td style="padding:36px 40px 28px">
        <p style="font-size:0.72rem;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;color:#2d7a52;margin:0 0 12px">Prevention Roadmap</p>
        <h1 style="font-family:Georgia,serif;font-size:1.5rem;color:#0f1a14;margin:0 0 16px;line-height:1.3">Your prevention profile is saved.</h1>
        <p style="font-size:0.97rem;color:#2d3d35;line-height:1.75;margin:0 0 20px">
          We&rsquo;ll send you a reminder when you&rsquo;re approaching a key screening age based on your profile &mdash; no spam, just timely nudges.
        </p>
        <table style="background:#e8f2ec;border:1px solid #c2d9cb;border-radius:3px;width:100%;margin-bottom:24px">
          <tr><td style="padding:16px 20px;font-size:0.88rem;color:#2d3d35;line-height:1.7">
            <strong style="color:#0f1a14">Your profile summary:</strong><br>
            Birth year: ${yob} &nbsp;&bull;&nbsp; Anatomy: ${organList}
            ${riskFlags.length ? `<br>Risk flags noted: ${riskFlags.join(', ')}` : ''}
          </td></tr>
        </table>
        <p style="font-size:0.88rem;color:#2d3d35;line-height:1.75;margin:0 0 20px">
          In the meantime, check out the weekly brief for evidence-based content on hormones, strength, and metabolic health.
        </p>
        <a href="${ORIGIN}" style="display:inline-block;background:#1a5c3a;color:#fff;padding:12px 24px;border-radius:2px;text-decoration:none;font-size:0.85rem;font-weight:500;letter-spacing:0.05em">Visit the site &rarr;</a>
      </td></tr>
      <tr><td style="padding:20px 40px;background:#f7f5f0;border-top:1px solid #ede9e1;font-size:0.75rem;color:#9aada3;line-height:1.6">
        Educational content only. Not medical advice. To update or delete your prevention profile, reply to this email or contact <a href="mailto:hello@evidencebasedhealth.me" style="color:#5c6e65">hello@evidencebasedhealth.me</a>.
        <br>To stop reminder emails, reply STOP or unsubscribe via any email we send.
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;

  const emailText = `Prevention Roadmap — Evidence-Based Health\n\nYour prevention profile is saved.\n\nBirth year: ${yob} | Anatomy: ${organList}${riskFlags.length ? ` | Risk flags: ${riskFlags.join(', ')}` : ''}\n\nWe'll send a reminder when you're approaching a key screening age.\n\nVisit: ${ORIGIN}\n\nTo delete your profile, reply to this email. To stop reminders, reply STOP.\nNot medical advice. Educational content only.`;

  try {
    await ses.send(new SendEmailCommand({
      Source:      FROM,
      Destination: { ToAddresses: [email] },
      Message: {
        Subject: { Data: 'Your prevention profile is saved — Evidence-Based Health', Charset: 'UTF-8' },
        Body: {
          Html: { Data: emailHtml, Charset: 'UTF-8' },
          Text: { Data: emailText, Charset: 'UTF-8' },
        },
      },
    }));
  } catch (err) {
    console.error('SES error:', err);
  }

  // ── Optional welcome SMS ─────────────────────────────────────────────────
  if (SMS_ENABLED && smsConsent && cleanPhone) {
    try {
      await smsV2.send(new SendTextMessageCommand({
        DestinationPhoneNumber: cleanPhone,
        OriginationIdentity:    SMS_ORIGINATION_ID,
        MessageBody:            `Prevention reminder set — ${ORIGIN}. We'll message when a screening is coming up for you. Reply STOP to opt out. Not medical advice.`,
        MessageType:            'TRANSACTIONAL',
      }));
    } catch (err) {
      console.error('SMS error:', err);
    }
  }

  return {
    statusCode: 200,
    headers: CORS,
    body: JSON.stringify({ ok: true }),
  };
}
