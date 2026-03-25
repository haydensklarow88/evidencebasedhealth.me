// lambda/subscribeHandler.mjs
//
// AWS Lambda handler for POST /subscribe
//
// Runtime: Node.js 18.x or 20.x
// NOTE: @aws-sdk/client-pinpoint-sms-voice-v2 is NOT bundled in the Lambda runtime.
//       Deploy with a package.json (see lambda/package.json) and run:
//         cd lambda && npm install && zip -r function.zip .
//       Then upload the zip to Lambda, or let Amplify's function build step do it.
//
// Required environment variables:
//   DYNAMODB_TABLE       — DynamoDB table name (partition key: email, type String)
//   SES_FROM             — verified SES sender, e.g. "info@evidencebasedhealth.me"
//   SITE_ORIGIN          — your domain, e.g. "https://evidencebasedhealth.me"
//   SMS_ENABLED          — set to "true" to send welcome SMS (default: false)
//   SMS_ORIGINATION_ID   — your SNS/Pinpoint phone number ID
//                          e.g. phone-aa451571172f48d2b48072b3b0a0d5b2
//
// IAM permissions needed on the Lambda execution role:
//   dynamodb:PutItem          on the Subscribers table
//   ses:SendEmail             with Source = SES_FROM
//   sms-voice:SendTextMessage (only if SMS_ENABLED=true)
//     Resource: arn:aws:sms-voice:*:*:phone-number/phone-aa451571172f48d2b48072b3b0a0d5b2

import { DynamoDBClient, PutItemCommand }                          from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand }                             from '@aws-sdk/client-ses';
import { PinpointSMSVoiceV2Client, SendTextMessageCommand }        from '@aws-sdk/client-pinpoint-sms-voice-v2';
import { randomUUID }                                              from 'crypto';

const db     = new DynamoDBClient({});
const ses    = new SESClient({});
const smsV2  = new PinpointSMSVoiceV2Client({});

const TABLE          = process.env.DYNAMODB_TABLE     || 'Subscribers';
const FROM           = process.env.SES_FROM           || 'info@evidencebasedhealth.me';
const ORIGIN         = process.env.SITE_ORIGIN        || 'https://evidencebasedhealth.me';
const SMS_ORIGINATION_ID = process.env.SMS_ORIGINATION_ID || 'phone-aa451571172f48d2b48072b3b0a0d5b2';
const SMS_ENABLED = process.env.SMS_ENABLED    === 'true';

// Strict-ish email validation (no regex injection risk — purely format check)
const EMAIL_RE = /^[^\s@"'<>]+@[^\s@"'<>]+\.[^\s@"'<>]{2,}$/;
// E.164 phone format required for SNS
const PHONE_RE = /^\+[1-9]\d{7,14}$/;

const CORS = {
  'Access-Control-Allow-Origin':  ORIGIN,
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Content-Type':                 'application/json',
};

const respond = (status, body) => ({
  statusCode: status,
  headers: CORS,
  body: JSON.stringify(body),
});

export const handler = async (event) => {

  // OPTIONS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: CORS, body: '' };
  }

  // Parse body safely
  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return respond(400, { error: 'Invalid request body' });
  }

  const {
    email             = '',
    phone             = '',
    smsConsent        = false,
    remarketingConsent = false,
    sourcePath        = '/',
    userAgent         = '',
  } = body;

  // ── Input validation ──────────────────────────────────────────────────────
  const cleanEmail = String(email).trim().toLowerCase();
  if (!cleanEmail || !EMAIL_RE.test(cleanEmail)) {
    return respond(400, { error: 'A valid email address is required' });
  }

  const cleanPhone = String(phone).trim();
  if (smsConsent && cleanPhone && !PHONE_RE.test(cleanPhone)) {
    return respond(400, { error: 'Phone number must be in E.164 format (e.g. +12125551234)' });
  }

  // Capture IP (API Gateway v1 format; v2 uses event.requestContext.http.sourceIp)
  const ip = event.requestContext?.identity?.sourceIp
          || event.requestContext?.http?.sourceIp
          || (event.headers?.['x-forwarded-for']?.split(',')[0]?.trim())
          || 'unknown';

  const id  = randomUUID();
  const now = new Date().toISOString();

  // ── Write subscriber to DynamoDB ──────────────────────────────────────────
  const item = {
    email:              { S: cleanEmail },
    id:                 { S: id },
    emailConsent:       { BOOL: true },
    smsConsent:         { BOOL: Boolean(smsConsent) },
    remarketingConsent: { BOOL: Boolean(remarketingConsent) },
    sourcePath:         { S: String(sourcePath).slice(0, 256) },
    userAgent:          { S: String(userAgent).slice(0, 512) },
    ipAddress:          { S: ip },
    createdAt:          { S: now },
    updatedAt:          { S: now },
  };

  if (smsConsent && cleanPhone) {
    item.phone = { S: cleanPhone };
  }

  try {
    await db.send(new PutItemCommand({
      TableName: TABLE,
      Item: item,
      // Prevent duplicate subscriptions (email is the partition key)
      ConditionExpression: 'attribute_not_exists(email)',
    }));
  } catch (err) {
    if (err.name === 'ConditionalCheckFailedException') {
      // Already subscribed — return 200 so the frontend redirects normally
      return respond(200, { message: 'Already subscribed' });
    }
    console.error('DynamoDB PutItem failed:', err);
    return respond(500, { error: 'Could not save subscription. Please try again.' });
  }

  // ── Send welcome email via SES ────────────────────────────────────────────
  const unsubUrl = `${ORIGIN}/unsubscribe?email=${encodeURIComponent(cleanEmail)}`;

  const textBody = [
    'Thanks for subscribing to Evidence-Based Health.',
    '',
    "Here's what to expect each week:",
    '  • 2–3 evidence-based insights on hormones, fitness, and metabolic health',
    '  • 1 small experiment worth trying this week',
    '  • 1 conversation starter for the people you care about',
    '',
    "I'll be in your inbox soon.",
    '',
    '— The Evidence-Based Health team',
    '',
    '─────────────────────────────────────────────',
    'Educational content only. Not medical advice.',
    `To unsubscribe: ${unsubUrl}`,
    `${ORIGIN}  |  ${FROM}`,
  ].join('\n');

  const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="background:#f7f5f0;font-family:'Helvetica Neue',Arial,sans-serif;margin:0;padding:40px 20px">
  <div style="max-width:540px;margin:0 auto;background:#ffffff;border:1px solid #ede9e1;border-radius:4px;overflow:hidden">
    <div style="background:linear-gradient(90deg,#1a5c3a,#2d7a52);height:4px"></div>
    <div style="padding:40px">
      <h1 style="font-family:Georgia,serif;font-size:1.4rem;color:#0f1a14;margin:0 0 16px;line-height:1.25">Welcome to the weekly brief.</h1>
      <p style="color:#2d3d35;line-height:1.75;margin:0 0 16px;font-size:0.97rem">Thanks for subscribing to <strong>Evidence-Based Health</strong>. You&rsquo;ll get one short email a week &mdash; no agenda, no supplements to push.</p>
      <p style="color:#2d3d35;line-height:1.75;margin:0 0 8px;font-size:0.95rem"><strong>Each week:</strong></p>
      <ul style="color:#2d3d35;line-height:1.9;padding-left:20px;margin:0 0 24px;font-size:0.93rem">
        <li>2&ndash;3 evidence-based insights on hormones, fitness &amp; metabolic health</li>
        <li>1 small experiment worth trying this week</li>
        <li>1 conversation starter for the people you care about</li>
      </ul>
      <p style="color:#2d3d35;line-height:1.75;margin:0;font-size:0.97rem">Talk soon,<br><strong>The Evidence-Based Health team</strong></p>
    </div>
    <div style="background:#f7f5f0;border-top:1px solid #ede9e1;padding:20px 40px;font-size:0.73rem;color:#9aada3;line-height:1.65">
      Educational content only. Not medical advice. &nbsp;<a href="${ORIGIN}/disclaimer.html" style="color:#5c6e65;text-decoration:none">Disclaimer</a><br>
      <a href="${ORIGIN}/privacy.html" style="color:#5c6e65;text-decoration:none">Privacy Policy</a> &nbsp;&middot;&nbsp;
      <a href="${unsubUrl}" style="color:#5c6e65;text-decoration:none">Unsubscribe</a>
    </div>
  </div>
</body>
</html>`;

  try {
    await ses.send(new SendEmailCommand({
      Destination: { ToAddresses: [cleanEmail] },
      Source: FROM,
      Message: {
        Subject: { Data: 'Welcome — your weekly evidence-based brief starts here' },
        Body: {
          Text: { Data: textBody },
          Html: { Data: htmlBody },
        },
      },
    }));
  } catch (err) {
    // Non-fatal: subscriber is saved in DB, just log the SES failure
    console.error('SES SendEmail failed:', err);
  }

  // ── Send welcome SMS via Pinpoint SMS Voice V2 (opt-in only) ───────────────
  // Uses the origination phone number ID (phone-xxx format) directly.
  if (SMS_ENABLED && smsConsent && cleanPhone) {
    try {
      await smsV2.send(new SendTextMessageCommand({
        DestinationPhoneNumber: cleanPhone,
        OriginationIdentity:    SMS_ORIGINATION_ID,
        MessageBody:            'You\'re subscribed to Evidence-Based Health. Occasional texts only. Reply STOP to opt out.',
        MessageType:            'TRANSACTIONAL',
      }));
    } catch (err) {
      // Non-fatal
      console.error('Pinpoint SMS SendTextMessage failed:', err);
    }
  }

  return respond(200, { message: 'Subscribed successfully', id });
};
