// lambda/reminderHandler.mjs
//
// EventBridge-triggered Lambda — runs on a schedule (e.g., daily at 8am UTC)
// Scans PreventionProfiles and sends age-appropriate screening reminders.
//
// Required env vars:
//   PREVENTION_TABLE     — PreventionProfiles
//   SES_FROM             — info@evidencebasedhealth.me
//   SITE_ORIGIN          — https://evidencebasedhealth.me
//   SMS_ENABLED          — "true"
//   SMS_ORIGINATION_ID   — phone-aa451571172f48d2b48072b3b0a0d5b2
//
// IAM permissions needed on execution role:
//   dynamodb:Scan         on PreventionProfiles
//   dynamodb:UpdateItem   on PreventionProfiles
//   ses:SendEmail
//   sms-voice:SendTextMessage

import { DynamoDBClient, ScanCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand }                   from '@aws-sdk/client-ses';
import { PinpointSMSVoiceV2Client, SendTextMessageCommand } from '@aws-sdk/client-pinpoint-sms-voice-v2';

const db    = new DynamoDBClient({});
const ses   = new SESClient({});
const smsV2 = new PinpointSMSVoiceV2Client({});

const TABLE              = process.env.PREVENTION_TABLE     || 'PreventionProfiles';
const FROM               = process.env.SES_FROM             || 'info@evidencebasedhealth.me';
const ORIGIN             = process.env.SITE_ORIGIN          || 'https://evidencebasedhealth.me';
const SMS_ORIGINATION_ID = process.env.SMS_ORIGINATION_ID   || 'pool-7ad57f44d3464b40a2fd4e695b7daf01';
const SMS_ENABLED        = process.env.SMS_ENABLED === 'true';

// Minimum months between reminders per topic (avoid repeat nagging)
const REMINDER_INTERVAL_MONTHS = 12;

function monthsAgo(isoString) {
  if (!isoString) return Infinity;
  return (Date.now() - new Date(isoString).getTime()) / (1000 * 60 * 60 * 24 * 30.4);
}

// ── Reminder rule definitions ─────────────────────────────────────────────
// Each rule: { topic, organ, ageMin, ageMax, lastReminderAttr, emailSubject, emailBody, smsBody }
function buildReminders(age, organs, riskFlags) {
  const reminders = [];

  // COLORECTAL
  // Sources: USPSTF 2021 Grade B — average-risk start 45, continue through 75 (Grade C 76–85)
  //          ACS 2023 — high-risk (family Hx/prior polyps): start at 40
  //          ACG 2021 / NCCN — Lynch syndrome: colonoscopy every 1–2 yr starting age 20–25
  if (organs.includes('colon')) {
    const lynchRisk  = riskFlags.includes('lynch-syndrome');
    const highRisk   = !lynchRisk && (riskFlags.includes('crc-family') || riskFlags.includes('crc-polyps'));
    const startAge   = lynchRisk ? 25 : highRisk ? 40 : 45;

    if (lynchRisk && age >= 20 && age <= 76) {
      // Lynch — send every 12 months regardless of when they last heard from us (colonoscopy is annual/biennial)
      reminders.push({
        topic:             'colorectal',
        lastReminderAttr:  'lastColorectalReminder',
        emailSubject:      'Reminder: colonoscopy (Lynch syndrome) — Evidence-Based Health',
        emailBody: `<p>With Lynch syndrome, guidelines (ACG, NCCN) recommend a <strong>colonoscopy every 1–2 years</strong> starting at age 20–25 — much earlier and more frequently than average-risk protocols. Stool-based tests (FIT, Cologuard) are not adequate substitutes.</p>
          <p><strong>Questions to ask your clinician:</strong></p>
          <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
            <li>Am I currently on an annual or biennial colonoscopy schedule?</li>
            <li>Which Lynch gene variant do I carry, and does that affect my surveillance interval?</li>
            <li>Should my first-degree relatives be offered Lynch syndrome testing?</li>
          </ul>`,
        smsBody: `Lynch syndrome reminder: Annual/biennial colonoscopy is recommended. Check with your gastroenterologist that your colonoscopy is scheduled. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
      });
    } else if (age >= startAge - 2 && age <= 76) {
      const statusText = age < startAge
        ? `You're approximately ${startAge - age} year${startAge - age > 1 ? 's' : ''} away from the recommended start age for colorectal cancer screening.`
        : `You're in the active window for colorectal cancer screening.`;
      reminders.push({
        topic:             'colorectal',
        lastReminderAttr:  'lastColorectalReminder',
        emailSubject:      'Reminder: colorectal cancer screening — Evidence-Based Health',
        emailBody: `<p>${statusText}</p>
          <p>Colorectal cancer is highly treatable when caught early. Options include a <strong>FIT test</strong> (annual stool test), <strong>Cologuard</strong> (stool DNA, every 1–3 years), or <strong>colonoscopy</strong> (every 10 years if normal).</p>
          ${highRisk ? '<p><strong>Note:</strong> Your family history or prior polyps may mean you need to start earlier or screen more frequently than average-risk guidelines suggest. Confirm your personal interval with your clinician.</p>' : ''}
          <p><strong>3 questions to ask your clinician:</strong></p>
          <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
            <li>Which screening test makes the most sense for my history?</li>
            <li>How often should I screen based on my risk level?</li>
            <li>Is a FIT test or colonoscopy a better starting point?</li>
          </ul>`,
        smsBody: `Prevention reminder: Based on your age, it may be time to ask your clinician about colorectal cancer screening (FIT test or colonoscopy). Call their office or check your patient portal. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
      });
    }
  }

  // CERVICAL
  // Source: USPSTF 2018 — Pap q3yr ages 21–29; Pap+HPV co-test q5yr ages 30–65; stop at 65 if adequate prior screening
  if (organs.includes('cervix')) {
    const highRisk = riskFlags.includes('cervix-hpv');
    if (age >= 21 && age <= 65) {
      reminders.push({
        topic:             'cervical',
        lastReminderAttr:  'lastCervicalReminder',
        emailSubject:      'Reminder: cervical cancer screening — Evidence-Based Health',
        emailBody: `<p>You're in the age range for cervical cancer screening.</p>
          <p>${age < 30
            ? 'Most guidelines recommend a <strong>Pap test every 3 years</strong> for people aged 21–29 with a cervix.'
            : 'Most guidelines recommend a <strong>Pap + HPV co-test every 5 years</strong> (or Pap alone every 3 years) for people aged 30–65 with a cervix.'
          }${highRisk ? ' Your history of abnormal results or HPV may require more frequent follow-up.' : ''}</p>
          <p><strong>Questions to ask your clinician:</strong></p>
          <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
            <li>When was my last Pap test and am I due for one?</li>
            <li>Should I get Pap alone, HPV alone, or a co-test?</li>
          </ul>`,
        smsBody: `Prevention reminder: Based on your age, it may be time to check if you're due for cervical cancer screening (Pap or HPV test). Contact your clinician. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
      });
    }
  }

  // PROSTATE
  // Sources: USPSTF 2018 Grade C — shared decision-making ages 55–69
  //          ACS 2023 — high-risk (first-degree relative, or Black race): start SDM at 40–45
  if (organs.includes('prostate')) {
    const prostateHighRisk = riskFlags.includes('prostate-family');
    const prostateStartAge = prostateHighRisk ? 40 : 48;
    if (age >= prostateStartAge && age <= 71) {
      reminders.push({
        topic:             'prostate',
        lastReminderAttr:  'lastProstateReminder',
        emailSubject:      'Reminder: prostate cancer screening discussion — Evidence-Based Health',
        emailBody: `<p>${prostateHighRisk
            ? 'With a first-degree relative diagnosed with prostate cancer, the ACS recommends starting a <strong>shared decision-making conversation about PSA screening at age 40&ndash;45</strong> — earlier than average-risk guidance.'
            : 'You\'re in the age range when most guidelines recommend a <strong>shared decision-making conversation</strong> about PSA (prostate-specific antigen) screening with your clinician.'
          }</p>
          <p>PSA testing has real benefits and real trade-offs — it's not a simple yes/no. The goal is an informed discussion, not a skipped appointment.</p>
          <p><strong>Questions to bring up:</strong></p>
          <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
            <li>What are the pros and cons of PSA screening at my age?</li>
            <li>Does my family history or race change when I should start?</li>
            <li>If I get a PSA, what does an elevated result mean?</li>
          </ul>`,
        smsBody: `Prevention reminder: At your age, many guidelines recommend discussing PSA screening with your clinician. It's a quick conversation worth having. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
      });
    }
  }

  // BREAST
  // Sources: USPSTF 2024 Grade B — biennial mammography start age 40, continue through 74
  //          NCCN — BRCA carriers: annual MRI from age 25, annual mammo from age 30
  //          ACS 2023 — ≥20% lifetime risk: annual MRI + mammo from age 30
  if (organs.includes('breasts')) {
    const brcaRisk   = riskFlags.includes('brca');
    const familyRisk = riskFlags.includes('breast-family');
    const highRisk   = brcaRisk || familyRisk;
    const startAge   = brcaRisk ? 25 : familyRisk ? 30 : 40;
    if (age >= startAge && age <= 76) {
      reminders.push({
        topic:             'breast',
        lastReminderAttr:  'lastBreastReminder',
        emailSubject:      'Reminder: breast cancer screening — Evidence-Based Health',
        emailBody: `<p>${brcaRisk
            ? `With a BRCA1/BRCA2 variant, NCCN recommends <strong>annual breast MRI starting at age 25</strong> and <strong>annual mammography starting at age 30</strong>.${age < 30 ? ' At your age, annual MRI is the primary screening tool.' : ' Both annual MRI and mammography are recommended at your age.'}`
            : familyRisk
              ? 'Given your family history, you may qualify for <strong>annual MRI + annual mammography starting at age 30</strong> (ACS, ≥20% lifetime risk). Ask your clinician to calculate your lifetime risk with a validated model.'
              : age < 50
                ? 'You are in the age range where guidelines vary. The USPSTF (2024) recommends starting mammography at 40; the ACS recommends discussing it at 40 and beginning no later than 45.'
                : 'You are in the active screening window for breast cancer. Most guidelines recommend mammography every 1–2 years for average-risk people aged 50–74.'
          }</p>
          <p><strong>Questions to ask your clinician:</strong></p>
          <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
            <li>Am I due for a mammogram${brcaRisk || familyRisk ? ' and/or breast MRI' : ''}?</li>
            <li>Should I screen annually or every 2 years?</li>
            ${highRisk ? '<li>Do I need MRI in addition to mammography?</li>' : '<li>Does my breast density affect my screening plan?</li>'}
          </ul>`,
        smsBody: `Prevention reminder: Based on your age${highRisk ? ' and risk factors' : ''}, it may be time for a mammogram or breast screening check-in. Contact your clinician. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
      });
    }
  }

  // LUNG CANCER
  // Source: USPSTF 2021 Grade B — annual LDCT ages 50–80, ≥20 pack-years, current or quit <15 yr
  if (riskFlags.includes('smoker-ldct') && age >= 50 && age <= 80) {
    reminders.push({
      topic:             'lung',
      lastReminderAttr:  'lastLungReminder',
      emailSubject:      'Reminder: annual lung cancer screening (LDCT) — Evidence-Based Health',
      emailBody: `<p>Based on your smoking history, the USPSTF (2021, Grade B) recommends <strong>annual low-dose CT (LDCT) of the chest</strong> for adults aged 50–80 with a ≥20 pack-year history who currently smoke or have quit within the past 15 years.</p>
        <p>Annual LDCT is covered by Medicare and most insurance with no cost-sharing when ordered for eligible patients. Screening should stop if you quit &gt;15 years ago or develop a condition that limits treatment options.</p>
        <p><strong>Questions to ask your clinician:</strong></p>
        <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
          <li>Am I enrolled in an annual LDCT lung cancer screening program?</li>
          <li>How do I find a lung cancer screening center covered by my insurance?</li>
          <li>What happens if a lung nodule is found on my CT?</li>
        </ul>`,
      smsBody: `Prevention reminder: Based on your smoking history, annual low-dose CT lung cancer screening is recommended (USPSTF Grade B, ages 50–80). Ask your clinician about scheduling. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
    });
  }

  // ABDOMINAL AORTIC ANEURYSM
  // Source: USPSTF 2019 Grade B — one-time abdominal ultrasound, men 65–75 who ever smoked
  if (riskFlags.includes('ever-smoker') && organs.includes('prostate') && age >= 65 && age <= 75) {
    reminders.push({
      topic:             'aaa',
      lastReminderAttr:  'lastAAAReminder',
      emailSubject:      'Reminder: abdominal aortic aneurysm (AAA) screening — Evidence-Based Health',
      emailBody: `<p>The USPSTF (2019, Grade B) recommends a <strong>one-time abdominal ultrasound to screen for abdominal aortic aneurysm (AAA)</strong> for men aged 65–75 who have ever smoked. AAA is often silent until rupture — this single ultrasound can be life-saving.</p>
        <p>The scan is quick, painless, and typically covered by insurance. If you have already had this done, no further routine screening is required unless an aneurysm was found.</p>
        <p><strong>Questions to ask your clinician:</strong></p>
        <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
          <li>Have I had a one-time AAA ultrasound yet? If not, can we order one?</li>
          <li>If an aneurysm is found, what are the monitoring and treatment options?</li>
        </ul>`,
      smsBody: `Prevention reminder: Men 65–75 who ever smoked should have a one-time abdominal ultrasound to screen for aortic aneurysm (USPSTF Grade B). Ask your clinician. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
    });
  }

  // PANCREATIC CANCER HIGH-RISK SURVEILLANCE
  // Source: NCCN Genetic/Familial High-Risk Assessment (2026)
  //   STK11 (Peutz-Jeghers): annual EUS/MRI from age 30–35
  //   CDKN2A (FAMMM):        annual EUS/MRI from age 40
  //   Hereditary pancreatitis: annual EUS/MRI from age 40 or 20yr after onset
  //   BRCA2, ATM, PALB2:     annual EUS/MRI from age 50 (regardless of family hx)
  //   Lynch syndrome + FDR with pancreatic cancer: annual EUS/MRI from age 50
  {
    const hasSTK11       = riskFlags.includes('stk11');
    const hasCDKN2A      = riskFlags.includes('cdkn2a');
    const hasHeredPanc   = riskFlags.includes('hereditary-pancreatitis');
    const hasBRCA        = riskFlags.includes('brca');
    const hasPALB2ATM    = riskFlags.includes('palb2-atm');
    const hasLynch       = riskFlags.includes('lynch-syndrome');
    const hasFamilyPanc  = riskFlags.includes('family-pancreatic');

    const pancFlag =
      (hasSTK11       && age >= 30) ||
      (hasCDKN2A      && age >= 40) ||
      (hasHeredPanc   && age >= 40) ||
      (hasPALB2ATM    && age >= 50) ||
      (hasBRCA        && age >= 50) ||
      (hasLynch && hasFamilyPanc && age >= 50);

    if (pancFlag && age <= 80) {
      const mutLabel = hasSTK11 ? 'STK11/Peutz-Jeghers'
        : hasCDKN2A   ? 'CDKN2A/FAMMM'
        : hasHeredPanc ? 'hereditary pancreatitis'
        : hasPALB2ATM  ? 'PALB2/ATM'
        : hasBRCA      ? 'BRCA1/BRCA2'
        : 'Lynch syndrome';

      reminders.push({
        topic:            'pancreatic',
        lastReminderAttr: 'lastPancreaticReminder',
        emailSubject:     'Reminder: annual pancreatic cancer surveillance — Evidence-Based Health',
        emailBody: `<p>Based on your <strong>${mutLabel} variant</strong>, NCCN guidelines recommend <strong>annual pancreatic surveillance (endoscopic ultrasound [EUS] or MRI/MRCP)</strong>. This surveillance should be performed at a center with expertise in hereditary GI cancers.</p>
          <p>Pancreatic cancer caught early — when still confined to the pancreas — has a much better prognosis than late-stage disease. Annual surveillance with EUS or MRI/MRCP is the current standard for high-risk individuals.</p>
          <p><strong>Questions to ask your clinician:</strong></p>
          <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
            <li>Am I enrolled in an annual pancreatic surveillance program?</li>
            <li>Should I have EUS, MRI/MRCP, or alternating both?</li>
            <li>Where is the nearest hereditary GI cancer surveillance center?</li>
            <li>Are there any registries or clinical trials I should enroll in?</li>
          </ul>`,
        smsBody: `Prevention reminder: Based on your hereditary risk variant, annual pancreatic surveillance (EUS or MRI/MRCP) is recommended per NCCN. Ask your clinician. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
      });
    }
  }

  // HEPATITIS C (HCV)
  // Source: USPSTF 2020 Grade B — one-time screening, ages 18–79
  // Uses a very long interval (9999 months) so the reminder fires at most once ever.
  if (age >= 18 && age <= 79) {
    reminders.push({
      topic:            'hcv',
      lastReminderAttr: 'lastHCVReminder',
      intervalOverride: 9999,
      emailSubject:     'Reminder: hepatitis C (HCV) screening — Evidence-Based Health',
      emailBody: `<p>The USPSTF (2020, <strong>Grade B</strong>) recommends <strong>one-time hepatitis C screening</strong> for all adults aged 18–79. Most people with HCV have no symptoms for years or decades, but untreated infection can cause cirrhosis and liver cancer. Modern direct-acting antivirals cure more than 95% of cases.</p>
        <p>If you have already had a negative HCV test and have had no new exposures, no further screening is needed.</p>
        <p><strong>Questions to ask your clinician:</strong></p>
        <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
          <li>Have I ever been tested for hepatitis C?</li>
          <li>If my anti-HCV antibody test is positive, what is the next step?</li>
        </ul>`,
      smsBody: `Prevention reminder: The USPSTF recommends one-time hepatitis C (HCV) screening for all adults 18–79 (Grade B). Ask your clinician if you have been tested. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
    });
  }

  // HIV
  // Source: USPSTF 2019 Grade A — at least once, ages 15–65; more often if higher risk
  // Uses a very long interval (9999 months) so the reminder fires at most once ever.
  if (age >= 15 && age <= 65) {
    reminders.push({
      topic:            'hiv',
      lastReminderAttr: 'lastHIVReminder',
      intervalOverride: 9999,
      emailSubject:     'Reminder: HIV screening — Evidence-Based Health',
      emailBody: `<p>The USPSTF (2019, <strong>Grade A</strong>) recommends HIV screening for <strong>all adults aged 15–65 at least once</strong>. HIV is now a manageable chronic condition when detected early, and treatment virtually eliminates transmission risk. People with ongoing risk factors should test more frequently.</p>
        <p><strong>Questions to ask your clinician:</strong></p>
        <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
          <li>Have I ever been tested for HIV?</li>
          <li>Based on my risk factors, how often should I be tested?</li>
          <li>Should I discuss PrEP (pre-exposure prophylaxis)?</li>
        </ul>`,
      smsBody: `Prevention reminder: The USPSTF (Grade A) recommends HIV screening at least once for all adults 15–65. Ask your clinician if you have been tested. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
    });
  }

  // DIABETES / PREDIABETES
  // Source: USPSTF 2021 Grade B — ages 35–70; ADA recommends all adults ≥35
  if (age >= 35 && age <= 70) {
    reminders.push({
      topic:            'diabetes',
      lastReminderAttr: 'lastDiabetesReminder',
      emailSubject:     'Reminder: prediabetes and diabetes screening — Evidence-Based Health',
      emailBody: `<p>The USPSTF (2021, <strong>Grade B</strong>) recommends screening for prediabetes and type 2 diabetes for adults aged 35–70 who are overweight or obese (BMI ≥25). The ADA recommends testing all adults starting at age 35. Catching prediabetes early allows lifestyle changes that can delay or prevent progression to diabetes.</p>
        <p>Screening options include HbA1c, fasting plasma glucose, or oral glucose tolerance test — most can be added to routine lab work.</p>
        <p><strong>Questions to ask your clinician:</strong></p>
        <ul style="padding-left:1.2rem;color:#2d3d35;font-size:0.93rem;line-height:1.75">
          <li>What is my current HbA1c or fasting glucose?</li>
          <li>Am I at risk for prediabetes or diabetes?</li>
          <li>If I have prediabetes, what steps can I take now?</li>
        </ul>`,
      smsBody: `Prevention reminder: Screening for prediabetes and type 2 diabetes is recommended for adults 35–70 (USPSTF Grade B). Ask your clinician. Reply STOP to opt out. Not medical advice. — evidencebasedhealth.me`,
    });
  }

  return reminders;
}

// ── Email template wrapper ─────────────────────────────────────────────────
function wrapEmail(subject, bodyHtml, yob, origin) {
  const age = new Date().getFullYear() - yob;
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:'DM Sans',system-ui,sans-serif;background:#f7f5f0;margin:0;padding:0">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5f0;padding:40px 20px">
  <tr><td align="center">
    <table width="100%" style="max-width:560px;background:#fff;border:1px solid #ede9e1;border-radius:4px;overflow:hidden">
      <tr><td style="background:linear-gradient(90deg,#1a5c3a,#2d7a52);height:4px;font-size:0;line-height:0">&nbsp;</td></tr>
      <tr><td style="padding:36px 40px 28px">
        <p style="font-size:0.72rem;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;color:#2d7a52;margin:0 0 12px">Prevention Reminder</p>
        <h1 style="font-family:Georgia,serif;font-size:1.4rem;color:#0f1a14;margin:0 0 20px;line-height:1.3">${subject.replace(' — Evidence-Based Health', '')}</h1>
        <div style="font-size:0.93rem;color:#2d3d35;line-height:1.75;margin-bottom:24px">
          ${bodyHtml}
        </div>
        <p style="font-size:0.85rem;color:#5c6e65;line-height:1.65;font-style:italic;margin-bottom:24px">
          This reminder is based on your birth year (${yob}, approx. age ${age}) and the anatomy profile you saved. It is educational only — not personalized medical advice. Always confirm timing and approach with your own clinician.
        </p>
        <a href="${origin}/my-roadmap.html" style="display:inline-block;background:#1a5c3a;color:#fff;padding:12px 24px;border-radius:2px;text-decoration:none;font-size:0.85rem;font-weight:500;letter-spacing:0.05em">View my roadmap &rarr;</a>
      </td></tr>
      <tr><td style="padding:20px 40px;background:#f7f5f0;border-top:1px solid #ede9e1;font-size:0.75rem;color:#9aada3;line-height:1.6">
        Educational content only. Not medical advice. To stop reminders, reply to this email with "STOP" or contact <a href="mailto:info@evidencebasedhealth.me" style="color:#5c6e65">info@evidencebasedhealth.me</a>. To delete your prevention profile, email us any time.
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

// ── Main handler ───────────────────────────────────────────────────────────
export async function handler() {
  const now     = new Date().toISOString();
  const curYear = new Date().getFullYear();
  let sent      = 0;
  let errors    = 0;
  let lastKey   = undefined;

  do {
    const resp = await db.send(new ScanCommand({
      TableName:  TABLE,
      ExclusiveStartKey: lastKey,
    }));

    for (const item of (resp.Items || [])) {
      const email      = item.email?.S;
      const yob        = parseInt(item.yearOfBirth?.N, 10);
      const organs     = (item.organs?.L || []).map(o => o.S);
      const riskFlags  = (item.riskFlags?.L || []).map(r => r.S);
      const emailCons  = item.emailConsent?.BOOL ?? false;
      const smsCons    = item.smsConsent?.BOOL ?? false;
      const phone      = item.phone?.S || null;

      if (!email || !emailCons || isNaN(yob)) continue;

      const age       = curYear - yob;
      const reminders = buildReminders(age, organs, riskFlags);

      for (const reminder of reminders) {
        const lastSentIso = item[reminder.lastReminderAttr]?.S;
        const interval = reminder.intervalOverride ?? REMINDER_INTERVAL_MONTHS;
        if (monthsAgo(lastSentIso) < interval) continue;

        // Send email
        if (emailCons) {
          try {
            await ses.send(new SendEmailCommand({
              Source:      FROM,
              Destination: { ToAddresses: [email] },
              Message: {
                Subject: { Data: reminder.emailSubject, Charset: 'UTF-8' },
                Body: {
                  Html: { Data: wrapEmail(reminder.emailSubject, reminder.emailBody, yob, ORIGIN), Charset: 'UTF-8' },
                  Text: { Data: `${reminder.emailSubject}\n\n${reminder.smsBody}\n\nVisit: ${ORIGIN}/my-roadmap.html\n\nNot medical advice. To stop reminders reply STOP.`, Charset: 'UTF-8' },
                },
              },
            }));
            sent++;
          } catch (err) {
            console.error(`Email error for ${email}:`, err);
            errors++;
          }
        }

        // Send SMS
        if (SMS_ENABLED && smsCons && phone) {
          try {
            await smsV2.send(new SendTextMessageCommand({
              DestinationPhoneNumber: phone,
              OriginationIdentity:    SMS_ORIGINATION_ID,
              MessageBody:            reminder.smsBody.replace(/evidencebasedhealth\.me\s*$/, `evidencebasedhealth.me/my-roadmap.html`),
              MessageType:            'TRANSACTIONAL',
            }));
          } catch (err) {
            console.error(`SMS error for ${email}:`, err);
          }
        }

        // Update last reminder timestamp
        try {
          await db.send(new UpdateItemCommand({
            TableName: TABLE,
            Key:       { email: { S: email } },
            UpdateExpression: `SET #attr = :now, updatedAt = :now`,
            ExpressionAttributeNames:  { '#attr': reminder.lastReminderAttr },
            ExpressionAttributeValues: { ':now': { S: now } },
          }));
        } catch (err) {
          console.error(`DynamoDB update error for ${email}:`, err);
        }
      }
    }

    lastKey = resp.LastEvaluatedKey;
  } while (lastKey);

  const summary = `Reminders run complete. Sent: ${sent}, Errors: ${errors}`;
  console.log(summary);
  return { statusCode: 200, body: summary };
}
