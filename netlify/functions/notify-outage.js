// netlify/functions/notify-outage.js
//
// Serverless endpoint used by the HyWeave CUSTOMER build to deliver outage notifications with
// zero manual steps on the customer's end -- no email client popup, no "click send" required.
// The customer's one click on "Report Outage & Notify Us" calls this function directly; this
// function is what actually sends the email.
//
// ---------------------------------------------------------------------------------------------
// SETUP (takes about 10 minutes)
// ---------------------------------------------------------------------------------------------
// 1. Put this file at netlify/functions/notify-outage.js in a Netlify site (the same site you're
//    already hosting the customer HTML on works fine -- Netlify auto-detects functions in that
//    folder, nothing else to configure on the Netlify side).
//
// 2. Create a free account at https://resend.com (or swap the SEND block below for SendGrid /
//    Mailgun / AWS SES if you already use one of those -- the rest of this file is provider-
//    agnostic). Verify a sending domain or address there; Resend will give you an API key.
//
// 3. In Netlify: Site settings -> Environment variables -> add these:
//      RESEND_API_KEY   = <the API key from Resend>
//      NOTIFY_TO        = jcoyle@ih2.us               (the ONE fixed inbox alerts always go to -
//                                                        already defaulted below, but setting it
//                                                        explicitly here means you can change the
//                                                        recipient later without touching code)
//      NOTIFY_FROM      = alerts@yourcompany.com     (a "from" address verified in Resend)
//      FUNCTION_SECRET  = <any random string you make up -- e.g. run: openssl rand -hex 24>
//
// 4. Redeploy the site. Your live endpoint is now:
//      https://<your-site-name>.netlify.app/.netlify/functions/notify-outage
//
// 5. Put that URL and the same FUNCTION_SECRET value into the customer HTML build (the build
//    script has NOTIFY_ENDPOINT_URL and NOTIFY_SECRET constants near the top -- see build.py).
//
// ---------------------------------------------------------------------------------------------
// WHY THE RECIPIENT IS FIXED HERE, NOT SENT BY THE BROWSER
// ---------------------------------------------------------------------------------------------
// NOTIFY_TO is set server-side, in your Netlify environment -- never accepted as input from the
// customer page. If this endpoint let any caller specify who it emails, anyone who discovered
// the URL could use your paid email account to send arbitrary mail to arbitrary addresses (an
// "open relay"). The browser can only ever supply the outage CONTENT; it can never choose WHERE
// it goes. That's deliberate, not an oversight.
//
// FUNCTION_SECRET is a basic abuse guard, not strong security -- since it's baked into the public
// customer HTML, a determined person could extract it from the page source and call this
// endpoint directly. It stops casual/automated scanning from spamming your inbox; it will not
// stop a targeted attacker. If that risk matters for your deployment, add real rate limiting
// (Netlify's own rate-limit config, or a service like Upstash) in front of this function.
// ---------------------------------------------------------------------------------------------

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const secret = event.headers['x-notify-secret'];
  if (!process.env.FUNCTION_SECRET || secret !== process.env.FUNCTION_SECRET) {
    return { statusCode: 401, body: 'Unauthorized' };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, body: 'Invalid JSON body' };
  }

  const { subject, text } = payload;
  if (!subject || !text || typeof subject !== 'string' || typeof text !== 'string') {
    return { statusCode: 400, body: 'Missing or invalid subject/text' };
  }
  // Basic sanity caps -- this is an alert email, not a document upload.
  if (subject.length > 300 || text.length > 20000) {
    return { statusCode: 400, body: 'Payload too large' };
  }

  const to = process.env.NOTIFY_TO || 'jcoyle@ih2.us';
  const from = process.env.NOTIFY_FROM;
  if (!to || !from || !process.env.RESEND_API_KEY) {
    return { statusCode: 500, body: 'Server not configured - set NOTIFY_FROM and RESEND_API_KEY in Netlify environment variables (NOTIFY_TO defaults to jcoyle@ih2.us if not set)' };
  }

  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from, to: [to], subject, text }),
    });
    if (!resp.ok) {
      const errText = await resp.text();
      return { statusCode: 502, body: `Email provider rejected the request: ${errText}` };
    }
    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    return { statusCode: 500, body: `Send failed: ${err.message}` };
  }
};
