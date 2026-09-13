const CREDSHELL_BASE = 'http://127.0.0.1:5209';

function getSenderDomain(sender) {
  const rawUrl = (sender.tab && sender.tab.url) || sender.url;
  if (!rawUrl) return null;
  try {
    const u = new URL(rawUrl);
    return u.hostname;
  } catch (_) {
    return null;
  }
}

const MULTI_TENANT_SUFFIXES = [
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app', 'now.sh',
  'netlify.app', 'herokuapp.com', 'herokussl.com', 'firebaseapp.com', 'web.app',
  'azurewebsites.net', 'cloudapp.net', 'azurestaticapps.net', 's3.amazonaws.com',
  's3-website.amazonaws.com', 'cloudfront.net', 'elasticbeanstalk.com', 'appspot.com',
  '000webhostapp.com', 'fly.dev', 'render.com', 'onrender.com', 'glitch.me', 'repl.co',
  'replit.dev', 'surge.sh', 'myshopify.com', 'wordpress.com', 'blogspot.com', 'wixsite.com',
  'weebly.com', 'squarespace.com', 'carrd.co', 'ghost.io', 'pantheonsite.io', 'kinsta.cloud',
  'ngrok.io', 'ngrok-free.app', 'loca.lt', 'nip.io', 'sslip.io'
];

function isPublicSuffix(d) {
  if (!d) return false;
  const parts = d.split('.');
  if (parts.length <= 1) return true;
  if (MULTI_TENANT_SUFFIXES.includes(d)) return true;
  if (parts.length === 2 && parts[1].length === 2) {
    const s2 = parts[0];
    if (['co', 'com', 'org', 'net', 'edu', 'gov', 'ac'].includes(s2)) return true;
  }
  return false;
}

function isRpAllowedForDomain(rpId, domain) {
  if (!rpId || !domain) return false;
  const rp = rpId.toLowerCase().trim().replace(/^\.+|\.+$/g, '');
  const d = domain.toLowerCase().trim().replace(/^\.+|\.+$/g, '');

  if (isPublicSuffix(rp) || isPublicSuffix(d)) return false;
  if (d === rp) return true;
  if (d.endsWith('.' + rp)) return true;
  if (rp.endsWith('.' + d)) return true;
  return false;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ success: false, error: 'Unauthorized sender context' });
    return false;
  }

  if (request.action === 'check_status') {
    fetch(`${CREDSHELL_BASE}/status`)
      .then(r => r.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  const tabDomain = getSenderDomain(sender);
  const payloadRp = request.payload ? (request.payload.rp_id || request.payload.rpId) : null;

  if (payloadRp && tabDomain && !isRpAllowedForDomain(payloadRp, tabDomain)) {
    sendResponse({
      success: false,
      error: `Security violation: Relying Party '${payloadRp}' does not match active tab '${tabDomain}'`
    });
    return false;
  }

  const commonHeaders = {
    'Content-Type': 'application/json',
    'X-CredShell-Tab-Origin': tabDomain || '',
    'X-CredShell-Confirmed': (request.user_confirmed === true) ? 'true' : 'false'
  };

  if (request.action === 'webauthn_create') {
    fetch(`${CREDSHELL_BASE}/webauthn/create`, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify(request.payload)
    })
      .then(async r => {
        if (!r.ok) {
          const errData = await r.json().catch(() => ({}));
          throw new Error(errData.error || `Registration failed with HTTP ${r.status}`);
        }
        return r.json();
      })
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (request.action === 'webauthn_query') {
    fetch(`${CREDSHELL_BASE}/webauthn/query`, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify(request.payload)
    })
      .then(async r => {
        if (!r.ok) {
          const errData = await r.json().catch(() => ({}));
          throw new Error(errData.error || `Query failed with HTTP ${r.status}`);
        }
        return r.json();
      })
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (request.action === 'webauthn_get') {
    fetch(`${CREDSHELL_BASE}/webauthn/get`, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify(request.payload)
    })
      .then(async r => {
        if (!r.ok) {
          const errData = await r.json().catch(() => ({}));
          throw new Error(errData.error || `Authentication declined with HTTP ${r.status}`);
        }
        return r.json();
      })
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
});
