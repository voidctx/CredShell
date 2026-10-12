const DEFAULT_CREDSHELL_BASE = 'http://127.0.0.1:5209';

function normalizeBaseUrl(value) {
  const raw = (value || DEFAULT_CREDSHELL_BASE).trim();
  return raw.endsWith('/') ? raw.slice(0, -1) : raw;
}

function isLocalBaseUrl(baseUrl) {
  try {
    const u = new URL(baseUrl);
    const host = (u.hostname || '').toLowerCase();
    return host === '127.0.0.1' || host === 'localhost' || host === '::1';
  } catch (_) {
    return false;
  }
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function loadConfig() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['base_url', 'tunnel_password_hash'], (cfg) => {
      resolve({
        baseUrl: normalizeBaseUrl(cfg.base_url || DEFAULT_CREDSHELL_BASE),
        tunnelPasswordHash: (cfg.tunnel_password_hash || '').toString().trim().toLowerCase()
      });
    });
  });
}

function saveConfig(baseUrl, tunnelPasswordHash) {
  return new Promise((resolve) => {
    chrome.storage.local.set({
      base_url: normalizeBaseUrl(baseUrl || DEFAULT_CREDSHELL_BASE),
      tunnel_password_hash: (tunnelPasswordHash || '').toString().trim().toLowerCase()
    }, resolve);
  });
}

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
  (async () => {
    if (request.action === 'get_config') {
      const cfg = await loadConfig();
      sendResponse({
        success: true,
        data: {
          base_url: cfg.baseUrl,
          requires_password: !isLocalBaseUrl(cfg.baseUrl),
          has_password_hash: !!cfg.tunnelPasswordHash
        }
      });
      return;
    }

    if (request.action === 'set_config') {
      const baseUrl = request.base_url || DEFAULT_CREDSHELL_BASE;
      const rawPassword = (request.tunnel_password || '').toString();
      const hash = rawPassword.trim() ? await sha256Hex(rawPassword) : '';
      await saveConfig(baseUrl, hash);
      sendResponse({ success: true, data: { saved: true } });
      return;
    }

    if (sender.id !== chrome.runtime.id) {
      sendResponse({ success: false, error: 'Unauthorized sender context' });
      return;
    }

    const cfg = await loadConfig();
    if (!isLocalBaseUrl(cfg.baseUrl) && !cfg.tunnelPasswordHash) {
      sendResponse({
        success: false,
        error: 'Tunnel password is required. Open the extension popup and set a tunnel password.'
      });
      return;
    }

    const tabDomain = getSenderDomain(sender);
    const payloadRp = request.payload ? (request.payload.rp_id || request.payload.rpId) : null;

    if (payloadRp && tabDomain && !isRpAllowedForDomain(payloadRp, tabDomain)) {
      sendResponse({
        success: false,
        error: `Security violation: Relying Party '${payloadRp}' does not match active tab '${tabDomain}'`
      });
      return;
    }

    const commonHeaders = {
      'Content-Type': 'application/json',
      'X-CredShell-Tab-Origin': tabDomain || '',
      'X-CredShell-Confirmed': (request.user_confirmed === true) ? 'true' : 'false'
    };
    if (cfg.tunnelPasswordHash) {
      commonHeaders['X-CredShell-Password-Hash'] = cfg.tunnelPasswordHash;
    }

    if (request.action === 'check_status') {
      const res = await fetch(`${cfg.baseUrl}/status`, { headers: commonHeaders });
      const body = await res.text();
      if (!res.ok) {
        throw new Error(body || `Status check failed with HTTP ${res.status}`);
      }
      let data = {};
      try {
        data = JSON.parse(body);
      } catch (_) {}
      sendResponse({ success: true, data: { ...data, base_url: cfg.baseUrl } });
      return;
    }

    const endpointByAction = {
      webauthn_create: '/webauthn/create',
      webauthn_query: '/webauthn/query',
      webauthn_get: '/webauthn/get'
    };
    const endpoint = endpointByAction[request.action];
    if (!endpoint) {
      throw new Error(`Unknown action: ${request.action}`);
    }

    const res = await fetch(`${cfg.baseUrl}${endpoint}`, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify(request.payload || {})
    });

    const responseData = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(responseData.error || `Request failed with HTTP ${res.status}`);
    }
    sendResponse({ success: true, data: responseData });
  })().catch((err) => {
    sendResponse({ success: false, error: err.message || 'Operation failed' });
  });

  return true;
});
