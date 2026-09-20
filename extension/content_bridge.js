let shadowRoot = null;
let activeModalPromise = null;

function ensureShadowRoot() {
  if (shadowRoot) return shadowRoot;
  let host = document.getElementById('credshell-passkey-root');
  if (!host) {
    host = document.createElement('div');
    host.id = 'credshell-passkey-root';
    (document.body || document.documentElement).appendChild(host);
  }
  try {
    shadowRoot = host.attachShadow({ mode: 'closed' });
  } catch (_) {
    shadowRoot = host;
  }

  const style = document.createElement('style');
  style.textContent = `
    :host {
      all: initial;
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      pointer-events: none;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    .credshell-modal-wrapper {
      pointer-events: auto;
      perspective: 1000px;
    }
    .credshell-card {
      width: 350px;
      max-width: calc(100vw - 40px);
      box-sizing: border-box;
      background: rgba(18, 20, 29, 0.95);
      backdrop-filter: blur(24px) saturate(180%);
      -webkit-backdrop-filter: blur(24px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 18px;
      padding: 18px 20px 20px;
      box-shadow:
        0 20px 45px -10px rgba(0, 0, 0, 0.75),
        0 0 0 1px rgba(255, 255, 255, 0.08),
        0 0 35px -5px rgba(124, 58, 237, 0.28);
      color: #f1f5f9;
      animation: credshell-slide-in 0.28s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      transform-origin: top right;
    }
    .credshell-card.credshell-closing {
      animation: credshell-slide-out 0.2s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }
    @keyframes credshell-slide-in {
      from { opacity: 0; transform: translateY(-14px) scale(0.96); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes credshell-slide-out {
      from { opacity: 1; transform: translateY(0) scale(1); }
      to { opacity: 0; transform: translateY(-10px) scale(0.96); }
    }
    .credshell-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
    }
    .credshell-brand {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .credshell-shield-icon {
      width: 28px;
      height: 28px;
      border-radius: 8px;
      background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      box-shadow: 0 2px 8px rgba(99, 102, 241, 0.4);
    }
    .credshell-brand-title {
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.3px;
      color: #cbd5e1;
    }
    .credshell-close-btn {
      background: transparent;
      border: none;
      color: #64748b;
      cursor: pointer;
      padding: 6px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.15s ease;
    }
    .credshell-close-btn:hover {
      color: #f1f5f9;
      background: rgba(255, 255, 255, 0.08);
    }
    .credshell-title {
      font-size: 16px;
      font-weight: 600;
      margin: 0 0 4px;
      color: #ffffff;
    }
    .credshell-subtitle {
      font-size: 12px;
      color: #94a3b8;
      margin: 0 0 14px;
      line-height: 1.45;
    }
    .credshell-detail-box {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 10px 14px;
      margin-bottom: 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .credshell-detail-row {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 13px;
    }
    .credshell-detail-icon {
      color: #818cf8;
      display: flex;
      align-items: center;
      flex-shrink: 0;
    }
    .credshell-detail-label {
      color: #64748b;
      width: 58px;
      flex-shrink: 0;
      font-size: 12px;
    }
    .credshell-detail-value {
      color: #f1f5f9;
      font-weight: 500;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .credshell-accounts-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-bottom: 16px;
      max-height: 160px;
      overflow-y: auto;
    }
    .credshell-account-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.06);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .credshell-account-item:hover {
      background: rgba(255, 255, 255, 0.07);
      border-color: rgba(99, 102, 241, 0.3);
    }
    .credshell-account-item.selected {
      background: rgba(99, 102, 241, 0.15);
      border-color: #6366f1;
    }
    .credshell-radio-circle {
      width: 14px;
      height: 14px;
      border-radius: 50%;
      border: 2px solid #64748b;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .credshell-account-item.selected .credshell-radio-circle {
      border-color: #818cf8;
    }
    .credshell-account-item.selected .credshell-radio-circle::after {
      content: '';
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #818cf8;
    }
    .credshell-actions {
      display: flex;
      gap: 10px;
      justify-content: flex-end;
    }
    .credshell-btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      color: #cbd5e1;
      font-size: 13px;
      font-weight: 500;
      padding: 8px 16px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .credshell-btn-secondary:hover {
      background: rgba(255, 255, 255, 0.12);
      color: #ffffff;
    }
    .credshell-btn-primary {
      background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #ec4899 100%);
      border: none;
      border-radius: 10px;
      color: #ffffff;
      font-size: 13px;
      font-weight: 600;
      padding: 8px 18px;
      cursor: pointer;
      box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35);
      transition: all 0.15s ease;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .credshell-btn-primary:hover {
      filter: brightness(1.1);
      transform: translateY(-1px);
      box-shadow: 0 6px 18px rgba(99, 102, 241, 0.45);
    }
    .credshell-toast {
      width: 320px;
      max-width: calc(100vw - 40px);
      background: rgba(18, 20, 29, 0.95);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 14px;
      padding: 12px 16px;
      color: #f1f5f9;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      animation: credshell-slide-in 0.25s ease forwards;
    }
    .credshell-toast.credshell-closing {
      animation: credshell-slide-out 0.2s ease forwards;
    }
  `;
  shadowRoot.appendChild(style);
  return shadowRoot;
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[m]));
}

function showToast(message) {
  const root = ensureShadowRoot();
  const toast = document.createElement('div');
  toast.className = 'credshell-toast';
  toast.innerHTML = `
    <div style="color: #a855f7; display: flex; align-items: center;">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    </div>
    <div style="flex: 1; line-height: 1.4;">${escapeHtml(message)}</div>
  `;
  root.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('credshell-closing');
    setTimeout(() => toast.remove(), 200);
  }, 2800);
}

function showPasskeyCreateModal({ rpId, rpName, userName, isOverwrite }) {
  if (activeModalPromise) {
    return Promise.reject(new Error('A passkey prompt is already active'));
  }

  const root = ensureShadowRoot();
  const container = document.createElement('div');
  container.className = 'credshell-modal-wrapper';

  const titleText = isOverwrite ? 'Overwrite passkey?' : 'Save passkey?';
  const subtitleText = isOverwrite
    ? 'A passkey for this account already exists in CredShell. Do you want to replace it?'
    : 'Save a passkey in your CredShell vault for fast, passwordless sign-in.';
  const confirmBtnText = isOverwrite ? 'Overwrite' : 'Save Passkey';
  const confirmBtnStyle = isOverwrite
    ? 'background: linear-gradient(135deg, #ef4444 0%, #f97316 100%); box-shadow: 0 4px 14px rgba(239, 68, 68, 0.4);'
    : '';
  const overwriteNotice = isOverwrite
    ? `<div style="background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 10px; padding: 8px 12px; margin-bottom: 14px; font-size: 12px; color: #fca5a5; display: flex; align-items: center; gap: 8px;">
        <span>⚠️</span>
        <span>Existing key for <strong>${escapeHtml(userName)}#${escapeHtml(rpId)}</strong> will be overwritten.</span>
      </div>`
    : '';

  container.innerHTML = `
    <div class="credshell-card" role="dialog" aria-modal="true">
      <div class="credshell-header">
        <div class="credshell-brand">
          <div class="credshell-shield-icon" style="${isOverwrite ? 'background: linear-gradient(135deg, #ef4444 0%, #f97316 100%);' : ''}">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <circle cx="12" cy="11" r="2"/>
              <path d="M12 13v3"/>
            </svg>
          </div>
          <span class="credshell-brand-title">CredShell Passkey</span>
        </div>
        <button class="credshell-close-btn" id="btn-close" aria-label="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>

      <h2 class="credshell-title">${escapeHtml(titleText)}</h2>
      <p class="credshell-subtitle">${escapeHtml(subtitleText)}</p>

      ${overwriteNotice}

      <div class="credshell-detail-box">
        <div class="credshell-detail-row">
          <div class="credshell-detail-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
          </div>
          <div class="credshell-detail-label">Website</div>
          <div class="credshell-detail-value">${escapeHtml(rpId)}</div>
        </div>
        <div class="credshell-detail-row">
          <div class="credshell-detail-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
            </svg>
          </div>
          <div class="credshell-detail-label">Account</div>
          <div class="credshell-detail-value">${escapeHtml(userName)}</div>
        </div>
        <div class="credshell-detail-row">
          <div class="credshell-detail-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            </svg>
          </div>
          <div class="credshell-detail-label">ID</div>
          <div class="credshell-detail-value">${escapeHtml(userName)}#${escapeHtml(rpId)}</div>
        </div>
      </div>

      <div class="credshell-actions">
        <button class="credshell-btn-secondary" id="btn-cancel">Cancel</button>
        <button class="credshell-btn-primary" id="btn-confirm" style="${confirmBtnStyle}">${escapeHtml(confirmBtnText)}</button>
      </div>
    </div>
  `;

  root.appendChild(container);

  activeModalPromise = new Promise((resolve) => {
    const card = container.querySelector('.credshell-card');
    const btnCancel = container.querySelector('#btn-cancel');
    const btnClose = container.querySelector('#btn-close');
    const btnConfirm = container.querySelector('#btn-confirm');

    function dismiss(approved, e) {
      if (approved && e && !e.isTrusted) {
        return;
      }
      card.classList.add('credshell-closing');
      window.removeEventListener('keydown', onKeyDown);
      setTimeout(() => {
        container.remove();
        activeModalPromise = null;
        resolve(approved);
      }, 180);
    }

    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        dismiss(false, e);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        dismiss(true, e);
      }
    }

    window.addEventListener('keydown', onKeyDown);
    btnCancel.addEventListener('click', (e) => dismiss(false, e));
    btnClose.addEventListener('click', (e) => dismiss(false, e));
    btnConfirm.addEventListener('click', (e) => dismiss(true, e));
  });

  return activeModalPromise;
}

function showPasskeyAuthModal({ rpId, accounts }) {
  if (activeModalPromise) {
    return Promise.reject(new Error('A passkey prompt is already active'));
  }

  const root = ensureShadowRoot();
  const container = document.createElement('div');
  container.className = 'credshell-modal-wrapper';

  let selectedAccountId = accounts.length > 0 ? accounts[0].id : null;

  const accountsHtml = accounts.length > 1 ? `
    <div class="credshell-accounts-list">
      ${accounts.map((acc, idx) => `
        <div class="credshell-account-item ${idx === 0 ? 'selected' : ''}" data-id="${escapeHtml(acc.id)}">
          <div class="credshell-radio-circle"></div>
          <div style="flex: 1; overflow: hidden;">
            <div style="font-weight: 500; font-size: 13px; color: #f1f5f9; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
              ${escapeHtml(acc.user_name || 'Passkey User')}
            </div>
            <div style="font-size: 11px; color: #64748b;">${escapeHtml(acc.custom_id || acc.id)}</div>
          </div>
        </div>
      `).join('')}
    </div>
  ` : (accounts.length === 1 ? `
    <div class="credshell-detail-box">
      <div class="credshell-detail-row">
        <div class="credshell-detail-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
          </svg>
        </div>
        <div class="credshell-detail-label">Account</div>
        <div class="credshell-detail-value">${escapeHtml(accounts[0].user_name || 'Passkey User')}</div>
      </div>
      <div class="credshell-detail-row">
        <div class="credshell-detail-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
        </div>
        <div class="credshell-detail-label">Website</div>
        <div class="credshell-detail-value">${escapeHtml(rpId)}</div>
      </div>
    </div>
  ` : '');

  container.innerHTML = `
    <div class="credshell-card" role="dialog" aria-modal="true">
      <div class="credshell-header">
        <div class="credshell-brand">
          <div class="credshell-shield-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <circle cx="12" cy="11" r="2"/>
              <path d="M12 13v3"/>
            </svg>
          </div>
          <span class="credshell-brand-title">CredShell Passkey</span>
        </div>
        <button class="credshell-close-btn" id="btn-close" aria-label="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>

      <h2 class="credshell-title">Sign in with passkey</h2>
      ${accounts.length === 1 ? `<p class="credshell-subtitle">Sign in instantly using your stored passkey.</p>` : ''}

      ${accountsHtml}

      <div class="credshell-actions">
        <button class="credshell-btn-secondary" id="btn-cancel">Cancel</button>
        <button class="credshell-btn-primary" id="btn-confirm">Sign In</button>
      </div>
    </div>
  `;

  root.appendChild(container);

  activeModalPromise = new Promise((resolve) => {
    const card = container.querySelector('.credshell-card');
    const btnCancel = container.querySelector('#btn-cancel');
    const btnClose = container.querySelector('#btn-close');
    const btnConfirm = container.querySelector('#btn-confirm');

    const accItems = container.querySelectorAll('.credshell-account-item');
    accItems.forEach(item => {
      item.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        accItems.forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        selectedAccountId = item.getAttribute('data-id');
      });
    });

    function dismiss(approved, e) {
      if (approved && e && !e.isTrusted) {
        return;
      }
      card.classList.add('credshell-closing');
      window.removeEventListener('keydown', onKeyDown);
      setTimeout(() => {
        container.remove();
        activeModalPromise = null;
        resolve({ approved, selectedId: selectedAccountId });
      }, 180);
    }

    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        dismiss(false, e);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        dismiss(true, e);
      }
    }

    window.addEventListener('keydown', onKeyDown);
    btnCancel.addEventListener('click', (e) => dismiss(false, e));
    btnClose.addEventListener('click', (e) => dismiss(false, e));
    btnConfirm.addEventListener('click', (e) => dismiss(true, e));
  });

  return activeModalPromise;
}

function sendToBackground(action, payload, user_confirmed = false) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action, payload, user_confirmed }, (response) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      if (response && response.success) {
        resolve(response.data);
      } else {
        reject(new Error(response ? response.error : 'Failed to communicate with CredShell'));
      }
    });
  });
}

window.addEventListener('message', async (event) => {
  if (event.source !== window || !event.data || event.data.target !== 'credshell-content-bridge') {
    return;
  }

  const currentOrigin = window.location.origin;
  if (!currentOrigin || currentOrigin === 'null' || event.origin !== currentOrigin) {
    return;
  }

  const targetOrigin = currentOrigin;
  const { id, action, payload } = event.data;

  if (payload && typeof payload === 'object') {
    delete payload.user_confirmed;
  }

  try {
    if (action === 'check_status' || action === 'webauthn_query') {
      const data = await sendToBackground(action, payload, false);
      window.postMessage({ target: 'credshell-page-hook', id, success: true, data }, targetOrigin);
      return;
    }

    if (action === 'webauthn_create') {
      const rpId = payload.rp_id || window.location.hostname;
      const rpName = payload.rp_name || rpId;
      const userName = payload.user_name || 'user';

      let isOverwrite = false;
      try {
        const queryResp = await sendToBackground('webauthn_query', { rp_id: rpId, user_name: userName }, false);
        isOverwrite = !!(queryResp && queryResp.exists);
      } catch (_) {}

      const approved = await showPasskeyCreateModal({ rpId, rpName, userName, isOverwrite });
      if (!approved) {
        window.postMessage({
          target: 'credshell-page-hook',
          id,
          success: false,
          error: 'User cancelled the passkey creation'
        }, targetOrigin);
        return;
      }

      const data = await sendToBackground('webauthn_create', payload, true);
      window.postMessage({ target: 'credshell-page-hook', id, success: true, data }, targetOrigin);
      return;
    }

    if (action === 'webauthn_get') {
      const rpId = payload.rp_id || window.location.hostname;
      let queryResp = null;
      try {
        queryResp = await sendToBackground('webauthn_query', {
          rp_id: rpId,
          allow_credentials: payload.allow_credentials || []
        }, false);
      } catch (_) {}

      const accounts = (queryResp && queryResp.accounts) ? queryResp.accounts : [];

      if (payload.mediation === 'conditional') {
        window.postMessage({
          target: 'credshell-page-hook',
          id,
          success: false,
          error: 'Conditional mediation passkey not selected'
        }, targetOrigin);
        return;
      }

      if (accounts.length === 0) {
        showToast(`No passkey found for ${rpId} in CredShell vault`);
        window.postMessage({
          target: 'credshell-page-hook',
          id,
          success: false,
          error: `No passkey found for ${rpId} in CredShell vault`
        }, targetOrigin);
        return;
      }

      const modalResult = await showPasskeyAuthModal({ rpId, accounts });
      if (!modalResult.approved) {
        window.postMessage({
          target: 'credshell-page-hook',
          id,
          success: false,
          error: 'User cancelled the passkey request'
        }, targetOrigin);
        return;
      }

      payload.selected_credential_id = modalResult.selectedId;
      const data = await sendToBackground('webauthn_get', payload, true);
      window.postMessage({ target: 'credshell-page-hook', id, success: true, data }, targetOrigin);
      return;
    }

    throw new Error(`Unknown action: ${action}`);
  } catch (err) {
    window.postMessage({
      target: 'credshell-page-hook',
      id,
      success: false,
      error: err.message || 'Operation failed'
    }, targetOrigin);
  }
});
