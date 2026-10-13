function callBackground(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      if (!response || !response.success) {
        reject(new Error(response ? response.error : 'Request failed'));
        return;
      }
      resolve(response.data || {});
    });
  });
}

async function loadConfigAndStatus() {
  const badge = document.getElementById('status');
  const text = document.getElementById('status-text');
  const baseInput = document.getElementById('base-url');
  const status = document.getElementById('save-status');

  try {
    const cfg = await callBackground({ action: 'get_config' });
    baseInput.value = cfg.base_url || 'http://127.0.0.1:5209';
  } catch (_) {
    baseInput.value = 'http://127.0.0.1:5209';
  }

  try {
    const data = await callBackground({ action: 'check_status' });
    badge.className = 'status-badge online';
    text.textContent = `Active (${data.passkeys || 0} passkeys in vault)`;
    status.textContent = `Endpoint: ${data.base_url || baseInput.value}`;
  } catch (e) {
    badge.className = 'status-badge offline';
    text.textContent = 'CredShell listener unreachable';
    status.textContent = e.message || '';
  }
}

async function saveConfig() {
  const baseUrl = document.getElementById('base-url').value.trim();
  const serverPassword = document.getElementById('server-password').value;
  const status = document.getElementById('save-status');

  try {
    await callBackground({
      action: 'set_config',
      base_url: baseUrl,
      server_password: serverPassword
    });
    status.textContent = 'Saved. Rechecking status...';
    document.getElementById('server-password').value = '';
    await loadConfigAndStatus();
  } catch (e) {
    status.textContent = e.message || 'Save failed';
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('save-btn').addEventListener('click', saveConfig);
  await loadConfigAndStatus();
});
