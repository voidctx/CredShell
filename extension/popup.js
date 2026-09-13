async function checkStatus() {
  const badge = document.getElementById('status');
  const text = document.getElementById('status-text');

  try {
    const res = await fetch('http://127.0.0.1:5209/status');
    if (res.ok) {
      const data = await res.json();
      badge.className = 'status-badge online';
      text.textContent = `Active (${data.passkeys || 0} passkeys in vault)`;
    } else {
      throw new Error();
    }
  } catch (e) {
    badge.className = 'status-badge offline';
    text.textContent = 'CredShell listener stopped';
  }
}

document.addEventListener('DOMContentLoaded', checkStatus);
