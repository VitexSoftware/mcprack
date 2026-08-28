// "Tools" button on the servers list - queries a server's capabilities and
// shows them in a modal. External file because CSP's script-src 'self'
// silently drops inline <script> blocks (see confirm-submit.js).
document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('capabilities-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalContent = document.getElementById('modal-content');

  const closeBtn = document.querySelector('[data-capabilities-close]');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => modal.close());
  }

  document.querySelectorAll('[data-capabilities-btn]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const serverId = btn.dataset.serverId;
      const serverName = btn.dataset.serverName;

      modalTitle.textContent = `🔍 ${serverName} — Tools & Resources`;
      modalContent.innerHTML = '<p style="color: var(--color-text-muted);">Loading capabilities…</p>';
      modal.showModal();

      try {
        const response = await fetch(`/admin/servers/${serverId}/capabilities`);
        const data = await response.json();

        if (!response.ok) {
          modalContent.innerHTML = `<div class="alert alert-error" style="margin: 0;"><strong>Error:</strong> ${data.error || 'Unknown error'}</div>`;
          return;
        }

        modalContent.innerHTML = renderCapabilities(data);
      } catch (err) {
        modalContent.innerHTML = `<div class="alert alert-error" style="margin: 0;"><strong>Connection failed:</strong> ${err.message}</div>`;
      }
    });
  });
});

function renderCapabilities(data) {
  const tools = data.tools || [];
  const resources = data.resources || [];

  if (tools.length === 0 && resources.length === 0) {
    return '<p style="color: var(--color-text-muted);">No tools or resources found.</p>';
  }

  let html = '';

  if (tools.length > 0) {
    html += '<h3>Tools</h3><ul style="margin: 0;">';
    tools.forEach(tool => {
      const name = tool.name || tool;
      const desc = tool.description ? `: ${tool.description}` : '';
      html += `<li><code>${name}</code>${desc}</li>`;
    });
    html += '</ul>';
  }

  if (resources.length > 0) {
    html += '<h3>Resources</h3><ul style="margin: 0;">';
    resources.forEach(res => {
      const uri = res.uri || res;
      const desc = res.description ? `: ${res.description}` : '';
      html += `<li><code>${uri}</code>${desc}</li>`;
    });
    html += '</ul>';
  }

  return html;
}
