/**
 * Loading Spinner - Show a loading indicator when navigating to pages that take time to load
 * or when submitting forms (especially when waiting for Vaultwarden responses)
 */

const loadingOverlay = document.getElementById('loadingOverlay');

// Show loading spinner when clicking on admin links that typically take time
document.addEventListener('click', (event) => {
  const link = event.target.closest('a');
  if (!link) return;

  const href = link.getAttribute('href');
  if (!href) return;

  // Show spinner for admin pages that load slowly:
  // - /admin/servers - lists all MCP servers with their status
  // - /admin/servers/*/edit - loads env vars from Vaultwarden
  // - /admin/users - lists all users
  // - /admin/proxy_instances - might load proxy status
  // - /admin/audit_log - loads audit log entries
  const slowPages = [
    /^\/admin\/servers(\/|$|\?)/,  // /admin/servers, /admin/servers/, /admin/servers?page=2
    /^\/admin\/servers\/\d+\/edit/,
    /^\/admin\/users/,
    /^\/admin\/proxy_instances/,
    /^\/admin\/audit_log/,
  ];

  const isSlow = slowPages.some(pattern => pattern.test(href));
  
  // Only show for same-origin navigation (not external links)
  if (isSlow && !href.startsWith('http') && !href.startsWith('//')) {
    loadingOverlay.classList.add('active');
    
    // Safety: hide spinner after 60 seconds (in case page fails to load)
    setTimeout(() => {
      loadingOverlay.classList.remove('active');
    }, 60000);
  }
});

// Show loading spinner when submitting forms (especially slow admin operations)
document.addEventListener('submit', (event) => {
  const form = event.target;
  const action = form.getAttribute('action') || window.location.pathname;
  
  // Show spinner for admin operations that might be slow:
  // - Save MCP server config (updates Vaultwarden secrets)
  // - Test MCP server (spawns process and tests connectivity)
  // - Autodetect servers
  // - Update user permissions
  const slowForms = [
    /^\/admin\/servers(\/\d+)?(\?|$)/,  // POST to /admin/servers or /admin/servers/N
    /^\/admin\/servers\/\d+\/test/,     // Test stdio server
    /^\/admin\/servers\/autodetect/,    // Autodetect
    /^\/admin\/users\/\d+(\?|$)/,       // User updates
  ];

  const isSlow = slowForms.some(pattern => pattern.test(action));
  
  if (isSlow) {
    loadingOverlay.classList.add('active');
    
    // Safety: hide spinner after 60 seconds
    setTimeout(() => {
      loadingOverlay.classList.remove('active');
    }, 60000);
  }
});

// Hide loading spinner when page fully loads
window.addEventListener('load', () => {
  loadingOverlay.classList.remove('active');
});

// Also hide when user navigates away and back (from history)
window.addEventListener('pageshow', () => {
  loadingOverlay.classList.remove('active');
});

// Hide if user starts interacting with the page while it's loading
document.addEventListener('keydown', () => {
  // Don't hide on first key, but give visual feedback that page is interactive
}, { once: true });
