// Auto-refreshes the install-wizard's "Installer-managed servers" table
// while any row is still in a non-terminal state. External file because
// CSP's script-src 'self' blocks inline <script> content entirely — this
// polling loop was silently dead code before the move.
document.addEventListener('DOMContentLoaded', function () {
  function pollInstallStatus() {
    document.querySelectorAll('tr[data-status]').forEach(function (row) {
      var status = row.dataset.status;
      if (status === 'success' || status === 'failed') return;

      var serverId = row.dataset.serverId;
      fetch('/admin/install/' + serverId + '/status')
        .then(function (r) {
          return r.json();
        })
        .then(function (data) {
          if (data.status && data.status !== status) {
            window.location.reload();
          }
        })
        .catch(function () {});
    });
  }

  if (document.querySelector('tr[data-status]')) {
    setInterval(pollInstallStatus, 3000);
  }
});
