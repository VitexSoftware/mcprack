// Shared confirm-before-submit for destructive admin forms (delete server,
// uninstall, stop proxy). External file because CSP's script-src 'self'
// silently drops inline onsubmit="return confirm(...)" handlers.
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.dataset.confirm)) {
        e.preventDefault();
      }
    });
  });
});
