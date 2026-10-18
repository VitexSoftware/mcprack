// Live uniqueness check for the "name" field on the admin server form.
// Debounced GET against admin.server_check_name; the POST handler re-checks
// on save, so this is purely a UX hint. External file because the CSP's
// script-src 'self' blocks inline <script> blocks (see confirm-submit.js).
document.addEventListener('DOMContentLoaded', function () {
  var input = document.getElementById('name');
  if (!input || input.readOnly) {
    // Edit form: the slug is read-only there, nothing to check.
    return;
  }
  var url = input.dataset.checkNameUrl;
  if (!url) {
    return;
  }
  var takenMessage = input.dataset.msgTaken || 'This name is already used by another server.';
  var exclude = input.dataset.serverId || '';

  var hint = document.createElement('small');
  hint.className = 'field-error-hint';
  hint.hidden = true;
  input.insertAdjacentElement('afterend', hint);

  var timer = null;

  function mark(taken) {
    input.classList.toggle('input-error', taken);
    input.setAttribute('aria-invalid', taken ? 'true' : 'false');
    hint.hidden = !taken;
    hint.textContent = taken ? takenMessage : '';
  }

  function check() {
    var name = input.value.trim();
    if (!name) {
      mark(false);
      return;
    }
    var qs = '?name=' + encodeURIComponent(name) +
      (exclude ? '&exclude=' + encodeURIComponent(exclude) : '');
    fetch(url + qs, { headers: { 'Accept': 'application/json' } })
      .then(function (resp) { return resp.ok ? resp.json() : null; })
      .then(function (data) {
        if (data) {
          mark(data.available === false);
        }
      })
      .catch(function () {
        // Network hiccup — stay silent; the server re-checks on save.
      });
  }

  input.addEventListener('input', function () {
    mark(false);
    clearTimeout(timer);
    timer = setTimeout(check, 300);
  });
});
