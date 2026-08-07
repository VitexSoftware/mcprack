// Populates the dynamic "environment variable" row editors on the admin
// server-form and install-wizard pages. External file because CSP's
// script-src 'self' blocks inline <script> content entirely — the whole
// block this replaced, including its onclick="addEnvRow(...)" trigger
// button, was silently dead code.

// Mirrors mcprack/env_detection.py's SENSITIVE_NAME_HINTS so imported .env
// keys get the same secret/plain default guess as server-side detection.
var ENV_SENSITIVE_NAME_HINTS = ['KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PASSWD', 'CREDENTIAL', 'APIKEY'];

function looksSensitiveEnvName(name) {
  var upper = (name || '').toUpperCase();
  return ENV_SENSITIVE_NAME_HINTS.some(function (hint) { return upper.indexOf(hint) !== -1; });
}

// Parses the subset of dotenv syntax admins are likely to actually paste:
// blank lines, '#' comments, an optional leading 'export ', and single- or
// double-quoted values (with \n/\t/\\/\" unescaping inside double quotes,
// matching common dotenv-parser behavior). Not a full spec implementation —
// good enough for reviewing/editing afterward in the row editor.
function parseDotEnv(text) {
  var rows = [];
  (text || '').split(/\r\n|\r|\n/).forEach(function (line) {
    var trimmed = line.trim();
    if (!trimmed || trimmed.charAt(0) === '#') {
      return;
    }
    if (trimmed.indexOf('export ') === 0) {
      trimmed = trimmed.slice(7).trim();
    }
    var eq = trimmed.indexOf('=');
    if (eq === -1) {
      return;
    }
    var key = trimmed.slice(0, eq).trim();
    var value = trimmed.slice(eq + 1).trim();
    if (!key) {
      return;
    }
    if (value.length >= 2 && value.charAt(0) === '"' && value.charAt(value.length - 1) === '"') {
      value = value.slice(1, -1)
        .replace(/\\n/g, '\n')
        .replace(/\\t/g, '\t')
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\');
    } else if (value.length >= 2 && value.charAt(0) === "'" && value.charAt(value.length - 1) === "'") {
      value = value.slice(1, -1);
    }
    rows.push({ key: key, value: value });
  });
  return rows;
}

document.addEventListener('DOMContentLoaded', function () {
  var counters = {};

  function addEnvRow(containerId, sensitiveLabel, key, value, sensitive, required, requiredLabel) {
    counters[containerId] = (counters[containerId] || 0) + 1;
    var id = containerId + '-' + counters[containerId];

    var row = document.createElement('div');
    row.className = 'env-row' + (required ? ' env-row-required' : '');
    row.dataset.rowId = id;
    row.style.cssText = 'display: flex; gap: var(--space-sm); align-items: center; margin-bottom: var(--space-sm);';

    var keyInput = document.createElement('input');
    keyInput.type = 'text';
    keyInput.name = 'env_key__' + id;
    keyInput.value = key || '';
    keyInput.placeholder = 'KEY';
    keyInput.style.flex = '1';

    var valueInput = document.createElement('input');
    valueInput.type = 'text';
    valueInput.name = 'env_value__' + id;
    valueInput.value = value || '';
    valueInput.placeholder = 'value';
    valueInput.style.flex = '2';

    var label = document.createElement('label');
    label.style.cssText = 'display: flex; align-items: center; gap: var(--space-xs); white-space: nowrap;';
    var sensitiveInput = document.createElement('input');
    sensitiveInput.type = 'checkbox';
    sensitiveInput.name = 'env_sensitive__' + id;
    sensitiveInput.checked = !!sensitive;
    label.appendChild(sensitiveInput);
    label.appendChild(document.createTextNode(' ' + sensitiveLabel));

    var requiredLabelEl = document.createElement('label');
    requiredLabelEl.style.cssText = 'display: flex; align-items: center; gap: var(--space-xs); white-space: nowrap;';
    var requiredInput = document.createElement('input');
    requiredInput.type = 'checkbox';
    requiredInput.name = 'env_required__' + id;
    requiredInput.checked = !!required;
    requiredInput.addEventListener('change', function () {
      row.classList.toggle('env-row-required', requiredInput.checked);
    });
    requiredLabelEl.appendChild(requiredInput);
    requiredLabelEl.appendChild(document.createTextNode(' ' + (requiredLabel || 'required')));

    var removeButton = document.createElement('button');
    removeButton.type = 'button';
    removeButton.className = 'btn btn-sm btn-danger';
    removeButton.textContent = '✕';
    removeButton.addEventListener('click', function () {
      row.remove();
    });

    row.append(keyInput, valueInput, label, requiredLabelEl, removeButton);
    document.getElementById(containerId).appendChild(row);
  }

  document.querySelectorAll('[data-env-rows-container]').forEach(function (container) {
    var sensitiveLabel = container.dataset.sensitiveLabel || 'sensitive';
    var requiredLabel = container.dataset.requiredLabel || 'required';
    var initial = [];
    try {
      initial = JSON.parse(container.dataset.initial || '[]');
    } catch (e) {
      initial = [];
    }
    initial.forEach(function (row) {
      addEnvRow(container.id, sensitiveLabel, row.key, row.value, row.sensitive, row.required, requiredLabel);
    });
  });

  document.querySelectorAll('.add-env-row-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var containerId = btn.dataset.target;
      var container = document.getElementById(containerId);
      var sensitiveLabel = (container && container.dataset.sensitiveLabel) || 'sensitive';
      var requiredLabel = (container && container.dataset.requiredLabel) || 'required';
      addEnvRow(containerId, sensitiveLabel, '', '', false, false, requiredLabel);
    });
  });

  document.querySelectorAll('[data-env-import-input]').forEach(function (input) {
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) {
        return;
      }
      var containerId = input.dataset.target;
      var container = document.getElementById(containerId);
      var sensitiveLabel = (container && container.dataset.sensitiveLabel) || 'sensitive';
      var requiredLabel = (container && container.dataset.requiredLabel) || 'required';
      var reader = new FileReader();
      reader.onload = function () {
        parseDotEnv(String(reader.result)).forEach(function (row) {
          addEnvRow(containerId, sensitiveLabel, row.key, row.value, looksSensitiveEnvName(row.key), false, requiredLabel);
        });
        input.value = '';
      };
      reader.readAsText(file);
    });
  });
});
