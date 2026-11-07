// Interactive Row Editor for MCP Server Configuration Overrides
// Supports partial overriding (inheriting admin defaults), autocomplete
// for known configuration keys, real-time validation, and .env file import.
// External file to comply with CSP script-src 'self'.

// looksSensitiveEnvName() and parseDotEnv() come from env-parse.js.

document.addEventListener('DOMContentLoaded', function () {
  var container = document.querySelector('[data-override-rows-container]');
  if (!container) {
    return;
  }

  var containerId = container.id || 'override-rows';
  var counter = 0;

  var initialRows = [];
  try {
    initialRows = JSON.parse(container.dataset.initial || '[]');
  } catch (e) {
    initialRows = [];
  }

  var knownKeys = [];
  try {
    knownKeys = JSON.parse(container.dataset.knownKeys || '[]');
  } catch (e) {
    knownKeys = [];
  }

  var knownMap = {};
  knownKeys.forEach(function (item) {
    knownMap[item.key] = item;
  });

  // Create or reuse datalist for autocomplete
  var datalistId = containerId + '-datalist';
  var datalist = document.getElementById(datalistId);
  if (!datalist) {
    datalist = document.createElement('datalist');
    datalist.id = datalistId;
    knownKeys.forEach(function (item) {
      var opt = document.createElement('option');
      opt.value = item.key;
      var label = item.description || (item.default ? 'default: ' + item.default : '');
      if (label) {
        opt.label = label;
      }
      datalist.appendChild(opt);
    });
    document.body.appendChild(datalist);
  }

  var sensitiveLabelText = container.dataset.sensitiveLabel || 'sensitive';
  var inheritedBadgeText = container.dataset.inheritedLabel || 'Inherited from admin';
  var overriddenBadgeText = container.dataset.overriddenLabel || 'Overridden';
  var customBadgeText = container.dataset.customLabel || 'Custom';
  var revertButtonText = container.dataset.revertLabel || '↺ Revert to admin default';
  var duplicateLabelText = container.dataset.duplicateLabel || 'Duplicate key — each variable name must be unique.';
  var emptyKeyLabelText = container.dataset.emptyKeyLabel || 'Key is required when a value is set.';
  var missingLabelText = container.dataset.missingLabel || 'Required value missing — the server cannot start until this is filled in.';
  var missingSummaryTemplate = container.dataset.missingSummary || '{n} required value(s) missing — the MCP server will not start until they are filled in.';

  // Only a required key with nothing to inherit is actually missing: an
  // admin-defined one left empty is inheriting on purpose.
  function rowIsMissing(row) {
    if (!row.classList.contains('override-row-required') || row.dataset.adminDefined === '1') {
      return false;
    }
    var valueInput = row.querySelector('.env-input-value');
    return !(valueInput && valueInput.value.trim());
  }

  function updateMissingSummary() {
    var summary = container.previousElementSibling;
    if (!summary || !summary.classList.contains('env-missing-summary')) {
      summary = document.createElement('div');
      summary.className = 'env-missing-summary';
      summary.setAttribute('role', 'alert');
      container.parentNode.insertBefore(summary, container);
    }
    var n = container.querySelectorAll('.env-row-missing').length;
    summary.hidden = n === 0;
    summary.textContent = '⚠ ' + missingSummaryTemplate.replace('{n}', String(n));
  }

  function refreshRowErrors() {
    var counts = {};
    var rows = container.querySelectorAll('.override-row');
    rows.forEach(function (row) {
      var keyInput = row.querySelector('.env-input-key');
      var key = keyInput ? keyInput.value.trim() : '';
      if (key) {
        counts[key] = (counts[key] || 0) + 1;
      }
    });

    rows.forEach(function (row) {
      var wrap = row.parentNode;
      var keyInput = row.querySelector('.env-input-key');
      var valueInput = row.querySelector('.env-input-value');
      var errorHint = wrap.querySelector('.env-row-error-hint');
      var key = keyInput ? keyInput.value.trim() : '';
      var value = valueInput ? valueInput.value.trim() : '';

      var message = '';
      if (key && counts[key] > 1) {
        message = duplicateLabelText;
      } else if (!key && value) {
        message = emptyKeyLabelText;
      }

      row.classList.toggle('env-row-error', !!message);
      if (keyInput) {
        keyInput.setAttribute('aria-invalid', message ? 'true' : 'false');
      }
      if (errorHint) {
        errorHint.hidden = !message;
        errorHint.textContent = message;
      }

      var missing = rowIsMissing(row);
      row.classList.toggle('env-row-missing', missing);
      var missingHint = wrap.querySelector('.env-row-missing-hint');
      if (missingHint) {
        missingHint.hidden = !missing;
        missingHint.textContent = missing ? missingLabelText : '';
      }
    });

    updateMissingSummary();
  }

  function addRow(data) {
    counter++;
    var rowId = containerId + '-' + counter;
    data = data || {};

    var wrap = document.createElement('div');
    wrap.className = 'override-row-wrap';

    var row = document.createElement('div');
    row.className = 'override-row' + (data.required ? ' override-row-required' : '');
    row.dataset.rowId = rowId;
    row.dataset.adminDefined = data.is_admin_defined ? '1' : '0';

    // Key input with autocomplete
    var keyCol = document.createElement('div');
    keyCol.className = 'override-col-key';

    var keyInput = document.createElement('input');
    keyInput.type = 'text';
    keyInput.name = 'env_key__' + rowId;
    keyInput.value = data.key || '';
    keyInput.placeholder = 'CONFIG_KEY';
    keyInput.className = 'env-input-key form-control';
    keyInput.setAttribute('list', datalistId);
    keyInput.autocomplete = 'off';

    keyCol.appendChild(keyInput);

    // Value input
    var valCol = document.createElement('div');
    valCol.className = 'override-col-value';

    var valueInput = document.createElement('input');
    valueInput.type = data.sensitive ? 'password' : 'text';
    valueInput.name = 'env_value__' + rowId;
    valueInput.value = data.value || '';
    valueInput.className = 'env-input-value form-control';

    var placeholderText = '';
    if (data.is_admin_defined) {
      placeholderText = data.admin_value ? 'Inherited: ' + data.admin_value : 'Inherited from admin';
    } else {
      placeholderText = 'value';
    }
    valueInput.placeholder = placeholderText;

    valCol.appendChild(valueInput);

    // Sensitive checkbox
    var optCol = document.createElement('div');
    optCol.className = 'override-col-opts';

    var sensLabel = document.createElement('label');
    sensLabel.className = 'override-label-sensitive';
    var sensInput = document.createElement('input');
    sensInput.type = 'checkbox';
    sensInput.name = 'env_sensitive__' + rowId;
    sensInput.checked = !!data.sensitive;
    sensInput.addEventListener('change', function () {
      if (valueInput.value) {
        valueInput.type = sensInput.checked ? 'password' : 'text';
      }
    });
    sensLabel.appendChild(sensInput);
    sensLabel.appendChild(document.createTextNode(' ' + sensitiveLabelText));
    optCol.appendChild(sensLabel);

    // Status badge
    var statusBadge = document.createElement('span');
    statusBadge.className = 'override-status-badge';

    function updateStatusBadge() {
      var isOverridden = !!valueInput.value.trim();
      var isAdmin = !!data.is_admin_defined;

      statusBadge.classList.remove('status-inherited', 'status-overridden', 'status-custom');
      if (isAdmin) {
        if (isOverridden) {
          statusBadge.textContent = '✏️ ' + overriddenBadgeText;
          statusBadge.className = 'override-status-badge status-overridden';
          if (revertBtn) {
            revertBtn.hidden = false;
          }
        } else {
          statusBadge.textContent = '🛡️ ' + inheritedBadgeText;
          statusBadge.className = 'override-status-badge status-inherited';
          if (revertBtn) {
            revertBtn.hidden = true;
          }
        }
      } else {
        statusBadge.textContent = '➕ ' + customBadgeText;
        statusBadge.className = 'override-status-badge status-custom';
        if (revertBtn) {
          revertBtn.hidden = true;
        }
      }
    }

    optCol.appendChild(statusBadge);

    // Action buttons (Revert for admin defined, Delete for custom)
    var actCol = document.createElement('div');
    actCol.className = 'override-col-actions';

    var revertBtn = null;
    if (data.is_admin_defined) {
      revertBtn = document.createElement('button');
      revertBtn.type = 'button';
      revertBtn.className = 'btn btn-sm btn-secondary revert-override-btn';
      revertBtn.textContent = revertButtonText;
      revertBtn.title = 'Clear value and inherit administrator setting';
      revertBtn.addEventListener('click', function () {
        valueInput.value = '';
        updateStatusBadge();
        refreshRowErrors();
      });
      actCol.appendChild(revertBtn);
    } else {
      var removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn btn-sm btn-danger remove-override-btn';
      removeBtn.textContent = '✕';
      removeBtn.title = 'Remove this row';
      removeBtn.addEventListener('click', function () {
        wrap.remove();
        refreshRowErrors();
      });
      actCol.appendChild(removeBtn);
    }

    row.append(keyCol, valCol, optCol, actCol);
    wrap.appendChild(row);

    // Hint & error lines
    var missingHint = document.createElement('small');
    missingHint.className = 'env-row-missing-hint';
    missingHint.hidden = true;
    wrap.appendChild(missingHint);

    var errorHint = document.createElement('small');
    errorHint.className = 'env-row-error-hint form-hint';
    errorHint.hidden = true;
    wrap.appendChild(errorHint);

    var descHint = document.createElement('small');
    descHint.className = 'override-desc-hint form-hint text-muted';
    if (data.description || data.source) {
      var parts = [];
      if (data.source && data.source !== 'admin') {
        parts.push('suggested from ' + data.source);
      }
      if (data.description) {
        parts.push(data.description);
      }
      descHint.textContent = parts.join(' — ');
      wrap.appendChild(descHint);
    } else {
      descHint.hidden = true;
      wrap.appendChild(descHint);
    }

    keyInput.addEventListener('input', function () {
      var key = keyInput.value.trim();
      var known = knownMap[key];
      if (known) {
        if (!sensInput.checked && known.sensitive) {
          sensInput.checked = true;
          valueInput.type = 'password';
        }
        if (known.description) {
          descHint.textContent = known.description;
          descHint.hidden = false;
        }
      }
      refreshRowErrors();
    });

    valueInput.addEventListener('input', function () {
      updateStatusBadge();
      refreshRowErrors();
    });

    updateStatusBadge();
    container.appendChild(wrap);
    refreshRowErrors();
  }

  // Populate initial rows
  initialRows.forEach(function (row) {
    addRow(row);
  });

  // "Add row" button
  document.querySelectorAll('.add-override-row-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      addRow({
        key: '',
        value: '',
        is_admin_defined: false,
        sensitive: false,
        required: false
      });
      var lastRow = container.querySelector('.override-row-wrap:last-child .env-input-key');
      if (lastRow) {
        lastRow.focus();
      }
    });
  });

  // Quick-add buttons from the Known Keys list
  document.querySelectorAll('[data-add-known-key]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var keyName = btn.dataset.addKnownKey;
      var existingInput = null;
      container.querySelectorAll('.env-input-key').forEach(function (inp) {
        if (inp.value.trim() === keyName) {
          existingInput = inp;
        }
      });

      if (existingInput) {
        var rowWrap = existingInput.closest('.override-row-wrap');
        var valInput = rowWrap ? rowWrap.querySelector('.env-input-value') : null;
        if (valInput) {
          valInput.focus();
        }
      } else {
        var known = knownMap[keyName] || {};
        addRow({
          key: keyName,
          value: '',
          is_admin_defined: !!known.admin_defined,
          admin_value: known.default || (known.sensitive ? '●●●●●●' : ''),
          sensitive: !!known.sensitive,
          required: !!known.required,
          description: known.description,
          source: known.source
        });
        var rowWrap = container.querySelector('.override-row-wrap:last-child');
        var valInput = rowWrap ? rowWrap.querySelector('.env-input-value') : null;
        if (valInput) {
          valInput.focus();
        }
      }
    });
  });

  // Import .env file
  document.querySelectorAll('[data-override-import-input]').forEach(function (input) {
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) {
        return;
      }
      var reader = new FileReader();
      reader.onload = function () {
        var parsed = parseDotEnv(String(reader.result));
        parsed.forEach(function (item) {
          var existing = null;
          container.querySelectorAll('.override-row-wrap').forEach(function (wrap) {
            var keyInp = wrap.querySelector('.env-input-key');
            if (keyInp && keyInp.value.trim() === item.key) {
              existing = wrap;
            }
          });

          if (existing) {
            var valInp = existing.querySelector('.env-input-value');
            if (valInp) {
              valInp.value = item.value;
              valInp.dispatchEvent(new Event('input'));
            }
          } else {
            var known = knownMap[item.key] || {};
            addRow({
              key: item.key,
              value: item.value,
              is_admin_defined: !!known.admin_defined,
              sensitive: known.sensitive || looksSensitiveEnvName(item.key),
              required: !!known.required,
              description: known.description
            });
          }
        });
        input.value = '';
      };
      reader.readAsText(file);
    });
  });
});
