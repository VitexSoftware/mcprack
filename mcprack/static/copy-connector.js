// Powers the per-server "Copy" buttons in the "Add as Individual
// Connectors" section of catalog.html (name + URL, for clients like Claude
// Desktop's "Add custom connector" dialog that want that instead of a JSON
// config). External file because the CSP's script-src 'self' (no
// 'unsafe-inline') silently drops inline <script> blocks and onclick="..."
// handlers alike - see copy-config.js for the same pattern.
function copyConnectorValue(value, button) {
  var originalLabel = button.textContent;

  function showCopied() {
    button.textContent = "✓";
    setTimeout(function () {
      button.textContent = originalLabel;
    }, 1500);
  }

  function fallbackCopy() {
    var scratch = document.createElement("textarea");
    scratch.value = value;
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    document.body.appendChild(scratch);
    scratch.focus();
    scratch.select();
    try {
      document.execCommand("copy");
      showCopied();
    } catch (err) {
      // Nothing else to fall back to - the value is still visible in the
      // row for the user to select and copy by hand.
    }
    document.body.removeChild(scratch);
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(value).then(showCopied, fallbackCopy);
  } else {
    fallbackCopy();
  }
}

document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".copy-btn[data-copy-value]").forEach(function (button) {
    button.addEventListener("click", function () {
      copyConnectorValue(button.dataset.copyValue, button);
    });
  });
});
