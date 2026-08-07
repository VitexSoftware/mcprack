// Shared by view_config.html and admin/user_config_view.html. External file
// because the CSP's script-src 'self' (no 'unsafe-inline') silently drops
// inline <script> blocks and onclick="..." handlers alike.
function copyConfig() {
  var textarea = document.getElementById("config-json");
  var status = document.getElementById("copy-status");
  var failMessage = textarea.dataset.copyFailMessage || "Copy failed — select the text manually.";

  function showCopied() {
    status.style.display = "block";
    setTimeout(function () {
      status.style.display = "none";
    }, 3000);
  }

  function fallbackCopy() {
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    try {
      document.execCommand("copy");
      showCopied();
    } catch (err) {
      status.textContent = failMessage;
      status.style.display = "block";
    }
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(textarea.value).then(showCopied, fallbackCopy);
  } else {
    fallbackCopy();
  }
}

document.addEventListener('DOMContentLoaded', function () {
  var textarea = document.getElementById('config-json');
  if (textarea) {
    textarea.addEventListener('click', function () {
      textarea.select();
    });
  }
  var copyButton = document.getElementById('copy-button');
  if (copyButton) {
    copyButton.addEventListener('click', copyConfig);
  }
});
