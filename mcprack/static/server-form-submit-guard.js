// Disable the submit button while the server registration/edit form is
// submitting, to prevent double-submit. External file because CSP's
// script-src 'self' silently drops inline <script> blocks (see
// confirm-submit.js). Loading-spinner overlay removal is already handled
// globally by loading-spinner.js's 'load' listener - no need to duplicate it
// here.
document.addEventListener('DOMContentLoaded', function () {
  const form = document.querySelector('form');
  if (form) {
    form.addEventListener('submit', function () {
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.style.opacity = '0.6';
        submitBtn.style.cursor = 'not-allowed';
      }
    });
  }
});
