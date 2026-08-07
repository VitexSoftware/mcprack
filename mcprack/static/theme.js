// Runs synchronously in <head> so the saved theme applies before first
// paint (must stay an external file — the CSP's script-src 'self' with no
// 'unsafe-inline' blocks inline <script> blocks and onclick="..." handlers
// alike, which is why this used to silently do nothing).
(function () {
  var saved = localStorage.getItem('mcprack-theme');
  if (saved === 'light' || saved === 'dark') {
    document.documentElement.setAttribute('data-theme', saved);
  }
})();

function toggleTheme() {
  var root = document.documentElement;
  var current = root.getAttribute('data-theme');
  if (!current) {
    var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    current = prefersDark ? 'dark' : 'light';
  }
  var next = current === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  localStorage.setItem('mcprack-theme', next);
}

function toggleUserMenu(event) {
  event.preventDefault();
  var dropdown = document.getElementById('userMenuDropdown');
  dropdown.classList.toggle('show');

  // Close menu if clicked outside
  document.addEventListener('click', function closeMenu(e) {
    if (!e.target.closest('.header-user-menu')) {
      dropdown.classList.remove('show');
      document.removeEventListener('click', closeMenu);
    }
  });
}

document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.theme-toggle').forEach(function (btn) {
    btn.addEventListener('click', toggleTheme);
  });
  var userMenuButton = document.querySelector('.header-user-menu-button');
  if (userMenuButton) {
    userMenuButton.addEventListener('click', toggleUserMenu);
  }
});
