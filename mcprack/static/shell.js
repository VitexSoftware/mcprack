// App shell: sidebar collapse (desktop) / overlay (mobile). External file —
// CSP script-src 'self' forbids inline handlers.
(function () {
  var KEY = 'mcprack-sidebar-collapsed';
  var root = document.documentElement;

  function get() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function set(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* ignore */ } }

  if (get() === '1') { root.classList.add('sidebar-collapsed'); }

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.querySelector('.sidebar-toggle');
    var scrim = document.querySelector('.sidebar-scrim');
    if (!btn) { return; }
    var mobile = window.matchMedia('(max-width: 800px)');

    btn.addEventListener('click', function () {
      if (mobile.matches) {
        root.classList.toggle('sidebar-open');
      } else {
        var c = root.classList.toggle('sidebar-collapsed');
        set(c ? '1' : '0');
      }
      btn.setAttribute('aria-expanded',
        String(mobile.matches ? root.classList.contains('sidebar-open')
                              : !root.classList.contains('sidebar-collapsed')));
    });
    if (scrim) {
      scrim.addEventListener('click', function () { root.classList.remove('sidebar-open'); });
    }
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { root.classList.remove('sidebar-open'); }
    });
  });
})();
