// Apply the persisted (or system) theme before first paint to avoid a
// flash of the wrong theme. Mirrors the resolution logic in
// src/utils/theme.js: localStorage `theme`, else prefers-color-scheme.
// Loaded as an external same-origin script: the backend CSP forbids
// inline scripts (script-src 'self').
(function () {
  try {
    var t = localStorage.getItem('theme');
    if (t === 'light' || (t !== 'dark' && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches)) {
      document.documentElement.classList.add('light');
    }
  } catch (e) { /* ignore */ }
})();
