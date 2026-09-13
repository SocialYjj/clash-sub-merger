import { useEffect, useState } from 'react';

const THEME_STORAGE_KEY = 'theme';
const THEME_CHANGE_EVENT = 'themechange';

/**
 * Theme utilities.
 *
 * Theme resolution order:
 *   1. localStorage key `theme` ('light' | 'dark')
 *   2. `prefers-color-scheme` media query
 *
 * The resolved theme is applied by toggling the `light` class on <html>; the
 * dark theme is the default (no class). index.html contains an inline copy of
 * the resolution logic so the class is present before first paint.
 */

export function getStoredTheme() {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return stored === 'light' || stored === 'dark' ? stored : null;
  } catch {
    return null;
  }
}

export function getSystemTheme() {
  try {
    return window.matchMedia?.('(prefers-color-scheme: light)').matches
      ? 'light'
      : 'dark';
  } catch {
    return 'dark';
  }
}

export function getActiveTheme() {
  return getStoredTheme() ?? getSystemTheme();
}

export function applyTheme(theme) {
  document.documentElement.classList.toggle('light', theme === 'light');
}

export function setTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch { /* storage unavailable (private mode etc.) — keep runtime-only */ }
  applyTheme(theme);
  window.dispatchEvent(new CustomEvent(THEME_CHANGE_EVENT, { detail: theme }));
}

export function toggleTheme() {
  setTheme(getActiveTheme() === 'light' ? 'dark' : 'light');
}

/**
 * React hook returning the active theme ('light' | 'dark') and re-rendering
 * on explicit theme changes and on OS scheme changes while no explicit
 * choice is stored.
 */
export function useTheme() {
  const [theme, setThemeState] = useState(getActiveTheme);

  useEffect(() => {
    const onThemeChange = (event) => {
      setThemeState(event.detail ?? getActiveTheme());
    };
    const onSystemChange = () => {
      if (!getStoredTheme()) {
        setThemeState(getSystemTheme());
      }
    };

    window.addEventListener(THEME_CHANGE_EVENT, onThemeChange);
    let media;
    try {
      media = window.matchMedia('(prefers-color-scheme: light)');
      media.addEventListener('change', onSystemChange);
    } catch { /* very old browsers: system changes are ignored */ }

    return () => {
      window.removeEventListener(THEME_CHANGE_EVENT, onThemeChange);
      media?.removeEventListener?.('change', onSystemChange);
    };
  }, []);

  return theme;
}
