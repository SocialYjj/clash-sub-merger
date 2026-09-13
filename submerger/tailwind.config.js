/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Semantic theme tokens. Values live in CSS variables declared in
        // src/index.css (`:root` = dark defaults, `:root.light` = light theme,
        // toggled via the `light` class on <html>). Every token maps to an
        // `rgb(var(--c-x) / <alpha-value>)` triple so opacity modifiers such
        // as bg-surface/50 or ring-ink/5 keep working in both themes.
        base: 'rgb(var(--c-base) / <alpha-value>)', // page background
        surface: 'rgb(var(--c-surface) / <alpha-value>)', // raised chrome: sidebar, solid cards
        'surface-2': 'rgb(var(--c-surface-2) / <alpha-value>)', // cards, modals, nested panels
        'surface-3': 'rgb(var(--c-surface-3) / <alpha-value>)', // inputs, nested fills, hover lifts
        'surface-4': 'rgb(var(--c-surface-4) / <alpha-value>)', // deepest fills: avatars, badges
        line: 'rgb(var(--c-line) / <alpha-value>)', // primary borders
        'line-strong': 'rgb(var(--c-line-strong) / <alpha-value>)', // input/checkbox borders
        'line-soft': 'rgb(var(--c-line-soft) / <alpha-value>)', // subtle dividers
        ink: 'rgb(var(--c-ink) / <alpha-value>)', // primary text (also translucent foreground layers)
        'ink-hi': 'rgb(var(--c-ink-hi) / <alpha-value>)', // emphasized body text
        'ink-2': 'rgb(var(--c-ink-2) / <alpha-value>)', // secondary text
        'ink-3': 'rgb(var(--c-ink-3) / <alpha-value>)', // muted text
        'ink-4': 'rgb(var(--c-ink-4) / <alpha-value>)', // disabled / decorative text
        scrim: 'rgb(var(--c-scrim) / <alpha-value>)', // modal overlays
        glass: {
          100: 'rgba(255, 255, 255, 0.1)',
          200: 'rgba(255, 255, 255, 0.2)',
          300: 'rgba(255, 255, 255, 0.3)',
        }
      },
    },
  },
  plugins: [],
}
