/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html", "./static/js/**/*.js"],
  // R-3 component classes are defined in input.css under @layer components.
  // Until the inline-class call sites are migrated to use them, the content
  // scan finds 0 references for variants like .btn-primary / .badge-success
  // and PurgeCSS drops them from the built bundle. This safelist forces
  // every R-3 class through so migration can land one call site at a time
  // without having to ship a dummy reference first.
  safelist: [
    'btn', 'btn-primary', 'btn-secondary', 'btn-danger', 'btn-ghost',
    'btn-sm', 'btn-lg',
    'card',
    'badge', 'badge-success', 'badge-warning', 'badge-error', 'badge-info',
    'form-input', 'form-select', 'form-label',
    // Semantic theme tokens — same rationale: keep them in the bundle so
    // template call sites can migrate onto them incrementally. Remove the
    // safelist once adoption is broad enough for the content scan to find
    // each utility on its own (THEME_MIGRATION.md, final phase).
    'bg-background', 'bg-surface', 'bg-surface-2',
    'text-foreground', 'text-muted', 'text-label', 'border-border', 'divide-border',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Consolas', 'monospace'],
      },
      // Single premium easing curve (ease-out-expo). Mirrors the literal
      // cubic-bezier already used by .panel-slide so entrances/exits share
      // one motion signature; also bound to --ease-premium in input.css.
      transitionTimingFunction: {
        premium: 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
      colors: {
        // Semantic theme tokens — backed by CSS variables defined in
        // input.css (:root / .dark). The `<alpha-value>` placeholder lets
        // the /opacity utilities (e.g. bg-surface/50) keep working. These
        // are the migration target: `bg-white dark:bg-surface-card` →
        // `bg-surface`, collapsing the dark: pairs. See THEME_MIGRATION.md.
        background:  'hsl(var(--color-background) / <alpha-value>)',
        foreground:  'hsl(var(--color-foreground) / <alpha-value>)',
        muted:       'hsl(var(--color-muted) / <alpha-value>)',
        label:       'hsl(var(--color-label) / <alpha-value>)',
        border:      {
          DEFAULT: 'hsl(var(--color-border) / <alpha-value>)',
          strong:  'hsl(var(--color-border-strong) / <alpha-value>)',  // hover/emphasis border
        },
        input:       'hsl(var(--color-input) / <alpha-value>)',   // form field fill (white / gray-700)
        sunken:      'hsl(var(--color-sunken) / <alpha-value>)',  // recessed fill (gray-50 / gray-700)
        hover:       'hsl(var(--color-hover) / <alpha-value>)',   // interactive hover wash (gray-100 / gray-700)
        accent:      'hsl(var(--color-accent) / <alpha-value>)',  // on-surface accent, blue-600 -> blue-400 on dark (nav/links)
        // Status callout tokens (Phase 6) — surface/line/fg/strong, var-backed
        // and theme-aware. Re-add success/warning/danger as token GROUPS (the
        // old flat aliases were removed for having zero call sites); the
        // green/red/amber/blue info-boxes now collapse onto these.
        info:    { surface: 'hsl(var(--color-info-surface) / <alpha-value>)',    line: 'hsl(var(--color-info-line) / <alpha-value>)',    fg: 'hsl(var(--color-info-fg) / <alpha-value>)',    strong: 'hsl(var(--color-info-strong) / <alpha-value>)' },
        success: { surface: 'hsl(var(--color-success-surface) / <alpha-value>)', line: 'hsl(var(--color-success-line) / <alpha-value>)', fg: 'hsl(var(--color-success-fg) / <alpha-value>)', strong: 'hsl(var(--color-success-strong) / <alpha-value>)' },
        warning: { surface: 'hsl(var(--color-warning-surface) / <alpha-value>)', line: 'hsl(var(--color-warning-line) / <alpha-value>)', fg: 'hsl(var(--color-warning-fg) / <alpha-value>)', strong: 'hsl(var(--color-warning-strong) / <alpha-value>)' },
        danger:  { surface: 'hsl(var(--color-danger-surface) / <alpha-value>)',  line: 'hsl(var(--color-danger-line) / <alpha-value>)',  fg: 'hsl(var(--color-danger-fg) / <alpha-value>)',  strong: 'hsl(var(--color-danger-strong) / <alpha-value>)' },
        // Brand aliases (used widely: bg-primary/text-primary ~375, gradients
        // from-secondary).
        primary: 'hsl(216, 76%, 43%)',   // brand-600 — was flat #3b82f6
        secondary: 'hsl(218, 72%, 35%)', // brand-700 (btn-primary hover)
        // Brand palette — HSL-based, deeper than raw Tailwind
        brand: {
          50:  'hsl(210, 100%, 97%)',
          100: 'hsl(210, 96%, 93%)',
          200: 'hsl(210, 92%, 85%)',
          300: 'hsl(210, 88%, 73%)',
          400: 'hsl(212, 84%, 62%)',
          500: 'hsl(214, 80%, 52%)',
          600: 'hsl(216, 76%, 43%)',
          700: 'hsl(218, 72%, 35%)',
          800: 'hsl(220, 68%, 28%)',
          900: 'hsl(222, 64%, 20%)',
          950: 'hsl(224, 60%, 12%)',
        },
        // Layered surface system for dark mode depth.
        // DEFAULT + `2` are var-backed theme tokens (bg-surface,
        // bg-surface-2); light/dark/card/elevated are the existing fixed
        // values kept for backward compat until call sites migrate.
        surface: {
          DEFAULT: 'hsl(var(--color-surface) / <alpha-value>)',
          2:       'hsl(var(--color-surface-2) / <alpha-value>)',
          light: 'hsl(220, 20%, 97%)',
          dark:  'hsl(222, 32%, 8%)',
          card:  'hsl(222, 24%, 13%)',
          elevated: 'hsl(222, 20%, 17%)',
        },
      },
    },
  },
  plugins: [],
}
