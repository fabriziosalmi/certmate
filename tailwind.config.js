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
      // one motion signature. Exposes `ease-premium` and `transition`-aware
      // utilities; the same curve is bound to --ease-premium in input.css
      // for the hand-written keyframe/transition rules.
      transitionTimingFunction: {
        premium: 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
      colors: {
        // Accent aliases — now wired to the brand ramp (Sprint 1, §5).
        // `primary`/`secondary` were flat blues unrelated to the HSL ramp
        // below; pointing them at brand-600/700 gives every `*-primary`
        // call site (375 of them) and the `.btn-primary` hover the deeper,
        // purpose-built blue for free. A per-theme accent (brand-400 on
        // dark) lands with the semantic CSS-var layer in a later sprint.
        primary: 'hsl(216, 76%, 43%)',   // brand-600
        secondary: 'hsl(218, 72%, 35%)', // brand-700
        // State groups (Sprint 4). DEFAULT keeps the legacy flat hex so
        // bg-success / text-danger etc. are unchanged; the surface/line/
        // fg/strong keys map to the callout CSS vars for the tokenised
        // info-box system (bg-info-surface, text-success-strong, …).
        success: {
          DEFAULT: '#22c55e',
          surface: 'rgb(var(--success-surface) / <alpha-value>)',
          line:    'rgb(var(--success-line) / <alpha-value>)',
          fg:      'rgb(var(--success-fg) / <alpha-value>)',
          strong:  'rgb(var(--success-strong) / <alpha-value>)',
        },
        warning: {
          DEFAULT: '#f59e0b',
          surface: 'rgb(var(--warning-surface) / <alpha-value>)',
          line:    'rgb(var(--warning-line) / <alpha-value>)',
          fg:      'rgb(var(--warning-fg) / <alpha-value>)',
          strong:  'rgb(var(--warning-strong) / <alpha-value>)',
        },
        danger: {
          DEFAULT: '#ef4444',
          surface: 'rgb(var(--danger-surface) / <alpha-value>)',
          line:    'rgb(var(--danger-line) / <alpha-value>)',
          fg:      'rgb(var(--danger-fg) / <alpha-value>)',
          strong:  'rgb(var(--danger-strong) / <alpha-value>)',
        },
        info: {
          surface: 'rgb(var(--info-surface) / <alpha-value>)',
          line:    'rgb(var(--info-line) / <alpha-value>)',
          fg:      'rgb(var(--info-fg) / <alpha-value>)',
          strong:  'rgb(var(--info-strong) / <alpha-value>)',
        },
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
        // Layered surface system for dark mode depth
        surface: {
          light: 'hsl(220, 20%, 97%)',
          dark:  'hsl(222, 32%, 8%)',
          card:  'hsl(222, 24%, 13%)',
          elevated: 'hsl(222, 20%, 17%)',
        },

        // ── Semantic tokens (Sprint 2, §2) ──────────────────────
        // Map onto the CSS vars defined in input.css. Using the
        // `rgb(var() / <alpha-value>)` form keeps every opacity
        // modifier working (bg-accent/10, border-line/60). These
        // replace the bg-white/dark:bg-… + text-gray-900/dark:… +
        // border-gray-200/dark:white-… triplets as templates migrate.
        base:    'rgb(var(--bg-base) / <alpha-value>)',
        card:    'rgb(var(--bg-card) / <alpha-value>)',
        inset:   'rgb(var(--bg-inset) / <alpha-value>)',
        'inset-hover': 'rgb(var(--bg-inset-hover) / <alpha-value>)',
        field:   'rgb(var(--bg-field) / <alpha-value>)',
        raised:  'rgb(var(--bg-raised) / <alpha-value>)',
        fg: {
          DEFAULT: 'rgb(var(--fg) / <alpha-value>)',
          body:    'rgb(var(--fg-body) / <alpha-value>)',
          muted:   'rgb(var(--fg-muted) / <alpha-value>)',
          subtle:  'rgb(var(--fg-subtle) / <alpha-value>)',
        },
        line: {
          DEFAULT: 'rgb(var(--border) / <alpha-value>)',
          strong:  'rgb(var(--border-strong) / <alpha-value>)',
        },
        accent: 'rgb(var(--accent) / <alpha-value>)',
      },
    },
  },
  plugins: [],
}
