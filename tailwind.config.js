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
        success: '#22c55e',
        warning: '#f59e0b',
        danger: '#ef4444',
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
      },
    },
  },
  plugins: [],
}
