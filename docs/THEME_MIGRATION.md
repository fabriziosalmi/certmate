# Theme Migration — decoupling light/dark via CSS-variable tokens

Status: **planning** · Owner: Fabrizio · Created: 2026-05-25

## Goal

Today, changing the theme means editing colors across ~19 templates and the
frontend JS. This migration makes a single block of CSS custom properties the
source of truth for the whole palette, so retheming (or adding a new theme)
means editing `:root` / `.dark` in one file — not hundreds of call sites.

## Baseline (measured 2026-05-25)

| Metric | Value |
|---|---|
| Color-class references in templates | ~3,197 across 19 files |
| `dark:` variant pairs in templates | ~1,665 |
| Color classes in app JS (non-vendored) | ~789 (dashboard.js 372, settings.js 150, setup-wizard.js 131, certmate.js 60, client-certs.js 57, …) |
| Hardcoded hex in app JS | ~17 (toast/chart palettes); 80 more in `redoc.standalone.js` are **vendored, ignore** |
| R-3 component classes adopted | `.card` only (12×); `.btn-*`, `.badge-*`, `.form-*` = 0 |

Heaviest files: `partials/settings_dns.html` (635 / 395 dark:), `index.html`
(311 / 150), `partials/settings_deploy.html`, `partials/settings_ca.html`.

## Process risks to fix first

1. **Built CSS is committed by hand.** `package.json` only has `css:build` /
   `css:watch`; no CI rebuilds `static/css/tailwind.min.css`. Editing
   `input.css` without rebuilding silently ships stale CSS. → add CI build +
   freshness check in Phase 0.
2. **~3,200 manual edits = guaranteed regressions.** Need a visual baseline
   (light+dark screenshots of every page) and a semi-automatic codemod for the
   mechanical `dark:` pairs, not blind find-replace.

## Strategy: CSS custom properties as single source

shadcn-style on Tailwind v3: colors become CSS variables in `:root` / `.dark`,
exposed to Tailwind as semantic tokens (HSL channel-triplets so the `/opacity`
utilities keep working). The ~1,665 `dark:` pairs collapse to single classes.

### Proposed token map

| Tailwind token | Replaces (examples) | Use |
|---|---|---|
| `bg-background` | `bg-gray-50 dark:bg-surface-dark` | page |
| `bg-surface` | `bg-white dark:bg-surface-card` | card |
| `bg-surface-2` | `bg-gray-100 dark:bg-gray-800` | elevated |
| `text-foreground` | `text-gray-900 dark:text-white` | primary text |
| `text-muted` | `text-gray-500 dark:text-gray-400` | secondary text |
| `border-border` | `border-gray-200 dark:border-gray-700` | borders |
| `bg-primary` / `text-primary` | brand (now var-backed) | brand |
| `*-success/warning/danger/info` | green=valid, red=expired… | **status, not surfaces** |

## Phases

Each phase = one atomic commit (split partials in Phase 3 into their own
commits). Phases group into one or more `vX.Y.Z` release PRs.

### Phase 0 — Foundations & guardrails (no visual change)
- [x] CI step runs `npm run css:build` and fails if `tailwind.min.css` is stale (`git diff --exit-code`). → `frontend-css` job in `.github/workflows/ci.yml`. The committed bundle was already drifted; rebuilt and committed.
- [x] Define token layer: CSS vars in `:root` / `.dark` (input.css) + mapping in `tailwind.config.js`, **alongside** the existing palette — no templates touched yet. Tokens: `bg-background`, `bg-surface`, `bg-surface-2`, `text-foreground`, `text-muted`, `border-border` (safelisted).
- [x] Write the codemod: `scripts/theme_codemod.py` — mapping table of recurring `dark:` pairs → tokens, dry-run report + `--apply`. Ambiguity report below.
- [x] Screenshot-baseline tooling: `scripts/theme_baseline.py` — builds Docker with a fresh ephemeral data dir, bootstraps a throwaway admin, captures every real UI page in light + dark. Re-run after each phase and diff. **Capture run still pending** (needs `playwright install chromium` + a Docker build locally).

#### Baseline scope (real pages only)
Captured: `/` (setup, then index), `/login`, `/settings`, `/help`, `/activity`, `/redoc` — 7 pages × light/dark.

> **Finding (out of scope, flagged):** the routes `/certificates` and `/audit` in `modules/web/ui_routes.py:25-41` render `certificates.html` / `audit.html`, which **do not exist** — both 500. Dead routes, excluded from the baseline. Worth a separate fix (remove the routes or restore the templates).

#### Codemod usage
```
python scripts/theme_codemod.py                     # dry-run report, all templates
python scripts/theme_codemod.py templates/base.html # report, one file
python scripts/theme_codemod.py --apply templates/base.html
```
After every `--apply`: `npm run css:build`, diff against baseline, review residual `dark:` variants.

#### Report snapshot (2026-05-25)
**607 pairs auto-collapse** out of ~1,665 `dark:` variants:

| Token | Pairs |
|---|---|
| `text-muted` | 203 |
| `border-border` | 169 |
| `text-foreground` | 141 |
| `bg-surface` | 77 |
| `bg-surface-2` | 16 |
| `bg-background` | 1 |

**557 occurrences / 29 variants are unmapped** — design decisions for the Phase 1 pilot, not auto-guessed:

- `dark:bg-gray-700` (137): pairs with `bg-white` (cards/inputs) **and** `bg-gray-50` — decide surface vs surface-2 per context.
- `dark:text-white` (120): the ones paired with `text-gray-900` already map to `text-foreground`; the rest are always-white text on colored backgrounds — likely leave as-is.
- `dark:text-gray-300` (112): mostly `text-gray-700 dark:text-gray-300` = the form-label pattern — decide a dedicated label token vs `text-muted`/`text-foreground`.
- `dark:border-gray-600` (41), `dark:text-gray-200` (39), opacity-suffixed surfaces (`dark:bg-gray-700/50` etc.), and `dark:border-white/5`.

A handful of leftovers (`dark:text-gray-400{%`, `dark:text-gray-300'`) are class attributes containing Jinja/JS expressions — migrate by hand.

### Phase 1 — Pilot: shell + primitives
- [x] Migrate `base.html` (nav/header/footer/tab bar) to tokens. 19 pairs collapsed; token values match originals exactly.
- [x] Migrate `login.html` to tokens. 12 pairs collapsed.
- [ ] Adopt `.btn` / `.form-*` component classes (deferred — pilot used tokens only; the login inputs differ in sizing from `.form-input`, so component adoption is its own step).
- [x] Validate light/dark parity. Verified live in Docker (base.html + login.html, both themes) — pilot accepted.

#### Open design decisions (surfaced by the pilot)
1. **Form-label text** (`text-gray-700 dark:text-gray-300`). **RESOLVED in Phase 5 → option (b):** added `--color-label` token at the exact gray-700/gray-300 values (faithful, no visual change) and migrated all 137 occurrences to `text-label`. Folding into `text-foreground` was rejected (would darken light mode 27%→11% L).
2. **Border unification**: `border-gray-300` (inputs) now maps to `border-border` (= gray-200), so input borders lighten one step in light mode. Accepted for the pilot (single border token is the goal); revisit with `--color-input-border` only if review dislikes it.
3. **Glass inputs / `dark:border-white/5` hairline / hover: variants / status colors**: intentionally NOT tokenized — glass controls have no light counterpart, the white/5 hairline is the canonical `.card` edge, and hover/status need their own variant-token pass (a later phase).

### Phase 2 — Dashboard ✅
- [x] `index.html` (dashboard chrome): create-cert form, list/stat cards, table headers + divides, detail panel, modals. Alpine `:class` ternaries and `divide-border` handled by hand.
- [x] `static/js/dashboard.js`: JS-rendered rows, stats, empty/welcome states, detail panel, alias-check output. `node --check` clean.
- Health/deployment status colors (green/amber/red/blue) deliberately left as literal status colors — they carry meaning and get a dedicated status-token pass later, not surface tokens.
- Glass form inputs (`dark:bg-gray-700`/`dark:text-white`), form labels, and hover: variants left for their own treatment (consistent with the pilot).

### Phase 3 — Settings cluster ✅
- [x] `settings.html` + 10 partials + `_modal`: 441 pairs collapsed. Alpine `:class` interior pairs tokenized by the codemod (quotes glue only the branch-edge classes); ternary structure verified intact.
- [x] `settings.js` + `setup-wizard.js`: 49 pairs, `node --check` clean. The other `settings-*.js` carry no color classes.
- Left as-is (consistent with prior phases): glass inputs (`dark:bg-gray-700` ~99), form labels (`dark:text-gray-300` ~78, deferred), status badges, opacity surfaces, hover: variants, and ternary branch-edge classes.

### Phase 4 — Remaining pages ✅
- [x] Templates: activity, help, setup, `_client_certs` (123 pairs; no Alpine ternaries here).
- [x] JS: client-certs.js, cmd-palette.js, report-issue.js, shortcuts.js (26 pairs, `node --check` clean). setup-wizard.js was already done in Phase 3.
- Same carve-outs as before: glass inputs, body/label grays, opacity surfaces, status colors, hover:, and string-concatenation-boundary classes.

### Phase 5 — Cleanup & lock-in ✅
- [x] Closed the label decision: `text-label` token + 137 sites migrated (see above).
- [x] Caught the codemod blind spot: it only scanned `class="..."`, missing `className='...'` assignments and JS string concatenation. Added a **boundary-aware literal-pass** (collapses adjacent `LIGHT DARK` substrings in any context) + the `--check` gate. Re-running the full sweep collapsed the remaining JS pairs (confirm/prompt dialog, report-issue + shortcuts modals).
- [x] Removed unused legacy aliases `success`/`warning`/`danger` from `tailwind.config.js` (0 call sites). Kept `primary` (~375) and `secondary` (gradients).
- [x] **CI guardrail**: `python3 scripts/theme_codemod.py --check` in the `frontend-css` job — fails the build if any collapsible light+dark pair is reintroduced in a template or first-party JS file.
- **JS hex left as-is, by design:** the `#60a5fa`/etc. palette in `certmate.js` is the **debug-console logger** on a fixed always-dark surface (`bg-black`); `TOAST_COLORS` are literal status classes. Both are theme-independent status accents — conventionally not part of light/dark theming — so they stay literal rather than becoming theme tokens. A future **status-token pass** (success/warning/danger/info as vars) is the place to unify these if ever wanted.
- Baseline refresh: optional; not run (capture was deferred — live Docker verification used at each phase instead).

## Status colors — explicit non-goal
Health/deployment/badge colors (green/amber/red/blue, with their `dark:`
variants) were deliberately **not** tokenized in any phase. They carry
semantic meaning and are conventionally theme-invariant. The codemod's
`_STATUS_RE` excludes them, and `--check` does not flag them. Tokenizing them
is a separate, optional "status-token pass", out of scope for this migration.

## Workflow alignment
- Zero emoji in commits/PRs/release notes.
- Atomic commits (one per phase, or per partial in Phase 3); one PR per release.
- Before public push: Docker smoke + real cert issuance against Fab's domain with random subdomains.
