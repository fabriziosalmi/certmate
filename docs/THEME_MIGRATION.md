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
1. **Form-label text** (`text-gray-700 dark:text-gray-300`, ~114 occurrences app-wide). Left unmigrated. Options: (a) fold into `text-foreground` — but light goes 27%→11% L, a *visible* darkening, so not faithful; (b) add a third neutral text token (`--color-label` = gray-700/gray-300). Leaning (b); decide once the baseline lets us compare. Until then the codemod has **no** mapping for this pair (correct — it stays in the ambiguity report).
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

### Phase 4 — Remaining pages
- [x] (setup-wizard.js already done in Phase 3)
- [ ] activity, help, setup, `_client_certs`, client-certs.js, cmd-palette.js, report-issue.js, shortcuts.js.

### Phase 5 — Cleanup & lock-in
- [ ] Move JS hex palettes (toast/chart in `certmate.js:356`) to read from CSS vars / token map.
- [ ] Remove legacy aliases + now-unused scales from `tailwind.config.js`.
- [ ] CI guardrail: grep that fails on new `dark:bg-gray-*` / hardcoded hex in templates.
- [ ] Refresh baseline as the final reference.

## Workflow alignment
- Zero emoji in commits/PRs/release notes.
- Atomic commits (one per phase, or per partial in Phase 3); one PR per release.
- Before public push: Docker smoke + real cert issuance against Fab's domain with random subdomains.
