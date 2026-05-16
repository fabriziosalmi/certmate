## v2.5.3 (Patch — multi-pass audit response + draconian test coverage push)

Twenty atomic commits over a single branch, the result of running every
finding from a multi-source audit (security CRITICAL/HIGH/MEDIUM/LOW + a
performance audit + a UI audit) through empirical verification before
acting. ~62 audit findings were checked; only the ones that survived
verification turned into commits. Honest summary: 8 real bugs fixed, 10
parziali / defense-in-depth landed, 35 false positives documented, the
rest pre-existing-and-deferred.

The release also nearly doubles unit test coverage on previously-uncovered
critical-path modules: +160 new tests across 5 new test files (570 unit
tests total, up from 410).

### Real bug fixes

- **`fix(certificates)`: race condition on metadata RMW** —
  `record_backend_deployment_status` and `record_browser_deployment_status`
  did load → mutate → save without holding the per-domain lock that already
  exists in the class. Two concurrent deployment-status updates lost one
  of the writes silently.

- **`fix(deployer)`: deploy-hook parameter-expansion bypass** — the
  safe-vars regex `\$\{?CERTMATE_[A-Z_]+\}?` accepted partial brace forms,
  letting `${CERTMATE_FOO:-/etc/passwd}` and the other bash expansion
  operators smuggle arbitrary paths past the validator. Closing-brace is
  now required immediately after the var name.

- **`fix(file_operations)`: UnboundLocalError in safe_file_write** —
  if `mkstemp()` raised before `temp_file` was bound, the except handlers
  referenced an unbound local, masking the actual OSError. Operators saw
  "no local variable temp_file" instead of "No space left on device".

- **`fix(certificates)`: corrupt metadata.json silently clobbered** —
  `_load_metadata` swallowed `JSONDecodeError` along with everything else
  and returned `{}`; the next save would overwrite the only copy. Now
  JSON corruption is quarantined to `metadata.json.corrupt-<utc>` and
  logged at ERROR, separately from IO errors which still get the empty-
  dict fallback.

- **`fix(health)`: scheduler-setup failure now surfaces on /health** —
  if APScheduler setup raised, the only signal was a single ERROR log
  line. `/health` now reports `scheduler: failed` with the exception
  message and timestamp; admins can detect a broken scheduler without
  grepping logs.

- **`fix(tests)`: stale UI test assertions rewritten against v2.5.x** —
  four `tests/test_ui.py` assertions had been failing on main since v2.5.0
  rewrote the help page and the dashboard create-form toggle. Updated
  them to current selectors + handle the setup-wizard overlay during
  Playwright clicks. e2e suite: 112 passed, 0 failed.

### Performance fixes

- **`perf(settings)`: request-scoped cache for load_settings** — typical
  `/api/certificates` requests called `settings_manager.load_settings()`
  ~100 times when listing 50 certs. Now cached on `flask.g` for the
  request's lifetime; first call hits disk, subsequent calls return a
  deepcopy. ~15-30ms saved per typical request; more at scale.

- **`perf(renewal)`: thread settings through check_renewals** — the
  request-scoped cache doesn't fire in background threads. Pass the
  once-loaded settings down to `get_certificate_info` so the hourly
  renewal job hits disk once, not N times.

- **`perf(probe)`: TLS probe timeout 5s → 3s + slow-probe warning** —
  unreachable hosts block a Flask worker for the full timeout. Tightened
  default + added `CERTMATE_TLS_PROBE_TIMEOUT_SECONDS` env var (clamped
  to `[1, 30]`) + WARN log when a probe takes more than 1s.

- **`perf(rate-limit)`: bound login-attempt dicts** — botnet IP rotation
  could grow `_login_attempts_by_ip` unbounded. Sweep empty buckets when
  either dict crosses the 10K soft cap.

- **`perf(backup)`: single iterdir pass in create_unified_backup** —
  `cert_dir.iterdir()` was called twice. Now once.

### Hardening (defense-in-depth)

- **`chore(hardening)`: SQLite WAL fallback detection** — `PRAGMA
  journal_mode=WAL` silently falls back on filesystems that don't support
  WAL (NFS, network mounts). Now logs a warning at startup if the effective
  mode is anything but WAL.
- **`chore(hardening)`: deploy-hook timeout int coercion** — `_run_hook`
  read `hook.get('timeout')` without `int()`; a string timeout from a
  hand-edited settings.json crashed the renewal worker. Coerce defensively.
- **`chore(ux)`: SSE retry give-up after 10 failures** — logged-out tabs
  produced a 401-every-30s loop indefinitely. Now gives up after ~3 minutes
  of exponential retries.
- **`chore(ux)`: MutationObserver readyState guard** — modal focus-trap
  observer was attached in `DOMContentLoaded` only; if certmate.js loaded
  later the listener never ran. Mirror the readyState pattern used by
  `CM.refreshRole`.
- **`chore(ux)`: confirm dialog before clear-cache** — settings.js's
  `clearDeploymentCache` now matches the dashboard's `invalidateAllCache`
  with a `CertMate.confirm()` step.

### Documentation

- **`docs(installation)`: document `BEHIND_PROXY=true`** — undocumented
  before; without it, per-client rate limiting collapses to per-proxy
  when CertMate sits behind nginx / traefik / cloudflare.
- **`docs(installation)`: NFS guidance** — Python blocking I/O semantics
  + recommended `soft,timeo=30,retrans=3` mount options.
- **`docs`: neutralize DNS provider counts** — README and docs/ cited
  22/23/24 inconsistently. Switched prose to neutral wording; canonical
  number lives only in the table at `docs/dns-providers.md`. Same change
  pushed to the GitHub Wiki.

### Test coverage push (the draconian part)

Five new test files, +160 unit tests on previously-uncovered modules:

| Module | Before | New tests | Focus |
|---|---|---|---|
| `modules/core/private_ca.py` | 0% | 34 | CA shape (RSA-4096, BC=CA-true, KU.keyCertSign), CSR signing, signature verification, CRL generation |
| `modules/core/csr_handler.py` | 0% | 38 | Validator entry-point: empty/garbage/truncated PEM, no-CN, control-char CN attacks (NUL, newline, CR), SAN ceiling at 100 |
| `modules/core/ocsp_crl.py` | 0% | 20 | Status branches (good/revoked/unknown), CRL signature verification, manager-failure → 'unknown' not 'good' |
| `modules/core/storage_backends.py` | ~25% | 56 | _is_transient heuristic, _with_retry decorator, _validate_storage_domain, Azure secret-name collision avoidance, StorageManager dispatch + fallback |
| `modules/core/certificates.py` (gaps) | ~40% | 12 | Concurrent-issuance non-blocking lock, DNS alias status surfacing (ok/missing/mismatch/error), trailing-dot normalisation |

Tests use real `cryptography` primitives (no mocked crypto operations);
cloud-SDK request paths deliberately out of scope (they're covered by
e2e). Total unit suite: 570 passed in ~12s.

### Audit precision summary (transparency)

Out of ~62 audit findings across 7 lists (CRITICAL/HIGH/MEDIUM/LOW for
security + perf-CRITICAL/HIGH + perf-MEDIUM/LOW + UI CRITICAL/HIGH):
- 8 true positives → fixes shipped
- 10 partial / defense-in-depth → hardening shipped
- 35 false positives → documented in commit messages why they were skipped
- 2 already fixed incidentally during earlier waves
- 7 YAGNI / over-engineering → deferred

Each audit list was verified empirically (test scripts in Python where
applicable) before deciding whether to commit. The audit author appears
to have pattern-matched on code SHAPES (`innerHTML`, no .catch, no
debounce, `except Exception`, `mkstemp`, etc.) without verifying the
actual behaviour — the most clamorous claim ("validator allows
backticks") was falsifiable in two lines of Python.

### Backward compatibility

- No API breakage. No data migration. No new required env vars.
- New optional env vars: `BEHIND_PROXY`, `CERTMATE_TLS_PROBE_TIMEOUT_SECONDS`.
- `/health` adds two new fields when the scheduler is in failure state
  (`checks.scheduler == "failed"` plus `scheduler_error` + `scheduler_failed_at`).
  Existing consumers that only read `status` and `checks.scheduler` see no
  contract change for the success path.

### Test results

- 570 unit tests pass in ~12s
- 112 e2e tests pass (real Cloudflare DNS-01 issuance + Playwright UI), 0 failures

---

## v2.5.2 (Patch — issue triage: 2 community bugs + 1 inconsistent web-auth response)

Three scoped fixes from the v2.5.x issue triage. Each commit is one fix, mergeable in isolation. No API breakage, no data migration, no new env vars.

### `fix(renew)` — pass `--no-random-sleep-on-renew` to certbot (closes [#171](https://github.com/fabriziosalmi/certmate/issues/171))

`certbot renew` injects a random sleep of up to ~8 minutes before contacting the ACME server. The default exists to avoid stampeding Let's Encrypt when run from a flock of crontabs; CertMate's renewal endpoint is always invoked interactively from the UI / API, so the sleep doesn't help — it makes the POST time out as `NETWORK_ERROR` in the browser even though certbot eventually completes the renewal in the background. End state: cert refreshes on disk but the user sees a flat error.

Add `--no-random-sleep-on-renew` unconditionally to the `cmd` built in [`modules/core/certificates.py:875-883`](modules/core/certificates.py#L875-L883). The flag has been in certbot since 1.5 (2020), so no version concern.

Regression test: [`tests/test_issue171_no_random_sleep_renew.py`](tests/test_issue171_no_random_sleep_renew.py) mocks the shell executor, drives `renew_certificate()` against a fake on-disk cert, and asserts the cmd list contains the flag. Pins the behaviour so a future refactor of the cmd construction cannot quietly drop it.

Reporter: [@ITJamie](https://github.com/ITJamie).

### `fix(dashboard)` — give Domain column a `w-1/2` width hint (closes [#170](https://github.com/fabriziosalmi/certmate/issues/170))

The Domain column used `max-w-0` + `truncate` on the `<td>` — the standard Tailwind technique for "let me truncate this cell in a table". It only works when the column has a width to truncate against. With the table's default `table-layout: auto` and no width on the `<th>`, the other `whitespace-nowrap` columns (Status, Expires "May 15, 2026 · 30 days left", Provider, Deployment, Actions) claimed their natural content width first and Domain got the leftover crumbs. On a viewport with all six columns visible the remaining space shrunk well below the width of any realistic FQDN and domain text truncated aggressively.

Add `w-1/2` to the Domain `<th>`. With auto layout this acts as a floor, not a max: Domain claims at least 50% of the table width but can grow when there's spare. On a 1280px viewport that's a 640px floor — comfortably wide for any practical FQDN. The `<td>` keeps `max-w-0` + `truncate` so genuinely long names (rare wildcards under deep subdomains) still clip with an ellipsis.

Reporter: [@ITJamie](https://github.com/ITJamie).

### `fix(auth)` — redirect browser to `/login` on auth failure (was JSON 401)

The `require_role` and `require_auth` decorators returned the API-style JSON
`{"code":"AUTH_HEADER_MISSING","error":"Authorization header required"}`
to every caller that wasn't authenticated, including browsers loading the protected HTML page routes (`/help`, `/settings`, `/audit`, `/activity`, `/redoc`, `/client-certificates`). Users saw the raw JSON body in the tab. The dashboard route `/` already redirected correctly via its hand-rolled flow; the rest were inconsistent.

Add a helper `_is_browser_html_request()` that returns True only when both:
- `request.path` does NOT live under `/api/` (the API surface is always JSON)
- `request.accept_mimetypes` prefers `text/html` over `application/json` (a browser POST that `fetch()`s to `/api/...` is unaffected)

Both decorators use it: on auth failure for browser HTML requests, return `redirect('/login?next=<path>')`; otherwise keep the existing JSON 401 byte-for-byte so curl, fetch, and API clients see no change.

Regression test pins all three branches:
- browser GET `/help` → 302 to `/login?next=/help`
- JSON GET `/help` → 401 JSON, `code=AUTH_HEADER_MISSING`
- browser GET `/api/...` → 401 JSON (never redirected)

Reporter: [@fabriziosalmi](https://github.com/fabriziosalmi) (live observation while testing v2.5.1).

### Tests

Full non-UI suite green (438 passed, 9 skipped, 15 deselected). New test files:
- `tests/test_issue171_no_random_sleep_renew.py` (1 test)
- `tests/test_help_browser_redirect.py` (3 tests)

### Backward compatibility

- Renewal endpoint: same shape, faster response (no 5-8 min stall).
- API responses to `/api/*` paths: byte-identical to v2.5.1.
- Browsers hitting protected HTML routes without a session now get a 302 to `/login?next=<path>` instead of a JSON body. Pre-existing browser behaviour on `/` was already this; v2.5.2 makes the other web routes match.

---

## v2.5.1 (Patch — v2.5.0 follow-up: 9 fixes from manual browser testing)

Nine small, scoped follow-ups caught during the manual browser pass on the v2.5.0 image. Each commit is one fix, mergeable in isolation. No API breakage, no data migration, no new env vars.

### `fix(theme)` — only one toggle icon visible at a time

The v2.5.0 swap from inline `style.display` to `classList.toggle('hidden')` broke the dark-mode toggle: FontAwesome's `.fas { display: inline-block }` is loaded after `tailwind.min.css` with equal specificity, so Tailwind's `.hidden` lost the cascade and both moon + sun icons rendered at once. Replaced the JS sync entirely with two CSS rules in `<head>` keyed off the `dark` class on `<html>` — ID-selector specificity (100) beats `.fas` (10), no `!important` needed, no FOUC, no JS race.

### `fix(settings)` — restore icon → text gap on the tab nav

The settings tab nav used `ml-1.5` on the label span. That class only appeared at this single callsite, so PurgeCSS dropped it from the prebuilt `tailwind.min.css` and the gap collapsed to zero. Switched to `ml-2`, which is bundled (32 callsites repo-wide). 2px visual delta.

### `fix(redoc)` — point at the real swagger.json endpoint

`/redoc` has been initialising ReDoc against `/static/swagger.json` since v2.2.0, but that static file has never existed — the OpenAPI spec is served by Flask-RESTx at `/api/swagger.json`. The bug went unnoticed because `/redoc` was an undocumented URL until v2.5.0 added it to the desktop nav and to the help page, surfacing the 404 to actual users.

### `fix(dashboard)` — single-row top toolbar (tabs + Create button)

Reflow the dashboard top-row so the cert-type toggle (Server / Client) sits on the same line as the **Create New Certificate** button on the right, instead of the button taking its own row underneath. `flex-wrap` lets the button drop to a second line on narrow viewports. The visual win is downstream: the stat cards and the certificate list move up by one row's worth of pixels.

### `fix(dashboard)` — compact stat cards

Drop the vertical footprint of the four metric cards (Total, Valid, Expiring, Deployed) by ~40%. The previous layout used a horizontal icon-then-label-and-value composition with `p-4` padding; the new layout stacks label + icon on one row, value on a second, with `px-3 py-2`. The skeleton placeholder is bumped down in lockstep so the pre-paint render matches the real card height — no layout shift when the API call resolves.

### `fix(dashboard)` — empty-state "Create Certificate" button now works

The CTA inside the welcome / empty-state block called `.focus()` directly on `#domain`. That input lives inside the create form container which is `display:none` by default, so `focus()` ran against a hidden element and silently did nothing — clicking the button looked broken. Added an `openCreateCertForm()` helper next to `toggleCreateCertForm()` that expands the form first (no-op if already open), focuses the domain input, and scrolls it into view. The top-right Create button is unaffected.

### `fix(help)` — rewrite for user help, drop marketing, theme-aware code blocks

Major surgery on the help page. The previous version was structured around a 6-card "quick links" grid duplicating the section headings below, an "About CertMate" marketing block, and per-feature promo cards under "What's New" — all of which read like the README, not like help.

- Replaced the 6-card grid + scattered changelog link with one horizontal section-nav strip at the top (Quick Start, DNS, CA, API, Multi-account, Backup, Troubleshooting, Report an issue, What's new, Full changelog). Scrolls horizontally on narrow viewports.
- Removed the "About CertMate" block entirely. Replaced with a single-line footer: *"CertMate is open source. github.com/fabriziosalmi/certmate"*.
- Dropped the "What's New" feature-card grid. Now a single sentence linking to `RELEASE_NOTES.md`.
- All section cards switched to `px-4 py-4` (was `px-6 py-6`): ~30% less vertical footprint.
- Rewrote content for self-service diagnosis. DNS section gains a 6-row table mapping provider → token type → minimum API scope. CA section trimmed to 3 bullets, calls out EAB requirement on DigiCert + Private CA explicitly. Troubleshooting is now a `<dl>` with 5 concrete failure modes (DNS auth, propagation timeout, LE rate limit, deployment "unknown" status, Alpine.js load failure) plus the fix.
- **New "Report an issue" section** with a diagnostic checklist (version, runtime, repro steps, console errors, `/health` output, screenshots) and a GitHub issue CTA — concrete artifacts the maintainer needs, not marketing copy.
- `/health` link added to the top-right alongside Swagger / ReDoc so users can grab a one-line system status to attach.
- **Theme-aware code blocks**: the two `<pre>` snippets used `bg-gray-900 text-green-300` unconditionally, which read as foreign dark islands inside the white cards in light mode. Switched to `bg-gray-100 text-gray-800` with `dark:` variants — terminal styling in dark mode, integrated with the surrounding card in light mode.

Rendered page weight: 1358 → 709 lines.

### `fix(palette)` — Cmd+K palette: adaptive height, no scrollbar when the viewport allows

The Cmd+K palette's results pane had a fixed `max-h-72` (288px), which produced a scrollbar even on tall viewports where every result would fit without it. Replaced the static cap with a viewport-aware size computed at `open()` time, with a resize listener for live re-sizing while the palette is open. Floor of 180px keeps ~3 rows visible on genuinely short windows.

### `fix(layout)` — reserve the scrollbar gutter to prevent horizontal shift

Navigating between pages of different heights — or between settings sub-tabs (DNS short, Backup tall) — caused the whole layout to jump ~15px horizontally as the scrollbar appeared / disappeared between renders. The shift was small but constant and made the UI feel unstable. Added `scrollbar-gutter: stable; overflow-y: scroll;` on `<html>`. `scrollbar-gutter` does the right thing on Chrome 94+ / Firefox 97+ / Safari 16+; `overflow-y: scroll` covers older Safari / iOS as a fallback.

### Tests

Unit suite green pre-push. CI runs the same suite plus build and security-scan jobs.

### Backward compatibility

All changes are at the template / asset / client-side layer plus the version bump. No API, schema, or env-var changes.

---

## v2.5.0 (Minor — v3 UI massive pass: 51 fixes across all templates)

A focused, single-branch sweep of the entire UI surface (`templates/`, `static/js/`, `static/css/`). 51 commits, each scoped to one fix, organized into four waves: cross-cutting refactors (R-1..R-6), per-page quick wins (QW-1..QW-15), per-page Tier A / Tier B work, and per-page section passes (2.x base, 3.x dashboard, 4.x settings, 5.x activity, 6.x login, 7.x help, 8.x cross-cutting).

No API breakage. No data migration. No new env vars. All changes are at the template / asset / client-side layer, plus three small `modules/web/` additions to support `?next=` and `current_user` rendering.

### Cross-cutting refactors

- **R-1 — `templates/settings.html` Alpine root repair.** A long-standing structural bug had Alpine partials sitting outside the root `x-data` element due to an `<!-- comment inside attribute -->` that broke HTML parsing. Tabs and modals were silently un-reactive in some browsers. Re-parented partials inside the main card and removed the comment-in-attribute.
- **R-2 — Standardized modal macro.** New `templates/partials/_modal.html` with a `{% call modal(id, title, size) %}` macro: dialog role, `aria-modal`, `aria-labelledby`, header with `[data-modal-close]`, scrollable body, panel sizing. Paired with `CertMate.modal.open/close` in [static/js/certmate.js](static/js/certmate.js): global Esc handler, backdrop click, focus trap, `modal:close` CustomEvent, MutationObserver-based discovery so partials added at runtime are wired automatically. Settings modals (`addAccountModal`, `editAccountModal`) migrated as the first callsites.
- **R-3 — Component-class scaffold in [static/css/input.css](static/css/input.css).** New `@layer components` with `.btn`, `.btn-primary/secondary/danger/ghost`, `.btn-sm/lg`, `.card`, `.badge`, `.badge-success/warning/error/info`, `.form-input`, `.form-select`, `.form-label` — all defined via `@apply`. [tailwind.config.js](tailwind.config.js) safelist added so PurgeCSS doesn't drop classes until the migration of callsites lands in a follow-up sprint. No existing markup changed in this release.
- **R-5 — Dashboard mobile card meta block.** On `md:hidden` widths each row gets a secondary line with expiry, provider, and deployment status. Previously these only rendered on desktop; mobile users couldn't tell certs apart at a glance.
- **R-6 — Debug surface gating.** `?debug=1` opt-in writes `localStorage.certmate_debug='1'` and exposes `CertMate.debugEnabled`. All `[data-debug-control]` elements stay hidden until both the localStorage flag AND `/api/auth/me` returns `role === 'admin'`. Two-layer defense-in-depth — URL opt-in plus role check.

### `templates/base.html` (2.1–2.3)

- **2.1 / A1** — Theme toggle icon swap switched from `style.display` to `classList.toggle('hidden')` so Tailwind's dark-mode variant cascades correctly.
- **2.2 / A4** — API Docs `/redoc` link added to the desktop nav alongside `/docs/`.
- **2.2 / B1** — Logout button now server-side rendered via `{% if current_user %}` instead of a 500 ms client-side `fetch('/api/auth/me')` probe. New Jinja `context_processor` in [modules/web/routes.py](modules/web/routes.py) injects `current_user`.
- **2.2 / B2** — Mobile-only search button (`sm:hidden`, icon-only).
- **2.3 / A2** — `aria-label` on every icon-only top-nav button (theme, keyboard shortcuts, notifications, logout, search).
- **2.3 / A3** — `aria-current="page"` on the active link in both desktop and mobile bottom nav.
- **2.3 / B3** — Notification panel migrated to a proper Disclosure pattern: `aria-expanded`, `aria-controls`, Esc handler, focus restoration via `_closeNotifPanel()`. No focus trap (it's a disclosure, not a dialog).

### `templates/index.html` (3.1–3.3) — dashboard

- **3.1 / A1** — Debug button + console gated behind `?debug=1` per R-6.
- **3.1 / A2** — Loading modal split `hidden` / `flex` classes correctly so it shows/hides without an extra reflow tick.
- **3.2 / A3** — Explanatory `title` / `aria-label` on the Check-All checkbox.
- **3.2 / A4** — Emoji prefixes dropped from CA provider `<option>` labels.
- **3.2 / A5** — Quick Tips bullets replaced with a link to the Help page (single source of truth).
- **3.2 / B3** — Cert-detail panel renders a skeleton on open and clears content on close so stale data never flashes.
- **3.2 / B4** — Stats cards render a JS-driven skeleton via `STAT_METRICS_COUNT`; empty container shipped in the template.
- **3.3 / B1** — `aria-label="${title} ${domain}"` on every per-row action button.
- **3.3 / B2** — Sortable column headers: implicit `columnheader` role on `<th>`, internal `<button>` for interaction, `aria-sort` toggled via `setAttribute` on each sort.
- **QW-4** — Dark-mode variants on the curl-snippet modal.
- **QW-5** — Confirm guard on the delete action via `CertMate.confirm`.
- **QW-11** — `autocomplete="off"` on cert-create domain inputs (primary + SAN), plus a more permissive SAN parser (`,;\n\t` separators, dedup).
- **QW-12** — Form lock during in-flight create requests: `isCreatingCert` flag, disabled fields, spinner.
- **QW-15** — `normalizeHostname()` strips scheme / port / path / trailing dot on submit, preserves `*.` wildcard prefix.

### `templates/settings.html` (4.1–4.2)

- **4.1 / A1** — Debug helper renamed `toggleDebugConsole` → `toggleSettingsDebugConsole` so it no longer collides with the dashboard's helper of the same name.
- **4.2 / A2** — Tabs go icon-only on mobile; `aria-selected` bound to `tab === t.id`.
- **4.2 / A3** — DNS-scope prefix added to status indicators. Orphan markup retained with an explanatory comment for the follow-up sprint that will migrate it to the new layout.

### `templates/activity.html` (5.1–5.3)

- **5.1** — Differentiated error states via `renderErrorState()` instead of a single generic banner.
- **5.2** — Date-range filter (Today / 7d / 30d / All), full-text search across loaded entries, skeleton rows during load, clickable cert entries that deep-link into the dashboard detail panel via `?cert=<domain>`, server-side `limit` param + client "Load more" button (also fixed a backend bug — `/api/activity` returned a bare array but the client read `data.entries`, so the page was always empty), and `api_request` event type hidden from the default view (still surfaced when filtered).
- **5.3** — ARIA semantics: `<ul role="feed">`, `<li role="article">`, `aria-busy` on the container during load. Errors use `role="alert"` with `aria-live="assertive"`.
- **QW-8** — Tooltip with absolute timestamp on every relative time via `absoluteTime()`.

### `templates/login.html` (6.1–6.3)

- **QW-1** — FOUC fix: dark-mode script in `<head>` mirrors `base.html` so a user who toggled dark inside the app no longer sees a light flash on every `/login` redirect. `meta theme-color` paired for light + dark.
- **6.2 / A1** — `/login` server-side redirects to `/` (or `?next=`) on a valid session cookie. The previous client-side check is kept as a defensive fallback.
- **6.2 / A2** — `autocomplete="username"` and `autocomplete="current-password"` so password managers fill correctly.
- **6.2 / A3** — `?next=` redirect with `safeNextUrl()` open-redirect guard: only same-origin relative paths (`/`-prefixed, no `//`).
- **6.2 / A4** — Forgot-password hint pointing at the admin + the `scripts/reset_admin_password.py` in-container reset script (no email infra assumption).
- **6.3 / A5** — Password visibility toggle: `aria-label`, `aria-pressed`, `aria-controls` swapped in lockstep with the icon glyph.

### `templates/help.html` (7.1–7.2)

- **7.1 / A1** — "What's New in v2.0" renamed to "v2.x" with a link to `RELEASE_NOTES.md`.
- **7.1 / A2** — Clean six-item Quick Links grid (`grid-cols-3`) including a Backup card.
- **7.2 / A3** — Swagger UI vs ReDoc disambiguated with explicit labels; eight `rel="noopener"` adds on outbound links.
- **7.2 / B1** — In-page search filter for help sections via `data-help-section` markers.

### Cross-cutting (8.x)

- **8.2 / A2** — Graceful red `role="alert"` banner if `window.Alpine === undefined` after `DOMContentLoaded`, so a CDN failure doesn't leave the UI looking broken-but-silent.
- **8.2 / A3** — Debug surface admin-role check (R-6 server-side leg).
- **8.3 / A1** — Skip-to-content link as the first body child on every page (keyboard a11y).

### Server-side additions

Three small, backwards-compatible additions in `modules/web/`:

- [modules/web/routes.py](modules/web/routes.py) — `context_processor` injecting `current_user` into every Jinja template render.
- [modules/web/ui_routes.py](modules/web/ui_routes.py) — `/` route sets `request.current_user = user_info` after `validate_session`; redirect to login passes `?next=request.path`.
- [modules/web/auth_routes.py](modules/web/auth_routes.py) — `login_page()` checks the session cookie server-side and 302s to `/` (or to `?next=` if present) instead of always rendering the login form.

### Tests

E2E suite run before push: **99 passed, 12 skipped, 2 xfailed in 55.5 s** against a freshly built `certmate:test` image (Docker fixture in `tests/conftest.py`, port 18888). The 2 xfailed are pre-existing markers in `test_ui.py`; the 12 skipped are real-cert / opt-in UI tests gated on explicit env. Unit suite green.

### Backward compatibility

- No API shape changes. No new required env vars.
- The `?next=` parameter is opt-in; absence falls back to `/`.
- `current_user` in Jinja is `None` for unauthenticated requests — no template that uses it assumes it's set.
- R-3 component classes are scaffolded only; no callsite migrated, no class renamed.
- Debug surface gating fails-closed: if `/api/auth/me` errors or returns a non-admin role, the surface stays hidden.

### Acknowledgement

This is a single-contributor sweep — 51 commits on `feature/v3-ui-fixes-2026-05-15`, each commit one fix. The discipline came out of the v2.4.x cycle where mixing fixes in single commits made review and rollback harder than they needed to be. Every fix in this release can be reverted in isolation.

---

## v2.4.17 (Patch — two community fixes from @rocogamer)

Bundle of two small, surgical community PRs from [@rocogamer](https://github.com/rocogamer) that came out of the maintainer-feedback loop earlier this session. Both are mergeable as-is and ship together because each is too small for a release of its own.

### `fix(api): bare-list /api/deploy/history` (closes [#152](https://github.com/fabriziosalmi/certmate/issues/152), PR [#153](https://github.com/fabriziosalmi/certmate/pull/153))

One functional line of diff in `modules/web/settings_routes.py`:

```diff
-            return jsonify({'history': history})
+            return jsonify(history)
```

Closes the convention point left as a follow-up after [#142](https://github.com/fabriziosalmi/certmate/pull/142). `GET /api/deploy/history` previously wrapped its result in `{"history": [...]}` while the sibling event-log endpoint `GET /api/webhooks/deliveries` already returned a bare list, and the frontend (`settings-deploy.js`, `settings-notifications.js`) was originally written to the bare-list convention. v2.4.12 had landed a dual-shape frontend handler so the panel would keep working while a backend flip was pending; this PR completes that flip and removes the asymmetry.

The success contract is now a bare list. The error path keeps the `{"error": "..."}` envelope so the frontend's catch branch can still surface a real reason instead of a generic literal.

`tests/test_issue152_deploy_history.py` — 4 new contract tests pinning the post-#152 shape: populated success returns a list in order; empty history returns `[]` (the historically most-visible symptom of the wrap was the empty case); `?limit=N` (capped at 200) and `?domain=...` are still threaded through to `DeployManager.get_history` verbatim; the 503 error path keeps its envelope. All four pass locally in 0.08 s.

The v2.4.12 dual-shape frontend handler stays in place as a forward-compatibility shim; rolling back to v2.4.16 / v2.4.15 won't break the UI, the bare-list path was always accepted.

### `build: EXTRA_REQUIREMENTS build-arg + certbot-dns-azure baked in` (PR [#155](https://github.com/fabriziosalmi/certmate/pull/155))

Two build-level improvements:

**`EXTRA_REQUIREMENTS` Dockerfile build-arg** — accepts a space-separated list of `requirements-*.txt` paths and runs `pip install -r <file>` for each after the main install. Defaults to empty (existing builds unchanged). Wired through `docker-compose.yml` as `EXTRA_REQUIREMENTS: ${EXTRA_REQUIREMENTS:-}` so a single env var in `.env` bakes optional storage / DNS plugins into the image at build time:

```bash
# Azure DNS + Azure Key Vault in one image
docker build \
  --build-arg EXTRA_REQUIREMENTS="requirements-azure-storage.txt" \
  -t certmate:azure .

# Every remote storage backend
docker build \
  --build-arg EXTRA_REQUIREMENTS=requirements-storage-all.txt \
  -t certmate:full .
```

The Dockerfile `COPY requirements.txt requirements-minimal.txt ./` was widened to `COPY requirements*.txt ./` so all optional sets are available to the layered install without rebuilding the COPY layer per combination. The intentional word-splitting carries an explicit `# shellcheck disable=SC2086` so a future maintainer doesn't quote it and break the loop.

**`certbot-dns-azure==2.5.0` baked into the main `requirements.txt`** — Azure is one of the four major DNS providers exposed in the UI dropdown, but until now selecting it on a default image produced a "plugin not installed" error. The pin is to 2.5.0 specifically: it's the last version in the `certbot<3.0,>=2.0` line; 2.6.0+ jumped to certbot 3.x and would conflict with the repo-wide `certbot==2.10.0`. The same constraint already lived as a comment in `requirements-azure.txt`; this commit promotes it to the main set.

**Image size note**: the bake-in adds `azure-identity`, `azure-mgmt-dns`, `msrest`, `msal` and their transitive dependencies — about 30–50 MB of image. The trade-off is consistent with the existing four bundled DNS plugins (cloudflare, route53, digitalocean, google), and the build-arg is the escape hatch for anyone who wants a slimmer image: ship without Azure, then layer it back in via `EXTRA_REQUIREMENTS=requirements-azure.txt` on demand.

### Tests

`tests/test_issue152_deploy_history.py` — 4 new contract tests (above). Full unit-test surface: 140 passes (136 pre-existing + 4 new) in ~1.0 s without Docker.

### Backward compatibility

- Both PRs are additive at the API / build level.
- The v2.4.12 dual-shape frontend handler keeps the deploy history panel working on rollback to older backends.
- Existing `docker build` invocations without `EXTRA_REQUIREMENTS` produce the same image (plus the `certbot-dns-azure` baked-in package, which on a default build is the only behavioural delta).
- No existing API call shape changes other than `GET /api/deploy/history` going from envelope to bare list — which the frontend already tolerates and which the documented contract test pins.

### Acknowledgement

Both PRs come out of a tight feedback loop earlier in the session: PR #141 was originally a three-feature monolith, asked to split, and rocogamer turned around four atomic PRs (#153, #154, #155, #156) plus a follow-up issue (#152) within the same day. v2.4.17 ships the two of those that were ready to merge without further changes; #154 (APScheduler `app_context` fix) needs a one-line `global` declaration and a regression test before it can land safely; #156 (configurable certificate key type/size + ECDSA) deserves its own dedicated review window.

## v2.4.16 (Patch — Sprint 1.7: in-app diagnostic snapshot + one-click bug report)

Implements [#150](https://github.com/fabriziosalmi/certmate/issues/150) end-to-end. When an action fails and you're signed in as admin, the error toast now surfaces a **Report this issue** button. One click → fetch `/api/diagnostics/snapshot` → merge with browser context → format Markdown → clipboard + open GitHub with the bug template pre-filled. You paste, review what you're sending, submit. No telemetry, no automatic upload, no new external dependency. PR [#157](https://github.com/fabriziosalmi/certmate/pull/157). Four atomic commits, 11 new unit tests on top of v2.4.15's 125 (136 total, 1.14 s runtime, no Docker).

### Backend — `GET /api/diagnostics/snapshot`

New admin-only resource under a new `/api/diagnostics/` namespace. Returns an **allowlist** (not a serialiser): every field is added by name in the handler, so a future contributor adding a field has to explicitly choose to expose it.

| Field | Source | Notes |
|---|---|---|
| `certmate_version`, `python_version`, `os_platform`, `container` | `modules.__version__`, `sys.version`, `platform.platform()`, `/.dockerenv` | public |
| `scheduler_running` | `container.scheduler.running` | bool |
| `certificate_count` | `len(certificate_manager.list_certificates())` | int |
| `dns_provider`, `default_ca`, `challenge_type`, `storage_backend` | settings scalar reads — provider/CA names, never credentials | low |
| `disk_free_bytes`, `disk_total_bytes` | `shutil.disk_usage(app.config['DATA_DIR'])` | low |
| `recent_audit` | last 5 entries from `audit_logger.get_recent_entries(5)`, sanitised | mid |
| `errors` | only present on partial failure | low |

Sanitisation of the audit tail is performed inline in the handler. Each entry is reduced to exactly `{timestamp, operation, resource_type, status}` — `resource_id` (often a domain), `user`, `ip_address`, `details` (full operation payload), and `error` are dropped. A future audit field has to be opted-in explicitly.

Partial-failure tolerance: if certificate enumeration / settings read / `shutil.disk_usage` / audit read raises, that single field becomes `null` and the response carries an `errors: {field: reason}` map alongside the working data — never 500s the whole call.

### Frontend — `static/js/report-issue.js`

`CM.reportIssue(errorContext)` is the public entry point:

1. Fetches `/api/diagnostics/snapshot`.
2. Merges with browser context (`userAgent`, page, viewport, the error envelope).
3. Formats a structured Markdown body via the pure `buildMarkdown()` (exposed on `CM.reportIssueInternals` for future test harnesses).
4. Copies to clipboard via `navigator.clipboard.writeText`.
5. Opens `github.com/fabriziosalmi/certmate/issues/new?template=bug_report.md&title=[Bug] <status> <code> on <method> <endpoint>` (title encodes the most useful triage facts; truncated at 200 chars).

Defensive plumbing: idempotent (in-flight Promise guards double-clicks), three fallback paths (clipboard reject → modal with editable textarea + clickable GitHub link; popup blocker → same modal; snapshot fetch fail → ship a client-only report tagged "Server snapshot was unavailable"). The user is never stranded.

### Frontend — `CM.toast` extension + role export

- `CM.toast(message, type, duration, options)` gains an optional 4th argument. When `options.errorContext` is supplied and `type === 'error'` and `CM.role === 'admin'`, the toast renders a **Report this issue** button below the message and extends auto-dismiss to 10 s so the user has time to find it. Every existing call works unchanged.
- `CM.role`, `CM.roleAtLeast`, `CM.refreshRole` exposed on `window.CertMate`. `dashboard.js` already tracked the role for its own UI gating; we mirror it on `CM` so cross-page helpers don't have to depend on `dashboard.js` being loaded (`/settings` doesn't load it). Auto-refresh on `DOMContentLoaded`.

### Wire-up — 8 high-impact error sites

| Action | File | Endpoint |
|---|---|---|
| Cert create (server error + network) | `dashboard.js` | `POST /api/certificates/create` |
| Cert renew | `dashboard.js` | `POST /api/certificates/<d>/renew` |
| Cert delete | `dashboard.js` | `DELETE /api/certificates/<d>` |
| Run deploy hooks | `dashboard.js` | `POST /api/certificates/<d>/deploy` |
| Settings save | `settings.js` | `POST /api/web/settings` |
| API key create | `settings-apikeys.js` | `POST /api/keys` |
| Backup create | `settings.js` | `POST /api/backups/create` |
| Backup restore | `settings.js` | `POST /api/backups/restore/unified` |

Each `errorContext` carries `{endpoint, status, code?, message?, hint?}`. `status: 0, code: 'NETWORK_ERROR'` is the convention for `.catch` branches that never got an HTTP response. The remaining ~80 error toasts in the codebase continue to work as before — they just don't surface the button. The pattern is documented inline so contributors extending coverage know what to pass.

Plumbing changes alongside the wires:
- `showMessage(msg, type)` in `dashboard.js` / `settings.js` / `settings-apikeys.js` grew an optional 3rd `options` parameter forwarded to `CertMate.toast`.
- Cert delete / renew handlers propagate `response.status` through their `.then()` wrap.
- Settings save / backup create / restore catch paths now parse the JSON response body when available and attach it as `error.responseBody` + `error.responseStatus`, so the toast can forward structured fields (`code`, `hint`).

### Tests

`tests/test_diagnostics_snapshot.py` — 11 new tests, 0.47 s runtime:

- **`TestSnapshotShape`** (3) — all 13 documented fields present; cert count reflects the manager; settings scalars round-trip.
- **`TestSnapshotSanitization`** (4) — response carries **none** of 8 forbidden values planted in the settings + audit fixtures (bearer token, hash, cloudflare_token, audit `details` leak, audit `resource_id`, audit `user`, audit `ip_address`, `password_hash` literal). Audit entries are stripped to exactly the four allowed keys. Audit list capped at 5. Full-settings keys (users, api_keys, dns_providers, deploy_hooks, …) never appear at the top level. The flatten-and-search assertion catches any future leak path that adds one of those tokens anywhere in the response.
- **`TestSnapshotPartialFailure`** (4) — certificate enumeration, audit log read, and `shutil.disk_usage` each individually injected with failure; the corresponding field becomes `null`, the `errors` map carries a documented reason, and the other fields still populate. Missing audit logger → empty list, no crash.

Total unit-test surface after this release: 136 passes (125 pre-existing + 11 new) in ~1.14 s without Docker.

### Documentation

README gains a **Reporting Bugs** subsection that explains the in-app flow and what's in the snapshot. The existing **Support Checklist** below it is preserved as the manual fallback for users hitting a bug before they can reach the UI; the `cat settings.json` curl example was replaced with a curl against `/api/diagnostics/snapshot` so a user copy-pasting the help guide doesn't leak credentials into a public issue.

### Backward compatibility

- No existing API shape changes; the new endpoint is purely additive.
- Every existing `CM.toast(msg, type, duration)` and `showMessage(msg, type)` callsite continues to work — the `options` arg is optional everywhere.
- No new external dependency, no new build step, no new CSP origin required (the GitHub URL is `_blank window.open`, not a same-origin fetch).
- The remaining ~80 error toasts not wired in this PR simply don't surface the button; their user experience is unchanged.

### Non-goals (explicit)

- No telemetry. No automatic upload. No phone-home. The flow is fully manual end-to-end — the user paste-reviews-submits.
- No Sentry / Bugsnag integration.
- No screenshot capture (the strict CSP blocks `html2canvas`; structured fields are more useful anyway).
- No coverage of all ~90 error sites — many are client-side validation errors with no server status / endpoint to report. The pattern is documented inline; future PRs (community or maintainer) can extend coverage where it adds value.

## v2.4.15 (Patch — Sprint 1.6 audit polish)

Audit polish sprint: the four zero/low-risk items from the [2026-05-12 API auth audit](https://github.com/fabriziosalmi/certmate/releases/tag/v2.4.12) that didn't need structural design, shipped together because each is small, additive, and shares no code paths. Four atomic commits, 13 new unit tests on top of v2.4.14's 112 (125 total, 0.87s runtime, no Docker). PR [#151](https://github.com/fabriziosalmi/certmate/pull/151).

### F-4 — Confirm dialog when creating an API key with no domain scope

The Allowed Domains field on the API Keys settings tab has always defaulted to "empty = unrestricted" — sensible for backward compatibility, easy to trip over: an admin who hits Create with the field blank just minted a key with role-scoped access to every certificate on the install.

`createKey` in `static/js/settings-apikeys.js` now gates on a confirm dialog when `parseAllowedDomains(...)` returns undefined:

> "This key will have no domain restrictions and will be authorized to operate on every certificate on this CertMate instance, scoped only by the role you selected. To restrict the key to specific domains, cancel and fill in the Allowed Domains field (comma-separated, supports wildcards like *.example.com). Create this unrestricted key?"

On cancel, focus jumps back to the Allowed Domains input so recovery is one keystroke. When the field has at least one pattern (including a single wildcard) the dialog is skipped — the admin already declared intent. Zero backend change.

### F-6 — Self-host ReDoc bundle + drop external CDN from CSP

`/redoc/` previously loaded the ReDoc bundle from `cdn.redoc.ly` and Montserrat / Roboto from `fonts.googleapis.com` + `fonts.gstatic.com`, breaking the project's air-gapped-ready promise and forcing three external origins into the global CSP.

Three changes:

1. `static/js/redoc.standalone.js` checked in as a vendored asset (918 KB; pulled from `cdn.redoc.ly/redoc/latest/bundles/` at the time of the commit; carries its own MIT license header).
2. `templates/redoc.html` switched from `<redoc spec-url=>` + CDN `<script>` to `Redoc.init()` against the locally-hosted bundle. ReDoc's `theme.typography.fontFamily` is pinned to the system-font stack so no Google Fonts request fires.
3. `modules/core/factory.py` CSP — dropped `cdn.redoc.ly`, `fonts.googleapis.com`, `fonts.gstatic.com`. `/redoc/` now satisfies the same `self`-only CSP as every other page on the install.

`tests/test_static_csp.py` — `test_redoc_csp_allows_external` rewritten to `test_redoc_csp_self_only` (asserts the three CDN origins are absent and `self` is present); new `test_redoc_html_self_hosts_bundle` confirms the rendered page references `/static/js/redoc.standalone.js`.

### GET role normalisation — `/api/web/settings` GET is now `viewer`

The Flask-RESTX surface at `/api/settings` GET already required only `viewer`; the web blueprint at the same path (plus its `/api/web/settings` alias) was `admin` for both GET and POST. Two endpoints, same data, different roles — confusing for integrators and inconsistent with the masking guarantee already in place on the web blueprint side.

The blueprint splits into two view functions: GET is `viewer`, POST stays `admin`. Why this is safe to open: `api_settings_get` already masks every key matching `/(token|secret|password|key|credential)/i` to `'********'` via the `_mask_dict` regex walker. The RESTX `Settings.get` resource achieves the same via `MaskedString` field types. Both endpoints have been masking on the read path since well before this change; the only thing that shifts is which roles can hit them.

### F-7 — Per-username login rate limit on top of per-IP

`/api/auth/login` had a single per-IP bucket (5 attempts / 60s). It fails open to a distributed brute-force where an attacker spreads attempts across N source IPs — N × 5 attempts/minute against a single account before any rate limit fires. The 12-character password policy mitigates the threat; SOC2 / ISO27001 audits still expect a per-account lockout for due diligence.

New per-username bucket on top:

| Bucket | Limit | Window |
|---|---|---|
| per-IP | 5 attempts | 60 s |
| per-username (new) | 10 attempts | 300 s |

Wider window for the username bucket because the threat model is slower than a per-IP burst and legitimate users mistyping a password from different devices should still recover quickly.

Defensive details:
- Username is lower-cased + trimmed before bucketing so an attacker cannot side-step the cap by varying case (`ADMIN` vs `admin`) or padding whitespace.
- Empty / whitespace-only usernames skip the per-user bucket — recording them would let an attacker pre-fill a wildcard slot to starve legitimate users.
- Attempts older than their respective window are pruned lazily on every check; in-memory dicts don't grow unbounded.
- When both buckets trip, `retry_after` is the **longer** of the two outstanding windows so the client backs off enough to clear both.
- `_check_login_rate_limit` and `_record_login_attempt` grew an optional `username` parameter; existing callers without a username keep working.

`auth_routes.py` POST `/api/auth/login` now reads the username from the request body **before** the rate-limit check but credential validation still happens after — so a hammered username cannot be probed for existence by comparing error codes; both rate-limit and bad-credentials paths return the same generic error envelope.

### Tests

`tests/test_sprint1_6_audit_polish.py` — 13 new tests, 0.07s runtime:

- `TestPerIpBucket` (3) — original behaviour preserved + backward-compatible no-username signature
- `TestPerUsernameBucket` (5) — distributed-attack blocked, per-user isolation, case/whitespace normalisation, empty username does not poison the bucket
- `TestRetryAfterIsWorstCase` (2) — `retry_after` picks the binding window
- `TestBucketWindowExpiry` (2) — stale entries pruned on next check
- `TestSettingsGetRoleNormalization` (1) — module exposes the split GET handler with viewer role

Total unit-test surface after this release: 125 passes (112 pre-existing + 13 new) in 0.87s without Docker. CI also runs the Docker-fixture integration suite and the updated `tests/test_static_csp.py` assertions for the ReDoc self-host.

### Backward compatibility

- Every existing API call continues to work for admin callers. The only observable changes for non-admin callers:
  - Viewers can now read `/api/web/settings` GET (where they previously got 403). The response is masked; no secret value is exposed.
  - The viewer cannot trip the per-username login bucket without doing 10 failed POSTs against the same username in 5 minutes.
- `parseAllowedDomains` is unchanged; the F-4 confirm only fires when the field is empty, so admins who routinely scope their keys see no new dialog.
- The `_check_login_rate_limit(ip)` signature is preserved (username defaults to None); legacy callers don't need to change.
- ReDoc renders identically — only the asset source changes.

### Non-goals (deferred to Sprint 2, with reason)

- **F-3** (legacy bearer deprecation flag + dedicated rotation endpoint + UI migration warning). Structural feature, needs UX design for the migration path. Deferred to a dedicated PR.
- **#138** (help.html rewrite). Pure UI but a large rewrite that deserves its own design + sprint.
- **#150** (diagnostic snapshot + one-click bug report from error toasts). New feature opened during this sprint after the audit walk-through; in the backlog now, separate PR.

## v2.4.14 (Patch — Sprint 1.5 API auth audit follow-up)

Direct follow-up to the [2026-05-12 draconian API auth audit](https://github.com/fabriziosalmi/certmate/releases/tag/v2.4.12) and the coverage matrix it produced. Four atomic commits, 23 new unit tests on top of v2.4.13's 89 (112 unit-test surface, 0.83s runtime, no Docker). PR [#148](https://github.com/fabriziosalmi/certmate/pull/148).

Picks up everything from the audit that was actionable in one sprint without re-opening structural design questions. The four deferred items (F-3 / F-4 / F-6 / F-7) are explicitly out of scope and reasoned below.

### Authentication architecture (F-1)

`AuthManager.require_role` previously called `self.require_auth(lambda: None)()` and then read `request.current_user` back as a side effect of the lambda's invocation. The chain worked, but it leaned on a cross-decorator side effect with no compile- or runtime-checkable guarantee — any middleware clearing `request.current_user` between the lambda call and the role-check line would silently downgrade authentication to None. Not exploitable today; fragile as a foundation.

New `AuthManager._authenticate_request()` is the single source of truth. Evaluates bypass mode -> session cookie -> bearer token in order and returns `(user, None)` on success or `(None, (error_dict, status))` on failure, **without touching `request.current_user`**. Both `require_auth` and `require_role` are now thin wrappers that call it, assign `request.current_user` exactly when they know the request is allowed to proceed, and dispatch. The decorator API surface is unchanged.

### Authorization audit trail (F-2)

Domain-scope denials have audited via `log_authz_denied` since v2.4.12; role-level denials returned `403 INSUFFICIENT_ROLE` silently, leaving privilege-enumeration attempts off the audit trail. `AuthManager` gains `set_audit_logger(audit_logger)` (wired in `factory.py` right after both objects are constructed) and `_log_rbac_denial(user, required_role, endpoint)`. The helper always emits a structured `logger.warning` so the signal is present even without an audit logger; when one is wired (the production path), it also writes `log_authz_denied` with `operation='access'`, `resource_type='endpoint'`, `resource_id=request.path`, `reason='role=X below required Y'`.

### Certificate download — private-key role split

Escalation of a finding the audit rated INFO/⚠️ in its coverage matrix. `DownloadCertificate.get` required only `viewer` and returned private-key material via four code paths: `?format=json`, `?file=privkey.pem`, `?file=combined.pem`, default ZIP. A scoped viewer key could therefore pull the private key for every certificate in its scope — information disclosure inconsistent with the read-only-monitoring intent of the role.

The decorator stays `viewer` so the authn check still fires, and the handler now gates per file:

| Path | Allowed roles |
|---|---|
| `?file=cert.pem`, `?file=chain.pem`, `?file=fullchain.pem` | viewer, operator, admin |
| `?include_private=0` (public-only ZIP, new) | viewer, operator, admin |
| `?file=privkey.pem`, `?file=combined.pem`, `?format=json`, default ZIP / `?include_private=1` | operator, admin |

Denied calls return `403 PRIVKEY_REQUIRES_OPERATOR` with a `hint` pointing at the viewer-safe variants, and write `audit_logger.log_authz_denied` so the attempt is visible. The public-only ZIP carries the suffix `_certificates_public.zip` so an attached file is unambiguous at a glance. `cert.pem` and `chain.pem` are newly legal `?file=` values — they were never reachable as single files before (the original whitelist only included `fullchain.pem` on the public side).

### Audit-log coverage matrix gaps

Six mutating endpoints landed in v2.4.12 without audit wiring; the audit's coverage matrix flagged them. Each now emits an audit entry on success:

| Endpoint | Audit method | Notes |
|---|---|---|
| `DELETE /api/certificates/<d>` | `log_operation(operation='delete', resource_type='certificate')` | |
| `POST /api/backups/create` | `log_operation(operation='create', resource_type='backup', details={type,reason})` | |
| `POST /api/backups/restore/<...>` | `log_operation(operation='restore', resource_type='backup', details={backup_type, pre_restore_backup})` | Heaviest of the four; wholesale-replaces settings + certificates. The audit entry surfaces both source filename and the pre-restore backup so an admin can roll back via the audit trail alone. |
| `DELETE /api/backups/delete/<...>` | `log_operation(operation='delete', resource_type='backup')` | |
| `POST /api/deploy/test/<id>` | `log_deploy_hook_changed(operation='test', scope=<domain>, hook_id=<id>)` | The dry-run executes the hook end-to-end against a test domain; the command itself is never logged (log-injection + secret-leak risk, consistent with the existing `log_deploy_hook_changed` semantics). |
| `POST /api/notifications/config` | `log_operation(operation='update', resource_type='notifications_config', details={channels_present})` | Channel config carries credentials inline (Slack/Discord webhook URLs, SMTP passwords); `details` records only the sorted list of channel keys present, never their secrets. |

### Tests

`tests/test_sprint1_5_audit_followup.py` — 23 new tests, 0.35s runtime:

- `TestAuthenticateRequestBypassMode` (2) — bypass mode returns setup_user without touching `request.current_user` (the F-1 invariant — the helper has no side effects)
- `TestAuthenticateRequestBearerToken` (5) — missing header / wrong scheme / invalid token / legacy token / scoped key allowed_domains propagation
- `TestRequireRoleDelegation` (3) — both decorators set `current_user` only on success, 403 INSUFFICIENT_ROLE for under-roled callers
- `TestRbacDenialAudit` (2) — `log_authz_denied` emitted with the right fields when an AuditLogger is wired; no crash when not wired (fallback warning path)
- `TestDownloadRoleSplit` (11) — full matrix of viewer-allowed and viewer-denied download paths plus operator-allowed counterparts; each viewer denial verified to emit `log_authz_denied`

Total unit-test surface after this release: 112 passes (89 pre-existing + 23 new) in ~0.83s without Docker. CI also runs the Docker-fixture integration suite (`test_auth.py`, `test_settings.py`, `test_cert_lifecycle.py`, ...) and passes.

### Backward compatibility

- The download endpoint still accepts every previous URL; only viewers see new 403s on the four private-key paths. The new `?include_private=0` parameter and `cert.pem` / `chain.pem` single-file paths are additive.
- The `_authenticate_request` refactor is internal to AuthManager; the decorator API surface (`@auth_manager.require_auth`, `@auth_manager.require_role`) is unchanged.
- `set_audit_logger` is optional — when unset, role denials still surface in `logger.warning`. No regression for tests or minimal setups.
- No changes to scoped API key creation, the `allowed_domains` matcher, or the settings whitelist.

### Non-goals (deferred to Sprint 2)

Listed so they don't get assumed:

- **F-3** (legacy bearer token deprecation flag + UI warning + dedicated rotation endpoint). Structural feature; needs UX design for the migration path.
- **F-4** (UI warning when `allowed_domains` left empty on key creation). UX nudge.
- **F-5** (in-memory session store lost on restart). Audit explicitly called this an accepted trade-off; not a fix target.
- **F-6** (self-host the ReDoc bundle to remove `cdn.redoc.ly` from CSP). INFO; air-gapped polish.
- **F-7** (per-username login rate limit on top of the existing per-IP limit). INFO; mitigated today by the 12-character password policy + per-IP limit.

## v2.4.13 (Patch — audit log performance + slow-request watchdog)

Single community PR from [@ITJamie](https://github.com/ITJamie) ([#146](https://github.com/fabriziosalmi/certmate/pull/146)). Two changes, both diagnostic-grade; neither alters application behavior for the happy path.

### Audit log read performance

`AuditLogger.get_recent_entries` previously read `min(file_size, limit * 512)` bytes from the end of `certificate_audit.log` and parsed the tail as ASCII. The 512-bytes-per-entry budget was already tight before v2.4.12 and became a real problem with the new audit methods that v2.4.12 added: `log_settings_changed` with several `changed_keys` lands at ~600 bytes per entry, and `log_api_key_created` with an `allowed_domains` list goes further. Result: the Activity page sometimes hung, and the tail it did return silently dropped recent entries.

The replacement walks backwards from EOF in 8 KB blocks, stops when the accumulated block count exceeds the caller's `limit`, and decodes UTF-8 with `errors='replace'` so a single malformed byte does not lose an otherwise valid record. Effective budget is now ~8 KB per expected entry — comfortable for everything the audit logger currently emits. Test (`tests/test_audit.py`) writes 2000 entries and asks for the last 3 to exercise both the multi-block walk and the trimming.

### Slow-request watchdog

New optional instrumentation registered by `setup_slow_request_logging(app, container)` in `modules/core/factory.py`. Tracks every in-flight Flask request by thread ID under a lock; on `after_request`, logs a `Slow request completed` event when duration crosses a configurable threshold; in parallel, a daemon watchdog thread periodically scans for requests still running past the threshold and emits a `Request still running` event including the captured thread stack so the operator can see where it is stuck.

Three env knobs (all optional, all default to sensible production values):

| Variable | Default | Effect |
|---|---|---|
| `CERTMATE_SLOW_REQUEST_LOGGING` | `true` | Master switch. Set to `false`/`0`/`no`/`off` to disable. |
| `CERTMATE_SLOW_REQUEST_THRESHOLD_SECONDS` | `30.0` | Request duration above which we start logging. |
| `CERTMATE_SLOW_REQUEST_SCAN_SECONDS` | `10.0` | How often the watchdog scans for in-flight slow requests. |
| `CERTMATE_SLOW_REQUEST_REPEAT_SECONDS` | matches threshold | Minimum gap between repeated "still running" logs for the same request. |

Output goes to a dedicated `request-watchdog` logger so it doesn't pollute the main log stream. The watchdog thread is a daemon, dies with the process, and its `stop_event` is stored on the app container for future shutdown plumbing.

### Tests

- `tests/test_audit.py::test_get_recent_entries_uses_tail_and_preserves_order` — 2000 entries, asks for last 3, verifies order.
- `tests/test_factory_logging.py::test_env_float_falls_back_on_invalid_value` — bad env value gracefully falls back to default.
- `tests/test_factory_logging.py::test_format_thread_stack_returns_current_thread_stack` — sanity check on the helper.

The watchdog thread itself is not tested end-to-end (would require timing-coupled Flask integration plumbing), but the helpers it depends on are covered and the rest is standard Flask `before/after_request` glue.

### Notes

- No application behavior change. The watchdog only logs; it does not abort, cancel, or modify requests in any way.
- Compatible with v2.4.12: the new audit-log read path is downstream of v2.4.12's audit writes; the line format is unchanged.

## v2.4.12 (Patch — Sprint 1 security hardening + two open bug fixes + repo hygiene)

Closes the first batch of an internal security audit on the v2.4.x API surface, plus two open community bug reports filed the same day against the dashboard and the deploy menu, plus a small repo-hygiene pass. Eleven atomic commits, 1427 insertions and 9135 deletions on `main` (the deletion total is dominated by seven tracked-by-mistake dev artifacts — `.coverage`, `coverage.xml`, `test_results.json`, `debug_*.py`, a stale Playwright screenshot — being untracked, not by application code being removed). 55 new unit tests in `tests/test_sprint1_security.py`; 86 unit tests pass in total. PR [#147](https://github.com/fabriziosalmi/certmate/pull/147).

### Authorization

- **Strict field whitelist on `POST /api/settings`** (both the Flask-RESTX surface at `/api/settings` and the web blueprint at `/api/web/settings`). The endpoint previously accepted any payload field and let `atomic_update` merge it on top of the on-disk settings. `atomic_update` already preserved `users`, `api_keys`, and `local_auth_enabled`, but did **not** protect `api_bearer_token` (token-rotation hijack via an admin-credentialed client) or `deploy_hooks` (shell-exec injection via the deploy hook command field). Each rejected field is now a `400` with a `hint` pointing at the dedicated endpoint (`/api/users`, `/api/keys`, `/api/auth/config`, `/api/deploy/config`). Unknown fields are also rejected to surface typos instead of silently dropping them. Masked-secret echoes (`'********'` placeholder values returned by the masked GET) are stripped recursively before validation so a UI round-trip POST does not falsely 400; the unmasked GET-then-POST-back round-trip is now a clean no-op.

- **`/api/auth/config` split into two routes.** The previous implementation registered a single `GET|POST` view with `require_role('viewer')` and an inline admin check inside the handler — defense-in-depth fail. Now `GET` is `viewer`, `POST` is `admin`, both enforced at the decorator level. POST also audit-logs the `local_auth_enabled` transition.

- **Scoped API keys with `allowed_domains`.** Optional per-key list of domain patterns; supports exact (`example.com`) and wildcard (`*.example.com`) forms. The wildcard matches subdomains at any depth but not the apex, matching Let's Encrypt's SAN semantics. `None` (or omitted on existing keys) preserves the legacy unrestricted behavior. `[]` is a deliberate locked-out state for staging keys. Enforced on every per-domain endpoint (RESTX + web blueprint): `GET /certificates` (filters the result set), `POST /certificates(/create)` (checks primary + every SAN), `PATCH /certificates/{d}`, `DELETE /certificates/{d}`, `GET /certificates/{d}/download`, `GET /certificates/{d}/dns-alias-check`, `POST /certificates/{d}/renew`, `PUT /certificates/{d}/auto-renew`, `POST /certificates/{d}/deploy`, plus batch create and batch download. Denials return `403 DOMAIN_OUT_OF_SCOPE` and are recorded in the audit log.

### Audit trail

Nine new `AuditLogger` methods cover settings mutations, auth-config toggle, user CRUD, scoped key CRUD, deploy hook changes, CA provider changes, and authorization denials. Wired into seven mutating endpoints. Sensitive values are never serialized — only key names, IDs, and operational metadata. Deploy hook commands themselves are explicitly not logged (log-injection + secret-leak risk).

### Bug fixes

- **[#144](https://github.com/fabriziosalmi/certmate/issues/144) (community, [@ITJamie](https://github.com/ITJamie))** — Dashboard 404s on DNS provider accounts. `dashboard.js` was calling `/api/settings/dns-providers/<p>/accounts`, which is not a registered route. Seven providers, seven 404s on every dashboard load. Corrected to `/api/dns/<p>/accounts`.

- **[#137](https://github.com/fabriziosalmi/certmate/issues/137) (community, [@SpeeDFireCZE](https://github.com/SpeeDFireCZE))** — *Recent Executions* in the Deploy menu showed *unexpected response*. The backend returns `{history: [...]}` but the Alpine.js handler branched only on `Array.isArray(res.body)`, so the wrapped object was discarded and the fallback fired. Handler now accepts both shapes, forward-compatible with any future raw-array return.

- **Drive-by**: `DELETE /api/keys/<id>` was treating `revoke_api_key`'s `(ok, msg)` tuple as truthy, so failed revocations always returned *API key revoked*. Now distinguishes 404 (not found) from 400 (other failure) and surfaces the underlying message.

### UI

- New *Allowed Domains* input on the API Keys settings tab. Comma-separated, inline help, defaults to empty (= unrestricted, preserves the existing zero-click workflow for admins who don't need scoping).
- New scope badge on the existing-keys list. Shows `N domain(s)` or `locked`, with the full pattern set in the title attribute and as a secondary line in monospace.

### Documentation

README gains two new subsections under *Security & Best Practices*:

- **Settings API Hardening** documents the strict whitelist on `POST /api/settings`, the per-field rejection behavior, and the new audit-log surface.
- **Secret Storage Hardening** documents the on-disk situation (DNS provider credentials remain in `data/settings.json` in their original form; the bearer token is HMAC-SHA256 hashed) and the five recommended hardening steps in order of effort (external secret backend > volume encryption > non-root user > avoid bind mounts > credential rotation). Explicit callout that the application does not encrypt secrets at the application layer — defers to an external secret backend or volume encryption.

### Repo hygiene

- **Seven tracked dev artifacts untracked** (`.coverage`, `coverage.xml`, `test_results.json`, `debug_response.py`, `debug_storage_simple.py`, `debug_storage_test.py`, and one stale Playwright failure screenshot under `test_screenshots/`). All were left over from local debugging sessions; none are referenced by the test suite, the CI workflow, or the application. `.gitignore` extended with the corresponding patterns so they do not drift back in.

- **Missing issue templates shipped**. `feature_request.md` and `.github/ISSUE_TEMPLATE/config.yml` existed locally but had never been committed, so the GitHub issue picker at `/issues/new/choose` only offered Bug Report and the `?template=feature_request.md` link in the README silently 404'd back to the blank-issue redirect. Both files are now committed; the `config.yml` keeps blank issues disabled and routes contributors at Discussions.

- **GitHub Wiki populated** (off-PR, same day). Eleven pages reflowed from the existing `docs/` tree, navigable left sidebar (`_Sidebar`), per-page footer (`_Footer`), and a project-wide `Home` landing page. Inter-page links rewritten to wiki page references; source-file links rewritten to absolute repo URLs so they resolve from the wiki. Closes [#140](https://github.com/fabriziosalmi/certmate/issues/140).

### Backward compatibility

- API keys without `allowed_domains` (existing rows in `settings.json`) keep full access.
- Session-authenticated local users and the legacy `api_bearer_token` keep full access.
- The setup wizard payload (`email`, `dns_provider`, `dns_providers`, `auto_renew`, `setup_completed`) is covered by the whitelist; a regression test guards this.
- The masked-secret round-trip pattern used by the web UI (GET → populateForm → POST same payload back) is preserved: masked values are stripped pre-validation and unchanged top-level fields are silently dropped as no-op echoes.
- `atomic_update`'s pre-existing `protected_keys` is unchanged — the whitelist is an additional gate at the HTTP layer, not a replacement.

### Breaking changes (security)

The whitelist on `POST /api/settings` rejects payloads that include `api_bearer_token`, `api_bearer_token_hash`, `deploy_hooks`, `users`, `api_keys`, or `local_auth_enabled` *with a value different from the current on-disk value*, returning `400` and a `hint` field pointing at the correct dedicated endpoint. No-op round-trip echoes of the same fields are silently dropped and do not break existing callers. Any integration that was *intentionally* mutating one of these fields through the generic settings endpoint will need to switch to the dedicated endpoint. The CertMate web UI already uses the dedicated endpoints for these fields and is unaffected.

### Non-goals (explicit)

Items deliberately out of scope for this sprint, listed so they do not get assumed:

- No secrets-at-rest encryption. DNS provider credentials remain in `data/settings.json` in their original form. The README now documents this explicitly and points at the existing external-storage backends (Vault, Infisical, AWS Secrets Manager, Azure Key Vault) as the recommended fix.
- No HMAC chain or tamper-evidence on the audit log itself.
- No dedicated API surface for rotating the legacy bearer token; rotation still requires editing `settings.json` or `.env`.
- No changes to the renewal path, OCSP/CRL, storage backends, or DNS provider plugins.

### Tests

- `tests/test_sprint1_security.py` — 55 new tests across seven classes covering whitelist accept/reject/unknown, settings-diff, masked-sentinel stripping (top-level and nested-collapse), no-op echo silent-drop semantics, scope matcher (exact, wildcard, apex non-match, locked, unrestricted), `_normalize_allowed_domains` validation, key creation with scope, and authentication propagating scope onto `current_user`.
- `tests/test_apikeys.py` + `tests/test_settings_atomic_update.py` — 31 pre-existing tests, no regressions.
- Total unit-test surface: 86 passes locally in 0.6s without Docker; the Docker-fixture integration suite (`test_auth.py::TestSetupModeBypass::test_web_settings_post_works`, etc.) runs in CI and passes.

## v2.4.8 (Patch — community PR merge + JSON download + lint fixes)

Merges the ITJamie PR chain ([#128](https://github.com/fabriziosalmi/certmate/pull/128), [#132](https://github.com/fabriziosalmi/certmate/pull/132), [#133](https://github.com/fabriziosalmi/certmate/pull/133)) and resolves three markdown lint findings. All changes validated end-to-end on a live Docker instance with real Cloudflare DNS-01 certificate creation.

### From the community

- **#133** [@ITJamie](https://github.com/ITJamie) (superset of #128 and #132) — three fixes in one:
  - **JSON certificate download** (`?format=json`): new query parameter on `GET /api/certificates/<domain>/download` returns a JSON object with `cert_pem`, `chain_pem`, `fullchain_pem`, `private_key_pem` as PEM strings. Mutually exclusive with the existing `?file=` parameter (returns 400 on conflict). Invalid format values return 400. Documented in `docs/api.md` and `README.md`.
  - **Tempdir data-loss fix**: `setup_directories()` in `factory.py` no longer calls `tempfile.mkdtemp()` — certificates, data, backups, and logs directories now always resolve to the project paths (`/app/certificates`, `/app/data`, etc.), surviving container restarts.
  - **Settings migration**: `SettingsManager.load_settings()` now migrates legacy single-account DNS provider config (`dns_providers.cloudflare.api_token`) to the multi-account structure (`dns_providers.cloudflare.accounts.default.api_token`), and correctly applies `CLOUDFLARE_TOKEN` env var override without resetting `setup_completed` (fixes setup wizard loop, issue #130).
  - **Dashboard table fix**: certificate rows in `dashboard.js` now use `rowRaw(rowHtml\`...\`)` for action buttons, fixing escaped HTML tags rendering as visible text.

### Lint fixes

- `README.md`: fixed docker-compose YAML code block indentation (duplicate `cpus`/`memory` keys at wrong nesting level)
- `README.md`: normalized `Backup & Recovery` headings to `Backup and Recovery` (resolves broken `#backup--recovery` anchor)
- `docs/guide.md`: fixed broken link `./CHANGELOG.md` → `../RELEASE_NOTES.md`

### Tests

- 2 new test files: `test_factory_directories.py` (tempdir fix) + `test_issue130_setup_wizard_loop.py` (migration + env override)
- 2 new test cases in `test_cert_lifecycle.py` (JSON download success + invalid format)
- 1 new test case in `test_download_file_param.py` (JSON 404 for missing domains)
- All validated against live Cloudflare DNS-01 with random subdomain `pr133test-91e7c166.certmate.org`

## v2.4.7 (Patch — base image bump bookworm → trixie)

Two-character `Dockerfile` change ([#127](https://github.com/fabriziosalmi/certmate/pull/127)): `python:3.12-slim` → `python:3.12-slim-trixie`. Expected to close ~11-13 of the 13 open Critical+High Trivy findings on the main branch image — all of them base-image OS CVEs (gnutls, libssh2, ncurses, systemd, libcap) fixed in trixie's package versions but not backported to bookworm.

| Component | bookworm (v2.4.6) | trixie (v2.4.7) |
|---|---|---|
| Debian | 12 | 13 |
| glibc | 2.36 | 2.40 (forward-compat, no wheel rebuild needed) |
| OpenSSL system | 3.0.x | 3.4.x (irrelevant — `cryptography` bundles its own) |
| gnutls | 3.7.9 | 3.8.7 (closes alerts #253, #254, #255, #256, #257) |
| ncurses | 6.4 | 6.5 (closes #182, #193, #200, #201) |
| systemd | 252 | 256+ (closes #190, #194) |
| libcap | 2.66 | 2.68+ (closes #178) |
| libssh2 | 1.10.0 | 1.11.x (probably closes #274) |

CI verified: multi-arch build (linux/amd64 + linux/arm64) green, full e2e test (3.12) suite green, full `requirements.txt` pip install (certbot 2.10 + 14 DNS plugins + cryptography + cloudflare + boto3 + azure-* + flask) succeeds on trixie. No application code touched, no behavior change. Trivy scan delta on main image will appear in the next nightly scan.

## v2.4.6 (Patch — domain alias mode + CI workflow fix)

Closes [#124](https://github.com/fabriziosalmi/certmate/issues/124). Substantive contribution from [@ITJamie](https://github.com/ITJamie) ([#122](https://github.com/fabriziosalmi/certmate/pull/122)).

### Domain alias mode that actually works

The previous DNS-01 alias flow assumed the **primary** domain's DNS was manageable by your provider; CertMate would still try to write the `_acme-challenge` TXT record on the primary zone and fail with `Unable to determine zone_id for <primary>`. The whole point of alias mode is the case where it **isn't** — only the alias zone is. This release reworks the flow:

- **`modules/core/dns_alias_hook.py`** — new Lexicon-backed manual DNS hook supporting cloudflare, route53, azure, google, powerdns, digitalocean, linode, gandi, ovh, namecheap, arvancloud, infomaniak, duckdns, acme-dns. Writes the TXT on the alias zone, lets the CNAME chain resolve. Unsupported providers are rejected up-front with a clear error instead of failing mid-certbot.
- **`POST /api/certificates/<domain>/check-cnames`** — new endpoint to verify the `_acme-challenge` CNAME chain exists for a domain (and all its SANs) before issuing. Surfaces missing records up-front instead of after a 60s certbot retry.
- **UI**: alias indicator pill on dashboard cert rows, alias display in cert detail panel, SAN list in the sidebar, hint help text in the create-cert form, "DNS-01 Alias" naming standardised.
- **Renewal path**: rebuilds the manual hook from cert metadata so renewals don't fail when the temp credentials file is gone (the Cloudflare/Hetzner/Linode/etc renewal sibling of #112 — different code path, same shape of bug, fixed here for the alias case at least).
- **Tests**: 47 cases in `tests/test_domain_alias.py` covering hook regeneration on renewal, SAN+wildcard expectations, CNAME existence reporter, unsupported-provider rejection, missing-credentials handling, ACME-DNS subdomain matching, lexicon adapter mapping for all 14 supported providers.

### CI workflow fix (visible to every external contributor)

`docker-multiplatform.yml` was constructing image tags like `docker.io//certmate:pr-NN` (note the double slash from an empty `secrets.DOCKERHUB_USER` on fork-originated PRs — GitHub Actions intentionally doesn't pass secrets to fork workflows). Every dependabot PR and every external contributor PR (#106, #104, #119, #122, …) had been red on the build job for that reason alone, hiding real signal. Added a one-line fallback: when `DOCKERHUB_USER` is empty, use `github.repository_owner` instead. Push to Docker Hub is still disabled for PRs (gated separately), so this only changes the tag, not what gets published.

### Maintainer reconciliation during the rebase

The PR was opened against `main` before the v2.4.x cleanup landed. To bring it on top of v2.4.5:
- `dashboard.js` cert-row template reconciled with the v2.4.2 `CertMate.html` auto-escape helper (alias indicator now uses `${domainAlias}` interpolation; `providerLabel` goes through `rowRaw()`).
- Bandit B310 hardening: scheme-validate the DNS-provider API URL in `_json_request`, `# nosec B310 - hardcoded https literal` on the two static URLs (api.ipify.org for Namecheap public-IP injection; cloudflare-dns.com for the new DoH lookup).

## v2.4.5 (Patch — community PR roundup)

Five merged community PRs + dependabot security bumps. No behavior change in CertMate's core flow; mostly bug fixes, Docker-secrets ergonomics, and new download flexibility.

### From the community

- **#119** [@rocogamer](https://github.com/rocogamer) — generalises the v2.4.3 #113 Azure ambiguous-flag fix to the base `DNSProviderStrategy.configure_certbot_arguments`. Every plugin now uses `--authenticator <name>` (immune to argparse prefix collisions) instead of the bare `--<name>` shorthand; more robust than the per-strategy override I shipped in v2.4.3 (also dropped here in favor of the base class fix). Repins `certbot-dns-azure==2.5.0` (was a phantom `2.11.0` not on PyPI; 2.6.0+ requires certbot>=3.0 which would break the certbot 2.10 pin). 4 new regression tests pin the contract on the base class.
- **#120** [@langtutheky](https://github.com/langtutheky) — adds `SECRET_KEY_FILE` and `API_BEARER_TOKEN_FILE` resolution for Docker Swarm / Kubernetes secret-file mounts. Resolution order: `*_FILE` → env var → fallback. 15 unit tests cover the edge cases (empty file, read error, file precedence over env var, restart persistence, insecure default ignored). Replaces remaining `ADMIN_TOKEN` references with `API_BEARER_TOKEN` across docs and config files.
- **#126** [@rob-infoglobe](https://github.com/rob-infoglobe) — adds `?file=` query param to `/api/certificates/<domain>/download` returning a single PEM (`fullchain.pem`, `privkey.pem`, or a server-side `fullchain || privkey` concatenation as `combined.pem`) for clients that can't unzip — lightweight scripts, embedded tools, simple webhook consumers. Tight whitelist on the filename; 400 on anything else, 404 on missing files. New `tests/test_download_file_param.py` (5 cases) pins the contract.

### Security bumps

- **#106** [@dependabot](https://github.com/apps/dependabot) — postcss 8.5.6 → 8.5.10. [XSS fix](https://github.com/postcss/postcss/releases/tag/8.5.10) for unescaped `</style>` in non-bundler cases. Dev-dep only, no runtime impact.
- **#104** [@dependabot](https://github.com/apps/dependabot) — pip group: requests 2.32.5 → 2.33.0 ([CVE-2026-25645](https://github.com/psf/requests/releases/tag/v2.33.0) in `extract_zipped_paths`; doesn't affect default usage), python-dotenv, cryptography.

### Tests

- **209 unit tests pass** (was 143; +47 from #120's secret-key tests + #119's authenticator tests + the rest from the merged PRs).
- 5 new e2e tests for #126.

### Still pending

- **#122** [@ITJamie](https://github.com/ITJamie) (DNS alias mode rewrite) — rebased on top of this release; the `dashboard.js` conflict from v2.4.2's CertMate.html refactor was reconciled. Awaiting the reporter's re-test before merge. Targeted for v2.4.6 / v2.5.0.

## v2.4.4 (Patch — wire up missing notification routes)

Closes [#114](https://github.com/fabriziosalmi/certmate/issues/114).

The frontend (`settings-notifications.js`, `base.html` SSE) had been calling four endpoints that were never registered server-side, so the browser saw 404 in the network tab and notification settings couldn't be saved from the UI. The backend logic (`Notifier`, `WeeklyDigest`) was already complete — this PR just surfaces it.

### New routes (admin role required, registered in `modules/web/misc_routes.py`)

| Method | Route | Backed by |
|---|---|---|
| GET / POST | `/api/notifications/config` | `Notifier._get_config()` / `SettingsManager.update()` writing the `notifications` block |
| POST | `/api/notifications/test` | `Notifier.test_channel(channel_type, config)` |
| POST | `/api/digest/send` | `WeeklyDigest.send()` |
| GET | `/api/webhooks/deliveries?limit=N` | `Notifier.get_deliveries(limit)` (clamped to 1..500, default 50) |

### Test coverage

New `tests/test_notifications_routes.py` — 9 e2e tests covering: GET shape, POST round-trip persistence, body-shape validation, transport-failure normalization (`{success:false, error:...}` instead of 500 when SMTP host is unreachable), missing/unknown `channel_type`, digest result envelope (`success`/`skipped`/`error`), deliveries list shape + limit param.

All 9 pass against the Docker test container (156s including image build). 143 unit tests still pass.

## v2.4.3 (Patch — issue triage)

Closes four open issues, comments on five more.

### Bug fixes
- **#125 Cross-origin deployment status checks blocked by CSP**: `connect-src` was `'self'`, so the dashboard's per-cert deployment check (which fetches the monitored domain to verify it serves the expected cert) was a no-op for any cert that didn't match the server URL. Relaxed to `'self' https: wss:` — narrower than the reporter's suggested `*` (still excludes `data:`/`blob:`/`file:`/`ftp:`) while unblocking the actual use case. Reported by @rob-infoglobe.
- **#113 Azure DNS: `ambiguous option: --dns-azure`**: certbot-dns-azure registers `--dns-azure-credentials`, `--dns-azure-propagation-seconds`, and `--dns-azure-config` — passing the bare `--dns-azure` flag as the authenticator selector hits argparse's ambiguity check. `AzureStrategy` now overrides `configure_certbot_arguments` to use the explicit `--authenticator dns-azure` form, mirroring `PowerDNSStrategy`. Reported by @jensaops.
- **#121 Docker compose silently fails when host dirs aren't writable**: `setup_directories` used to catch the `OSError`, fall back to creating tempdirs, and let the wizard half-succeed. It now probes each of `certificates/`, `data/`, `backups/`, `logs/` with a write+unlink test at boot and raises `RuntimeError` with a clear list of failed paths — including the hint that the container runs as UID/GID 1000:1000. Reported by @ITJamie.

### Documentation
- **#117 Deploy hooks docs**: new [`docs/deploy-hooks.md`](docs/deploy-hooks.md) covering hook schema, UI vs API config, the `CERTMATE_*` environment variables, manual triggering paths, the v2.4.0 security model (blocked patterns + sensitive-file denylist), common recipes, and the audit/history/debug paths.

### Triaged (commented, not yet fixed)
- **#114 Missing API routes (notifications/digest/webhooks)**: 4 of the 5 routes the frontend references (`/api/notifications/config`, `/api/notifications/test`, `/api/digest/send`, `/api/webhooks/deliveries`) are 404 — the backend logic exists but isn't surfaced. Audit posted on the issue, fix scoped for v2.4.4.
- **#112 Route53 + credentials-file DNS providers fail at renewal**: `renew_certificate` skips both `prepare_environment` (env-var providers like Route53) and the credentials-file recreate path (Cloudflare, Hetzner, Linode, OVH, etc), so renewals always need ambient Docker env vars to work, and credentials-file providers fail outright on the second renewal. Diagnosed jointly by @jplandry908 and @jensaops; fix shape posted on the issue, scoped for v2.4.4.
- **#115 Webhook command validator + GUI script editor request**: the bug part (curl POST blocked by `[\`$]` character class) was already fixed in v2.4.1 — verified the reporter's exact command runs through the current validator. The feature request (GUI script CRUD on the host) deferred — would substantially widen the threat model from "execute a vetted whitelist" to "write arbitrary code into the container", and the docs now explicitly cover the "wrap multi-step logic in a script you mount via Dockerfile/compose" pattern instead.
- **#124 Domain alias mode**: tracked via PR #122 from the reporter (@ITJamie) — substantive 700-line fix with 479 lines of tests. Will review and aim to merge in v2.4.3 → v2.5.0 timeframe.
- **#116 Akamai EdgeDNS missing**: closed as not-a-bug — already supported as the `edgedns` provider (UI label "Akamai Edge DNS"). Discoverability could improve.

## v2.4.2 (Patch — UI debt repayment)

Frontend-only cleanup driven by a UI tech-debt audit. No behavior changes for end users; bundle shrinks and the theme toggle finally works correctly.

### Refactor
- **Removed unused `htmx.min.js`**: was loaded synchronously from `base.html` on every page but no template ever used `hx-*` attributes — 51 KB of vendor JS for zero benefit. The `<script>` tag and the file itself are gone.
- **Split `settings.js` into per-component modules**: three self-contained Alpine components extracted to `settings-notifications.js`, `settings-deploy.js`, and `settings-apikeys.js`. `settings.js` is now 2651 lines (was 3048, −13%). Cross-module helpers (`addDebugLog`, `showMessage`) bridged via a small `window.CmSettings` surface.
- **Added `CertMate.html` tagged-template helper**: each `${value}` interpolation is auto-escaped; `CertMate.raw()` opts out for pre-rendered fragments. Converts the two largest `innerHTML` sites in `dashboard.js` (stats cards + cert table row) — removes a class of XSS-by-omission risk where a future PR could forget to call `escapeHtml()` on a user-provided field.

### Build hygiene
- **Rebuilt `tailwind.min.css`**: the bundle was months stale and missing ~128 `dark:*` utilities. Most visible symptom: the theme toggle showed both moon and sun icons simultaneously because `dark:hidden` / `dark:inline` didn't exist in the bundle. Other silently-broken classes included `safe-area-bottom` and `pb-16`. Run `npm run css:build` after touching templates to keep this fresh.

### Tests
- Updated `test_static_csp` parametrization to match the new module layout (drop `htmx.min.js`, add `settings-*` bundles).

## v2.4.1 (Patch — client-cert UI fixes)

Addresses [#123](https://github.com/fabriziosalmi/certmate/issues/123): the client-certificate dashboard was unusable from the GUI.

### Bug fixes
- **#123 405 Method Not Allowed creating a client certificate**: the create form posted to `/api/client-certs`, but that route is the list resource (GET only) — the create endpoint lives at `/api/client-certs/create`. Repointed the fetch to the documented Swagger path; `/create` is also the convention used elsewhere in the API (`/api/certificates/create`, `/api/backups/create`).
- **Batch CSV upload was a dead button**: `#submitBatchBtn` was rendered after CSV preview but had no click handler — clicking it did nothing. Wired up a handler that POSTs `{headers, rows}` from the parsed CSV to `/api/client-certs/batch`, surfaces a `successful/total` toast (warning when any row failed), clears the preview, and reloads stats + list. CSRF is still covered by the existing Origin/Referer check, no token plumbing needed.

## v2.4.0 (Minor — issue triage + audit hardening)

Closes seven open issues and adds one round of post-batch hardening driven by a 360° audit.

### Features
- **#111 Per-certificate auto-renew toggle + delete UI**: each certificate row gets an auto-renew toggle (purple/amber) and a delete button. The cert detail panel now also exposes "Disable Auto-Renew" / "Enable Auto-Renew" and "Delete Certificate". `CertificateManager.check_renewals()` honors the per-cert flag — domains with `auto_renew=False` are skipped by the daily 02:00 UTC scheduler. Legacy string-form domain entries continue to renew normally; toggling auto-renew on a legacy entry upgrades it to the dict form. `PUT /api/certificates/<domain>/auto-renew` (operator role) drives the toggle.
- **#109 Manual deploy hook trigger**: new `POST /api/certificates/<domain>/deploy` (admin role) and a "Run Deploy Hooks Now" button in the cert detail panel. Fires every enabled global + domain-specific hook on demand with `CERTMATE_EVENT=manual`, ignoring the `on_events` filter — the user explicitly asked. Returns a structured summary (`ok` / `total` / `succeeded` / `failed` / per-hook `results`) plus a helpful error string for the no-hooks-configured and feature-disabled cases.

### Bug fixes
- **#108 Cannot finish setup**: a misconfigured `API_BEARER_TOKEN` env var (empty `${API_BEARER_TOKEN}` from docker-compose, or a hand-typed weak placeholder) was poisoning every `save_settings` call with a misleading "API token length must be between 32 and 512 characters", blocking the setup wizard from saving DNS provider credentials and breaking user creation. We now validate the env var on read; if it fails `validate_api_token` we log a warning naming the env var and fall back to a freshly generated token. The save-time error message also identifies the field as `api_bearer_token` (distinct from any DNS provider credential) so future bad-token reports can be diagnosed from one log line.
- **#110 Deploy hooks save shows error toast on success + missing debug logs**: the server returned `{message: 'Deploy configuration saved'}` on success but the client checked `d.status === 'saved'` (a key that never existed) — the success branch never ran and users always saw "Save failed: unknown" even when the save worked. Switched the client to use HTTP status (`r.ok`) as source of truth. Separately, the `deployManager` Alpine factory never called `addDebugLog()` so the settings-page debug console stayed empty during deploy actions; `loadConfig` / `saveConfig` / `testHook` / `loadHistory` now log start, success, and failure.
- **#101 "Webhook not found" error**: `test_hook` returned a bare unactionable "Hook not found". Now returns a message that names the two real-world causes (stale UI state vs save-time validator rejection) plus a structured `reason: 'hook_missing_from_config'` field for log triage.
- **#102 Deploy command field documentation + actionable rejection reason**: Settings → Deploy now has an info banner listing the blocked shell metacharacters (`|`, `&&`, `||`, `;`, `$(...)`, `${...}`, backticks, redirects to absolute paths, here-docs, `eval`, `source`) and the blocked sensitive-file references (`.pem`, `.env`, `settings.json`, private keys, vault tokens). Added `CERTMATE_DRY_RUN` to the available-env-vars list (was missing). `save_config` now returns `(ok, error_msg)` and the UI surfaces the specific reason — "Global hook rejected: hook 'Pipeline' command contains dangerous shell metacharacters" instead of a generic "Invalid configuration or save failed".
- **#100 Decorative cert-row icon read like a button**: the rounded blue panel wrapping the `fa-certificate` glyph in the leftmost column of each cert row had no handler attached, but the rounded background + colored panel made it look interactive. Flattened to a subtle inline glyph; the per-row auto-renew toggle and delete button (added in #111) carry the meaningful actions.

### Hardening (post-batch audit)
A draconian audit on the batch above identified three classes of MUST-FIX hazards.

- **Settings races**: every `load_settings → mutate → save_settings` outside `SettingsManager` was racing under concurrent admin writes — two parallel user creations could lose one user; two parallel cert creations could drop a domain entry from `settings['domains']`; deploy-hook saves could clobber a concurrent DNS provider edit and vice versa. Added `SettingsManager.update(mutator, reason)` that runs the read-modify-write under the existing RLock. Migrated 9 call sites: `_save_users`, `_save_api_keys`, the API-token `last_used_at` update during auth, `enable_local_auth`, `create_dns_account` / `delete_dns_account` / `set_default_account`, `DeployManager.save_config`, and the cert-creation domain-list append in both REST and web routes. A 20-thread concurrent stress test pins the fix.
- **Newline injection in deploy-hook commands**: `_DANGEROUS_SHELL` blocked `;` / `&&` / `||` but not `\n` / `\r`. `sh -c` treats newlines as `;` so a multi-line textarea entry could chain. Defense-in-depth — admin role still required to create hooks — but the denylist is now complete on chaining metacharacters.
- **Role-aware UI gating**: viewers and operators saw "Run Deploy Hooks Now" and "Delete Certificate" buttons that produced 403s when clicked. Server authz unchanged (still authoritative); the dashboard now calls `/api/auth/me` on first load and gates the row + detail-panel buttons by role. `/api/auth/me` returns 200 with `role: admin` during onboarding (auth disabled or no users yet) so the dashboard can render in setup mode.

### Polish
- "Run Deploy Hooks Now" toast discriminates 401/403 (now suggests signing in as admin), 404 (cert missing), generic non-2xx (HTTP code in message), and the 200-with-`ok=false` no-hooks-configured case — instead of one catch-all "Deploy hook run failed".
- Settings → Notifications "Load Config" and Webhook "Load Deliveries", and the setup-wizard auto-detect, no longer swallow fetch failures into empty `.catch()` handlers — failures now go to `console.error()` for triage. Toast suppression preserved on first-load paths so a stale session doesn't spam the user.
- `SettingsManager.load_settings()` now logs at ERROR (was silent) when a migration save fails — when this fires, the in-memory copy diverges from `settings.json` and the operator needs to see why.

### Tests
- 26 unit tests pass (was 16): added concurrent-writer stress test, newline/CRLF rejection, env-var validation fallback (5 cases), per-cert auto-renew skip + flag persistence, manual-deploy aggregate behavior, actionable test-hook error message, and `/api/auth/me` bypass behavior.
- 35-test deployer suite green; one stale `'not found' in error` assertion updated for the #101 message change. Test fixture `MagicMock` for `settings_manager` now wires `update` to call through to `save_settings` so existing call-args assertions still work after the atomic-update migration.

## v2.3.9 (Patch — v2.3.8 follow-up)

Addresses a CI regression and four review comments on [#105](https://github.com/fabriziosalmi/certmate/pull/105).

- **Fix CI regression in `tests/test_pages.py`**: `TestWelcomeBanner.setup_initialized_state` created the admin user with `password123`, which the new password policy from v2.3.8 (≥12 chars + digit + symbol) rejects with 400 → no admin → page stays in welcome/setup mode → `dashboard.js` not in response. Bumped the fixture password to `Password123!`.
- **CSRF host comparison handles ports**: Origin/Referer comparison previously did a literal string match against `request.host`, which gave false 403s when one side included a default port (`:443`/`:80`) and the other didn't. Both sides are now normalized — default ports stripped, explicit non-default ports preserved.
- **`AuthManager.hash_api_token` is now public**: `SettingsManager.set_token_hasher()` was wired to `auth_manager._hash_api_token` (a private symbol). Renamed to `hash_api_token` and kept `_hash_api_token` as a backwards-compat alias.
- **Removed unused `cert_dir` local in `DELETE /api/certificates/<domain>`**: the path was validated for the side-effect of rejecting traversal attempts but the resolved `Path` was never used. Replaced with `_, err = ...`.

## v2.3.8 (Patch — security & robustness)

Audit-driven hardening pass. No new features; everything below addresses a verified defect, race condition, missing endpoint, or piece of dead code.

**Data integrity**
- Race condition in `SettingsManager`: `save_settings()` and `load_settings()` were unprotected, while `atomic_update()` held a `Lock` only on its own merge — concurrent writes from API + scheduler + UI could lose data. Lock is now `RLock` and wraps both methods, with internal callers (load → save during migration) re-entering safely.
- `SettingsManager` `_compat` shims (`_save_settings_compat`, `_safe_file_write_compat`, …) removed. They were dead code — `app.py` no longer exposes any of the functions they probed.
- API Settings `POST /api/settings` and Storage Backend `POST /api/storage/config` now route through `atomic_update`; the previous `save_settings(payload)` could wipe `users` / `api_keys` if absent from the payload.
- Backup rotation: `MAX_BACKUPS_PER_TYPE=50` and `BACKUP_RETENTION_DAYS=30` were defined but never enforced. `_prune_unified_backups()` now runs after each `create_unified_backup()`.

**Security**
- Legacy `api_bearer_token` is hashed (HMAC-SHA256) and the plaintext is dropped from `settings.json` on the next save. Auth still accepts the original token via `api_bearer_token_hash` compare; rotate via the API Keys UI. Backwards compatible: installs that haven't migrated yet still authenticate via plaintext fallback.
- CSRF defense: `before_request` middleware rejects state-changing requests carrying the session cookie when `Origin`/`Referer` don't match `Host`. Bearer-token API clients are unaffected. Defense-in-depth on top of the existing `SameSite=Strict` cookie.
- Web `POST /api/users` now enforces a minimum password policy (≥12 chars + a digit + a symbol).
- Web `DELETE /api/users/<username>` refuses if the caller is deleting their own account.

**Missing endpoints / endpoints in wrong shape**
- `DELETE /api/certificates/<domain>` exposed (admin role). The underlying `CertificateManager.delete_certificate()` already existed; only the route was missing.
- `GET /api/events/stream` (SSE) implemented. The browser was already opening an `EventSource` to this URL; the route did not exist, so every page load entered a 404 retry loop.
- `GET /api/health` now reports scheduler status alongside settings load (the Flask-level `/health` already did; the namespaced API one was a stub).
- `POST /api/settings/test-ca-provider`: dead `return` after the inner `if` is now reachable, and the missing branch for HTTP non-200 ACME directory responses is now handled.

**Cleanup**
- `CertificateManager._infer_dns_provider()` no longer hardcodes user-specific patterns (`test.certmate.org`, `*.audiolibri.org`, `aws-*`, `cf-*`). It now defers to `SettingsManager.get_domain_dns_provider()`.
- `datetime.utcnow()` (deprecated in 3.12) replaced with a `utc_now()` helper that returns a *naive* UTC datetime — same shape as `utcnow()` so existing on-disk timestamps remain comparable. 7 modules migrated.

## v2.3.7 (Patch)

- Fix #99 (cosmetic follow-up): Dashboard no longer surfaces filesystem artifacts (`lost+found`, hidden `.cache` / `.git`, and unrelated subdirectories like `certs` or `config`) as "Not Found" certificate rows when the cert storage root is a volume mount point. Introduced a single `iter_cert_domain_dirs()` helper in `modules/core/constants.py` that filters to subdirectories actually containing `cert.pem`, and applied it at every domain-enumeration call site: the `/api/certificates` list endpoint, weekly digest, metrics collection, and the startup `_ensure_certificate_metadata` rescue path (which previously wrote stray `metadata.json` files into non-cert directories). 7 regression tests pin the filter. Reported by @SpeeDFireCZE.

## v2.3.6 (Patch)

- Fix #99 (follow-up): Akamai Edge DNS certificate issuance failed with `Either an edgerc_path or individual edgegrid credentials are required when using the EdgeDNS API` even after the v2.3.4 settings fix. CertMate was writing the credentials INI in raw Akamai `.edgerc` format (`[default]` section + unprefixed keys), but `certbot-plugin-edgedns` v0.1.0 uses certbot's standard `dns_common.CredentialsConfiguration` parser, which reads a flat INI with keys prefixed by the plugin namespace (`edgedns_*`). The fix rewrites the credentials file as `edgedns_client_token`, `edgedns_client_secret`, `edgedns_access_token`, `edgedns_host` at top level (no section header). Verified by reading the v0.1.0 plugin source and feeding the regenerated INI through certbot's own `CredentialsConfiguration` in a regression test. Reported by @SpeeDFireCZE.

## v2.3.5 (Patch — security)

- Security: bump build-time dependency `picomatch` from 2.3.1 to 2.3.2 ([#94](https://github.com/fabriziosalmi/certmate/pull/94)) to address [CVE-2026-33671](https://github.com/micromatch/picomatch/security/advisories/GHSA-c2c7-rcm5-vvqj) and [CVE-2026-33672](https://github.com/micromatch/picomatch/security/advisories/GHSA-3v7f-55p6-f55p). The dependency is dev-only (transitive of `tailwindcss`, used at CSS build time) — runtime image and end-user installations are not exposed, but the bump keeps SCA scanners and CI clean.
- Security: bump runtime dependency `pyopenssl` from 25.3.0 to 26.0.0 ([#86](https://github.com/fabriziosalmi/certmate/pull/86)). Routine maintenance — no known CVEs at the previous pin, but the new version closes a moderate-severity advisory in upstream OpenSSL bindings and is what fresh installs get by default.

## v2.3.4 (Patch)

- New: DuckDNS DNS-01 provider — first-class support for free `*.duckdns.org` subdomains via `certbot-dns-duckdns`. Enables publicly-trusted Let's Encrypt certificates for homelabs, self-hosted services and IoT devices without owning a domain. Includes UI integration (provider tile + dedicated config section + multi-account modal), settings/API/Swagger wiring, and 14 unit tests covering strategy, INI format, validation and certbot-arg shape. Smoke-tested end-to-end against Let's Encrypt staging.
- Fix #99: Akamai Edge DNS (`edgedns`) configuration could not be saved via the web UI or API — `save_settings()` rejected it with `Invalid dns_provider: edgedns` because the provider was not registered in `supported_providers`, the propagation defaults, the multi-account migration map, or the Swagger/REST enums. Reported by @SpeeDFireCZE.
- Fix: DuckDNS plugin selection now uses `--authenticator dns-duckdns` instead of the bare `--dns-duckdns` flag, which certbot rejected as ambiguous (the plugin exposes multiple `--dns-duckdns-*` options).
- Fix: `CertificateManager.create_certificate()` no longer raises `UnboundLocalError` from its finally block when an early failure occurs (e.g. plugin-not-installed). The original `RuntimeError` now surfaces correctly to API clients. Regression tests pinned.
- Test: New cross-validation suite (`tests/test_provider_wiring_consistency.py`) breaks the build the moment a future DNS provider is registered in the strategy factory but missed in the settings or credential validation surfaces — preventing any recurrence of the #99 wiring gap.

## v2.3.3 (Patch)

- Fix #98: Add Akamai Edge DNS as a dedicated DNS provider (separate from Linode / Akamai Connected Cloud), backed by `certbot-plugin-edgedns` and a standard `.edgerc` credentials file.

## v2.3.2 (Patch)

- Fix #96: Resolve setup loop due to cache, fix download curl link, and persist domains created via web UI
- Fix #97: Add native ACME providers: ZeroSSL, Google Trust Services, BuyPass Go, SSL.com
- Fix #98: Clarify Linode DNS provider as Akamai Connected Cloud (not Akamai Edge)

# Release v2.2.7

## Hetzner Cloud DNS Provider Support

Adds the new Hetzner Cloud API DNS provider (`hetzner-cloud`) to address the upcoming shutdown of the legacy Hetzner DNS console API ([#95](https://github.com/fabriziosalmi/certmate/issues/95)).

### New: Hetzner Cloud DNS provider plugin

The legacy `certbot-dns-hetzner` plugin relies on the Hetzner DNS console API, which [Hetzner is deprecating in May 2025](https://status.hetzner.com/incident/c2146c42-6dd2-4454-916a-19f07e0e5a44). The new `certbot-dns-hetzner-cloud` plugin (v1.0.5) uses the replacement [Hetzner Cloud API](https://docs.hetzner.cloud/reference/cloud) for DNS record management.

Both providers are available simultaneously so existing users can migrate at their own pace. New users should use `hetzner-cloud` directly.

**Configuration:**
```json
{
  "dns_provider": "hetzner-cloud",
  "dns_providers": {
    "hetzner-cloud": {
      "api_token": "your_hetzner_cloud_api_token"
    }
  }
}
```

**Files changed:** `requirements.txt`, `requirements-extended.txt`, `modules/core/utils.py`, `modules/core/settings.py`, `docs/dns-providers.md`

## Test Suite

All existing unit tests pass with zero regressions. Provider integration verified via config generation and credential validation checks.

---

# Release v2.2.6

## Security Hardening and Code Quality

Seven fixes addressing security, correctness, and reliability across authentication, deploy hooks, certificate routes, and storage backends. All 83 unit tests pass with zero regressions.

### Critical: Web certificate routes passed DNS provider as email to certbot

The `/api/certificates/create` and `/api/web/certificates/create` routes in `cert_routes.py` called `certificate_manager.create_certificate(domain, provider)`, passing the DNS provider name as the `email` positional argument. This caused certbot to receive a provider name (e.g., "cloudflare") where it expected an email address, resulting in silent failures or malformed certificate requests. The batch creation route had the same defect.

**Fix:** Rewrote both routes to match the calling convention used by the REST API resource layer: resolve email, CA provider, challenge type, and DNS provider from settings when not explicitly provided, and pass all parameters as keyword arguments.

**Files changed:** `modules/web/cert_routes.py`

### Critical: Deploy hook command validation expanded

The existing deploy hook command blocklist did not cover `eval`, `source`, here-documents (`<<`), parameter expansion (`${}`), or references to `.pem` private key files. An admin-level account compromise could have leveraged these to exfiltrate credentials or escalate privileges.

**Fix:** Extended the validation regex to block `eval`, `source`, `. /path` (source shorthand), here-documents, and `${}` parameter expansion. Added `.pem` and `private.*key` to the sensitive file pattern. Validation is now also enforced at execution time (defense in depth), not only at hook save time.

**Files changed:** `modules/core/deployer.py`

### High: API token hashing upgraded from SHA-256 to HMAC-SHA256

Scoped API tokens were hashed with plain SHA-256. If an attacker obtained the `settings.json` file, they could brute-force the 40-character hex tokens offline. HMAC-SHA256 with the application's `SECRET_KEY` as the HMAC key makes offline brute-force infeasible without the server-side secret.

**Fix:** New tokens are hashed as `hmac-sha256:<digest>`. Verification falls back to plain `sha256:<digest>` for tokens created before this release, so no existing API keys are invalidated.

**Files changed:** `modules/core/auth.py`, `modules/core/factory.py`

### High: Broad exception handling in authentication module

All CRUD methods in `AuthManager` (`create_api_key`, `revoke_api_key`, `create_user`, `update_user`, `delete_user`, `authenticate_user`, `authenticate_api_token`) caught bare `Exception`, masking programming errors such as `TypeError` or `AttributeError` behind generic "internal error" messages and making debugging difficult.

**Fix:** Narrowed exception handlers to `(OSError, ValueError, KeyError)` -- the specific exception types that can legitimately occur during settings I/O and data validation. Unexpected errors now propagate with a full traceback.

**Files changed:** `modules/core/auth.py`

### Medium: Retry decorator relied on error message string matching

The `_with_retry` decorator in `storage_backends.py` determined whether an error was transient by searching for keywords like "timeout" and "429" in the exception message string. This approach is fragile and locale-dependent, and could retry non-transient errors or miss transient ones.

**Fix:** Added `_is_transient()` which checks exception types first (`ConnectionError`, `TimeoutError`, `OSError`), then HTTP status codes on cloud-SDK exception objects (429, 500, 502, 503, 504), and only falls back to keyword matching as a last resort.

**Files changed:** `modules/core/storage_backends.py`

### Low: Deploy history loaded entire file into memory

Both `_truncate_history()` and `get_history()` called `read_text().splitlines()`, loading the complete JSONL file into memory. With the default 500-entry limit this is manageable, but unnecessary.

**Fix:** Replaced with `collections.deque(f, maxlen=N)` which streams the file and retains only the tail, reducing peak memory usage from O(total lines) to O(retained lines).

**Files changed:** `modules/core/deployer.py`

## Test Suite

**83 unit tests passed, 0 failed**. Integration tests (Docker-dependent) excluded from this run.

---

# Release v2.2.5

## Bug Fixes -- Issues #91, #92, #93

Three community-reported issues fixed. All 83 unit tests pass with zero regressions.

### Fix: Scoped API Keys never display (#91)

`create_api_key()` returns a `(bool, dict)` tuple, but the route handler in `settings_routes.py` passed the entire tuple to `jsonify()`. The frontend received `[true, {...}]` instead of the expected `{...}` object, so `data.token` was always `undefined` and the newly created key was never shown to the user.

**Fix:** Unpacked the tuple before serialization: `success, result_data = auth_manager.create_api_key(...)`. The error path now returns the actual error message from the auth layer with a 400 status instead of a generic 500.

**Files changed:** `modules/web/settings_routes.py`

### Fix: Newly created certificate still shows expired (#92)

The certificate date parser in `_parse_certificate_info()` used a single `strptime` format (`%b %d %H:%M:%S %Y %Z`) that fails silently on certain platforms or OpenSSL versions (double-space padding for single-digit days, missing timezone suffix). When parsing failed, the method returned `exists: False`, causing the dashboard to either hide the certificate or display it with a null/expired status.

**Fix:** Added `_parse_openssl_date()` with three format fallbacks for cross-platform compatibility. Switched from `openssl -dates` to `openssl -enddate` for cleaner single-line output. When a certificate file exists but its expiry cannot be parsed, the response now returns `exists: True` with `needs_renewal: True`, preventing false "expired" status on the dashboard. Improved error logging to capture the actual OpenSSL output on failure.

**Files changed:** `modules/core/certificates.py`

### Fix: certbot does not support dns alias mode (#93)

The code passed `--domain-alias` as a certbot CLI flag in all DNS provider strategy classes. Certbot does not have this argument -- it is a concept from tools like acme.sh and lego. Certbot failed immediately with `unrecognized arguments: --domain-alias`.

**Fix:** Removed the invalid flag from all six `configure_certbot_arguments()` implementations (base class, PowerDNS, Namecheap, Infomaniak, ACME-DNS, HTTP-01). When a domain alias is specified, CertMate now logs an informational message guiding the user to set up the required CNAME delegation. DNS alias validation with certbot works transparently via CNAME records: create a CNAME from `_acme-challenge.<domain>` pointing to `_acme-challenge.<alias-domain>`, and certbot follows the chain automatically during the DNS-01 challenge.

**Files changed:** `modules/core/dns_strategies.py`

## Test Suite

**83 unit tests passed, 0 failed**. Integration tests (Docker-dependent) excluded from this run.

---

# Release v2.2.4

## Bug Fixes — Settings, Certificate Status & DNS Alias Mode

Three community-reported issues (#88, #89, #90) fixed. Zero regressions: 165 tests passed, 10 skipped.

### Fix: API Key management and Deploy hooks returning 404 (#90)

The Settings → API Keys tab called `/api/keys` (GET/POST/DELETE) and the Settings → Deploy tab called `/api/deploy/config`, `/api/deploy/test/<id>`, and `/api/deploy/history` — none of which had registered routes in the web layer, producing 404 errors for all operations.

**Fix:** Added all missing routes in `modules/web/settings_routes.py`, wiring them to the existing `AuthManager` (API key CRUD) and `DeployManager` (hook config, test, history).

**Files changed:** `modules/web/settings_routes.py`

### Fix: HashiCorp Vault / OpenBao address not shown after save (#90)

Storage backend config was saved flat at the top level of `certificate_storage` (e.g. `certificate_storage.vault_url`) but the UI loader expected it nested under the backend key (`certificate_storage.hashicorp_vault.vault_url`), so the URL disappeared from the form on next page load.

**Fix:** `collectStorageBackendSettings()` now nests backend-specific config under its key. `loadStorageBackendSettings()` additionally falls back to the legacy flat format for existing config files.

**Files changed:** `static/js/settings.js`

### Fix: Newly created certificates displayed as "Expired" (#88)

JavaScript's `null <= 0` evaluates to `true`, so any certificate whose `days_until_expiry` was `null` (cert info parse failed or cert does not exist on disk) was shown as red "Expired" instead of a neutral state. Stats counters, filter logic, table rows, and the detail panel were all affected.

**Fix:** All four comparison sites now guard with `days_until_expiry !== null && days_until_expiry !== undefined` before the `<= 0` test. Certificates that don't exist show as "Unknown" rather than "Expired".

**Files changed:** `static/js/dashboard.js`

### Fix: Renewal always reported as failure despite succeeding (#88)

The renewal API response contains `{message, domain, duration}` — no `success` field. The JS checked `result.success` (always `undefined` → falsy) and branched to the error path, showing the success message text styled as an error and never reloading the certificate list.

**Fix:** Response check now uses `response.ok` (HTTP 2xx) instead of `result.success`.

**Files changed:** `static/js/dashboard.js`

### Feature: DNS Alias Mode configurable via Web UI (#89)

DNS alias validation via CNAME delegation was already supported by the backend but had no UI entry point.

**Fix:** Added a "DNS Alias Domain" text field in the Advanced Options section of the certificate creation form. When filled, the value is passed as `domain_alias` in the creation request.

**Note:** v2.2.5 subsequently removed an invalid `--domain-alias` certbot flag that was added in this release. DNS alias validation works via standard CNAME delegation and requires no special certbot flags. See the v2.2.5 release notes for details.

**Files changed:** `templates/index.html`, `static/js/dashboard.js`

---

# Release v2.2.3

## Security Hardening — Authentication, Injection & Data Integrity

Full-stack security audit with 16 fixes across authentication bypass, shell injection, path traversal, race conditions, and information leakage. Zero regressions: 165 tests passed, 10 skipped.

### Critical: Unauthenticated certificate management endpoints

All web route endpoints for certificate CRUD (`/api/certificates`, `/api/web/certificates/create`, `/api/web/certificates/batch`, `/api/web/certificates/download/batch`, `/api/web/certificates/dns-providers`, `/api/web/certificates/test-provider`, `/api/web/certificates/<domain>/renew`) were missing `@auth_manager.require_role()` decorators. Any unauthenticated user could create, renew, list, and download certificates.

**Fix:** Added role-based auth guards: `viewer` for read operations, `operator` for create/renew, `admin` for provider testing.

**Files changed:** `modules/web/cert_routes.py`

### Critical: Unauthenticated backup and cache endpoints

All backup and cache routes (`/api/web/backups`, `/api/web/backups/create`, `/api/cache/stats`, `/api/cache/clear`) had no authentication.

**Fix:** Added `admin` role requirement for backup create/list and cache clear, `viewer` for cache stats.

**Files changed:** `modules/web/backup_cache_routes.py`

### Critical: Deploy hook shell injection via metacharacters

Deploy hook commands were passed to `sh -c` with only a blocklist of sensitive filenames. Shell metacharacters like `` ` ``, `$()`, `&&`, `||`, `;`, `|` were not blocked, allowing command chaining.

**Fix:** Added regex-based shell metacharacter blocking (`_DANGEROUS_SHELL`) that rejects commands containing backticks, `$()`, `&&`, `||`, `;`, `|`, and redirects to root paths.

**Files changed:** `modules/core/deployer.py`

### High: Path traversal in backup restore via string prefix bypass

`restore_from_backup()` validated ZIP entry paths using `str.startswith(str(cert_dir) + os.sep)`, which is bypassable with crafted paths. Replaced with `Path.relative_to()` which raises `ValueError` on any path outside the target directory.

**Files changed:** `modules/core/file_operations.py`

### High: Rate limiting bypassed for all web routes

The rate limiter explicitly excluded `/api/web/`, `/api/users`, and `/api/backups` paths. Certificate creation, backup operations, and user management were completely unthrottled.

**Fix:** Removed the blanket exclusion; only `/api/auth/` (which has its own dedicated login rate limiter) is now exempt.

**Files changed:** `modules/core/factory.py`

### High: Race condition in `delete_certificate()` using unreliable `lock.locked()`

`delete_certificate()` used `domain_lock.locked()` to check if an operation was in progress. `Lock.locked()` is unreliable for cross-thread coordination. Replaced with `lock.acquire(blocking=False)` + `try/finally/release` for correct mutual exclusion.

**Files changed:** `modules/core/certificates.py`

### High: Scheduler failure completely silent

If APScheduler failed to start (e.g., corrupted SQLite DB), the application continued without automatic certificate renewal and no visible warning was emitted. Added `warnings.warn()` with `RuntimeWarning` so operators are alerted.

**Files changed:** `modules/core/factory.py`

### High: `__import__('time')` anti-pattern in Vault backend

`HashiCorpVaultBackend._get_client()` used `__import__('time').time()` instead of a standard import. Replaced with a module-level `import time` and removed the redundant inline import.

**Files changed:** `modules/core/storage_backends.py`

### Medium: Batch download accepted unsanitized domain names

`download_batch_web()` passed user-supplied domain strings directly to `certificate_manager.get_certificate_path()` without validation. Now validates each domain through `_sanitize_domain()` before use. Also added explicit `mimetype='application/zip'` to the response.

**Files changed:** `modules/web/cert_routes.py`

### Medium: Role validation was dead code

In `create_api_key()`, the role was normalized via `_normalize_role()` before checking `if role not in ROLE_HIERARCHY`. Since `_normalize_role()` maps invalid roles to `'viewer'`, the validation always passed. Moved the validation before normalization.

**Files changed:** `modules/core/auth.py`

### Medium: DNS propagation `int()` crash on invalid settings

`int(propagation_map.get(dns_provider, default_seconds))` crashed with `ValueError`/`TypeError` if the settings value was a non-numeric string or `None`. Wrapped in `try/except` with fallback to the strategy default.

**Files changed:** `modules/core/certificates.py`

### Medium: SMTP connection leak on send failure

Both `NotifierManager._send_email()` and `DigestManager.send()` called `server.quit()` outside a `finally` block. If `sendmail()` or `login()` raised an exception, the SMTP connection was never closed. Wrapped in `try/finally`.

**Files changed:** `modules/core/notifier.py`, `modules/core/digest.py`

### Medium: Non-atomic file truncation in delivery/deploy logs

`_truncate_delivery_log()` and `_truncate_history()` read all lines, then wrote back directly. A crash between read and write caused data loss. Now uses `tempfile.mkstemp()` + `os.replace()` for atomic truncation.

**Files changed:** `modules/core/notifier.py`, `modules/core/deployer.py`

### Medium: Predictable temporary file path in `safe_file_write()`

Temporary files were created at `{file_path}.tmp` (predictable path, symlink attack vector). Replaced with `tempfile.mkstemp()` in the same directory for unpredictable names.

**Files changed:** `modules/core/file_operations.py`

### Medium: CA certificate expiry not rechecked at runtime

`is_ca_loaded()` only checked `_ca_loaded` flag set during initial load. If the CA certificate expired while CertMate was running, new signing operations would fail with cryptic errors. `is_ca_loaded()` now checks expiry on every call.

**Files changed:** `modules/core/private_ca.py`

### Medium: Error messages leaked internal details to HTTP clients

Settings, backup, cache, and DNS account routes returned `str(e)` in JSON error responses, exposing file paths, stack traces, and configuration details. Replaced with generic messages; full errors logged server-side only.

**Files changed:** `modules/web/settings_routes.py`, `modules/web/backup_cache_routes.py`

### Low: Missing auth on `/redoc` and `/client-certificates` UI routes

Both pages were accessible without authentication. Added `viewer` role requirement.

**Files changed:** `modules/web/ui_routes.py`

## Test Suite

**165 passed, 10 skipped, 0 failed**.

---

# Release v2.2.2

## Comprehensive Security and Reliability Hardening

Full remediation of all Critical, High, and Medium findings from the 360-degree codebase audit. Zero regressions: 166 tests passed, 9 skipped.

### Critical: TOCTOU race in settings read-modify-write

Concurrent `POST /api/settings` requests could silently overwrite each other's changes. Added a `threading.Lock` to `SettingsManager` and a new `atomic_update()` method that performs the load → merge → protect → save cycle atomically under the lock. The settings route now calls `atomic_update()` instead of the separate load+save pattern.

### Critical: Non-atomic certificate file writes during renewal

`renew_certificate()` copied cert files using direct `open()` writes. A process kill mid-copy left partially written `cert.pem`/`privkey.pem` files that could not be parsed. Added `_atomic_binary_copy()` (write to `.tmp` sibling, then atomic rename) and replaced all copy sites.

### High: Create certificate not idempotent

`create_certificate()` silently overwrote an existing certificate on a duplicate request. It now raises `FileExistsError` with a clear message directing the caller to use the renew endpoint.

### High: Renew certificate had no existence check

`renew_certificate()` called certbot without verifying the certificate directory or `cert.pem` existed, producing confusing certbot errors instead of a 404-style response. An explicit existence check now raises `FileNotFoundError` before any external process is spawned.

### High: Delete during active renewal not blocked

Added a check in `delete_certificate()` that reads the per-domain lock state; if a create/renew is in progress for the domain, the delete raises `RuntimeError` immediately.

### High: Deploy hook command validation

Added a 1024-character length cap and a blocklist regex that rejects commands referencing CertMate's own credential/settings files (`settings.json`, `api_bearer_token`, `vault_token`, etc.). Every hook execution is now logged at INFO level.

### High: UTC datetime in certificate expiry calculation

`_parse_certificate_info()` compared `notAfter` (UTC from openssl) against `datetime.now()` (local clock). On servers in non-UTC timezones this produced incorrect `days_left`. Changed to `datetime.utcnow()`.

### High: HashiCorp Vault token not renewed

The Vault client was initialized once at startup and never renewed. After token TTL expiry all operations failed silently. `_get_client()` now calls `auth.token.renew_self()` every 6 hours and re-authenticates if the renewal fails.

### High: Retry on transient cloud backend errors

Added `_with_retry()` decorator (3 attempts, exponential back-off) applied to `store_certificate`, `retrieve_certificate`, and `list_certificates` on all three cloud backends (Azure, AWS, Vault). Non-transient errors are re-raised immediately; transient ones (timeout, rate-limit, 429, 503, connection reset) are retried.

### High: Credential validation ignored leading/trailing whitespace

All four cloud backends (`AzureKeyVaultBackend`, `AWSSecretsManagerBackend`, `HashiCorpVaultBackend`, `InfisicalBackend`) now strip whitespace from credential fields before the emptiness check, so a value like `"  "` is correctly rejected at initialization time rather than failing silently at first use.

### Medium: Settings GET exposed secrets in plain text

`GET /api/settings` returned raw values for DNS tokens, client secrets, passwords, and API keys. The response is now deep-copied and all string values whose key matches `(token|secret|password|key|credential)` are replaced with `'********'` before the JSON is sent to the client.

### Medium: Session timeout hardcoded at 8 hours

`AuthManager` session lifetime is now configurable via the `SESSION_TIMEOUT_HOURS` environment variable (default: 8). Set a shorter value (e.g. `SESSION_TIMEOUT_HOURS=1`) for high-security deployments.

### Medium: Last-admin protection ignored disabled accounts

The "cannot delete the last admin" guard counted only `enabled=True` admins. Disabling the last admin left no active admins without triggering the guard. The count now includes all admins regardless of enabled state.

### Medium: Relative cert/data paths could break on CWD change

`cert_dir` and `data_dir` were constructed as `Path("certificates")` and `Path("data")` (relative to CWD). They are now resolved to absolute paths anchored to the project root at startup, so they remain valid if the process CWD changes.

### Medium: Orphan `.tmp` files from previous crashes not cleaned

On startup, `setup_directories()` now scans `cert_dir` and `data_dir` recursively and removes any `*.tmp` files left by a previous hard kill.

### Medium: Corrupt `settings.json` fell back to factory defaults

On JSON parse failure, `load_settings()` now attempts to restore from the five most recent unified backup archives before falling back to factory defaults. The attempted and successful restores are logged.

### Medium: Azure secret name collisions for hyphenated domains

`_sanitize_secret_name()` converted all non-alphanumeric characters to hyphens. Two different domains could produce the same key (e.g. `my-app.example.com` and `my.app-example.com` both became `my-app-example-com`). A CRC32 suffix of the original name is now appended, guaranteeing uniqueness.

### Medium: UTF-8 decode errors on binary certificate data

All `.decode('utf-8')` calls in `storage_backends.py` now use `errors='replace'` to prevent `UnicodeDecodeError` on non-UTF-8 binary content.

### Medium: LocalFS `metadata.json` lacked restrictive permissions

`LocalFileSystemBackend.store_certificate()` now calls `os.chmod(metadata_file, 0o600)` after writing, consistent with the private key and certificate file permissions.

### Medium: SQLite APScheduler without WAL mode

The APScheduler SQLite job store now runs in WAL (Write-Ahead Logging) mode with `synchronous=NORMAL`. This eliminates writer-blocks-readers contention under concurrent renewal load.

### Medium: Batch endpoint accepted unlimited domain lists

`POST /api/web/certificates/batch` with a 100,000-element domain list was accepted without limit. The batch size is now capped at 50 domains per request.

### Medium: Health endpoint was minimal

`GET /health` now reports scheduler state, cert directory presence, and available disk space (warns below 100 MB free) in a structured `checks` object. The HTTP status is always 200 (Flask is serving), and `status` is `"healthy"` or `"degraded"` for monitoring systems.

### Medium: Nginx container lacked a health check

The optional `nginx` Docker Compose profile now includes a `healthcheck` directive that verifies the proxy is serving responses.

### Low: Username/password length not bounded

`POST /api/users` now rejects usernames over 64 characters and passwords over 256 characters.

### Low: Mixed-type domain list caused migration panic

The domain format migration guard used `isinstance(domains[0], str)` which panicked on mixed-type lists. Changed to `all(isinstance(d, str) for d in domains)`.

### Low: Module-level import cleanup in storage backends

`shutil` and `re` are now imported at module level in `storage_backends.py` rather than inside individual methods.

## Test Suite

**166 passed, 9 skipped, 0 failed** — including a real certificate lifecycle on `certmate.org` via Cloudflare DNS.

---

# Release v2.2.1

## Bug Fixes & Reliability Improvements

This release addresses critical reliability, security, and correctness issues identified during a full 360° codebase audit, plus resolves GitHub issues #83, #84, and #80.

### Critical: APScheduler never started — certificate auto-renewal completely disabled

**Root cause:** `setup_scheduler()` was defined in `modules/core/factory.py` but never called in `create_app()`. This meant APScheduler was never initialised, so no background jobs ran in any deployment: certificates were never auto-renewed and digest emails were never sent.

**Fix:** Added the missing `setup_scheduler(container)` call in `create_app()`.

**Files changed:** `modules/core/factory.py`

---

### Critical: `AttributeError` crash on audit log and activity endpoints

**Root cause:** `modules/web/misc_routes.py` called `audit_manager.get_recent_logs()`, but the method is named `get_recent_entries()` in `modules/core/audit.py`. Both `/api/activity` and `/api/web/audit-logs` raised an unhandled `AttributeError` on every request.

**Fix:** Corrected both call sites to use `get_recent_entries()`.

**Files changed:** `modules/web/misc_routes.py`

---

### Critical: `/api/activity`, `/metrics`, `/api/web/logs/stream` unauthenticated

**Root cause:** All three endpoints were missing `@auth_manager.require_role()` decorators, making them publicly accessible without any authentication.

**Fix:** Added role-based auth guards: `viewer` for `/api/activity`, `admin` for `/metrics` and `/api/web/logs/stream`. `/metrics` now returns a JSON error instead of an HTML page on auth failure.

**Files changed:** `modules/web/misc_routes.py`

---

### Critical: CORS configured with `origins=None` — allows all origins

**Root cause:** `flask_cors.CORS(app, origins=None)` permits cross-origin requests from any domain. This is the unsafe default; the intent was to deny all cross-origin requests.

**Fix:** Changed to `origins=[]` (empty list = deny all).

**Files changed:** `modules/core/factory.py`

---

### Issues #83 and #84 — Settings save wipes user accounts and re-triggers setup wizard

**Root cause:** The `POST /api/settings` handler saved `request.json` directly, discarding all fields the UI form does not submit (`users`, `api_keys`, `local_auth_enabled`). On every settings save, all user accounts were deleted and `local_auth_enabled` was reset to `False`, causing the setup wizard to re-appear on next page load.

**Fix:** Load existing settings first, deep-merge with incoming data, then hard-protect the three auth-critical keys (`users`, `api_keys`, `local_auth_enabled`) from any accidental overwrite.

**Files changed:** `modules/web/settings_routes.py`

---

### Issue #80 — `PORT` and `GUNICORN_TIMEOUT` environment variables not honoured in Docker

**Root cause:** The `Dockerfile` CMD used `exec` form (JSON array), which does not expand shell variables. `PORT` and `GUNICORN_TIMEOUT` had no `ENV` defaults, so the values were ignored.

**Fix:** Added `ENV PORT=8000` and `ENV GUNICORN_TIMEOUT=300` defaults, switched CMD to shell form so env vars expand correctly, and updated the `HEALTHCHECK` to use `${PORT}`. `docker-compose.yml` environment section updated to forward both variables.

**Files changed:** `Dockerfile`, `docker-compose.yml`

---

### High: No per-domain lock — concurrent create/renew on same domain caused corruption

**Root cause:** Two simultaneous requests for the same domain (e.g., an API call racing with the scheduler) could both run `certbot` and overwrite each other's certificate files in a non-atomic sequence.

**Fix:** Added a `dict[str, threading.Lock]` per-domain lock registry in `CertificateManager`. Both `create_certificate()` and `renew_certificate()` acquire the per-domain lock non-blocking and immediately raise `RuntimeError` if the lock is already held.

**Files changed:** `modules/core/certificates.py`

---

### High: Non-atomic metadata writes — partial JSON on crash

**Root cause:** `metadata.json` writes used a direct `open(..., 'w')` call. A process crash mid-write left a truncated/invalid JSON file that broke all subsequent certificate reads for the domain.

**Fix:** New `_atomic_json_write()` static method writes to a `.tmp` sibling file, then uses `Path.replace()` (atomic rename). All three metadata write sites updated.

**Files changed:** `modules/core/certificates.py`

---

### High: `LETSENCRYPT_EMAIL` env var silently overrides UI-configured email

**Root cause:** When `LETSENCRYPT_EMAIL` is set, it overrides `settings['email']` with no log output. Administrators had no way to know their UI-configured email was being ignored.

**Fix:** Added an explicit `logger.warning()` when the env var differs from the stored value, including both values and instructions to unset the variable.

**Files changed:** `modules/core/settings.py`

---

### High: Infisical `create_secret()` always fails on certificate renewal

**Root cause:** `store_certificate()` always called `create_secret()`. Infisical raises an exception when a secret with that name already exists, so every certificate renewal via the Infisical backend raised an unhandled error.

**Fix:** Changed to an upsert pattern: try `update_secret()` first; if it raises `NotFoundError`, fall through to `create_secret()`.

**Files changed:** `modules/core/storage_backends.py`

---

### High: Azure and Infisical `list_certificates()` broken for hyphenated domains

**Root cause:** Both backends reconstructed domain names from secret name keys using `replace('-', '.')`. A domain like `my-app.example.com` stored as `my-app-example-com` would be incorrectly reconstructed as `my.app.example.com`.

**Fix:** Both backends now read the metadata secret (which stores the original `domain` string) instead of performing lossy name reversal.

**Files changed:** `modules/core/storage_backends.py`

---

### Medium: Audit log `limit` parameter unbounded — potential DoS

**Fix:** Capped `limit` at 1000 entries in `GET /api/activity` and `/api/web/audit-logs`.

**Files changed:** `modules/web/misc_routes.py`

---

### Medium: Pre-save backup failures silent

**Fix:** `save_settings()` now logs an explicit `WARNING` when the pre-save backup fails (disk full, permission error, etc.), rather than silently proceeding.

**Files changed:** `modules/core/settings.py`

---

### Medium: Duplicate user creation returns HTTP 500 instead of 409

**Fix:** `POST /api/users` now returns `409 Conflict` when the username already exists.

**Files changed:** `modules/web/settings_routes.py`

---

### Medium: Silent fallback to LocalFileSystemBackend logs nothing

**Fix:** When the configured storage backend fails to initialise and falls back to local filesystem, an explicit `ERROR` is now logged with the backend name and exception.

**Files changed:** `modules/core/storage_backends.py`

---

## Test Suite

**Full suite result: 160 passed, 0 failed** — including a real certificate lifecycle test on `certmate.org` via Cloudflare DNS (create, list, download ZIP, download TLS components, renew).

---

# Release v2.1.2

## Bug Fixes

### Issue #82 — RFC2136 credentials file generated with wrong certbot key

**Root cause:** The RFC2136 credentials writer generated `dns_rfc2136_nameserver`, but certbot expects `dns_rfc2136_server` in `rfc2136.ini`. This caused RFC2136-based DNS-01 validation to fail when certbot loaded the generated credentials file.

**Fix:** Corrected the RFC2136 INI key generation in `modules/core/utils.py` and added a regression test to verify the generated credentials file content and permissions.

**Files changed:** `modules/core/utils.py`, `tests/test_issue82_rfc2136_config.py`

## Test Suite

**Full suite result: 166 passed, 9 skipped, 0 failed**.

---

# Release v2.3.0

## Bug Fixes

### Issue #77 — Default Certificate Authority setting ignored during certificate creation

**Root cause:** A triple-failure chain prevented the user-configured default CA from being applied:

1. **Settings key mismatch** — The settings UI saves as `default_ca`, but `certificates.py` looked for `default_ca_provider`, always falling back to `letsencrypt`.
2. **Missing API resolution** — The `/api/certificates/create` endpoint resolved `challenge_type` and `dns_provider` from settings when empty, but had no equivalent logic for `ca_provider`.
3. **Combined effect** — When the form sent "Use default from settings" (empty value), neither the API layer nor the core logic retrieved the actual configured default.

**Fix:** Corrected the settings key in `certificates.py` and added CA provider resolution in `resources.py`.

**Files changed:** `modules/core/certificates.py`, `modules/api/resources.py`

### Backup download returning 404 despite file existing

**Root cause:** Flask's `send_file()` resolves relative paths against `app.root_path` (`/app/modules/core` due to the factory pattern), not the process working directory (`/app`). The backup file existed at `/app/backups/unified/...` but `send_file` looked for `/app/modules/core/backups/unified/...`.

**Fix:** Pass the absolute resolved path to `send_file()`.

**Files changed:** `modules/api/resources.py`

### CI bandit security check failure

**Root cause:** Two `B104` (hardcoded bind to all interfaces) findings on legitimate uses: Docker bind address default and client IP fallback.

**Fix:** Added `# nosec B104` inline suppressions.

**Files changed:** `app.py`, `modules/core/factory.py`

## Test Suite

**Full suite result: 77 passed, 0 failed** — including real certificate lifecycle on `certmate.org` via Cloudflare DNS (create, list, download ZIP, download TLS components, renew).

---

# Release v2.2.0

## 10x Surgical Architecture Refactoring

This release brings massive scalability and resilience improvements to the core CertMate architecture, along with UX polish, fulfilling the '10x Surgical Project Analysis and Proposal'.

### Architecture & Resiliency
- **Routes Decoupled**: The massive `routes.py` file has been cleanly split into modular Flask Blueprints (`ui_routes.py`, `auth_routes.py`, `cert_routes.py`, `settings_routes.py`, etc.), greatly improving code maintainability.
- **Application Factory Pattern**: Transformed `app.py` by abstracting the monolithic app initialization into `modules/core/factory.py`. Added a Dependency Injection container for all managers.
- **Persistent Job Scheduler**: Migrated away from the fragile, in-memory `ThreadPoolExecutor` for background tasks. CertMate now uses `APScheduler` backed by a persistent SQLite database (`SQLAlchemyJobStore`) to guarantee task execution across restarts.

### UX & Polish
- **Optimistic UI (Toast Notifications)**: Replaced standard javascript popups/alerts with a rich, stylized toast notification system (`CertMate.toast`) across the web UI for immediate feedback on user actions.
- **Anti-Slop Audit**: Cleared out redundant, auto-generated code comments and professionalized all Markdown documentation removing emojis and marketing fluff.

---

# Release v2.1.0

## Bug Fixes

### Issue #76 — Unable to save settings (HTTP 500)

**Root cause:** The web UI GET endpoint masks `api_bearer_token` as `'********'`
before returning settings. When the user saves settings, this 8-character masked
value is sent back in the POST payload and overwrites the real token during the
settings merge. `save_settings()` then validates the masked string against a
32-character minimum length requirement, causing the validation to fail and
returning HTTP 500.

**Fix (defense-in-depth, two layers):**
- **`modules/web/routes.py`**: Strip masked or empty `api_bearer_token` from
  incoming POST data before merging with current settings, preserving the real
  token already stored on disk.
- **`modules/core/settings.py`**: Safety net in `save_settings()` — if the
  token is empty or the `'********'` placeholder, remove it from the dict
  instead of failing validation. The real token on disk remains untouched.

**Files changed:** `modules/web/routes.py`, `modules/core/settings.py`

## Test Suite

- 4 new unit tests in `tests/test_issue76_masked_token.py`:
  - Masked token (`'********'`) → save succeeds, placeholder NOT persisted
  - Empty token → save succeeds
  - Valid token → validated and persisted correctly
  - Invalid short token → still properly rejected

---

# Release v2.0.3

## Bug Fixes

### Issue #75 — AWS Route53 DNS Provider: unrecognised argument `--dns-route53-propagation-seconds`

**Root cause:** certbot-dns-route53 ≥ 1.22 removed the `--dns-route53-propagation-seconds`
CLI flag. The plugin now polls Route53 internally until the TXT record propagates, making
the flag redundant. Passing it caused an "unrecognised arguments" error that aborted every
certificate request using the Route53 provider.

**Fix:**
- Added `supports_propagation_seconds_flag` property to `DNSProviderStrategy` (base class,
  defaults to `True`).
- `Route53Strategy` overrides the property to `False`.
- `CertificateManager.create_certificate()` now only appends the propagation-seconds flag to
  the certbot command when the strategy's `supports_propagation_seconds_flag` is `True`.

**Files changed:** `modules/core/dns_strategies.py`, `modules/core/certificates.py`

---

### Issue #74 — Private CA ACME endpoint connection test fails with SSL error

**Root cause:** The "Test Connection" API endpoint used `verify=True` (system CA bundle)
for all HTTPS requests to private ACME servers. Private CAs with self-signed or
internal-root certificates are not trusted by the system bundle, causing every connection
test to report "ACME endpoint is not accessible" even when the endpoint was reachable.

**Fix:**
- When the user provides a CA certificate in the Private CA configuration form, the
  certificate is written to a temporary PEM file and passed as `verify=<path>` to
  `requests.get()`, allowing the self-signed / private-root to be properly validated.
- The temporary file is always removed in a `finally` block to avoid leaking disk state.
- SSL error messages now include a targeted hint: whether to supply a CA certificate
  (if none was given) or verify that the provided certificate is the correct root/intermediate.

**Files changed:** `modules/api/resources.py`

---

### Issue #56 — Residual Route53 failures still reported after v2.0.2

The `san_domains` keyword argument and Cloudflare-hardcoded DNS provider fallback were
already resolved in v2.0.1 and v2.0.2. The remaining failure mode reported by users
("unrecognised arguments: --dns-route53-propagation-seconds") is the same bug addressed
by the Issue #75 fix above. Closing as fully resolved in v2.0.3.

---

## Test Suite

- 4 new unit tests added to `tests/test_san_domains.py`:
  - `TestRoute53PropagationFlag`: verifies `Route53Strategy.supports_propagation_seconds_flag`
    is `False`, all other strategies are `True`, and the flag is absent from the constructed
    certbot command for Route53.
  - `TestAcmeConnectionSSLHandling`: verifies temp-file CA bundle creation and the
    no-cert system-bundle fallback.

**Full suite result: 161 passed, 9 skipped, 0 failed** (9 skipped require live credentials
or a real CA; all automatable tests are green).

---

# Release v1.9.0

## Docker First-Run UX

### Fix: API auth bypass for initial setup
- `require_auth` decorator now bypasses authentication when local auth is disabled
  or no users exist, matching `require_web_auth` behavior
- Fixes all API 401 errors on fresh Docker launch (settings, DNS accounts, certs)
- Fixed settings POST localhost restriction blocking Docker users
- Fixed `GET /api/web/settings` returning 401 after first save

### Welcome banner and setup guidance
- Dashboard shows setup guide when no certificates exist (configure DNS, create cert, enable auth)
- Help page includes Docker Quick Start section
- Settings page shows security reminder when authentication is disabled

### Bundled static assets (no more CDN)
- Tailwind CSS and Font Awesome served from `/static/` — no external CDN requests
- CSP headers tightened to `'self'` only (ReDoc exempted for its own CDN needs)
- All pages work fully offline / air-gapped

### Test suite
- New `tests/` directory with structured e2e test suite (77 tests)
- Real Cloudflare cert lifecycle with random subdomain per run
- Static assets, CSP, auth bypass, settings, pages, backups, DNS accounts
- `tests/run_tests.sh` pre-commit hook script
- Removed 21 legacy test files from project root

### Bug fixes
- Fixed `testCAProvider` JS error (undefined `API_HEADERS.Authorization`)
- Fixed `safeDomain` undefined in `updateDeploymentStats`
- Navbar logo size increased from w-9 to w-12
- Fixed `and`/`or` inconsistency between `require_auth` and `require_web_auth`

---

# Release v1.8.0

## Documentation

### Consolidated Documentation Structure
- Moved 17 root-level documentation files into organized `/docs/` directory
- Created `docs/installation.md`, `docs/dns-providers.md`, `docs/ca-providers.md`, `docs/docker.md`, `docs/testing.md`
- Expanded `docs/architecture.md` with full system architecture overview
- Updated `docs/README.md` and `docs/index.md` with complete navigation
- Fixed all cross-references across README and internal docs

## Bug Fixes

### Timezone-Aware DateTime in Private CA
- Fixed `datetime.utcnow()` (deprecated, naive) to `datetime.now(timezone.utc)` in 8 places
- Resolves comparison errors with timezone-aware certificate attributes in cryptography >= 42.0

### Test Suite Improvements
- Added `conftest.py` to exclude server-dependent E2E tests from collection
- Fixed pytest warnings: renamed `TestResults` class, replaced return values with asserts
- Removed `testpaths` from `pytest.ini` to avoid collection issues
- Result: 29 passed, 1 skipped, 0 warnings

## Improvements

### Security Hardening
- Various module-level security improvements across core modules

### UI
- Transparent logo with favicon and apple-touch-icon integration
- Removed `app.py.notmodular` dead code

---

# Release v1.7.2

## New Features

### Structured JSON Logging for Observability
- New `StructuredLogger` class in `modules/core/structured_logging.py`
- JSON-formatted log output for log aggregation systems (ELK, Splunk, etc.)
- Automatic correlation IDs for request tracing
- Environment-based configuration (`LOG_FORMAT=json`)
- Compatible with existing log file output

### Playwright UI E2E Test Suite
- New `test_ui_e2e.py` with comprehensive browser-based testing
- Human-readable test output with severity levels
- Tests for Settings, Certificates, Client Certificates workflows
- Supports headed/headless modes and screenshots on failure
- Python 3.9+ compatible

## Improvements

### Documentation Cleanup
- Removed all emojis from documentation for professional appearance
- Clean, consistent formatting across all markdown files

### CI/CD Improvements
- E2E tests excluded from CI (require running server)
- All unit and integration tests passing on Python 3.9, 3.11, 3.12

## Bug Fixes
- Fixed Python indentation issues in 47 files
- Fixed Python 3.9 f-string compatibility in test_ui_e2e.py

---

# Release v1.7.0

## New Features

### Issue #53: Local Authentication Support
- **Full user management system** with username/password authentication
- Password hashing using SHA-256 with cryptographic salt
- Session-based authentication with secure HTTP-only cookies
- User CRUD operations (Create, Read, Update, Delete)
- Role-based access control (admin/user roles)
- Login page with modern UI design
- Toggle to enable/disable local authentication
- Protection against deleting the last admin user

### Issue #48: SAN (Subject Alternative Names) Certificate Support
- Create certificates with multiple domains in a single certificate
- New `san_domains` field in API for specifying additional domains
- Comma-separated SAN input in web UI
- Automatic deduplication of domain entries
- Full support across all DNS providers

## Bug Fixes

### Issue #54: Settings Save - API Bearer Token Required Error
- Added missing API Bearer Token input field to settings form
- Added Cache TTL configuration field
- Token generation button with cryptographic random token
- Conditional validation: token required only after initial setup
- Auto-generation of token during first-time setup

### Issue #50: Certificates Not Showing After Generation
- Fixed certificate listing to scan both settings AND filesystem
- Certificates created outside settings now properly displayed
- Unified domain discovery from multiple sources
- Automatic deduplication using set-based approach

### Issue #49: Better Error Messages
- Added descriptive hints to all validation errors
- Pre-validation checks before async operations
- Specific error hints for common issues:
 - DNS provider authentication failures
 - Rate limiting from certificate authorities
 - DNS propagation timeouts
 - Missing configuration
- Clear guidance on how to resolve each error type

## Technical Changes
- Enhanced `AuthManager` class in `modules/core/auth.py`
- New `login.html` template
- Updated `require_auth` decorator to support both session and bearer token
- Modified `CertificateList.get()` to scan certificate directories
- Extended `create_certificate()` to accept `san_domains` parameter
- Added `san_domains` field to API models

## Testing
- All 32 existing tests pass
- No regressions detected

---

# Release v1.2.1

## Bug Fixes

### Fix #47: Complete fix for Save Settings not working

**Root Cause:** The `saveSettings()` function was trying to get email from `formData.get('email')`, but no field with `name="email"` existed in the form. Additionally, the Private CA configuration panel wasn't being shown correctly due to ID mapping mismatch (`private_ca` → `private_ca-config` instead of `private-ca-config`).

**Solution:**
1. Modified `saveSettings()` to extract email from the selected CA provider's configuration section (Let's Encrypt, DigiCert, or Private CA)
2. Added explicit `caProviderToConfigId` mapping to correctly handle the `private_ca` → `private-ca-config` ID translation
3. Improved error messages to indicate which CA provider section requires the email address

**Changes:**
- `templates/settings.html`: Updated email collection logic and CA provider config ID mapping

**Testing:**
- Verified settings save correctly for all CA providers (Let's Encrypt, DigiCert, Private CA)
- Confirmed no more "An invalid form control is not focusable" browser console errors
- Validated proper show/hide of CA configuration sections

Closes #47
