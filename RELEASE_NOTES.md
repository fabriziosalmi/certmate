## Unreleased

### Features
- **Azure Key Vault stale read detection in `both` mode**: the two storage surfaces (Secrets and Certificate objects) can diverge when a renewal succeeds on one surface but fails on the other. `retrieve_certificate` now compares the `updated_on` timestamps of both surfaces and returns whichever is freshest, preventing stale reads from surface skew.
- **Azure Key Vault Certificate-object support**: the Azure Key Vault storage backend can now persist certificates as native `Certificate` objects (PKCS12) in addition to — or instead of — the existing per-PEM Secrets layout. The mode is controlled by `certificate_storage.azure_keyvault.storage_mode` (`secrets` / `certificate` / `both`, default `secrets` for backwards compatibility). Certificates imported in `certificate` or `both` mode get `issuer_name="Unknown"` so Key Vault does not try to renew them — CertMate stays the source of truth — and carry domain/DNS-provider/email/etc. metadata as tags. Native Certificate objects unlock direct binding from App Service, Application Gateway, Front Door, API Management and AKS Ingress without exporting/importing PFX manually. A new admin-only endpoint `POST /api/storage/azure-keyvault/backfill-certificates` (and a "Backfill Certificate objects" button in Settings → Storage) imports Certificate objects for existing Secrets-only domains, skipping any already imported. The backfill endpoint accepts an optional `?limit=N` query parameter that caps how many domains it processes per call — large vaults can paginate by calling repeatedly until the response reports `remaining: 0`. The Service Principal needs Certificates `Get/List/Import/Delete` in addition to its previous Secrets permissions in `certificate`/`both` mode.

### Bug Fixes
- **CRC-aware secret domain listing in Azure Key Vault**: the regex filter in `_list_secret_domains` was `endswith('-metadata')`, which never matched any secret in production because `_sanitize_secret_name` always appends an 8-char CRC32 suffix. Anchored the regex to `^cert-.+-metadata-[0-9a-f]{8}$`. Without this fix, `list_certificates()` and the backfill endpoint would walk an empty domain list for every Azure Key Vault backend, silently showing zero certificates in the list view.

---

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
|---|---|---|
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
