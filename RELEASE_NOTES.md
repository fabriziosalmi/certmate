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
