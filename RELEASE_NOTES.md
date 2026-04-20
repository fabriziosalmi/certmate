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
