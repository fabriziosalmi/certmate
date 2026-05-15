"""
Settings management module for CertMate
Handles loading/saving settings, migrations, and configuration management
"""

import os
import threading
import logging
from pathlib import Path

from .constants import iter_cert_domain_dirs
from .file_operations import FileOperations
from .utils import (
    generate_secure_token,
    validate_email,
    validate_api_token,
    validate_domain,
)

logger = logging.getLogger(__name__)


# --- POST /api/settings input validation -----------------------------------
# Strict whitelist enforced by validate_settings_post() below. Two callsites
# share this: the Flask-RESTX Settings resource (external API) and the web
# blueprint's api_settings handler (UI). Both go through the same gate so
# the rules can't drift.
#
# Adding a key here authorizes a generic admin POST to mutate it. For
# anything with side-effects (shell exec, auth/token rotation, RBAC), prefer
# a dedicated endpoint and keep the key in SETTINGS_REJECT_KEYS.

PUBLIC_SETTINGS_WRITABLE_KEYS = frozenset(
    {
        "email",
        "dns_provider",
        "dns_providers",
        "domains",
        "auto_renew",
        "renewal_threshold_days",
        "challenge_type",
        "certificate_storage",
        "storage_backend",  # ADD THIS
        "notifications",
        "setup_completed",
        "cloudflare_token",
        "ca_providers",
        "default_ca",  # ADD THIS
        "default_ca_accounts",
        "default_accounts",
        "dns_propagation_seconds",
        "cache_ttl",
    }
)

# Keys whose mutation via the bulk settings endpoint would create a privilege
# escalation, RCE injection, or token-rotation risk. Each has (or should have)
# a dedicated endpoint with its own auth and audit:
#   - api_bearer_token / _hash : future /api/auth/bearer/rotate
#   - deploy_hooks             : /api/deploy/config
#   - users                    : /api/users
#   - api_keys                 : /api/keys
#   - local_auth_enabled       : /api/auth/config
SETTINGS_REJECT_KEYS = frozenset(
    {
        "api_bearer_token",
        "api_bearer_token_hash",
        "deploy_hooks",
        "users",
        "api_keys",
        "local_auth_enabled",
    }
)


SECRET_MASK_SENTINEL = "********"


def _strip_masked_values(payload):
    """Recursively strip keys whose value equals the masking sentinel.

    GET /api/web/settings masks secret-named fields with '********' so the
    UI can render the form without leaking the real values. A round-trip
    POST that echoes the GET response back (which is what the web UI and
    integration tests do) would otherwise overwrite the real on-disk
    secret with the literal string '********'. Stripping these placeholders
    pre-validation makes the round-trip a no-op for the masked fields
    while leaving every other key untouched.

    Operates on dicts of arbitrary depth. Lists and non-dict values are
    returned unchanged. A key whose value is a dict that was originally
    non-empty but became empty after stripping is dropped from the result
    — its content was entirely masked, so the only safe interpretation is
    "preserve existing on-disk value". An originally-empty dict ({}) is
    kept as {}: it carries the caller's actual intent (e.g. clear
    users/api_keys, which the reject list will then catch).
    """
    if not isinstance(payload, dict):
        return payload
    out = {}
    for key, value in payload.items():
        if value == SECRET_MASK_SENTINEL:
            continue
        if isinstance(value, dict):
            original_size = len(value)
            cleaned = _strip_masked_values(value)
            if not cleaned and original_size > 0:
                # Every nested entry was masked — drop the outer key so
                # the on-disk value is preserved by the merge layer.
                continue
            out[key] = cleaned
        else:
            out[key] = value
    return out


def validate_settings_post(payload, current=None):
    """Filter a POST /api/settings payload against the writable whitelist.

    Args:
        payload: dict received from the client.
        current: optional dict of the on-disk settings *before* this POST.
            When provided, any incoming top-level field whose value already
            equals the current value is silently dropped as a no-op
            round-trip echo. This is what makes the GET-then-POST-back
            pattern (used by the web UI and integration test fixtures)
            interoperate with the strict whitelist without false positives.

    Returns:
        tuple (filtered, rejected, unknown):
          filtered: payload restricted to PUBLIC_SETTINGS_WRITABLE_KEYS,
                    with masked sentinels stripped and no-op echoes removed
          rejected: keys in SETTINGS_REJECT_KEYS that the caller tried to
                    mutate with a value different from current (each one is
                    a security event — log & audit)
          unknown:  keys neither allowed nor explicitly blocked (treat as
                    400; likely a typo or a field that needs to be added
                    to the whitelist intentionally)
    """
    if not isinstance(payload, dict):
        raise ValueError("Settings payload must be an object")

    cleaned_payload = _strip_masked_values(payload)

    filtered = {}
    rejected = []
    unknown = []
    for key, value in cleaned_payload.items():
        # No-op echo: incoming value matches the on-disk value. Silently
        # drop — applies uniformly to writable, reject-listed, and
        # unknown keys so the same payload that came out of GET goes
        # straight back in without surfacing spurious 400s.
        if current is not None and key in current and value == current.get(key):
            continue
        if key in SETTINGS_REJECT_KEYS:
            rejected.append(key)
        elif key in PUBLIC_SETTINGS_WRITABLE_KEYS:
            filtered[key] = value
        else:
            unknown.append(key)
    return filtered, rejected, unknown


def diff_settings_keys(before, after):
    """Compute the set of top-level keys whose value differs between two
    settings dicts. Used by audit logging to record what changed without
    serializing secret values.

    Returns:
        list of changed top-level key names (sorted)
    """
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    changed = set()
    for key in set(before.keys()) | set(after.keys()):
        if before.get(key) != after.get(key):
            changed.add(key)
    return sorted(changed)


def _bearer_token_from_env_or_generate():
    """Return a valid api_bearer_token for the default settings template.

    Resolution order (mutually exclusive):
    1. API_BEARER_TOKEN_FILE — if set, read the token from that file. Any
       read error or validation failure generates a fresh token immediately;
       API_BEARER_TOKEN is never consulted (to avoid encouraging both vars).
    2. API_BEARER_TOKEN — only checked when API_BEARER_TOKEN_FILE is absent.
       An invalid value (too short, weak pattern, insufficient entropy) is
       logged and a fresh token is generated instead. This prevents a
       misconfigured env var (issue #108: docker-compose passing an empty or
       weak ${API_BEARER_TOKEN}) from poisoning save_settings with a
       misleading "API token length must be between 32 and 512 characters"
       rejection.
    3. generate_secure_token() — fallback when neither variable is set or
       both fail validation.
    """
    token_file = os.getenv("API_BEARER_TOKEN_FILE")
    if token_file:
        try:
            file_token = Path(token_file).read_text().strip()
            is_valid, reason = validate_api_token(file_token)
            if is_valid:
                return file_token
            logger.warning(
                "API_BEARER_TOKEN_FILE token is invalid (%s); "
                "falling back to API_BEARER_TOKEN or a generated token.",
                reason,
            )
        except Exception as e:
            logger.warning(
                "Could not read API_BEARER_TOKEN_FILE (%s): %s", token_file, e
            )
            return generate_secure_token()

    env_token = os.getenv("API_BEARER_TOKEN")
    if env_token:
        is_valid, reason = validate_api_token(env_token)
        if is_valid:
            return env_token
        logger.warning(
            "API_BEARER_TOKEN environment variable is invalid (%s); "
            "ignoring it and generating a fresh random bearer token. "
            "Set a valid token (32-512 chars, no weak patterns, >=12 unique "
            "chars) in your .env file or unset API_BEARER_TOKEN to silence "
            "this warning.",
            reason,
        )
    return generate_secure_token()


class SettingsManager:
    """Class to handle settings management and migrations"""

    def __init__(self, file_ops: FileOperations, settings_file: Path):
        self.file_ops = file_ops
        self.settings_file = settings_file
        # RLock so internal calls (atomic_update -> load -> save, or
        # load -> save during migration) do not deadlock on the same thread.
        self._lock = threading.RLock()
        # Optional callable that hashes a legacy api_bearer_token at save time.
        # Wired by the factory after AuthManager is constructed.
        self._token_hasher = None

    def set_token_hasher(self, hasher):
        """Inject the hasher used to migrate legacy api_bearer_token to its
        hashed form on the next save. None disables migration."""
        self._token_hasher = hasher

    def update(self, mutator, reason="auto_save"):
        """Atomic read-modify-write under the settings lock.

        Use this when atomic_update's shallow merge isn't enough — e.g. a
        deeply-nested mutation to dns_providers, or a write to a protected
        key (users, api_keys) that atomic_update would silently strip.

        ``mutator`` receives the current settings dict and is expected to
        mutate it in place. The merged result is then validated and
        persisted atomically. Returns the bool from save_settings so
        callers can react to validation failures.
        """
        with self._lock:
            settings = self.load_settings()
            mutator(settings)
            return self.save_settings(settings, reason)

    def atomic_update(
        self, incoming: dict, protected_keys=("users", "api_keys", "local_auth_enabled")
    ) -> bool:
        """Thread-safe read-merge-write for settings.

        Loads the current on-disk settings, merges *incoming* on top, restores
        any *protected_keys* from the on-disk copy, then saves — all under a
        re-entrant lock so concurrent requests cannot race.
        """
        with self._lock:
            existing = self.load_settings()
            merged = {**existing, **incoming}
            for key in protected_keys:
                if key in existing:
                    merged[key] = existing[key]
                elif key in merged:
                    del merged[key]
            return self.save_settings(merged)

    def _try_restore_from_backup(self):
        """Attempt to restore settings from the most recent unified backup."""
        try:
            import zipfile, json

            backup_dir = self.file_ops.backup_dir / "unified"
            if not backup_dir.exists():
                return None
            backups = sorted(
                backup_dir.glob("backup_*.zip"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for backup_path in backups[:5]:  # try the 5 most recent
                try:
                    with zipfile.ZipFile(backup_path, "r") as zf:
                        if "settings.json" not in zf.namelist():
                            continue
                        raw = json.loads(zf.read("settings.json").decode("utf-8"))
                        settings = (
                            raw.get("settings")
                            if isinstance(raw, dict) and "settings" in raw
                            else raw
                        )
                        if isinstance(settings, dict) and settings:
                            logger.info(
                                f"Restored settings from backup: {backup_path.name}"
                            )
                            return settings
                except Exception as e:
                    logger.debug(f"Could not read backup {backup_path.name}: {e}")
        except Exception as e:
            logger.error(f"Backup restore failed: {e}")
        return None

    def load_settings(self):
        """Load settings from file with improved error handling.

        Acquires the re-entrant lock so concurrent saves cannot observe a
        half-written file or race with the migration write below.
        """
        with self._lock:
            default_settings = {
                "cloudflare_token": "",
                "domains": [],
                "email": "",
                "auto_renew": True,
                "renewal_threshold_days": 30,  # Configurable certificate expiry threshold (days)
                "api_bearer_token": _bearer_token_from_env_or_generate(),
                "setup_completed": False,  # Track if initial setup is done
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",  # 'dns-01' or 'http-01'
                "dns_providers": {},  # Start with empty DNS providers - only add what's actually configured
                "certificate_storage": {  # New storage backend configuration
                    "backend": "local_filesystem",  # Default to local filesystem for backward compatibility
                    "cert_dir": "certificates",
                    "azure_keyvault": {
                        "vault_url": "",
                        "client_id": "",
                        "client_secret": "",
                        "tenant_id": "",
                    },
                    "aws_secrets_manager": {
                        "region": "us-east-1",
                        "access_key_id": "",
                        "secret_access_key": "",
                    },
                    "hashicorp_vault": {
                        "vault_url": "",
                        "vault_token": "",
                        "mount_point": "secret",
                        "engine_version": "v2",
                    },
                    "infisical": {
                        "site_url": "https://app.infisical.com",
                        "client_id": "",
                        "client_secret": "",
                        "project_id": "",
                        "environment": "prod",
                    },
                },
            }

            # Only create full template for first-time setup
            first_time_template = {
                "cloudflare_token": "",
                "domains": [],
                "email": "",
                "auto_renew": True,
                "renewal_threshold_days": 30,  # Configurable certificate expiry threshold (days)
                "api_bearer_token": _bearer_token_from_env_or_generate(),
                "setup_completed": False,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                "dns_providers": {
                    "cloudflare": {"api_token": ""},
                    "route53": {
                        "access_key_id": "",
                        "secret_access_key": "",
                        "region": "us-east-1",
                    },
                    "azure": {
                        "subscription_id": "",
                        "resource_group": "",
                        "tenant_id": "",
                        "client_id": "",
                        "client_secret": "",
                    },
                    "google": {"project_id": "", "service_account_key": ""},
                    "powerdns": {"api_url": "", "api_key": ""},
                    "digitalocean": {"api_token": ""},
                    "linode": {"api_key": ""},
                    "edgedns": {
                        "client_token": "",
                        "client_secret": "",
                        "access_token": "",
                        "host": "",
                    },
                    "gandi": {"api_token": ""},
                    "ovh": {
                        "endpoint": "",
                        "application_key": "",
                        "application_secret": "",
                        "consumer_key": "",
                    },
                    "namecheap": {"username": "", "api_key": ""},
                    "arvancloud": {"api_key": ""},
                    "infomaniak": {"api_token": ""},
                    "acme-dns": {
                        "api_url": "",
                        "username": "",
                        "password": "",
                        "subdomain": "",
                    },
                    "duckdns": {"api_token": ""},
                    "hetzner-cloud": {"api_token": ""},
                },
                "certificate_storage": default_settings["certificate_storage"],
            }

            if not self.settings_file.exists():
                # First time setup - create with full template for web UI
                logger.info(
                    "Creating initial settings file with full provider template for first-time setup"
                )
                self.save_settings(first_time_template)
                return first_time_template

            try:
                settings = self.file_ops.safe_file_read(
                    self.settings_file, is_json=True
                )
                if settings is None:
                    logger.warning(
                        "Settings file exists but is empty or corrupted, attempting backup restore"
                    )
                    settings = self._try_restore_from_backup()
                    if settings is None:
                        logger.warning(
                            "No usable backup found, recreating settings with defaults"
                        )
                        self.save_settings(first_time_template)
                        return first_time_template
                    logger.info("Settings restored successfully from backup")

                # Apply migrations for backward compatibility
                settings, was_migrated = self._migrate_settings_format(settings)

                # Only merge essential missing keys, NOT the full dns_providers template
                essential_keys = [
                    "cloudflare_token",
                    "domains",
                    "email",
                    "auto_renew",
                    "renewal_threshold_days",
                    "api_bearer_token",
                    "setup_completed",
                    "dns_provider",
                    "challenge_type",
                ]
                for key in essential_keys:
                    if key not in settings:
                        # Don't regenerate api_bearer_token if its hash is already
                        # stored — that means we already migrated to the hashed
                        # form and stripping the plaintext is intentional.
                        if key == "api_bearer_token" and settings.get(
                            "api_bearer_token_hash"
                        ):
                            continue
                        settings[key] = default_settings[key]

                # Ensure dns_providers exists but don't overwrite with empty template
                if "dns_providers" not in settings:
                    settings["dns_providers"] = {}
                    was_migrated = True

                dns_providers_before = {
                    provider: dict(config) if isinstance(config, dict) else config
                    for provider, config in settings.get("dns_providers", {}).items()
                }
                settings = self.migrate_dns_providers_to_multi_account(settings)
                if settings.get("dns_providers", {}) != dns_providers_before:
                    was_migrated = True

                # Ensure certificate_storage exists with default configuration
                if "certificate_storage" not in settings:
                    settings["certificate_storage"] = default_settings[
                        "certificate_storage"
                    ]
                    was_migrated = True
                else:
                    # Merge missing storage backend configuration keys
                    for key, value in default_settings["certificate_storage"].items():
                        if key not in settings["certificate_storage"]:
                            settings["certificate_storage"][key] = value
                            was_migrated = True

                # Validate critical settings — only regenerate if no hash is
                # already stored (otherwise we've intentionally stripped the
                # plaintext and authentication uses api_bearer_token_hash).
                if settings.get("api_bearer_token") in [
                    "change-this-token",
                    "certmate-api-token-12345",
                    "",
                ] and not settings.get("api_bearer_token_hash"):
                    logger.warning(
                        "Using default API token - please change for security"
                    )
                    settings["api_bearer_token"] = generate_secure_token()
                    was_migrated = True

                # Save migrated settings if any changes were made.
                # If the save fails (disk full, permission denied, validation
                # rejection of a field migrated up from an older format),
                # the in-memory copy diverges from disk: callers receive the
                # migrated dict but the next process to load_settings will
                # re-run migration. Log at ERROR so the operator notices —
                # the previous behavior swallowed save_settings's bool and
                # the next save attempt would silently fail too.
                if was_migrated:
                    logger.info("Settings migrated, saving updated format")
                    if not self.save_settings(settings, backup_reason="migration"):
                        logger.error(
                            "Migration save failed — in-memory settings are "
                            "now ahead of settings.json on disk. The next "
                            "save will retry; check earlier log lines for "
                            "the validation or I/O error that blocked it."
                        )

                # Override settings with environment variables.
                # LETSENCRYPT_EMAIL takes precedence over the value saved via the UI.
                # Set it in docker-compose.yml or as -e LETSENCRYPT_EMAIL=... to pin the email.
                letsencrypt_email = os.getenv("LETSENCRYPT_EMAIL")
                if letsencrypt_email:
                    if settings.get("email") and settings["email"] != letsencrypt_email:
                        logger.warning(
                            "LETSENCRYPT_EMAIL env var (%s) overrides the email saved in settings (%s). "
                            "Unset LETSENCRYPT_EMAIL to use the UI-configured value.",
                            letsencrypt_email,
                            settings["email"],
                        )
                    settings["email"] = letsencrypt_email

                if os.getenv("CLOUDFLARE_TOKEN"):
                    dns_providers = settings.setdefault("dns_providers", {})
                    cloudflare_config = dns_providers.get("cloudflare")
                    if not isinstance(cloudflare_config, dict):
                        cloudflare_config = {}
                        dns_providers["cloudflare"] = cloudflare_config
                    accounts = cloudflare_config.get("accounts")
                    if not isinstance(accounts, dict):
                        accounts = {}
                        cloudflare_config["accounts"] = accounts
                    default_account = accounts.get("default")
                    if not isinstance(default_account, dict):
                        default_account = {}
                        accounts["default"] = default_account
                    default_account["api_token"] = os.getenv("CLOUDFLARE_TOKEN")

                return settings

            except Exception as e:
                logger.error(f"Error loading settings: {e}")
                logger.warning(
                    "Returning default settings in-memory (existing file preserved on disk)"
                )
                return default_settings

    def save_settings(self, settings, backup_reason="auto_save"):
        """Save settings to file with validation and automatic backup.

        Acquires the re-entrant lock to serialize writes. Reads-then-writes
        from a single caller must use atomic_update() to be race-free across
        threads — wrapping save_settings alone is not enough.
        """
        with self._lock:
            try:
                # Create backup before saving (if settings file exists).
                # A failed backup is logged as a warning but does not block the save —
                # the caller's changes should not be lost just because disk is temporarily full.
                # backup_reason=None disables backup (high-frequency writes like
                # API key last_used_at updates).
                if backup_reason is not None and self.settings_file.exists():
                    try:
                        result = self.file_ops.create_unified_backup(
                            settings, backup_reason
                        )
                        if not result:
                            logger.warning(
                                "Pre-save backup failed (disk full or permission error?). "
                                "Proceeding with save, but no restore point was created."
                            )
                    except Exception as backup_err:
                        logger.warning(
                            "Pre-save backup raised an exception: %s. "
                            "Proceeding with save.",
                            backup_err,
                        )

                # Validate settings structure
                if not isinstance(settings, dict):
                    logger.error("Settings must be a dictionary")
                    return False

                # Validate critical settings before saving
                if "email" in settings and settings["email"]:
                    is_valid, email_or_error = validate_email(settings["email"])
                    if not is_valid:
                        logger.error(f"Invalid email in settings: {email_or_error}")
                        return False
                    settings["email"] = email_or_error

                if "api_bearer_token" in settings:
                    token = settings["api_bearer_token"]
                    # Skip validation for masked/placeholder tokens — the real
                    # token is preserved in the file; callers should strip these
                    # before calling save_settings, but this is a safety net.
                    if not token or token == "********":
                        settings.pop("api_bearer_token")
                        logger.info(
                            "Stripped masked/empty api_bearer_token from settings before save"
                        )
                    else:
                        is_valid, token_or_error = validate_api_token(token)
                        if not is_valid:
                            logger.error(
                                "Invalid api_bearer_token (the application's "
                                "internal API authentication token, distinct "
                                "from any DNS provider credential): %s",
                                token_or_error,
                            )
                            return False
                        # Hash the legacy token and drop the plaintext from disk.
                        # Auth still accepts the original token because authenticate_api_token
                        # checks api_bearer_token_hash first; admins keep the plaintext they
                        # already configured in their clients (we never had a way to recover it).
                        # Always re-hash on save so a rotation overwrites the previous hash.
                        if self._token_hasher:
                            settings["api_bearer_token_hash"] = self._token_hasher(
                                token_or_error
                            )
                            # settings.pop("api_bearer_token")
                            logger.warning(
                                "Hashed api_bearer_token and removed plaintext from settings.json. "
                                "The token still authenticates via its hash; rotate it via the API Keys UI "
                                "if you no longer have a copy."
                            )

                # Validate dns_provider against supported set.
                # IMPORTANT: when adding a provider, also update tests/test_provider_wiring_consistency.py
                # which extracts this literal via inspect.getsource.
                supported_providers = {
                    "cloudflare",
                    "route53",
                    "azure",
                    "google",
                    "powerdns",
                    "digitalocean",
                    "linode",
                    "edgedns",
                    "gandi",
                    "ovh",
                    "namecheap",
                    "vultr",
                    "dnsmadeeasy",
                    "nsone",
                    "rfc2136",
                    "hetzner",
                    "hetzner-cloud",
                    "porkbun",
                    "godaddy",
                    "he-ddns",
                    "dynudns",
                    "arvancloud",
                    "infomaniak",
                    "acme-dns",
                    "duckdns",
                }
                if (
                    "dns_provider" in settings
                    and settings["dns_provider"] not in supported_providers
                ):
                    logger.error(f"Invalid dns_provider: {settings['dns_provider']}")
                    return False

                # Validate domains
                if "domains" in settings:
                    validated_domains = []
                    for domain_entry in settings["domains"]:
                        if isinstance(domain_entry, str):
                            is_valid, domain_or_error = validate_domain(domain_entry)
                            if is_valid:
                                validated_domains.append(domain_or_error)
                            else:
                                logger.warning(
                                    f"Invalid domain skipped: {domain_or_error}"
                                )
                        elif (
                            isinstance(domain_entry, dict) and "domain" in domain_entry
                        ):
                            is_valid, domain_or_error = validate_domain(
                                domain_entry["domain"]
                            )
                            if is_valid:
                                domain_entry["domain"] = domain_or_error
                                validated_domains.append(domain_entry)
                            else:
                                logger.warning(
                                    f"Invalid domain in object skipped: {domain_or_error}"
                                )
                    settings["domains"] = validated_domains

                # Ensure required fields exist (but don't fail on missing fields, just warn).
                # api_bearer_token is satisfied by either the plaintext field or its hashed form.
                required_fields = [
                    "email",
                    "domains",
                    "auto_renew",
                    "api_bearer_token",
                    "dns_provider",
                ]
                for field in required_fields:
                    if field not in settings:
                        if field == "api_bearer_token" and settings.get(
                            "api_bearer_token_hash"
                        ):
                            continue
                        logger.warning(f"Missing required field '{field}' in settings")

                # Allow DNS propagation seconds override per provider
                defaults = {
                    "cloudflare": 60,
                    "route53": 60,
                    "digitalocean": 120,
                    "linode": 120,
                    "azure": 180,
                    "google": 120,
                    "powerdns": 60,
                    "gandi": 180,
                    "ovh": 180,
                    "namecheap": 300,
                    "arvancloud": 120,
                    "infomaniak": 300,
                    "acme-dns": 30,
                    "duckdns": 60,
                    "edgedns": 90,
                    "hetzner-cloud": 120,
                }
                if "dns_propagation_seconds" not in settings or not isinstance(
                    settings["dns_propagation_seconds"], dict
                ):
                    settings["dns_propagation_seconds"] = defaults
                else:
                    # Merge with defaults for missing providers
                    for k, v in defaults.items():
                        settings["dns_propagation_seconds"].setdefault(k, v)

                # Save settings
                if self.file_ops.safe_file_write(
                    self.settings_file, settings, is_json=True
                ):
                    logger.info("Settings saved successfully")
                    return True
                else:
                    logger.error("Failed to save settings")
                    return False

            except Exception as e:
                logger.error(f"Error saving settings: {e}")
                return False

    def migrate_domains_format(self, settings):
        """Migrate old domain format (string) to new format (object with dns_provider)"""
        try:
            if "domains" not in settings:
                return settings

            domains = settings["domains"]
            default_provider = settings.get("dns_provider", "cloudflare")
            migrated_domains = []

            for domain_entry in domains:
                if isinstance(domain_entry, str):
                    # Old format: just domain string
                    migrated_domains.append(
                        {
                            "domain": domain_entry,
                            "dns_provider": default_provider,
                            "account_id": "default",
                        }
                    )
                elif isinstance(domain_entry, dict):
                    # New format: already has structure
                    if "domain" in domain_entry:
                        # Ensure required fields exist
                        if "dns_provider" not in domain_entry:
                            domain_entry["dns_provider"] = default_provider
                        if "account_id" not in domain_entry:
                            domain_entry["account_id"] = "default"
                        migrated_domains.append(domain_entry)
                    else:
                        logger.warning(f"Invalid domain entry format: {domain_entry}")
                else:
                    logger.warning(
                        f"Unexpected domain entry type: {type(domain_entry)}"
                    )

            settings["domains"] = migrated_domains
            return settings

        except Exception as e:
            logger.error(f"Error during domain format migration: {e}")
            return settings

    def migrate_dns_providers_to_multi_account(self, settings):
        """Migrate old single-account DNS provider configurations to multi-account format"""
        try:
            dns_providers = settings.get("dns_providers", {})

            # Define credential keys for each provider (same as used later)
            old_config_keys = {
                "cloudflare": ["api_token"],
                "route53": ["access_key_id", "secret_access_key", "region"],
                "azure": [
                    "subscription_id",
                    "resource_group",
                    "tenant_id",
                    "client_id",
                    "client_secret",
                ],
                "google": ["project_id", "service_account_key"],
                "powerdns": ["api_url", "api_key"],
                "digitalocean": ["api_token"],
                "linode": ["api_key"],
                "gandi": ["api_token"],
                "ovh": [
                    "endpoint",
                    "application_key",
                    "application_secret",
                    "consumer_key",
                ],
                "namecheap": ["username", "api_key"],
                "rfc2136": ["nameserver", "tsig_key", "tsig_secret", "api_key"],
                "vultr": ["api_key"],
                "hetzner": ["api_token"],
                "hetzner-cloud": ["api_token"],
                "porkbun": ["api_key", "secret_key"],
                "godaddy": ["api_key", "secret"],
                "he-ddns": ["username", "password"],
                "arvancloud": ["api_key"],
                "infomaniak": ["api_token"],
                "acme-dns": ["api_url", "username", "password", "subdomain"],
                "duckdns": ["api_token"],
                "edgedns": ["client_token", "client_secret", "access_token", "host"],
            }

            # Check if migration is needed
            needs_migration = False
            for provider_name, provider_config in dns_providers.items():
                if provider_config and isinstance(provider_config, dict):
                    # If it doesn't have 'accounts' key but has credential keys, it needs migration
                    if "accounts" not in provider_config:
                        provider_keys = old_config_keys.get(
                            provider_name, ["api_token", "api_key", "username"]
                        )
                        if any(key in provider_config for key in provider_keys):
                            needs_migration = True
                            break

            if not needs_migration:
                return settings

            logger.info("Migrating DNS providers to multi-account format")

            # Migrate each provider
            for provider_name, provider_config in dns_providers.items():
                if not provider_config or not isinstance(provider_config, dict):
                    continue

                # Skip if already in multi-account format
                if "accounts" in provider_config:
                    continue

                provider_keys = old_config_keys.get(
                    provider_name, ["api_token", "api_key", "username"]
                )

                # Check if this provider has old-style configuration
                has_old_config = any(key in provider_config for key in provider_keys)

                # Check if it already has account-like objects
                has_account_objects = any(
                    isinstance(v, dict)
                    and ("name" in v or any(k in v for k in provider_keys))
                    for k, v in provider_config.items()
                    if k not in provider_keys
                )

                if not has_old_config or has_account_objects:
                    continue

                # Extract old configuration keys
                old_config = {}
                remaining_config = {}

                for key, value in provider_config.items():
                    if key in provider_keys:
                        old_config[key] = value
                    else:
                        remaining_config[key] = value

                # Create new multi-account structure
                new_config = {
                    "accounts": {
                        "default": {
                            "name": f"Default {provider_name.title()} Account",
                            "description": "Migrated from single-account configuration",
                            **old_config,
                        }
                    },
                    **remaining_config,
                }

                dns_providers[provider_name] = new_config

            # Update default accounts if not set
            if "default_accounts" not in settings:
                settings["default_accounts"] = {}

            # Set default account for each configured provider
            for provider_name, provider_config in dns_providers.items():
                if (
                    provider_config
                    and isinstance(provider_config, dict)
                    and "accounts" in provider_config
                ):
                    if provider_name not in settings["default_accounts"]:
                        # Use 'default' as the default account ID
                        settings["default_accounts"][provider_name] = "default"

            logger.info("DNS provider migration completed successfully")
            return settings

        except Exception as e:
            logger.error(f"Error during DNS provider migration: {e}")
            return settings

    def get_domain_dns_provider(self, domain, settings=None):
        """Get the DNS provider for a specific domain with backward compatibility

        Args:
            domain: The domain name to check
            settings: Current settings dict (optional, loads current if not provided)

        Returns:
            str or None: DNS provider name (e.g., 'cloudflare', 'route53'),
                         or None if no provider is configured.
        """
        try:
            if settings is None:
                settings = self.load_settings()

            default_provider = settings.get("dns_provider")

            # Check if domain has specific provider in new object format
            for domain_config in settings.get("domains", []):
                if (
                    isinstance(domain_config, dict)
                    and domain_config.get("domain") == domain
                ):
                    return domain_config.get("dns_provider", default_provider)
                elif isinstance(domain_config, str) and domain_config == domain:
                    # Legacy string format - use default provider
                    return default_provider

            # Domain not found in settings, use default provider
            return default_provider

        except Exception as e:
            logger.error(f"Error getting DNS provider for domain {domain}: {e}")
            return None

    def _migrate_settings_format(self, settings):
        """Migrate settings to handle format changes and ensure backward compatibility"""
        migrated = False

        # Migration 1: Handle backup format wrapping
        if "settings" in settings and "metadata" in settings:
            logger.info("Migrating settings from backup format")
            settings = settings["settings"]
            migrated = True

        # Migration 2: Handle domains format transition (string array <-> object array)
        if "domains" in settings:
            domains = settings["domains"]
            if domains and all(isinstance(d, str) for d in domains):
                # Convert simple string array to object array for new multi-account support
                logger.info(
                    "Migrating domains from string array to object array format"
                )
                default_provider = settings.get("dns_provider", "cloudflare")
                default_accounts = settings.get("default_accounts", {})
                default_account = default_accounts.get(default_provider, "default")

                new_domains = []
                for domain in domains:
                    new_domains.append(
                        {
                            "domain": domain,
                            "dns_provider": default_provider,
                            "account_id": default_account,
                        }
                    )
                settings["domains"] = new_domains
                migrated = True

        # Migration 3: Ensure metadata exists for existing certificates
        if migrated:
            self._ensure_certificate_metadata()

        return settings, migrated

    def _ensure_certificate_metadata(self):
        """Ensure all existing certificates have metadata.json files"""
        try:
            cert_dir = self.file_ops.cert_dir
            settings = self.load_settings()

            # iter_cert_domain_dirs already requires a cert.pem, so we never
            # try to write metadata into lost+found or other non-cert dirs.
            for cert_path in iter_cert_domain_dirs(cert_dir):
                metadata_file = cert_path / "metadata.json"
                if metadata_file.exists():
                    continue
                domain = cert_path.name
                dns_provider = self._get_domain_provider_from_settings(domain, settings)

                metadata = {
                    "domain": domain,
                    "dns_provider": dns_provider,
                    "created_at": "unknown",
                    "version": "2.2.0",
                    "migrated": True,
                }

                try:
                    with open(metadata_file, "w") as f:
                        import json

                        json.dump(metadata, f, indent=2)
                    logger.info(f"Created metadata for certificate: {domain}")
                except Exception as e:
                    logger.warning(f"Failed to create metadata for {domain}: {e}")

        except Exception as e:
            logger.error(f"Error ensuring certificate metadata: {e}")

    def _get_domain_provider_from_settings(self, domain, settings):
        """Get DNS provider for a domain from settings"""
        # Check if domain has specific provider in new format
        for domain_config in settings.get("domains", []):
            if (
                isinstance(domain_config, dict)
                and domain_config.get("domain") == domain
            ):
                return domain_config.get(
                    "dns_provider", settings.get("dns_provider", "cloudflare")
                )

        # Fall back to default provider
        return settings.get("dns_provider", "cloudflare")
