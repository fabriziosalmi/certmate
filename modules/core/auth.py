"""
Authentication module for CertMate
Handles authentication decorators and security functions
Supports both API token and local username/password authentication
"""

import logging
import os
import secrets
import hashlib
import hmac
import threading
import uuid
import time
from functools import wraps
from flask import request, jsonify, session
from datetime import datetime, timedelta
from .utils import utc_now

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

logger = logging.getLogger(__name__)

ROLE_HIERARCHY = {'viewer': 0, 'operator': 1, 'admin': 2}

# Distinct from None/False so the operator-bearer-token detection can be
# memoised (env/file are fixed for the process lifetime) without a False
# result being mistaken for "not computed yet".
_UNSET = object()


class AuthManager:
    """Class to handle authentication and authorization"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager
        self._sessions = {}  # In-memory session store: {session_id: {user, expires, created}}
        self._session_lock = threading.Lock()  # Thread-safe session access
        self._hmac_key = None  # Set by set_hmac_key() after app init
        self._audit_logger = None  # Set by set_audit_logger() after AuditLogger constructed
        # Debounce API-key last_used_at persistence. Rewriting the whole
        # settings.json under the global lock on EVERY authenticated API
        # request was a hot-path write amplifier; track the last persist time
        # per key and skip the write within the configured interval.
        self._last_used_persist_ts = {}
        self._last_used_lock = threading.Lock()
        import os
        _timeout_hours = int(os.getenv('SESSION_TIMEOUT_HOURS', '8'))
        self._session_timeout = max(1, _timeout_hours) * 60 * 60
        if not BCRYPT_AVAILABLE:
            logger.warning("bcrypt not available; using the scrypt KDF fallback. "
                           "Install bcrypt for the preferred password hashing.")

    def set_audit_logger(self, audit_logger):
        """Inject the AuditLogger so authorization denials emit a real audit
        entry instead of a stderr-only warning. Optional — when unset, the
        decorator falls back to logger.warning so role/scope denials are at
        least surfaced in the application log."""
        self._audit_logger = audit_logger

    def set_hmac_key(self, key):
        """Set the server-side secret used for HMAC-based API token hashing.

        Must be called after the Flask app's secret_key is available.
        New tokens will be hashed with HMAC; verification falls back to
        plain SHA-256 for tokens created before this change.
        """
        self._hmac_key = key.encode() if isinstance(key, str) else key

    @staticmethod
    def _normalize_role(role):
        """Normalize legacy role names to the current 3-tier model."""
        if role == 'user':
            return 'operator'  # backward compat: 'user' → 'operator'
        return role if role in ROLE_HIERARCHY else 'viewer'

    def _hash_password(self, password, salt=None):
        """Hash a password with bcrypt (preferred) or scrypt (fallback).

        bcrypt is the industry standard — slow and GPU/ASIC-resistant. If bcrypt
        cannot be imported, fall back to scrypt (a slow, memory-hard KDF from the
        stdlib) rather than a fast hash: a bare SHA-256 of salt+password would be
        trivially GPU-crackable for low-entropy passwords.
        """
        if BCRYPT_AVAILABLE:
            # bcrypt handles salt internally, rounds=12 provides good security
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        # bcrypt import failed — scrypt KDF fallback (NOT a fast hash).
        # Format: "scrypt:<n>:<r>:<p>:<salt_hex>:<hash_hex>".
        if salt is None:
            salt = secrets.token_hex(16)
        n, r, p = 2 ** 14, 8, 1  # ~16 MiB work factor, under scrypt's default maxmem
        dk = hashlib.scrypt(password.encode(), salt=salt.encode(),
                            n=n, r=r, p=p, dklen=32)
        return f"scrypt:{n}:{r}:{p}:{salt}:{dk.hex()}"

    def _verify_password(self, password, stored_hash):
        """Verify a password against a stored hash.

        Supports bcrypt, the scrypt fallback, and the pre-existing legacy
        SHA-256 formats ("sha256:salt:hash" and bare "salt:hash") so operators
        hashed under the old fallback can still log in after upgrade.
        """
        try:
            # bcrypt hash (starts with $2b$ / $2a$)
            if stored_hash.startswith('$2'):
                if BCRYPT_AVAILABLE:
                    return bcrypt.checkpw(password.encode(), stored_hash.encode())
                logger.error("bcrypt hash found but bcrypt not available")
                return False

            # scrypt fallback: "scrypt:<n>:<r>:<p>:<salt>:<hash>"
            if stored_hash.startswith('scrypt:'):
                _, n_s, r_s, p_s, salt, expected_hash = stored_hash.split(':', 5)
                n, r, p = int(n_s), int(r_s), int(p_s)
                # Bounds-check the stored KDF params BEFORE the (costly) work so a
                # corrupted settings.json can't turn each login into an expensive
                # scrypt run. These bracket what _hash_password writes
                # (n=2**14, r=8, p=1); scrypt's own maxmem is the hard backstop.
                if not (2 ** 12 <= n <= 2 ** 17 and (n & (n - 1)) == 0
                        and 1 <= r <= 16 and 1 <= p <= 8
                        and 0 < len(expected_hash) <= 256
                        and all(c in '0123456789abcdefABCDEF' for c in expected_hash)):
                    return False
                dk = hashlib.scrypt(password.encode(), salt=salt.encode(),
                                    n=n, r=r, p=p, dklen=len(expected_hash) // 2)
                return secrets.compare_digest(dk.hex(), expected_hash)

            # Legacy SHA-256 formats (verify-only, for pre-upgrade hashes):
            # "sha256:salt:hash" or the older bare "salt:hash".
            if stored_hash.startswith('sha256:'):
                parts = stored_hash.split(':', 2)
                if len(parts) == 3:
                    _, salt, expected_hash = parts
                else:
                    return False
            else:
                salt, expected_hash = stored_hash.split(':', 1)

            actual_hash = hashlib.sha256((salt + password).encode()).hexdigest()
            return secrets.compare_digest(actual_hash, expected_hash)
        except (ValueError, AttributeError) as e:
            logger.debug(f"Password verification error: {e}")
            return False
    
    def _get_users(self):
        """Get all users from settings"""
        settings = self.settings_manager.load_settings()
        return settings.get('users', {})
    
    def _save_users(self, users):
        """Save users to settings.

        Uses settings_manager.update so the read-modify-write happens
        under the settings lock — two concurrent admin requests creating
        different users no longer race and lose one of them.
        """
        def _mutate(settings):
            settings['users'] = users
        return self.settings_manager.update(_mutate, "user_management")

    # --- Scoped API Key management ---

    # Domain pattern used by allowed_domains validation. Mirrors the existing
    # _DOMAIN_RE in modules/api/resources.py but also accepts the bare
    # wildcard form "*.example.com" (no leading label before the asterisk).
    _ALLOWED_DOMAIN_RE = __import__('re').compile(
        r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )

    @classmethod
    def _normalize_allowed_domains(cls, allowed_domains):
        """Normalize / validate an allowed_domains value before storage.

        Returns (normalized_list_or_None, error_or_None).

        - None / missing  → returns (None, None)  (unrestricted; back-compat)
        - empty list      → returns ([], None)    (locked-out key — valid use)
        - list of strings → each entry validated against _ALLOWED_DOMAIN_RE;
                            stripped + lowercased; duplicates collapsed.
        - any other type  → error
        """
        if allowed_domains is None:
            return None, None
        if not isinstance(allowed_domains, list):
            return None, "allowed_domains must be a list of domain patterns or null"
        normalized = []
        seen = set()
        for entry in allowed_domains:
            if not isinstance(entry, str):
                return None, "allowed_domains entries must be strings"
            cleaned = entry.strip().lower()
            if not cleaned:
                continue
            if not cls._ALLOWED_DOMAIN_RE.match(cleaned):
                return None, f"Invalid domain pattern: {entry!r}"
            if cleaned not in seen:
                seen.add(cleaned)
                normalized.append(cleaned)
        return normalized, None

    @staticmethod
    def domain_matches_scope(domain, allowed_domains):
        """Return True if *domain* is reachable by a caller scoped to
        *allowed_domains*.

        - allowed_domains is None → unrestricted (every domain matches).
        - allowed_domains is []   → locked out (no domain matches).
        - allowed_domains is a list of patterns where each pattern is either
          an exact domain ("example.com") matched case-insensitively, or a
          wildcard "*.example.com" that matches any single-level subdomain
          ("foo.example.com" ✓, "a.b.example.com" ✓, "example.com" ✗).
        - A wildcard *request* ("*.example.com") is authorized only by an
          identical wildcard scope entry; an apex scope ("example.com") does
          NOT cover it, because the wildcard cert is strictly broader (valid
          for every subdomain).
        """
        if allowed_domains is None:
            return True
        if not allowed_domains:
            return False
        if not isinstance(domain, str) or not domain:
            return False
        d = domain.strip().lower()
        # A wildcard REQUEST ("*.example.com") is a distinct, broader resource
        # than the apex: the issued cert is valid for every subdomain. It must
        # therefore be authorized only by an identical wildcard scope entry —
        # an apex scope of "example.com" does NOT imply it. (The previous
        # `lstrip('*.')` stripped a character SET, collapsing "*.example.com"
        # to "example.com", so an apex-scoped key could mint the wildcard
        # cert — a scope-boundary privilege escalation.)
        if d.startswith('*.'):
            return any(pattern.strip().lower() == d for pattern in allowed_domains)
        for pattern in allowed_domains:
            p = pattern.strip().lower()
            if p.startswith('*.'):
                suffix = p[1:]  # ".example.com"
                # Wildcard must match a strict subdomain — "example.com" by
                # itself does NOT match "*.example.com".
                if d.endswith(suffix) and len(d) > len(suffix):
                    return True
            else:
                if d == p:
                    return True
        return False

    def user_can_access_domain(self, user, domain):
        """Return True if the request's current_user is allowed to operate on
        *domain* according to its scoped key's allowed_domains.

        Users without allowed_domains (legacy keys, session-authenticated
        local users, the legacy bearer token) keep full access (the audit's
        "no multi-tenancy by design" baseline).
        """
        if not user:
            return False
        scope = user.get('allowed_domains')
        return self.domain_matches_scope(domain, scope)

    def _get_api_keys(self):
        """Get all API keys from settings."""
        settings = self.settings_manager.load_settings()
        return settings.get('api_keys', {})

    def _save_api_keys(self, api_keys):
        """Save API keys to settings (atomic under the settings lock)."""
        def _mutate(settings):
            settings['api_keys'] = api_keys
        return self.settings_manager.update(_mutate, "api_key_management")

    def hash_api_token(self, token):
        """Hash an API token using HMAC-SHA256 (with server secret) or plain
        SHA-256 as fallback. Public so SettingsManager can migrate the legacy
        api_bearer_token without depending on a private symbol."""
        if self._hmac_key:
            digest = hmac.new(self._hmac_key, token.encode(), hashlib.sha256).hexdigest()
            return f"hmac-sha256:{digest}"
        digest = hashlib.sha256(token.encode()).hexdigest()
        return f"sha256:{digest}"

    # Backwards-compat alias for callers that imported the private name.
    _hash_api_token = hash_api_token

    def _verify_api_token(self, token, stored_hash):
        """Verify an API token against a stored hash.

        Supports both HMAC-SHA256 (preferred) and legacy plain SHA-256.
        """
        if not stored_hash:
            return False
        if stored_hash.startswith('hmac-sha256:') and self._hmac_key:
            expected = stored_hash.split(':', 1)[1]
            actual = hmac.new(self._hmac_key, token.encode(), hashlib.sha256).hexdigest()
            return secrets.compare_digest(actual, expected)
        if stored_hash.startswith('sha256:'):
            expected = stored_hash.split(':', 1)[1]
            actual = hashlib.sha256(token.encode()).hexdigest()
            return secrets.compare_digest(actual, expected)
        return False

    def create_api_key(self, name, role='viewer', expires_at=None, created_by=None,
                       allowed_domains=None, is_agent=False):
        """Create a new scoped API key.

        Args:
            name: human-readable label, 1-64 chars, unique among active keys
            role: viewer | operator | admin
            expires_at: optional ISO-8601 expiry
            created_by: username of the admin creating the key
            allowed_domains: optional list of domain patterns scoping the
                key to specific certificates. None = unrestricted (legacy
                behavior). Empty list = locked-out key (creatable for
                staging). See AuthManager.domain_matches_scope() for the
                matching semantics.
            is_agent: mark this key as belonging to an AI/MCP agent. Actions
                authenticated with the key are then attributed in the audit
                trail with ``actor.kind='agent'`` (vs ``api_token``). Point the
                MCP server at a dedicated agent-flagged key so the audit trail
                can distinguish an agent from a human operator.

        Returns:
            tuple: (success, result_dict_or_error_string)
        """
        try:
            if not name or len(name) > 64:
                return False, "Key name must be 1-64 characters"

            if role not in ROLE_HIERARCHY:
                return False, f"Invalid role: {role}. Must be viewer, operator, or admin"
            normalized_role = self._normalize_role(role)

            scoped_domains, scope_err = self._normalize_allowed_domains(allowed_domains)
            if scope_err:
                return False, scope_err

            api_keys = self._get_api_keys()

            # Check name uniqueness among active keys
            for existing in api_keys.values():
                if existing.get('name') == name and not existing.get('revoked'):
                    return False, "An active key with that name already exists"

            key_id = str(uuid.uuid4())
            plaintext = 'cm_' + secrets.token_hex(20)

            api_keys[key_id] = {
                'name': name,
                'role': normalized_role,
                'token_hash': self._hash_api_token(plaintext),
                'token_prefix': plaintext[:7],
                'created_at': utc_now().isoformat(),
                'created_by': created_by,
                'expires_at': expires_at,
                'last_used_at': None,
                'revoked': False,
                'allowed_domains': scoped_domains,
                'is_agent': bool(is_agent),
            }

            if self._save_api_keys(api_keys):
                logger.info(
                    f"API key '{name}' (role={normalized_role}, "
                    f"allowed_domains={scoped_domains}) created by {created_by}"
                )
                return True, {
                    'id': key_id,
                    'name': name,
                    'role': normalized_role,
                    'token': plaintext,
                    'token_prefix': plaintext[:7],
                    'created_at': api_keys[key_id]['created_at'],
                    'expires_at': expires_at,
                    'allowed_domains': scoped_domains,
                    'is_agent': bool(is_agent),
                }
            return False, "Failed to save API key"
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Error creating API key: {e}")
            return False, "An internal error occurred"

    def list_api_keys(self):
        """List all API keys without token hashes."""
        api_keys = self._get_api_keys()
        now = utc_now().isoformat()
        result = {}
        for key_id, data in api_keys.items():
            exp = data.get('expires_at')
            is_expired = bool(exp and exp < now)
            result[key_id] = {
                'name': data.get('name'),
                'role': data.get('role'),
                'token_prefix': data.get('token_prefix'),
                'created_at': data.get('created_at'),
                'created_by': data.get('created_by'),
                'expires_at': exp,
                'last_used_at': data.get('last_used_at'),
                'revoked': data.get('revoked', False),
                'is_expired': is_expired,
                'allowed_domains': data.get('allowed_domains'),
                'is_agent': bool(data.get('is_agent')),
            }
        return result

    def revoke_api_key(self, key_id):
        """Revoke an API key by ID (soft-delete)."""
        try:
            api_keys = self._get_api_keys()
            if key_id not in api_keys:
                return False, "API key not found"
            if api_keys[key_id].get('revoked'):
                return False, "API key is already revoked"

            api_keys[key_id]['revoked'] = True
            api_keys[key_id]['revoked_at'] = utc_now().isoformat()

            if self._save_api_keys(api_keys):
                logger.info(f"API key '{api_keys[key_id].get('name')}' revoked")
                return True, "API key revoked successfully"
            return False, "Failed to save changes"
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Error revoking API key: {e}")
            return False, "An internal error occurred"

    @staticmethod
    def _last_used_persist_interval() -> float:
        """Minimum seconds between persisting an API key's last_used_at.
        0 persists on every request (the original behaviour). Default 60."""
        import os
        try:
            return max(0.0, float(os.environ.get('CERTMATE_LAST_USED_PERSIST_SECONDS', '60')))
        except (TypeError, ValueError):
            return 60.0

    def _should_persist_last_used(self, key_id: str) -> bool:
        """True at most once per interval per key (debounce). Records the
        persist time when it returns True."""
        interval = self._last_used_persist_interval()
        if interval <= 0:
            return True
        mono = time.monotonic()
        with self._last_used_lock:
            if mono - self._last_used_persist_ts.get(key_id, 0.0) >= interval:
                self._last_used_persist_ts[key_id] = mono
                return True
        return False

    def authenticate_api_token(self, token):
        """Authenticate a bearer token against legacy token and scoped keys.

        Returns user info dict or None.
        """
        try:
            settings = self.settings_manager.load_settings()

            # 1. Check legacy api_bearer_token (backward compat).
            # Prefer the hashed form (api_bearer_token_hash); fall back to
            # plaintext compare for installs that have not yet been migrated.
            legacy_hash = settings.get('api_bearer_token_hash')
            if legacy_hash and self._verify_api_token(token, legacy_hash):
                return {'username': 'api_user', 'role': 'admin'}
            legacy_token = settings.get('api_bearer_token')
            if legacy_token and secrets.compare_digest(token, legacy_token):
                return {'username': 'api_user', 'role': 'admin'}

            # 2. Check scoped API keys
            now = utc_now().isoformat()
            api_keys = settings.get('api_keys', {})
            for key_id, key_data in api_keys.items():
                if key_data.get('revoked'):
                    continue
                exp = key_data.get('expires_at')
                if exp and exp < now:
                    continue
                if self._verify_api_token(token, key_data.get('token_hash', '')):
                    # Update last_used_at via settings_manager.update so a
                    # concurrent admin creating a new API key on a parallel
                    # request can't be silently overwritten by our stale
                    # in-memory api_keys snapshot. Best-effort: failure
                    # must NOT block authentication.
                    matched_id = key_id
                    # Debounce: persist last_used_at at most once per
                    # CERTMATE_LAST_USED_PERSIST_SECONDS per key instead of on
                    # every authenticated request (each write rewrote the whole
                    # settings.json under the global lock).
                    if self._should_persist_last_used(matched_id):
                        def _touch(s):
                            keys = s.get('api_keys') or {}
                            target = keys.get(matched_id)
                            if target is not None:
                                target['last_used_at'] = now
                                s['api_keys'] = keys
                        try:
                            self.settings_manager.update(_touch, None)
                        except Exception:
                            pass  # Non-critical, don't fail auth on last_used update
                    return {
                        'username': 'api_key:' + key_data.get('name', key_id),
                        'role': self._normalize_role(key_data.get('role', 'viewer')),
                        'allowed_domains': key_data.get('allowed_domains'),
                        'api_key_id': key_id,
                        # Stable, non-secret identifiers for audit attribution.
                        'token_prefix': key_data.get('token_prefix'),
                        'is_agent': bool(key_data.get('is_agent')),
                    }

            return None
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Error authenticating API token: {e}")
            return None

    def create_user(self, username, password, role='operator', email=None):
        """Create a new user"""
        try:
            users = self._get_users()

            if username in users:
                return False, "User already exists"

            normalized = self._normalize_role(role)
            users[username] = {
                'password_hash': self._hash_password(password),
                'role': normalized,
                'email': email,
                'created_at': utc_now().isoformat(),
                'last_login': None,
                'enabled': True
            }
            
            if self._save_users(users):
                logger.info(f"User '{username}' created successfully")
                return True, "User created successfully"
            return False, "Failed to save user"
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Error creating user: {e}")
            return False, "An internal error occurred"
    
    def update_user(self, username, password=None, role=None, email=None, enabled=None):
        """Update an existing user"""
        try:
            users = self._get_users()
            
            if username not in users:
                return False, "User not found"

            user = users[username]
            original_role = self._normalize_role(user.get('role', 'operator'))

            # SSO-managed accounts authenticate against the IdP and carry an
            # empty password_hash on purpose. Refuse to set a local password so
            # the row can never silently fall back to password login.
            if password and user.get('oidc_subject'):
                return False, "Cannot set a password for an SSO-managed user"

            # Never let the last *active* admin be disabled — that would lock
            # everyone out of admin-gated endpoints. delete_user carries the
            # parallel guard for removal.
            if enabled is False and user.get('role') == 'admin':
                active_admins = sum(
                    1 for u in users.values()
                    if u.get('role') == 'admin' and u.get('enabled', True)
                )
                if active_admins <= 1:
                    return False, "Cannot disable the last active admin user"

            # Demoting the last active admin out of the admin role is the same
            # lockout in a different shape, so it carries the same guard as the
            # disable/delete paths above.
            if role is not None and user.get('role') == 'admin' and self._normalize_role(role) != 'admin':
                active_admins = sum(
                    1 for u in users.values()
                    if u.get('role') == 'admin' and u.get('enabled', True)
                )
                if active_admins <= 1:
                    return False, "Cannot change the role of the last active admin user"

            if password:
                user['password_hash'] = self._hash_password(password)
            if role is not None:
                user['role'] = self._normalize_role(role)
            if email is not None:
                user['email'] = email
            if enabled is not None:
                user['enabled'] = enabled
            
            if self._save_users(users):
                logger.info(f"User '{username}' updated successfully")
                # A privilege change must not be outlived by a live session:
                # disabling the account or changing its role revokes any
                # in-memory sessions so the change takes effect immediately —
                # the user re-authenticates under the new role, or is blocked.
                role_changed = role is not None and self._normalize_role(role) != original_role
                if enabled is False or role_changed:
                    self._invalidate_sessions_for_user(username)
                return True, "User updated successfully"
            return False, "Failed to save user"
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Error updating user: {e}")
            return False, "An internal error occurred"
    
    def delete_user(self, username):
        """Delete a user"""
        try:
            users = self._get_users()
            
            if username not in users:
                return False, "User not found"
            
            # Prevent deleting the last admin
            # Count ALL admins (enabled or not) to prevent locking out by disabling the last one
            admin_count = sum(1 for u in users.values() if u.get('role') == 'admin')
            if users[username].get('role') == 'admin' and admin_count <= 1:
                return False, "Cannot delete the last admin user"
            
            del users[username]
            
            if self._save_users(users):
                logger.info(f"User '{username}' deleted successfully")
                # Kill any live sessions so a deleted account can't keep acting.
                self._invalidate_sessions_for_user(username)
                return True, "User deleted successfully"
            return False, "Failed to delete user"
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Error deleting user: {e}")
            return False, "An internal error occurred"
    
    def list_users(self):
        """List all users (without password hashes).

        ``sso`` flags rows linked to an external IdP (presence of an
        ``oidc_subject``); the UI uses it to badge the account and hide the
        local-password reset action. ``oidc_issuer`` is surfaced for display
        only — never the subject claim.
        """
        users = self._get_users()
        return {
            username: {
                'role': self._normalize_role(data.get('role', 'operator')),
                'email': data.get('email'),
                'created_at': data.get('created_at'),
                'last_login': data.get('last_login'),
                'enabled': data.get('enabled', True),
                'sso': bool(data.get('oidc_subject')),
                'oidc_issuer': data.get('oidc_issuer'),
            }
            for username, data in users.items()
        }
    
    def authenticate_user(self, username, password):
        """Authenticate user with username and password"""
        try:
            users = self._get_users()
            
            if username not in users:
                logger.warning(f"Login attempt for non-existent user: {username}")
                return None
            
            user = users[username]
            
            if not user.get('enabled', True):
                logger.warning(f"Login attempt for disabled user: {username}")
                return None
            
            if self._verify_password(password, user.get('password_hash', '')):
                # Update last login
                user['last_login'] = utc_now().isoformat()
                self._save_users(users)
                
                logger.info(f"User '{username}' authenticated successfully")
                return {
                    'username': username,
                    'role': self._normalize_role(user.get('role', 'operator')),
                    'email': user.get('email')
                }
            
            logger.warning(f"Failed login attempt for user: {username}")
            return None
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Error authenticating user: {e}")
            return None
    
    def create_session(self, username, source='local'):
        """Create a new session for authenticated user.

        ``source`` tags the identity origin (``'local'`` for the username/
        password form, ``'oidc'`` when the session was minted by the OIDC
        callback). Role checks are unchanged — this is metadata only —
        but `api_logout` consults it to decide whether to surface an IdP
        end-session URL.
        """
        session_id = secrets.token_urlsafe(32)
        users = self._get_users()
        user = users.get(username, {})

        with self._session_lock:
            self._sessions[session_id] = {
                'user': username,
                'role': self._normalize_role(user.get('role', 'operator')),
                'source': source,
                'created': time.time(),
                'expires': time.time() + self._session_timeout
            }
            # Cleanup expired sessions occasionally
            self._cleanup_sessions()

        return session_id

    def validate_session(self, session_id):
        """Validate a session and return user info if valid"""
        with self._session_lock:
            if not session_id or session_id not in self._sessions:
                return None

            session_data = self._sessions[session_id]

            if time.time() > session_data['expires']:
                del self._sessions[session_id]
                return None

            return {
                'username': session_data['user'],
                'role': self._normalize_role(session_data['role']),
                'source': session_data.get('source', 'local'),
            }

    def invalidate_session(self, session_id):
        """Invalidate/logout a session"""
        with self._session_lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def _invalidate_sessions_for_user(self, username):
        """Drop every in-memory session belonging to ``username``.

        Called when a user is disabled, demoted, or deleted so a live session
        cannot outlive the privilege change. The role is otherwise snapshotted
        into the session at login (see ``create_session``) and stays valid
        until ``SESSION_TIMEOUT_HOURS``, which would leave a just-disabled /
        just-demoted / deleted account fully privileged for up to the session
        lifetime. Returns the number of sessions dropped.
        """
        with self._session_lock:
            stale = [sid for sid, data in self._sessions.items()
                     if data.get('user') == username]
            for sid in stale:
                del self._sessions[sid]
        if stale:
            logger.info(f"Invalidated {len(stale)} active session(s) for user '{username}'")
        return len(stale)

    def _cleanup_sessions(self):
        """Remove expired sessions (caller must hold _session_lock)"""
        current_time = time.time()
        expired = [sid for sid, data in self._sessions.items() if current_time > data['expires']]
        for sid in expired:
            del self._sessions[sid]
    
    def is_local_auth_enabled(self):
        """Check if local authentication is enabled"""
        settings = self.settings_manager.load_settings()
        return settings.get('local_auth_enabled', False)
    
    def enable_local_auth(self, enable=True):
        """Enable or disable local authentication (atomic)."""
        def _mutate(settings):
            settings['local_auth_enabled'] = enable
        return self.settings_manager.update(_mutate, "auth_config")
    
    def has_any_users(self):
        """Check if any users exist"""
        return len(self._get_users()) > 0

    @staticmethod
    def _detect_operator_bearer_token():
        """Return True iff the operator explicitly provided a *valid* API
        bearer token via API_BEARER_TOKEN_FILE or API_BEARER_TOKEN.

        settings.json ALWAYS carries an api_bearer_token (an auto-generated
        random one when the operator supplied none — see
        _bearer_token_from_env_or_generate), so the mere presence of a stored
        token is NOT a usable signal: enforcing the auto-generated one would
        lock a fresh install out (the operator never sees it). The env/file the
        operator set is the signal that they configured auth and know the
        token."""
        from .utils import validate_api_token
        token_file = os.getenv('API_BEARER_TOKEN_FILE')
        if token_file:
            try:
                from pathlib import Path
                token = Path(token_file).read_text().strip()
            except Exception:
                return False
            return bool(token) and validate_api_token(token)[0]
        env_token = os.getenv('API_BEARER_TOKEN')
        if env_token:
            return validate_api_token(env_token)[0]
        return False

    def has_operator_bearer_token(self):
        """Memoised wrapper over _detect_operator_bearer_token (env/file are
        fixed for the process lifetime)."""
        cached = getattr(self, '_operator_bearer_token', _UNSET)
        if cached is _UNSET:
            cached = self._detect_operator_bearer_token()
            self._operator_bearer_token = cached
        return cached

    def _is_oidc_configured(self):
        """True iff the operator fully configured OIDC (enabled + issuer_url +
        client_id). That is an operator-controlled credential exactly like
        API_BEARER_TOKEN or local-auth-plus-a-user, so it must turn setup mode
        OFF. Otherwise an SSO-only deployment (no bearer token, local auth left
        disabled) stays in setup mode forever and serves every gated endpoint
        to anonymous callers as admin — local_auth_enabled defaults False and
        OIDC JIT provisioning never flips it, so the local-auth branch below
        can never become True on such a box. Mirrors OIDCManager.is_enabled()
        without importing it (settings is the single source of truth)."""
        try:
            cfg = self.settings_manager.load_settings().get('oidc', {}) or {}
        except (OSError, ValueError, KeyError, AttributeError):
            return False
        return bool(cfg.get('enabled') and cfg.get('issuer_url') and cfg.get('client_id'))

    def is_setup_mode(self):
        """True on a genuinely unconfigured instance, where unauthenticated
        access is allowed so the operator can bootstrap (reach the UI, create
        the first admin, enable local auth).

        Becomes False as soon as ANY credential the operator controls exists:
          * local auth is enabled AND at least one user exists, OR
          * the operator provided an API bearer token (API_BEARER_TOKEN[_FILE]), OR
          * OIDC is fully configured (enabled + issuer_url + client_id).

        Once False, every gated surface requires a real credential. This closes
        the gap where an operator configured auth — API_BEARER_TOKEN, or an
        OIDC/SSO-only deployment — but the instance stayed world-open because
        local auth was never enabled. A fresh install with no operator-provided
        credential is unchanged: it stays in setup mode so onboarding works."""
        if self.has_operator_bearer_token():
            return False
        if self._is_oidc_configured():
            return False
        return not (self.is_local_auth_enabled() and self.has_any_users())

    def needs_credentialed_bootstrap(self):
        """RESTRICTED (never world-open) bootstrap signal for the web UI only.

        True iff the operator configured an API bearer token but local auth is
        not yet provisioned — local auth is disabled, or no admin user exists
        yet (the predicate returns False only once BOTH hold). In this state
        ``is_setup_mode()`` is ALREADY False, so ``_authenticate_request()``
        still demands the bearer token on every gated surface — this predicate
        does NOT grant access and is deliberately kept out of the auth gate. It
        only tells the UI to render the create-admin form instead of a
        dead-end login page (local auth is off, so ``/api/auth/login`` 403s).
        The form authenticates its two bootstrap POSTs with the operator's
        bearer token, so creating the first admin requires proof-of-possession
        of the token the operator configured — nothing is granted for free.

        Returns False on a fresh no-token install (``has_operator_bearer_token``
        is False there), keeping it disjoint from genuine setup mode and from
        OIDC-only deployments. See issue #397."""
        if self.is_local_auth_enabled() and self.has_any_users():
            return False
        # OIDC-capable boxes bootstrap their first user through SSO (JIT
        # provisioning), not this local-admin form. Mirror is_setup_mode()'s
        # OIDC branch so the SSO login page stays reachable instead of being
        # hidden behind the create-admin form on an OIDC+bearer deployment.
        if self._is_oidc_configured():
            return False
        return self.has_operator_bearer_token()
    
    def _authenticate_request(self):
        """Resolve the caller's identity for the current Flask request.

        Single source of truth for authentication. Both ``require_auth`` and
        ``require_role`` delegate here instead of chaining decorators or
        relying on cross-decorator side effects on ``request.current_user``
        (the previous implementation called ``self.require_auth(lambda:
        None)()`` to populate the request, then read the side-effect — an
        architecture flagged as fragile by the 2026-05-12 API auth audit
        finding F-1).

        Returns:
            (user_dict, None)            on success
            (None, (error_dict, status)) on failure

        Side effects: none. The caller is responsible for assigning
        ``request.current_user`` once it knows the request is allowed to
        proceed. That keeps the side effect localized to the decorator that
        owns it, instead of leaking across two helpers.
        """
        try:
            # Allow unauthenticated access ONLY during genuine initial setup.
            # is_setup_mode() is False as soon as the operator configures a
            # credential (local auth + a user, OR an API bearer token), so a
            # configured bearer token is always enforced here.
            if self.is_setup_mode():
                return {'username': 'setup_user', 'role': 'admin'}, None

            # Check for session-based auth first (for web UI)
            session_id = request.cookies.get('certmate_session')
            if session_id:
                user_info = self.validate_session(session_id)
                if user_info:
                    return user_info, None

            # Fall back to bearer token auth (for API)
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return None, ({'error': 'Authorization header required',
                               'code': 'AUTH_HEADER_MISSING'}, 401)

            try:
                scheme, token = auth_header.split(' ', 1)
                if scheme.lower() != 'bearer':
                    return None, ({'error': 'Invalid authorization scheme. Use Bearer token',
                                   'code': 'INVALID_AUTH_SCHEME'}, 401)
                if not token.strip():
                    return None, ({'error': 'Invalid authorization header format. Use: Bearer <token>',
                                   'code': 'INVALID_AUTH_FORMAT'}, 401)
            except ValueError:
                return None, ({'error': 'Invalid authorization header format. Use: Bearer <token>',
                               'code': 'INVALID_AUTH_FORMAT'}, 401)

            # Authenticate against legacy token and scoped API keys
            user_info = self.authenticate_api_token(token)
            if not user_info:
                logger.warning(f"Invalid API token attempt from {request.remote_addr}")
                return None, ({'error': 'Invalid or expired token',
                               'code': 'INVALID_TOKEN'}, 401)

            return user_info, None
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None, ({'error': 'Authentication failed',
                           'code': 'AUTH_ERROR'}, 401)

    def _is_browser_html_request(self):
        """True when the current request looks like a browser asking for HTML.

        Used by the auth decorators to decide between a 302 to /login
        (browser, friendly) and the API-style JSON 401 (curl, fetch).
        Two conditions both have to hold so a browser POST to /api/...
        isn't redirected away from its JSON error path:

          - request.path does NOT live under /api/  -- our API surface
            lives under /api/ and always wants JSON responses
          - request.accept_mimetypes prefers text/html over JSON --
            browsers send `Accept: text/html,application/xhtml+xml,...`,
            fetch() and curl typically send `Accept: */*` or JSON
        """
        try:
            if request.path.startswith('/api/'):
                return False
            accept = request.accept_mimetypes
            # best_match returns text/html when the browser-style Accept
            # ranks it above application/json; for `Accept: */*` from
            # curl, html wins by alphabetical tiebreak, which is fine —
            # curl users typically hit /api/ paths anyway.
            best = accept.best_match(['text/html', 'application/json'])
            return best == 'text/html'
        except Exception:
            return False

    def require_auth(self, f):
        """Decorator: require authentication (API token or session)."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user, err = self._authenticate_request()
            if err is not None:
                # Same browser-vs-API split as require_role — keep the
                # two decorators behaviourally consistent so a route
                # author doesn't have to remember which one redirects.
                if self._is_browser_html_request():
                    from flask import redirect, url_for
                    return redirect(url_for('login_page', next=request.path))
                return err
            request.current_user = user
            return f(*args, **kwargs)
        return decorated_function

    def require_role(self, min_role):
        """Decorator factory requiring a minimum role level.

        Usage::

            @auth_manager.require_role('operator')
            def create_cert(): ...
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                user, err = self._authenticate_request()
                if err is not None:
                    # When a browser hits an HTML page route without a
                    # session, return a 302 to /login?next=<path> instead
                    # of the API-style 401 JSON. Without this the user
                    # sees a bare {"code":"AUTH_HEADER_MISSING",…} body
                    # in the browser tab — disorienting because the
                    # adjacent dashboard route (`/`) already redirects
                    # cleanly via its hand-rolled flow. /api/ paths and
                    # non-HTML clients keep getting the JSON response.
                    if self._is_browser_html_request():
                        from flask import redirect, url_for
                        return redirect(url_for('login_page', next=request.path))
                    return err

                # current_user is set here only after auth is known to
                # have succeeded; downstream code that reads it can trust
                # the value is fresh from this request, not a leftover.
                request.current_user = user

                user_level = ROLE_HIERARCHY.get(user.get('role'), -1)
                required_level = ROLE_HIERARCHY.get(min_role, 999)
                if user_level < required_level:
                    # Audit + log every role denial so privilege-enumeration
                    # attempts surface in the audit trail instead of vanishing
                    # behind a silent 403 (2026-05-12 API auth audit, F-2).
                    self._log_rbac_denial(
                        user=user,
                        required_role=min_role,
                        endpoint=request.path,
                    )
                    # A browser navigating to a role-gated HTML page (e.g. an
                    # operator opening /settings) should land on a styled page
                    # inside the app chrome — with the nav still present so they
                    # can move to a tab they can use — instead of a bare JSON
                    # body they can only escape with the back button (#256).
                    # /api/ paths and non-HTML clients keep the machine-readable
                    # 403 so programmatic callers are unaffected.
                    if self._is_browser_html_request():
                        from flask import render_template
                        return render_template(
                            '403.html',
                            required_role=min_role,
                            current_role=user.get('role'),
                        ), 403
                    return {'error': f'{min_role} privileges required',
                            'code': 'INSUFFICIENT_ROLE'}, 403

                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def _log_rbac_denial(self, user, required_role, endpoint):
        """Record an RBAC role-level denial.

        Always emits a structured warning on the application logger so the
        signal is present even when no AuditLogger is wired. When one IS
        wired (the production path), also writes a structured audit
        entry via log_authz_denied so the denial sits in the same log
        admins already scan.
        """
        username = (user or {}).get('username')
        actual_role = (user or {}).get('role')
        try:
            from flask import request as _request
            ip = _request.remote_addr
        except Exception:
            ip = None

        logger.warning(
            "RBAC denial: user=%s role=%s required=%s endpoint=%s ip=%s",
            username, actual_role, required_role, endpoint, ip,
        )

        if self._audit_logger is not None:
            try:
                self._audit_logger.log_authz_denied(
                    operation='access',
                    resource_type='endpoint',
                    resource_id=endpoint,
                    reason=f'role={actual_role} below required {required_role}',
                    user=username,
                    ip_address=ip,
                )
            except Exception as e:
                logger.debug(f"Failed to write RBAC denial audit entry: {e}")

    def require_admin(self, f):
        """Decorator to require admin role (backward compat wrapper)."""
        return self.require_role('admin')(f)

    def validate_api_token(self, token):
        """Validate API token against legacy token and scoped keys."""
        return self.authenticate_api_token(token) is not None

    def get_current_token(self):
        """Get the current API bearer token from settings"""
        try:
            settings = self.settings_manager.load_settings()
            return settings.get('api_bearer_token')
        except Exception as e:
            logger.error(f"Error getting current token: {e}")
            return None
