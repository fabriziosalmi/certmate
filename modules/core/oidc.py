"""OIDC/SSO identity source for CertMate.

Implements an additive identity source that coexists with local auth and
scoped API keys. See ``modules/core/auth.py`` for the rest of the auth
surface — every successful OIDC callback ends in
``AuthManager.create_session(..., source='oidc')``, so downstream
decorators (``@require_auth``, ``@require_role``) treat OIDC sessions
identically to local ones. The only behavioural difference is that
``api_logout`` reads ``source`` to decide whether to return an IdP
end-session URL.

Design notes:
- Authorization Code + PKCE only. PKCE is forced on for both confidential
  and public clients.
- Discovery via ``.well-known/openid-configuration``; Authlib handles
  JWKS rotation, signature/audience/issuer/expiry/nonce verification.
- ``state``, ``nonce``, ``code_verifier`` and the post-login ``next`` URL
  are stashed in ``flask.session`` (server-side cookie signed by
  ``app.secret_key``). Authlib reads them back during
  ``authorize_access_token``.
- JIT provisioning: any successfully-authenticated IdP user gets a row
  in ``settings['users']`` with ``password_hash=''`` so the local login
  path refuses them outright. Identity is keyed by ``(oidc_issuer,
  oidc_subject)``; email is a fallback link for migrating local accounts
  to SSO.
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlparse, urlencode

from flask import session as flask_session

from .settings import _strip_masked_values
from .utils import utc_now

logger = logging.getLogger(__name__)


SECRET_MASK_SENTINEL = '********'

VALID_ROLES = ('admin', 'operator', 'viewer')

# Default scopes match what most IdPs need to populate the username,
# email and role claims. ``groups`` is widely supported (Keycloak,
# Authentik, Okta) but is silently dropped by providers that don't
# implement it — that's fine, the role-mapping path just won't match.
DEFAULT_SCOPES = ['openid', 'email', 'profile', 'groups']


def _normalize_oidc_config(raw: dict) -> dict:
    """Return a fully-populated OIDC config dict.

    Settings written by an older version may not carry every field;
    fill in defaults so the rest of the code can assume the shape.
    """
    cfg = dict(raw or {})
    cfg.setdefault('enabled', False)
    cfg.setdefault('provider_name', 'SSO')
    cfg.setdefault('issuer_url', '')
    cfg.setdefault('client_id', '')
    cfg.setdefault('client_secret', '')
    scopes = cfg.get('scopes')
    if not isinstance(scopes, list) or not scopes:
        cfg['scopes'] = list(DEFAULT_SCOPES)
    cfg.setdefault('redirect_uri_override', '')
    cfg.setdefault('username_claim', 'preferred_username')
    cfg.setdefault('email_claim', 'email')
    cfg.setdefault('role_claim', 'groups')
    mappings = cfg.get('role_mappings')
    cfg['role_mappings'] = mappings if isinstance(mappings, list) else []
    if cfg.get('default_role') not in VALID_ROLES:
        cfg['default_role'] = 'viewer'
    cfg.setdefault('auto_create_users', True)
    cfg.setdefault('link_by_email', True)
    # Re-derive the role from the IdP claims on EVERY login, not just at JIT
    # provisioning (#408): otherwise removing someone from an admin group in
    # the IdP never demotes them here. Flip off when roles are managed inside
    # CertMate and the IdP only authenticates.
    cfg.setdefault('sync_role_on_login', True)
    # Refuse to link an IdP identity onto an existing local user unless
    # the IdP attests that the user controls the email. Defaults to True
    # because the alternative is an account-takeover vector on any IdP
    # with self-service signup: an attacker registers
    # ``admin@target.com`` (unverified), waits for the JIT/link to fire,
    # and inherits the local admin role. Operators who trust their IdP
    # to verify email ownership server-side can flip this off.
    cfg.setdefault('require_verified_email', True)
    cfg.setdefault('post_logout_redirect_uri', '')
    return cfg


class OIDCConfigError(ValueError):
    """Raised when a settings payload fails validation."""


class OIDCManager:
    """Configuration + Authlib client + identity resolution for OIDC.

    Construction is cheap (no network). Authlib's discovery fetch happens
    lazily inside ``_build_oauth_client`` on first login attempt, after
    which the client is cached for the process lifetime. Disabling and
    re-enabling OIDC via the settings UI invalidates the cache so the
    next login pulls the new issuer's metadata.
    """

    # Stable Flask-session key prefixes for the values Authlib needs to
    # validate the callback. Authlib itself manages most of them under
    # ``_state_<client>_<state>`` internally; we only keep ``next`` here.
    _SESSION_NEXT_KEY = '_oidc_next'
    # id_token retained past the callback so build_end_session_url can
    # emit it as ``id_token_hint`` — Keycloak/Okta/Authentik treat the
    # hint as effectively required for RP-initiated logout.
    _SESSION_ID_TOKEN_KEY = '_oidc_id_token'

    def __init__(self, settings_manager, auth_manager, audit_logger=None):
        self.settings_manager = settings_manager
        self.auth_manager = auth_manager
        self._audit_logger = audit_logger
        self._oauth = None  # cached OAuth registry (Authlib)
        self._cached_issuer = None  # invalidate cache if issuer changes

    # ----------------------------------------------------------------- config

    def set_audit_logger(self, audit_logger):
        """Inject the AuditLogger after AuthManager is constructed."""
        self._audit_logger = audit_logger

    def _load_config(self) -> dict:
        settings = self.settings_manager.load_settings()
        return _normalize_oidc_config(settings.get('oidc', {}))

    def is_enabled(self) -> bool:
        cfg = self._load_config()
        return bool(cfg['enabled'] and cfg['issuer_url'] and cfg['client_id'])

    def get_public_config(self) -> dict:
        """Pre-login config visible to anonymous callers.

        Surfaces only the affordances the UI needs to render the SSO
        button. Secrets, claim names and role mappings stay private.
        """
        cfg = self._load_config()
        return {
            'enabled': self.is_enabled(),
            'provider_name': cfg.get('provider_name') or 'SSO',
            'login_url': '/api/auth/oidc/login',
            'post_logout_redirect_uri': cfg.get('post_logout_redirect_uri') or '',
        }

    def get_admin_config(self) -> dict:
        """Full config for the admin UI. ``client_secret`` is masked so a
        GET-then-POST round-trip preserves the on-disk value."""
        cfg = self._load_config()
        if cfg.get('client_secret'):
            cfg['client_secret'] = SECRET_MASK_SENTINEL
        return cfg

    def update_config(self, payload: dict) -> tuple[bool, Optional[str]]:
        """Validate and atomically persist a new OIDC config block.

        Returns ``(ok, error_message)``. On validation error, returns
        ``(False, str)`` and nothing is written. ``'********'`` sentinels
        in the payload are stripped first so the UI's GET→edit→POST
        round-trip is a no-op for the masked ``client_secret`` field.
        """
        if not isinstance(payload, dict):
            return False, 'payload must be an object'

        # Strip masked sentinels recursively (covers client_secret).
        cleaned_payload = _strip_masked_values(payload)
        if not isinstance(cleaned_payload, dict):
            return False, 'payload must be an object'

        # Merge on top of the existing config so partial updates (e.g.
        # toggling `enabled`) don't blow away unrelated fields.
        existing = self._load_config()
        merged = {**existing, **cleaned_payload}

        try:
            self._validate_config(merged)
        except OIDCConfigError as exc:
            return False, str(exc)

        normalized = _normalize_oidc_config(merged)

        # Drop the cached OAuth client — if issuer/client_id changed, the
        # next login must rediscover.
        if normalized.get('issuer_url') != self._cached_issuer:
            self._oauth = None
            self._cached_issuer = None

        def _mutate(settings):
            settings['oidc'] = normalized

        ok = self.settings_manager.update(_mutate, 'oidc_config')
        if not ok:
            return False, 'failed to persist OIDC settings'
        return True, None

    @staticmethod
    def _validate_config(cfg: dict) -> None:
        enabled = bool(cfg.get('enabled'))
        if enabled:
            issuer = (cfg.get('issuer_url') or '').strip()
            client_id = (cfg.get('client_id') or '').strip()
            if not issuer:
                raise OIDCConfigError('issuer_url is required when OIDC is enabled')
            parsed = urlparse(issuer)
            if parsed.scheme not in ('https', 'http') or not parsed.netloc:
                raise OIDCConfigError('issuer_url must be a valid http(s) URL')
            if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1'):
                raise OIDCConfigError('issuer_url must use https (except localhost)')
            if not client_id:
                raise OIDCConfigError('client_id is required when OIDC is enabled')

        default_role = cfg.get('default_role', 'viewer')
        if default_role not in VALID_ROLES:
            raise OIDCConfigError(f'default_role must be one of {VALID_ROLES}')

        scopes = cfg.get('scopes', DEFAULT_SCOPES)
        if not isinstance(scopes, list) or not all(isinstance(s, str) and s for s in scopes):
            raise OIDCConfigError('scopes must be a list of non-empty strings')
        if 'openid' not in scopes:
            raise OIDCConfigError("scopes must include 'openid'")

        mappings = cfg.get('role_mappings', [])
        if not isinstance(mappings, list):
            raise OIDCConfigError('role_mappings must be a list')
        for idx, m in enumerate(mappings):
            if not isinstance(m, dict):
                raise OIDCConfigError(f'role_mappings[{idx}] must be an object')
            claim_value = m.get('claim_value')
            role = m.get('role')
            if not isinstance(claim_value, str) or not claim_value:
                raise OIDCConfigError(f'role_mappings[{idx}].claim_value must be a non-empty string')
            if role not in VALID_ROLES:
                raise OIDCConfigError(f'role_mappings[{idx}].role must be one of {VALID_ROLES}')

    # ----------------------------------------------------------- Authlib glue

    def _build_oauth_client(self, app):
        """Return a cached Authlib client bound to ``app``.

        Lazy because Authlib's ``server_metadata_url`` fetch hits the
        IdP's discovery doc — we don't want that on every Flask boot,
        only on the first login attempt after the config changes.
        """
        cfg = self._load_config()
        if not (cfg['enabled'] and cfg['issuer_url'] and cfg['client_id']):
            raise RuntimeError('OIDC is not enabled or fully configured')

        if self._oauth is not None and self._cached_issuer == cfg['issuer_url']:
            return self._oauth

        # Lazy import so units tests that don't exercise the flow don't
        # require Authlib to be installed.
        from authlib.integrations.flask_client import OAuth

        oauth = OAuth(app)
        issuer = cfg['issuer_url'].rstrip('/')
        # Authlib accepts either ``server_metadata_url`` (preferred — full
        # discovery doc) or individual endpoint URLs. Always use
        # discovery for JWKS rotation support.
        oauth.register(
            name='certmate_oidc',
            client_id=cfg['client_id'],
            client_secret=cfg['client_secret'] or None,
            server_metadata_url=f"{issuer}/.well-known/openid-configuration",
            client_kwargs={
                'scope': ' '.join(cfg['scopes']),
                # Force PKCE S256 challenge regardless of client type.
                'code_challenge_method': 'S256',
            },
        )
        self._oauth = oauth
        self._cached_issuer = cfg['issuer_url']
        return oauth

    def _client(self, app):
        """Shortcut for the registered OAuth client instance."""
        return self._build_oauth_client(app).certmate_oidc

    def _resolve_redirect_uri(self, request) -> str:
        cfg = self._load_config()
        override = (cfg.get('redirect_uri_override') or '').strip()
        if override:
            return override
        # url_for would require an active app context with the route
        # registered; building from the request preserves scheme/host
        # behind a reverse proxy when ProxyFix is enabled.
        return request.url_root.rstrip('/') + '/api/auth/oidc/callback'

    def start_login(self, request, next_url: Optional[str] = None):
        """Begin the Authorization Code + PKCE flow.

        Returns the Flask ``Response`` that 302-redirects to the IdP's
        authorize endpoint. ``next_url`` (post-login redirect target,
        same-origin only — caller is responsible for validating that)
        is stashed in the Flask session.
        """
        from flask import current_app
        client = self._client(current_app)
        flask_session[self._SESSION_NEXT_KEY] = next_url or '/'
        return client.authorize_redirect(self._resolve_redirect_uri(request))

    def handle_callback(self, request) -> tuple[Optional[dict], Optional[str]]:
        """Exchange the authorization code for tokens and return claims.

        Authlib validates the id_token's signature, audience, issuer,
        expiry and nonce during ``authorize_access_token`` — so a
        success return here means cryptographic validation already
        passed. Returns ``(claims_dict, None)`` on success or
        ``(None, error_code)`` on failure.
        """
        from flask import current_app
        try:
            client = self._client(current_app)
            token = client.authorize_access_token()
        except Exception as exc:
            logger.warning(f"OIDC token exchange failed: {exc}")
            return None, 'token_exchange'

        # Retain the raw id_token past this request so
        # ``build_end_session_url`` can emit it as ``id_token_hint`` at
        # logout time. Several major IdPs (Keycloak/Okta/Authentik)
        # silently no-op the end-session call without it.
        id_token = token.get('id_token') if isinstance(token, dict) else None
        if id_token:
            try:
                flask_session[self._SESSION_ID_TOKEN_KEY] = id_token
            except Exception:
                logger.debug("OIDC id_token stash skipped (session unavailable)")

        # userinfo() is optional — some IdPs return all claims in the
        # id_token. Merge both so role/email/username claims can come
        # from either side.
        claims = dict(token.get('userinfo') or {})
        try:
            userinfo = client.userinfo(token=token)
            if isinstance(userinfo, dict):
                # id_token claims win over userinfo on conflict because
                # the id_token is cryptographically validated.
                merged = dict(userinfo)
                merged.update(claims)
                claims = merged
        except Exception as exc:
            # Non-fatal: many IdPs require an extra scope for the
            # userinfo endpoint; if id_token already has everything we
            # need, that's enough.
            logger.debug(f"OIDC userinfo fetch skipped: {exc}")

        if not claims:
            return None, 'no_claims'
        return claims, None

    def consume_next_url(self) -> str:
        """Pop the post-login redirect from the Flask session."""
        try:
            value = flask_session.pop(self._SESSION_NEXT_KEY, None)
        except RuntimeError:
            value = None
        if not value or not isinstance(value, str):
            return '/'
        # Same-origin guard: only allow absolute paths (caller already
        # validated, but defense-in-depth).
        if not value.startswith('/') or value.startswith('//'):
            return '/'
        return value

    # ------------------------------------------------- identity resolution

    def resolve_or_provision_user(self, claims: dict) -> tuple[Optional[str], Optional[str]]:
        """Map IdP claims to a CertMate ``users`` row.

        Returns ``(username, error_code)``. ``username`` is the key into
        ``settings['users']``; the caller passes it to
        ``auth_manager.create_session(..., source='oidc')``.

        Resolution order:
          1. Existing user with matching ``oidc_subject`` + ``oidc_issuer``
             → refused when the row is disabled (the same gate the local
             password path applies — otherwise disabling an SSO user is a
             no-op), otherwise reuse and refresh ``last_login``. The role
             is re-derived from the current claims unless
             ``sync_role_on_login`` is false: an IdP group change must be
             able to demote, and CertMate is not the source of truth for
             roles while SSO is on. Set ``sync_role_on_login: false`` to
             keep roles managed locally (an admin promoting someone by
             hand then survives the next login).
          2. ``link_by_email`` enabled AND existing local user with
             matching email → refused when that row is disabled, else link
             by writing ``oidc_subject`` + ``oidc_issuer`` onto the
             existing row, preserving their role.
             Gated on ``require_verified_email`` (default True): an IdP
             that does NOT attest ``email_verified=True`` for the
             authenticated subject cannot link onto an existing row.
             Without this, an attacker who can register
             ``admin@target.com`` on a self-service IdP would inherit the
             local admin role on first SSO login.
          3. ``auto_create_users`` enabled → JIT create with the role
             derived from the role_mappings (default_role on no match).
             ``password_hash=''`` so the local login path refuses them.
          4. Otherwise → ``(None, 'no_user')``.

        The whole read-modify-write happens inside
        ``settings_manager.update(mutator)`` so two concurrent first-time
        callbacks for distinct subjects cannot race the username
        uniqueness check or clobber one another's ``users`` row.
        """
        cfg = self._load_config()
        sub = claims.get('sub')
        iss = claims.get('iss') or cfg.get('issuer_url')
        if not sub:
            return None, 'missing_sub'

        username_claim = cfg.get('username_claim') or 'preferred_username'
        email_claim = cfg.get('email_claim') or 'email'
        username_value = claims.get(username_claim) or claims.get('preferred_username') \
            or claims.get('email') or sub
        email = claims.get(email_claim) or claims.get('email') or ''
        # OIDC Core §5.1 specifies ``email_verified`` as a boolean. Some
        # IdPs serialise it as the string "true"/"false"; accept either
        # but never coerce a missing claim to True.
        raw_verified = claims.get('email_verified')
        email_verified = (
            raw_verified is True
            or (isinstance(raw_verified, str) and raw_verified.lower() == 'true')
        )
        # `email_verified` (OIDC Core §5.1) attests the STANDARD `email` claim
        # only. When a custom `email_claim` is configured and its value differs
        # from the standard `email`, email_verified does NOT cover it — an IdP
        # that lets a user self-set the custom claim (e.g. `mail`) could present
        # a verified throwaway standard `email` while matching an admin's address
        # via the custom claim and inherit that row's role at the link seam.
        # Only treat the address used for the link as verified when it IS the
        # verified standard email.
        standard_email = claims.get('email') or ''
        email_is_verified = email_verified and bool(email) and email == standard_email
        role = self._map_role(claims, cfg)

        # Captured outcome — written by the mutator, read after update()
        # returns so audit logging (which can be slow) happens OUTSIDE
        # the settings lock.
        outcome: dict = {'username': None, 'error': None, 'audit': None}

        def _mutate(settings):
            users = settings.setdefault('users', {})

            # 1. Subject match — always allowed, no verified-email gate
            #    (the subject identity is the IdP's own attestation).
            existing_by_sub = self._find_by_subject(users, sub, iss)
            if existing_by_sub:
                username = existing_by_sub
                # An SSO row is still a CertMate user: honour the same
                # `enabled` gate the local-password path applies (auth.py).
                # Without this, disabling a user was a no-op against anyone
                # who logs in through the IdP — they simply logged back in
                # and got a fresh session with their old role (#408).
                if not users[username].get('enabled', True):
                    outcome['error'] = 'user_disabled'
                    outcome['audit'] = (
                        'oidc_login_refused', username, 'failure',
                        {'issuer': iss, 'reason': 'user disabled'},
                    )
                    return
                # Re-derive the role from the CURRENT claims on every login,
                # so removing someone from an admin group in the IdP actually
                # demotes them here. Opt out with sync_role_on_login=false
                # when roles are managed locally instead.
                if cfg.get('sync_role_on_login', True):
                    previous_role = users[username].get('role')
                    if role != previous_role:
                        users[username]['role'] = role
                        outcome['audit'] = (
                            'oidc_user_role_synced', username, 'success',
                            {'issuer': iss, 'from': previous_role, 'to': role},
                        )
                users[username]['last_login'] = utc_now().isoformat()
                outcome['username'] = username
                return

            # 2. Email link — only fires when an existing local user has
            #    the same email. The verified-email gate applies ONLY at
            #    that seam (writing ``oidc_subject`` onto an existing
            #    row would inherit that row's role). A missing match
            #    falls through to JIT, where there's no row to take over
            #    so the verification status is irrelevant for safety.
            if cfg.get('link_by_email') and email:
                existing_by_email = self._find_by_email(users, email)
                if existing_by_email:
                    if cfg.get('require_verified_email', True) and not email_is_verified:
                        outcome['error'] = 'email_not_verified'
                        outcome['audit'] = (
                            'oidc_user_link_refused',
                            existing_by_email,
                            'failure',
                            {'email': email, 'issuer': iss,
                             'reason': 'email not verified (email_verified missing/false, '
                                       'or a custom email_claim not covered by the standard '
                                       'email_verified claim)'},
                        )
                        return
                    username = existing_by_email
                    # Same gate as the subject-match branch: linking must not
                    # be a way back in for a disabled account (#408).
                    if not users[username].get('enabled', True):
                        outcome['error'] = 'user_disabled'
                        outcome['audit'] = (
                            'oidc_user_link_refused', username, 'failure',
                            {'email': email, 'issuer': iss, 'reason': 'user disabled'},
                        )
                        return
                    users[username]['oidc_subject'] = sub
                    users[username]['oidc_issuer'] = iss
                    users[username]['last_login'] = utc_now().isoformat()
                    outcome['username'] = username
                    outcome['audit'] = (
                        'oidc_user_linked', username, 'success',
                        {'email': email, 'issuer': iss},
                    )
                    return

            # 3. JIT.
            if not cfg.get('auto_create_users', True):
                outcome['error'] = 'provisioning_disabled'
                return

            username = self._unique_username(users, username_value)
            users[username] = {
                'password_hash': '',  # blocks local password login on this row
                'role': role,
                'email': email,
                'created_at': utc_now().isoformat(),
                'last_login': utc_now().isoformat(),
                'enabled': True,
                'oidc_subject': sub,
                'oidc_issuer': iss,
            }
            outcome['username'] = username
            outcome['audit'] = (
                'oidc_user_provisioned', username, 'success',
                {'email': email, 'issuer': iss, 'role': role},
            )

        # update() runs the mutator under the settings RLock so two
        # concurrent first-time callbacks for distinct subjects observe
        # each other's writes via the freshly-loaded users dict.
        self.settings_manager.update(_mutate, reason='oidc_resolve_or_provision')

        if outcome['audit']:
            op, who, status, details = outcome['audit']
            self._audit(op, who, status=status, details=details)

        return outcome['username'], outcome['error']

    def _map_role(self, claims: dict, cfg: dict) -> str:
        """Apply the configured role_mappings against the chosen claim.

        First match wins (in mapping order). Comparison is case-insensitive:
        AD ships uppercase (``Domain Admins``), Authentik capitalises
        (``Admin``), Keycloak follows whatever the realm operator typed —
        admins should be able to configure ``eng-admins`` once and have it
        match every casing the IdP returns. The claim value may be a list
        (typical for ``groups``) or a scalar (typical for ``role``).
        """
        claim_name = cfg.get('role_claim') or 'groups'
        default_role = cfg.get('default_role', 'viewer')
        if default_role not in VALID_ROLES:
            default_role = 'viewer'

        raw_value = claims.get(claim_name)
        if raw_value is None:
            return default_role
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        values_lower = {str(v).lower() for v in values}

        for mapping in cfg.get('role_mappings', []):
            cv = mapping.get('claim_value')
            role = mapping.get('role')
            if (isinstance(cv, str) and cv.lower() in values_lower
                    and role in VALID_ROLES):
                return role
        return default_role

    @staticmethod
    def _find_by_subject(users: dict, sub: str, iss: str) -> Optional[str]:
        for username, data in users.items():
            if data.get('oidc_subject') == sub and data.get('oidc_issuer') == iss:
                return username
        return None

    @staticmethod
    def _find_by_email(users: dict, email: str) -> Optional[str]:
        target = (email or '').strip().lower()
        if not target:
            return None
        for username, data in users.items():
            existing = (data.get('email') or '').strip().lower()
            if existing and existing == target:
                return username
        return None

    @staticmethod
    def _unique_username(users: dict, candidate: str) -> str:
        """Sanitize and uniquify a candidate username.

        IdP-provided values may contain characters CertMate's existing
        admin UI doesn't render well (spaces, ``@`` from email
        fallbacks). Keep alphanumerics, dot, dash, underscore; replace
        the rest with ``_``. Append numeric suffix on collision.
        """
        if not candidate:
            candidate = 'oidc_user'
        cleaned_chars = []
        for ch in str(candidate):
            if ch.isalnum() or ch in ('.', '-', '_', '@'):
                cleaned_chars.append(ch)
            else:
                cleaned_chars.append('_')
        cleaned = ''.join(cleaned_chars).strip('_') or 'oidc_user'
        if cleaned not in users:
            return cleaned
        suffix = 2
        while f"{cleaned}_{suffix}" in users:
            suffix += 1
        return f"{cleaned}_{suffix}"

    # ------------------------------------------------------------- logout

    def build_end_session_url(self, post_logout_redirect_uri: Optional[str] = None) -> Optional[str]:
        """Return the IdP's end_session_endpoint URL or None.

        Best-effort: requires that the OAuth registry was already built
        (i.e. the user previously logged in via OIDC this process).
        Emits ``id_token_hint`` (when retained from the callback) and
        ``client_id`` alongside ``post_logout_redirect_uri`` because
        Keycloak/Okta/Authentik treat the hint as effectively required
        for headless RP-initiated logout.
        """
        try:
            from flask import current_app
            client = self._client(current_app)
            metadata = getattr(client, 'server_metadata', None) or {}
            end_session = metadata.get('end_session_endpoint')
            if not end_session:
                return None
            cfg = self._load_config()
            redirect = (post_logout_redirect_uri or cfg.get('post_logout_redirect_uri') or '').strip()
            params: dict = {}
            try:
                id_token = flask_session.get(self._SESSION_ID_TOKEN_KEY)
            except Exception:
                id_token = None
            if id_token:
                params['id_token_hint'] = id_token
            client_id = (cfg.get('client_id') or '').strip()
            if client_id:
                params['client_id'] = client_id
            if redirect:
                params['post_logout_redirect_uri'] = redirect
            if not params:
                return end_session
            return f"{end_session}?{urlencode(params)}"
        except Exception as exc:
            logger.debug(f"build_end_session_url failed: {exc}")
            return None

    def clear_session_artifacts(self) -> None:
        """Drop OIDC-specific values from the Flask session.

        Called by the logout handler after invalidating the CertMate
        session cookie so the next OIDC login starts from a clean slate.
        Safe to call when no session exists.
        """
        try:
            flask_session.pop(self._SESSION_ID_TOKEN_KEY, None)
            flask_session.pop(self._SESSION_NEXT_KEY, None)
        except Exception:
            logger.debug("OIDC session cleanup skipped (session unavailable)")

    # ------------------------------------------------------------- audit

    def _audit(self, operation: str, username: str, status: str = 'success',
               details: Optional[dict] = None, error: Optional[str] = None,
               ip_address: Optional[str] = None) -> None:
        if not self._audit_logger:
            return
        try:
            self._audit_logger.log_operation(
                operation=operation,
                resource_type='oidc_user',
                resource_id=username or 'unknown',
                status=status,
                details=details or {},
                user=username,
                ip_address=ip_address,
                error=error,
            )
        except Exception as exc:
            logger.debug(f"OIDC audit log failed: {exc}")
