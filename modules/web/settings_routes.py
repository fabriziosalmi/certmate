import logging
import re
from functools import partial, wraps
from pathlib import Path

from flask import abort, request, jsonify

from modules.core.request_fields import json_booleans
from modules.core.constants import iter_cert_domain_dirs
from modules.core.domain_entries import entry_domain

logger = logging.getLogger(__name__)

# Secret-name masking is single-sourced in modules/core/settings.py
# (_SECRET_KEY_RE + mask_secrets_in_settings); the GET handler below
# imports it. A local duplicate of that regex used to live here but had
# been dead code since the handlers switched to the shared helper.


def _refuse_during_setup(auth_manager, audit_logger, operation, resource_type,
                         resource_id, only_if=None):
    """409 SETUP_BOOTSTRAP_ONLY while the instance is in setup mode.

    *only_if*, when given, narrows the refusal (a first user is the
    bootstrap and must be allowed). Every refusal is audited: an attempt to
    create credentials in the setup window is worth knowing about.
    """
    if not auth_manager.is_setup_mode():
        return None
    if only_if is not None and not only_if():
        return None
    if audit_logger:
        audit_logger.log_authz_denied(
            operation=operation, resource_type=resource_type,
            resource_id=str(resource_id)[:64],
            reason='setup mode allows only the bootstrap admin',
            user=(getattr(request, 'current_user', None) or {}).get('username'),
            ip_address=request.remote_addr,
        )
    return jsonify({
        'error': ('Setup is not complete: every request is still served as '
                  'admin to anyone who can reach this instance, so it only '
                  'creates the first admin. Enable local authentication (or '
                  'set API_BEARER_TOKEN), sign in, then create this.'),
        'code': 'SETUP_BOOTSTRAP_ONLY',
    }), 409


def bootstrap_only(auth_manager, audit_logger, operation, resource_type,
                   id_field, methods=('POST',), only_if=None):
    """Decorator: refuse *methods* with 409 while the instance is in setup mode.

    A decorator rather than a check inside each view, so the views stay as they
    were: the rule is "setup mode only bootstraps", and it reads that way at the
    top of the route it applies to.
    """
    def decorator(view):
        @wraps(view)
        def guarded(*args, **kwargs):
            if request.method in methods:
                data = request.get_json(silent=True) or {}
                refusal = _refuse_during_setup(
                    auth_manager, audit_logger, operation, resource_type,
                    data.get(id_field) or '-', only_if=only_if)
                if refusal is not None:
                    return refusal
            return view(*args, **kwargs)
        return guarded
    return decorator


def _is_bootstrap_admin(auth_manager, role):
    """Is this request creating the instance's first admin, in setup mode?"""
    return (role == 'admin' and auth_manager.is_setup_mode()
            and not auth_manager.list_users())


def _close_setup_with(auth_manager, audit_logger, username, body, bootstrap_admin):
    """Enable local auth together with the first admin, and say so in *body*.

    Setup used to take two requests (create the admin, then enable local
    auth), and an instance whose second request never came stayed open to
    anyone as admin while its operator believed it had one.
    """
    if not bootstrap_admin or not auth_manager.enable_local_auth(True):
        return
    body['local_auth_enabled'] = True
    if audit_logger:
        audit_logger.log_auth_config_changed(
            local_auth_enabled_before=False, local_auth_enabled_after=True,
            user=username, ip_address=request.remote_addr,
            confirm_unauthenticated=False)


def _confirm_setup_key(auth_manager, audit_logger, key_id):
    """PATCH /api/keys/<id> {"confirmed": true}: vouch for a key created
    while the instance was in setup mode, clearing its review flag."""
    data = request.get_json(silent=True) or {}
    if data.get('confirmed') is not True:
        return jsonify({'error': 'Body must be {"confirmed": true}',
                        'code': 'INVALID_REQUEST'}), 400
    # Confirming in setup mode would let the same anonymous admin who
    # could mint the key vouch for it.
    refusal = _refuse_during_setup(auth_manager, audit_logger, 'confirm_api_key',
                                   'api_key', key_id)
    if refusal:
        return refusal
    user = getattr(request, 'current_user', {}) or {}
    ok, msg = auth_manager.confirm_setup_key(key_id, user.get('username'))
    if not ok:
        status = 404 if 'not found' in msg.lower() else 400
        code = 'API_KEY_NOT_FOUND' if status == 404 else 'API_KEY_NOT_CONFIRMABLE'
        return jsonify({'error': msg, 'code': code}), status
    if audit_logger:
        audit_logger.log_operation(
            operation='confirm_api_key', resource_type='api_key',
            resource_id=key_id, status='success',
            details={'reason': 'created during setup, vouched for by an operator'},
            user=user.get('username'), ip_address=request.remote_addr,
        )
    return jsonify({'message': msg, 'key_id': key_id})


def _refuse(status, body):
    """Answer *body* with *status* and stop the request, from anywhere in a handler."""
    response = jsonify(body)
    response.status_code = status
    abort(response)


def _provider_of_account(dns_manager, account_id, provider):
    """The provider an account belongs to: *provider* when the path named one, else found.

    `/api/dns-providers/accounts/<id>` and `/api/web/settings/accounts/<id>` carry no
    provider, and the handler used to run with `provider=None`: a DELETE answered 500
    for an account that exists, and a PUT answered 200 after writing the credentials it
    was sent under a provider called `null`, for an id that did not exist too (#1088).

    The id alone names an account only when exactly one provider has it. When it names
    nothing the request stops with a 404; when it names several, with a 409 that lists
    them and names the provider-qualified path, which is not ambiguous. Every provider
    has an account called `default`, so that one always needs the long form.

    The refusal is raised rather than returned so the handler, which is a closure inside
    `register_settings_routes`, gains no branch: that function's complexity is a budget
    that only comes down (scripts/check_complexity_budget.py).
    """
    if provider is not None:
        return provider
    owners = sorted({account.get('provider') for account in dns_manager.list_accounts()
                     if account.get('account_id') == account_id and account.get('provider')})
    if not owners:
        _refuse(404, {'error': f"No DNS account called '{account_id}'"})
    if len(owners) > 1:
        _refuse(409, {
            'error': f"'{account_id}' exists under several providers ({', '.join(owners)}); "
                     f"name the provider: /api/dns/<provider>/accounts/{account_id}",
            'providers': owners})
    return owners[0]


# A CA account ID is chosen by the operator and ends up in the URL, in
# certificate metadata and in log lines ("Using CA account: <id>"), so a new
# one is held to a plain charset. IDs that already exist are still accepted
# for edit and delete, so an account named before this rule is not stranded.
_CA_ACCOUNT_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
_CA_ACCOUNT_FIELDS = frozenset({'name', 'email', 'acme_url', 'eab_kid', 'eab_hmac', 'ca_cert'})


def _ca_accounts_of(settings, provider):
    existing = (settings.get('ca_providers') or {}).get(provider) or {}
    if isinstance(existing.get('accounts'), dict):
        return existing['accounts']
    return {'default': existing} if existing else {}


def _as_accounts(settings, provider):
    """Convert the provider entry to the accounts shape, in place, and return
    its accounts. The flat keys MOVE into the default account: left beside
    `accounts` they would be a credential copy nothing reads or rotates."""
    configured = settings.setdefault('ca_providers', {}).setdefault(provider, {})
    if not isinstance(configured.get('accounts'), dict):
        legacy = {k: v for k, v in configured.items() if k != 'accounts'}
        if not legacy and provider == 'letsencrypt' and settings.get('email'):
            legacy = {'email': settings['email']}
        configured.clear()
        configured['accounts'] = {'default': legacy} if legacy else {}
    else:
        for key in [k for k in configured if k != 'accounts']:
            del configured[key]
    return configured['accounts']


def _audit_ca_account(audit_logger, operation, provider, account_id, status,
                      fields=None, error=None):
    if not audit_logger:
        return
    user = getattr(request, 'current_user', None) or {}
    # Field NAMES only: the values include the EAB secret.
    details = {'fields': sorted(fields)} if fields else None
    audit_logger.log_operation(
        operation=operation, resource_type='ca_provider',
        resource_id=f"{provider}:{account_id}", status=status,
        details=details, user=user.get('username'),
        ip_address=request.remote_addr, error=error,
    )


def _ca_account_in_use(managers, settings_manager, settings, provider, account_id):
    service = managers.get('cert_service')
    if not service:
        return False
    domains = {entry_domain(entry) for entry in settings.get('domains') or []}
    cert_dir = getattr(getattr(settings_manager, 'file_ops', None), 'cert_dir', None)
    if isinstance(cert_dir, Path) and cert_dir.is_dir():
        domains.update(path.name for path in iter_cert_domain_dirs(cert_dir))
    for domain in domains:
        metadata = service.read_metadata(domain) if domain else {}
        if (metadata.get('ca_provider') == provider and
                (metadata.get('ca_account_id') or 'default') == account_id):
            return True
    return False


def _delete_ca_account(managers, settings_manager, audit_logger, settings,
                       accounts, provider, account_id):
    if account_id not in accounts:
        return jsonify({'error': 'CA account not found'}), 404
    chosen = (settings.get('default_ca_accounts') or {}).get(provider) or (
        'default' if 'default' in accounts else next(iter(accounts)))
    if provider == settings.get('default_ca', 'letsencrypt') and account_id == chosen:
        return jsonify({'error': 'Choose another default CA account before deleting this one'}), 409
    if _ca_account_in_use(managers, settings_manager, settings, provider, account_id):
        return jsonify({'error': 'Reissue or delete certificates using this account first'}), 409

    def remove_account(s):
        remaining = _as_accounts(s, provider)
        remaining.pop(account_id, None)
        defaults = s.get('default_ca_accounts') or {}
        if not remaining:
            s['ca_providers'].pop(provider, None)
            defaults.pop(provider, None)
        elif defaults.get(provider) == account_id:
            defaults[provider] = next(iter(remaining))

    if not settings_manager.update(remove_account, 'ca_account_deleted'):
        _audit_ca_account(audit_logger, 'delete_ca_account', provider, account_id,
                          'failure', error='settings write failed')
        return jsonify({'error': 'Failed to delete CA account'}), 500
    _audit_ca_account(audit_logger, 'delete_ca_account', provider, account_id, 'success')
    return jsonify({'message': 'CA account deleted'})


def _save_ca_account(settings_manager, audit_logger, accounts,
                     ca_manager, provider, account_id):
    from modules.core.settings import _strip_masked_values
    from modules.core.utils import validate_email

    creating = account_id not in accounts
    if request.args.get('create') == '1' and not creating:
        return jsonify({'error': 'CA account already exists; use Edit'}), 409
    if creating and not _CA_ACCOUNT_ID_RE.fullmatch(account_id):
        return jsonify({'error': 'Account name must be 1-64 letters, digits, dots, '
                                 'dashes or underscores, starting with a letter or digit'}), 400
    raw = request.get_json(silent=True) or {}
    if not isinstance(raw, dict) or set(raw) - _CA_ACCOUNT_FIELDS:
        return jsonify({'error': 'Invalid CA account configuration'}), 400
    submitted = _strip_masked_values(raw)
    config = {**accounts.get(account_id, {}), **submitted}
    if not config.get('email') or not validate_email(config['email'])[0]:
        return jsonify({'error': 'A valid CA account email is required'}), 400
    valid, reason = ca_manager.validate_ca_configuration(provider, config)
    if not valid:
        return jsonify({'error': reason}), 400

    def save_account(s):
        _as_accounts(s, provider)[account_id] = config

    operation = 'create_ca_account' if creating else 'update_ca_account'
    if not settings_manager.update(save_account, 'ca_account_saved'):
        _audit_ca_account(audit_logger, operation, provider, account_id,
                          'failure', error='settings write failed')
        return jsonify({'error': 'Failed to save CA account'}), 500
    _audit_ca_account(audit_logger, operation, provider, account_id, 'success',
                      fields=submitted)
    return jsonify({'message': 'CA account saved'})


def _ca_provider_account(managers, settings_manager, audit_logger, provider, account_id):
    """POST (create/edit) or DELETE one account of a CA provider."""
    from modules.core.ca_manager import CAManager

    ca_manager = managers.get('ca') or CAManager(settings_manager)
    if (provider not in ca_manager.ca_providers or not account_id or len(account_id) > 100
            or account_id in ('__proto__', 'constructor', 'prototype')):
        return jsonify({'error': 'Invalid CA provider or account ID'}), 400
    settings = settings_manager.load_settings() or {}
    accounts = _ca_accounts_of(settings, provider)
    if request.method == 'DELETE':
        return _delete_ca_account(managers, settings_manager, audit_logger,
                                  settings, accounts, provider, account_id)
    return _save_ca_account(settings_manager, audit_logger, accounts,
                            ca_manager, provider, account_id)


def _stamp_key_delivery_consent(deploy_manager, audit_logger, data):
    """Record, on the server, who confirmed where a webhook target sends the private key.

    A webhook target whose template names the key sends it to the host in its URL.
    The client only ACKNOWLEDGES that host (`acknowledge_key_delivery_to`); the
    consent itself, with who and when, is written here and never read from the
    request, so a client cannot confirm for itself. Returns ``(data, None)`` or
    ``(None, reason)``.
    """
    if not isinstance(data, dict) or not isinstance(data.get('targets'), list):
        return data, None
    from modules.core.deploy_target_webhook import stamp_consent
    actor = getattr(request, 'current_user', None) or {}
    previous = (deploy_manager.get_config() or {}).get('targets') or []
    targets, error = stamp_consent(data['targets'], previous, actor.get('username') or 'unknown')
    if error:
        return None, error
    before = {(t.get('id'), (t.get('delivery_consent') or {}).get('at'))
              for t in previous if isinstance(t, dict)}
    if audit_logger:
        for target in targets:
            consent = target.get('delivery_consent') if isinstance(target, dict) else None
            if consent and (target.get('id'), consent.get('at')) not in before:
                audit_logger.log_operation(
                    operation='confirm_key_delivery', resource_type='deploy_target',
                    resource_id=str(target.get('id')), status='success',
                    details={'host': consent.get('host'), 'target': target.get('name')},
                    user=actor.get('username'), ip_address=request.remote_addr)
    return dict(data, targets=targets), None


def _save_deploy_config(deploy_manager, audit_logger):
    """POST /api/deploy/config: confirm key delivery, validate, save, audit."""
    data, err = _stamp_key_delivery_consent(deploy_manager, audit_logger, request.json or {})
    if err:
        return jsonify({'error': err}), 400
    ok, err = deploy_manager.save_config(data)
    if ok:
        if audit_logger:
            actor = getattr(request, 'current_user', {}) or {}
            # Hook commands themselves are NEVER logged (would leak
            # secrets + risk log-injection). We record that the
            # configuration was touched, by whom, from where.
            audit_logger.log_deploy_hook_changed(
                scope='global',
                hook_id='config',
                operation='update',
                user=actor.get('username'),
                ip_address=request.remote_addr,
            )
        return jsonify({'message': 'Deploy configuration saved'})
    # Surface the specific reason (issue #102) so users see *why*
    # a hook was rejected rather than a generic save failure.
    return jsonify({'error': err or 'Invalid configuration or save failed'}), 400


def _register_target_preview_route(app, auth_manager, deploy_manager):
    @app.route('/api/deploy/targets/preview', methods=['POST'])
    @auth_manager.require_role('admin')
    def api_deploy_target_preview():
        """Render what a webhook target would send. Reads no file and sends nothing."""
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 503
        from modules.core.deploy_target_webhook import (
            TARGET_WEBHOOK, WebhookTarget, _url_host, validate_webhook_target)
        target = request.get_json(silent=True)
        if not isinstance(target, dict) or target.get('type') != TARGET_WEBHOOK:
            return jsonify({'error': 'send a target of type "webhook"'}), 400
        target = dict(target, config=dict(target.get('config') or {}))
        target['config'].pop('acknowledge_key_delivery_to', None)
        # Validated as if the destination were confirmed: a preview is how an
        # operator sees what they are about to confirm.
        ok, error = validate_webhook_target(dict(
            target, delivery_consent={'host': _url_host(target['config'].get('url'))}))
        if not ok:
            return jsonify({'error': error}), 400
        return jsonify(WebhookTarget(target).preview(
            domain=str(request.args.get('domain') or 'example.com')[:253]))


def _register_ca_account_route(app, auth_manager, managers, settings_manager, audit_logger):
    @app.route('/api/web/settings/ca-providers/<string:provider>/accounts/<string:account_id>',
               methods=['POST', 'DELETE'])
    @auth_manager.require_role('admin')
    def ca_provider_account(provider, account_id):
        return _ca_provider_account(managers, settings_manager, audit_logger,
                                    provider, account_id)


def register_settings_routes(app, managers, require_web_auth, auth_manager,
                             settings_manager, dns_manager):
    """Register settings-related routes"""
    auth_manager_ref = auth_manager
    deploy_manager = managers.get('deployer')
    audit_logger = managers.get('audit')

    @app.route('/api/settings', methods=['GET'])
    @app.route('/api/web/settings', methods=['GET'])
    @auth_manager.require_role('viewer')
    def api_settings_get():
        """Read settings (viewer-accessible).

        Aligns the web blueprint with the Flask-RESTX surface, which
        already allowed viewer-role reads. Secret values are masked
        with '********' regardless of caller role, so a viewer never
        sees real bearer tokens, DNS provider credentials, or
        storage-backend credentials. The Sprint 1.6 audit follow-up
        flagged the previous admin-only GET as inconsistent with
        RESTX and unnecessarily restrictive (a UI-rendering viewer
        already needs the masked structure to show form fields).
        """
        try:
            from modules.core.settings import mask_secrets_in_settings
            settings = settings_manager.load_settings()
            # Centralised masking via modules/core/settings — same helper
            # the backup-ZIP and notifications GET paths use, so the
            # contract is single-sourced. Picks up the provider-specific
            # acme-dns shared-secret fields (username + subdomain) that
            # the older local walker missed (audit finding M2).
            masked = mask_secrets_in_settings(settings)

            # Audit M4: scoped API keys (allowed_domains set) must not
            # see the full org-wide `domains` array. Mirrors the same
            # scope filter `Settings.get` applies in resources.py. The
            # `masked` dict is a fresh deep-copy from
            # `mask_secrets_in_settings`, so mutating it in place here
            # cannot affect the on-disk settings.
            user = getattr(request, 'current_user', None) or {}
            scope = user.get('allowed_domains')
            if scope is not None:
                raw_domains = masked.get('domains') or []
                filtered = []
                for entry in raw_domains:
                    domain_name = entry_domain(entry)
                    if domain_name and auth_manager.domain_matches_scope(domain_name, scope):
                        filtered.append(entry)
                masked['domains'] = filtered

            # Recovery helper: if the UI is about to show the wizard,
            # surface a flag so the frontend can suggest restoring
            # from backup instead of silently overwriting settings.
            has_users = bool(settings.get('users'))
            has_domains = bool(settings.get('domains'))
            cert_dir = getattr(settings_manager.file_ops, 'cert_dir', None)
            has_certs = (
                cert_dir is not None
                and any(iter_cert_domain_dirs(cert_dir))
            ) if cert_dir else False
            if not has_users and not has_domains and has_certs:
                masked['certmate_recovery_suggested'] = True

            # The user roster and API-key inventory have dedicated admin-only
            # endpoints (/api/users, /api/keys). mask_secrets_in_settings only
            # redacts secret-named LEAF values, so usernames/roles/emails and
            # key names/roles/allowed_domains/token_prefix would otherwise leak
            # to any viewer through this settings view. Strip them for anyone
            # who is not an admin (kept for admin so the settings UI is
            # unchanged for the role that already reads them elsewhere).
            #
            # `deploy_hooks` belongs on that list for the same reason, and
            # more sharply. A hook is a shell command an admin typed, and
            # the settings route two hundred lines down refuses to LOG those
            # commands precisely because they carry credentials — a reload
            # with an API key in a header, an scp with a token in the URL.
            # `mask_secrets_in_settings` masks by FIELD NAME, and `command`
            # is not a secret-sounding name, so the whole command came back
            # verbatim to any viewer. Its editor is admin-only and reads
            # /api/deploy/config, so nothing in the product loses a field.
            if (user.get('role') != 'admin'):
                masked.pop('users', None)
                masked.pop('api_keys', None)
                masked.pop('deploy_hooks', None)

            response = jsonify(masked)
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '-1'
            return response
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
            return jsonify({'error': 'Failed to load settings'}), 500

    _register_ca_account_route(app, auth_manager, managers, settings_manager, audit_logger)
    _register_target_preview_route(app, auth_manager, deploy_manager)

    @app.route('/api/settings', methods=['POST'])
    @app.route('/api/web/settings', methods=['POST'])
    @auth_manager.require_role('admin')
    def api_settings():
        """Update settings (admin-only). Same whitelist + audit as the
        Flask-RESTX Settings.post resource."""
        try:
            from modules.core.settings import (
                validate_settings_post,
                diff_settings_keys,
            )
            data = request.json or {}
            # Load *before* validating: validate_settings_post uses the
            # current state to drop no-op echoes from a GET-then-POST-back
            # round-trip (the dominant pattern from the web UI).
            before = settings_manager.load_settings() or {}
            try:
                filtered, rejected, unknown = validate_settings_post(
                    data, current=before)
            except ValueError as e:
                return jsonify({'error': str(e)}), 400

            current = getattr(request, 'current_user', {}) or {}

            if rejected:
                logger.warning(
                    "Rejected POST /api/web/settings: caller tried to write "
                    "blocked fields %s (user=%s)",
                    rejected, current.get('username'),
                )
                if audit_logger:
                    for field in rejected:
                        audit_logger.log_authz_denied(
                            operation='update',
                            resource_type='settings',
                            resource_id=field,
                            reason=f'field {field} requires a dedicated endpoint',
                            user=current.get('username'),
                            ip_address=request.remote_addr,
                        )
                return jsonify({
                    'error': 'Forbidden fields in payload',
                    'rejected': sorted(rejected),
                    'hint': 'Use the dedicated endpoint for these fields '
                            '(e.g. /api/deploy/config, /api/users, '
                            '/api/keys, /api/auth/config).',
                }), 400

            if unknown:
                return jsonify({
                    'error': 'Unknown fields in payload',
                    'unknown': sorted(unknown),
                    'hint': 'Only documented settings keys are accepted.',
                }), 400

            if not settings_manager.atomic_update(filtered):
                return jsonify({'error': 'Update failed'}), 500

            # The deployment-status cache only reads its TTL at construction, so
            # a persisted cache_ttl change was a silent no-op until restart. Push
            # it live now that the write succeeded.
            if 'cache_ttl' in filtered:
                cache_manager = managers.get('cache')
                if cache_manager and hasattr(cache_manager, 'update_cache_settings'):
                    try:
                        cache_manager.update_cache_settings()
                    except Exception as e:
                        logger.warning("Failed to apply cache_ttl live: %s", e)

            after = settings_manager.load_settings() or {}
            changed = diff_settings_keys(before, after)
            if audit_logger and changed:
                sensitive_changed = [
                    k for k in changed
                    if k in audit_logger._SENSITIVE_SETTINGS_KEYS
                ]
                audit_logger.log_settings_changed(
                    changed_keys=changed,
                    sensitive_changed=sensitive_changed,
                    user=current.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'message': 'Settings updated'})
        except Exception as e:
            logger.error(f"Failed to update settings: {e}")
            return jsonify({'error': 'Failed to update settings'}), 500

    @app.route('/api/users', methods=['GET', 'POST'])
    @app.route('/api/web/settings/users', methods=['GET', 'POST'])
    @auth_manager.require_role('admin')
    # Setup mode serves every request as admin, so it may only bootstrap: the
    # first admin, then local auth. A second user created now would be created
    # by whoever can reach the instance and would outlive setup. 409 is what
    # the setup page already reads as "an admin exists, go on and enable
    # login", so a half-finished setup still completes.
    @bootstrap_only(auth_manager, audit_logger, 'create_user', 'user', 'username',
                    only_if=auth_manager.list_users)
    def api_users():
        """User management"""
        if request.method == 'GET':
            users = auth_manager.list_users()
            return jsonify({'users': users})

        data = request.json or {}
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'viewer')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        if len(username) > 64 or len(password) > 256:
            return jsonify({'error': 'Username must be ≤ 64 chars, password ≤ 256 chars'}), 400
        # Password policy: 12 chars minimum with at least one digit and one
        # non-alphanumeric character. Aligns with the OWASP ASVS L1 guidance
        # for shared-credential apps.
        if (len(password) < 12
                or not re.search(r'\d', password)
                or not re.search(r'[^A-Za-z0-9]', password)):
            return jsonify({
                'error': 'Password must be at least 12 characters and include a digit and a symbol'
            }), 400

        bootstrap_admin = _is_bootstrap_admin(auth_manager, role)
        success, msg = auth_manager.create_user(username, password, role)
        if success:
            if audit_logger:
                actor = getattr(request, 'current_user', {}) or {}
                audit_logger.log_user_created(
                    username=username,
                    role=role,
                    user=actor.get('username'),
                    ip_address=request.remote_addr,
                )
            body = {'message': 'User created'}
            _close_setup_with(auth_manager, audit_logger, username, body,
                              bootstrap_admin)
            return jsonify(body), 201
        if 'already exists' in msg.lower():
            return jsonify({'error': msg}), 409
        return jsonify({'error': msg}), 500

    @app.route('/api/users/<string:username>', methods=['DELETE', 'PUT'])
    @app.route('/api/web/settings/users/<string:username>',
               methods=['DELETE', 'PUT'])
    @auth_manager.require_role('admin')
    def api_user_edit(username):
        """Edit or delete user"""
        if request.method == 'DELETE':
            current = getattr(request, 'current_user', None) or {}
            if current.get('username') == username:
                return jsonify({
                    'error': 'Cannot delete your own account; ask another admin'
                }), 400
            success, msg = auth_manager.delete_user(username)
            if success:
                if audit_logger:
                    audit_logger.log_user_deleted(
                        username=username,
                        user=current.get('username'),
                        ip_address=request.remote_addr,
                    )
                return jsonify({'message': msg})
            if 'not found' in msg.lower():
                return jsonify({'error': msg}), 404
            return jsonify({'error': msg}), 400

        data = request.json or {}
        role = data.get('role')
        password = data.get('password')
        email = data.get('email')
        enabled = data.get('enabled')

        # At least one mutable field must be present. The UI sends a single
        # field per action (role change, password reset, enable/disable).
        if role is None and password is None and email is None and enabled is None:
            return jsonify({'error': 'Nothing to update'}), 400

        if enabled is not None and not isinstance(enabled, bool):
            return jsonify({'error': 'enabled must be a boolean'}), 400

        # Mirror the create-user password policy on resets so a weakened
        # credential cannot be slipped in through the edit surface.
        if password is not None:
            if len(password) > 256:
                return jsonify({'error': 'Password must be ≤ 256 chars'}), 400
            if (len(password) < 12
                    or not re.search(r'\d', password)
                    or not re.search(r'[^A-Za-z0-9]', password)):
                return jsonify({
                    'error': 'Password must be at least 12 characters and include a digit and a symbol'
                }), 400

        # Capture the previous role so the audit entry records the transition.
        old_users = auth_manager.list_users() or {}
        old_role = (old_users.get(username) or {}).get('role')

        success, msg = auth_manager.update_user(
            username, role=role, password=password, email=email, enabled=enabled,
        )
        if success:
            if audit_logger and role is not None and old_role != role:
                actor = getattr(request, 'current_user', {}) or {}
                audit_logger.log_user_role_changed(
                    username=username,
                    old_role=old_role,
                    new_role=role,
                    user=actor.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'message': msg})
        if 'not found' in msg.lower():
            return jsonify({'error': msg}), 404
        return jsonify({'error': msg}), 400

    @app.route('/api/dns/<string:provider>/accounts', methods=['GET', 'POST'])
    # Its own endpoint name, not a shared one. This function serves three
    # paths, and DEPRECATIONS is keyed by `request.endpoint`: without a
    # separate name, announcing that this duplicate is going away would put
    # Deprecation and Sunset headers on /api/web/settings/accounts too, which
    # is the dashboard's own call and is not going anywhere.
    @app.route('/api/dns-providers/accounts', methods=['GET', 'POST'],
               endpoint='api_dns_accounts_deprecated')
    @app.route('/api/web/settings/accounts', methods=['GET', 'POST'])
    @auth_manager.require_role('admin')
    def api_dns_accounts(provider=None):
        """Route for getting or adding DNS provider accounts"""
        if request.method == 'GET':
            accounts = dns_manager.list_accounts()
            if provider:
                # Filter by provider if specified in legacy URL
                accounts = [a for a in accounts if a.get('provider') == provider]
            return jsonify(accounts)

        try:
            data = request.json or {}
            name = data.get('name') or data.get('account_id')
            req_provider = provider or data.get('provider')
            config = data.get('config', {})
            set_as_default = data.get('set_as_default', False)

            if not name or not req_provider:
                return jsonify({'error': 'Account name and provider required'}), 400

            if dns_manager.add_account(name, req_provider, config):
                # Honour the operator's explicit "set as default" choice on
                # create, mirroring the update path — the flag the UI sends was
                # previously dropped here.
                if set_as_default:
                    dns_manager.set_default_account(req_provider, name)
                if audit_logger:
                    user = getattr(request, 'current_user', None) or {}
                    audit_logger.log_operation(
                        operation='create_account',
                        resource_type='dns_provider',
                        resource_id=f"{req_provider}:{name}",
                        status='success',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return jsonify({'message': 'Account added', 'id': name})

            if audit_logger:
                user = getattr(request, 'current_user', None) or {}
                audit_logger.log_operation(
                    operation='create_account',
                    resource_type='dns_provider',
                    resource_id=f"{req_provider}:{name}" if req_provider and name else 'unknown',
                    status='failure',
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'error': 'Failed to add account'}), 500
        except Exception as e:
            logger.error(f"Failed to add DNS account: {e}")
            if audit_logger:
                user = getattr(request, 'current_user', None) or {}
                audit_logger.log_operation(
                    operation='create_account',
                    resource_type='dns_provider',
                    resource_id=f"{req_provider}:{name}" if 'req_provider' in locals() and 'name' in locals() else 'unknown',
                    status='failure',
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                    error=str(e)
                )
            return jsonify({'error': 'Failed to add account'}), 500

    @app.route('/api/dns/<string:provider>/accounts/<string:account_id>',
               methods=['DELETE', 'PUT'])
    # Same reasoning as the listing above: a name of its own, so the
    # announcement reaches this path and not the dashboard's.
    @app.route('/api/dns-providers/accounts/<string:account_id>',
               methods=['DELETE', 'PUT'],
               endpoint='api_dns_account_detail_deprecated')
    @app.route('/api/web/settings/accounts/<string:account_id>',
               methods=['DELETE', 'PUT'])
    @auth_manager.require_role('admin')
    def api_dns_account_detail(account_id, provider=None):
        """Route for updating or deleting a DNS provider account"""
        provider = _provider_of_account(dns_manager, account_id, provider)
        if request.method == 'DELETE':
            if dns_manager.delete_account(provider, account_id):
                if audit_logger:
                    user = getattr(request, 'current_user', None) or {}
                    audit_logger.log_operation(
                        operation='delete_account',
                        resource_type='dns_provider',
                        resource_id=f"{provider}:{account_id}",
                        status='success',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return jsonify({'message': 'Account deleted'})
            
            if audit_logger:
                user = getattr(request, 'current_user', None) or {}
                audit_logger.log_operation(
                    operation='delete_account',
                    resource_type='dns_provider',
                    resource_id=f"{provider}:{account_id}",
                    status='failure',
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'error': 'Failure to delete account'}), 500

        # PUT: update existing account
        try:
            data = request.json or {}
            current_settings = settings_manager.load_settings()
            current_settings = settings_manager.migrate_dns_providers_to_multi_account(current_settings)
            existing = (current_settings.get('dns_providers', {})
                        .get(provider, {})
                        .get('accounts', {})
                        .get(account_id, {}))
            # Merge: keep existing secret values when masked placeholder is sent
            set_as_default = data.get('set_as_default', False)
            merged = dict(existing)
            for k, v in data.items():
                if k == 'set_as_default':
                    continue
                if v != '********':
                    merged[k] = v
            if dns_manager.add_account(account_id, provider, merged):
                if set_as_default:
                    dns_manager.set_default_account(provider, account_id)
                if audit_logger:
                    user = getattr(request, 'current_user', None) or {}
                    audit_logger.log_operation(
                        operation='update_account',
                        resource_type='dns_provider',
                        resource_id=f"{provider}:{account_id}",
                        status='success',
                        details={
                            'set_as_default': set_as_default
                        },
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return jsonify({'message': 'Account updated', 'id': account_id})
            
            if audit_logger:
                user = getattr(request, 'current_user', None) or {}
                audit_logger.log_operation(
                    operation='update_account',
                    resource_type='dns_provider',
                    resource_id=f"{provider}:{account_id}",
                    status='failure',
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'error': 'Failed to update account'}), 500
        except Exception as e:
            logger.error(f"Failed to update DNS account: {e}")
            if audit_logger:
                user = getattr(request, 'current_user', None) or {}
                audit_logger.log_operation(
                    operation='update_account',
                    resource_type='dns_provider',
                    resource_id=f"{provider}:{account_id}",
                    status='failure',
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                    error=str(e)
                )
            return jsonify({'error': 'Failed to update account'}), 500

    # ------------------------------------------------------------------ #
    # API Key management routes                                            #
    # ------------------------------------------------------------------ #

    @app.route('/api/keys', methods=['GET', 'POST'])
    @auth_manager_ref.require_role('admin')
    # A key minted in setup mode is minted by whoever can reach the instance,
    # and it stays valid once the operator completes setup.
    @bootstrap_only(auth_manager_ref, audit_logger, 'create_api_key', 'api_key', 'name')
    @json_booleans(is_agent=False)
    def api_keys():
        """List or create API keys"""
        if request.method == 'GET':
            try:
                keys = auth_manager_ref.list_api_keys()
                return jsonify({'keys': keys})
            except Exception as e:
                logger.error(f"Failed to list API keys: {e}")
                return jsonify({'error': 'Failed to list API keys'}), 500

        try:
            data = request.json or {}
            name = data.get('name', '').strip()
            role = data.get('role', 'viewer')
            expires_at = data.get('expires_at')
            allowed_domains = data.get('allowed_domains')
            is_agent = request.json_booleans['is_agent']

            if not name:
                return jsonify({'error': 'Key name is required'}), 400
            if len(name) > 64:
                return jsonify({'error': 'Key name must be ≤ 64 characters'}), 400

            user = getattr(request, 'current_user', {}) or {}

            # Prevent privilege escalation through key creation. require_role
            # ('admin') gates this endpoint by role LEVEL only — it never checks
            # the caller's own allowed_domains — so a *scoped* admin key
            # (role=admin, allowed_domains=[...]) could otherwise mint an
            # unrestricted admin key and escape its own scope. A minted key must
            # never exceed its creator's role or domain scope.
            from ..core.auth import ROLE_HIERARCHY
            caller_role = user.get('role', 'viewer')
            caller_scope = user.get('allowed_domains')  # None = unrestricted
            requested_level = ROLE_HIERARCHY.get(role)
            if requested_level is not None and requested_level > ROLE_HIERARCHY.get(caller_role, -1):
                return jsonify({'error': 'Cannot create a key with a role higher than your own'}), 403
            if caller_scope is not None:
                # A domain-scoped creator may only mint keys scoped within its
                # own domains: never an unscoped key, never a domain outside
                # scope. An empty list (locked-out key) is more restrictive, so
                # it is allowed.
                if allowed_domains is None:
                    return jsonify({'error': 'A domain-scoped key cannot create an unscoped key'}), 403
                requested_scope = allowed_domains if isinstance(allowed_domains, list) else [allowed_domains]
                outside = [d for d in requested_scope
                           if not auth_manager_ref.domain_matches_scope(d, caller_scope)]
                if outside:
                    return jsonify({'error': 'Cannot grant domains outside your own key scope'}), 403
            if role == 'admin' and allowed_domains is not None:
                # admin bypasses domain scope on every non-per-domain endpoint
                # (backups, settings, key management), so a "scoped admin" key is
                # a false containment. Reject it; use operator for scoped access.
                return jsonify({'error': 'Admin keys cannot be domain-scoped; use the operator role for scoped access'}), 400

            success, result_data = auth_manager_ref.create_api_key(
                name, role=role, expires_at=expires_at,
                created_by=user.get('username'),
                allowed_domains=allowed_domains,
                is_agent=is_agent,
            )
            if success:
                if audit_logger:
                    audit_logger.log_api_key_created(
                        key_id=result_data.get('id'),
                        name=result_data.get('name'),
                        role=result_data.get('role'),
                        allowed_domains=result_data.get('allowed_domains'),
                        expires_at=result_data.get('expires_at'),
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return jsonify(result_data), 201
            return jsonify({'error': result_data}), 400
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            return jsonify({'error': 'Failed to create API key'}), 500

    # PATCH is registered separately, as a module-level view bound to this
    # instance's managers: an operator confirming a key created during setup
    # has nothing to do with revoking one.
    app.add_url_rule(
        '/api/keys/<string:key_id>', 'api_key_confirm',
        auth_manager_ref.require_role('admin')(
            partial(_confirm_setup_key, auth_manager_ref, audit_logger)),
        methods=['PATCH'])

    @app.route('/api/keys/<string:key_id>', methods=['DELETE'])
    @auth_manager_ref.require_role('admin')
    def api_key_detail(key_id):
        """Revoke an API key"""
        try:
            # Capture name before revocation for the audit record.
            existing = auth_manager_ref.list_api_keys().get(key_id) or {}
            key_name = existing.get('name')

            ok, msg = auth_manager_ref.revoke_api_key(key_id)
            if not ok:
                # Distinguish "not found" so the UI can show 404 vs 400.
                status = 404 if 'not found' in (msg or '').lower() else 400
                return jsonify({'error': msg or 'Failed to revoke'}), status

            if audit_logger:
                user = getattr(request, 'current_user', {}) or {}
                audit_logger.log_api_key_revoked(
                    key_id=key_id,
                    name=key_name,
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'message': msg or 'API key revoked'})
        except Exception as e:
            logger.error(f"Failed to revoke API key {key_id}: {e}")
            return jsonify({'error': 'Failed to revoke API key'}), 500

    # ------------------------------------------------------------------ #
    # Deploy hooks routes                                                  #
    # ------------------------------------------------------------------ #

    @app.route('/api/deploy/config', methods=['GET', 'POST'])
    @auth_manager_ref.require_role('admin')
    def api_deploy_config():
        """Get or update deploy hooks configuration"""
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 503

        if request.method == 'GET':
            try:
                return jsonify(deploy_manager.get_config())
            except Exception as e:
                logger.error(f"Failed to get deploy config: {e}")
                return jsonify({'error': 'Failed to get deploy config'}), 500

        try:
            return _save_deploy_config(deploy_manager, audit_logger)
        except Exception as e:
            logger.error(f"Failed to save deploy config: {e}")
            return jsonify({'error': 'Failed to save deploy config'}), 500

    @app.route('/api/deploy/test/<string:hook_id>', methods=['POST'])
    @auth_manager_ref.require_role('admin')
    def api_deploy_test(hook_id):
        """Dry-run a deploy hook"""
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 503

        try:
            data = request.json or {}
            domain = data.get('domain', 'test.example.com')
            result = deploy_manager.test_hook(hook_id, domain=domain)
            if audit_logger:
                actor = getattr(request, 'current_user', {}) or {}
                # We audit the *attempt* (success or failure of the dry-run)
                # because the test path executes the hook command end-to-end
                # against a test domain — admins need a trail of who poked
                # what, even on a successful no-op test.
                audit_logger.log_deploy_hook_changed(
                    scope=domain,
                    hook_id=hook_id,
                    operation='test',
                    user=actor.get('username'),
                    ip_address=request.remote_addr,
                )
            if 'error' in result:
                return jsonify(result), 404
            return jsonify(result)
        except Exception as e:
            logger.error(f"Failed to test deploy hook {hook_id}: {e}")
            return jsonify({'error': 'Failed to test deploy hook'}), 500

    @app.route('/api/deploy/pending', methods=['GET'])
    @auth_manager_ref.require_role('admin')
    def api_deploy_pending():
        """Deploys held for a maintenance window (#632).

        A held deploy is invisible everywhere else: the certificate renewed,
        the history has no entry, and nothing failed. Without this an operator
        cannot tell "waiting for 02:00" from "the hook never fired", which are
        the same picture and very different problems.

        Returns a bare list, like the sibling history endpoint.
        """
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 503

        try:
            return jsonify(deploy_manager.get_pending())
        except Exception as e:
            logger.error(f"Failed to list pending deploys: {e}")
            return jsonify({'error': 'Failed to list pending deploys'}), 500

    @app.route('/api/deploy/history', methods=['GET'])
    @auth_manager_ref.require_role('admin')
    def api_deploy_history():
        """Get deploy hook execution history.

        Returns a bare list ``[...]`` — matches the sibling event-log
        endpoint ``/api/webhooks/deliveries`` (modules/web/misc_routes.py)
        and the convention the UI (``static/js/settings-deploy.js``,
        ``static/js/settings-notifications.js``) was originally written
        against. The error path keeps the ``{"error": ...}`` envelope so
        the frontend's catch branch can surface a real reason.
        """
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 503

        try:
            limit = min(int(request.args.get('limit', 50)), 200)
            domain = request.args.get('domain')
            history = deploy_manager.get_history(limit=limit, domain=domain)
            return jsonify(history)
        except Exception as e:
            logger.error(f"Failed to get deploy history: {e}")
            return jsonify({'error': 'Failed to get deploy history'}), 500
