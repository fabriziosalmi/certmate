import logging
from flask import request, jsonify

logger = logging.getLogger(__name__)


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
            settings = settings_manager.load_settings()
            import copy, re
            masked = copy.deepcopy(settings)
            _SECRET_KEYS = re.compile(
                r'(token|secret|password|key|credential)',
                re.IGNORECASE
            )
            def _mask_dict(d):
                if not isinstance(d, dict):
                    return
                for k in list(d.keys()):
                    if _SECRET_KEYS.search(k) and isinstance(d[k], str) and d[k]:
                        d[k] = '********'
                    elif isinstance(d[k], dict):
                        _mask_dict(d[k])
            _mask_dict(masked)
            response = jsonify(masked)
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '-1'
            return response
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
            return jsonify({'error': 'Failed to load settings'}), 500

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
            data = request.json
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
    def api_users():
        """User management"""
        if request.method == 'GET':
            users = auth_manager.list_users()
            return jsonify({'users': users})

        data = request.json
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
        import re
        if (len(password) < 12
                or not re.search(r'\d', password)
                or not re.search(r'[^A-Za-z0-9]', password)):
            return jsonify({
                'error': 'Password must be at least 12 characters and include a digit and a symbol'
            }), 400

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
            return jsonify({'message': 'User created'}), 201
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

        data = request.json
        role = data.get('role')
        if not role:
            return jsonify({'error': 'Role required'}), 400

        # Capture the previous role so the audit entry records the transition.
        old_users = auth_manager.list_users() or {}
        old_role = (old_users.get(username) or {}).get('role')

        success, msg = auth_manager.update_user(username, role=role)
        if success:
            if audit_logger and old_role != role:
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
    @app.route('/api/dns-providers/accounts', methods=['GET', 'POST'])
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
            data = request.json
            name = data.get('name') or data.get('account_id')
            req_provider = provider or data.get('provider')
            config = data.get('config', {})

            if not name or not req_provider:
                return jsonify({'error': 'Account name and provider required'}), 400

            if dns_manager.add_account(name, req_provider, config):
                return jsonify({'message': 'Account added', 'id': name})
            return jsonify({'error': 'Failed to add account'}), 500
        except Exception as e:
            logger.error(f"Failed to add DNS account: {e}")
            return jsonify({'error': 'Failed to add account'}), 500

    @app.route('/api/dns/<string:provider>/accounts/<string:account_id>',
               methods=['DELETE', 'PUT'])
    @app.route('/api/dns-providers/accounts/<string:account_id>',
               methods=['DELETE', 'PUT'])
    @app.route('/api/web/settings/accounts/<string:account_id>',
               methods=['DELETE', 'PUT'])
    @auth_manager.require_role('admin')
    def api_dns_account_detail(account_id, provider=None):
        """Route for updating or deleting a DNS provider account"""
        if request.method == 'DELETE':
            if dns_manager.delete_account(provider, account_id):
                return jsonify({'message': 'Account deleted'})
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
                return jsonify({'message': 'Account updated', 'id': account_id})
            return jsonify({'error': 'Failed to update account'}), 500
        except Exception as e:
            logger.error(f"Failed to update DNS account: {e}")
            return jsonify({'error': 'Failed to update account'}), 500

    # ------------------------------------------------------------------ #
    # API Key management routes                                            #
    # ------------------------------------------------------------------ #

    @app.route('/api/keys', methods=['GET', 'POST'])
    @auth_manager_ref.require_role('admin')
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

            if not name:
                return jsonify({'error': 'Key name is required'}), 400
            if len(name) > 64:
                return jsonify({'error': 'Key name must be ≤ 64 characters'}), 400

            user = getattr(request, 'current_user', {}) or {}
            success, result_data = auth_manager_ref.create_api_key(
                name, role=role, expires_at=expires_at,
                created_by=user.get('username'),
                allowed_domains=allowed_domains,
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
            data = request.json
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
            return jsonify({
                'error': err or 'Invalid configuration or save failed'
            }), 400
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

    @app.route('/api/deploy/history', methods=['GET'])
    @auth_manager_ref.require_role('admin')
    def api_deploy_history():
        """Get deploy hook execution history"""
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 503

        try:
            limit = min(int(request.args.get('limit', 50)), 200)
            domain = request.args.get('domain')
            history = deploy_manager.get_history(limit=limit, domain=domain)
            return jsonify({'history': history})
        except Exception as e:
            logger.error(f"Failed to get deploy history: {e}")
            return jsonify({'error': 'Failed to get deploy history'}), 500
