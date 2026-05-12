import logging
from flask import request, jsonify

logger = logging.getLogger(__name__)


def register_settings_routes(app, managers, require_web_auth, auth_manager,
                             settings_manager, dns_manager):
    """Register settings-related routes"""
    auth_manager_ref = auth_manager
    deploy_manager = managers.get('deployer')

    @app.route('/api/settings', methods=['GET', 'POST'])
    @app.route('/api/web/settings', methods=['GET', 'POST'])
    @auth_manager.require_role('admin')
    def api_settings():
        """Get or update settings"""
        if request.method == 'GET':
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

        try:
            data = request.json
            if settings_manager.atomic_update(data):
                return jsonify({'message': 'Settings updated'})
            return jsonify({'error': 'Update failed'}), 500
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
            if auth_manager.delete_user(username):
                return jsonify({'message': 'User deleted'})
            return jsonify({'error': 'Deletion failed'}), 500

        data = request.json
        role = data.get('role')
        if not role:
            return jsonify({'error': 'Role required'}), 400

        if auth_manager.update_user(username, role=role):
            return jsonify({'message': 'User updated'})
        return jsonify({'error': 'Update failed'}), 500

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

            if not name:
                return jsonify({'error': 'Key name is required'}), 400
            if len(name) > 64:
                return jsonify({'error': 'Key name must be ≤ 64 characters'}), 400

            user = getattr(request, 'current_user', {})
            success, result_data = auth_manager_ref.create_api_key(
                name, role=role, expires_at=expires_at,
                created_by=user.get('username')
            )
            if success:
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
            if auth_manager_ref.revoke_api_key(key_id):
                return jsonify({'message': 'API key revoked'})
            return jsonify({'error': 'Key not found or already revoked'}), 404
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
            if 'error' in result:
                return jsonify(result), 404
            return jsonify(result)
        except Exception as e:
            logger.error(f"Failed to test deploy hook {hook_id}: {e}")
            return jsonify({'error': 'Failed to test deploy hook'}), 500

    @app.route('/api/deploy/history', methods=['GET'])
    @auth_manager_ref.require_role('admin')
    def api_deploy_history():
        """Get deploy hook execution history.

        Returns the history list directly (newest first), matching the
        sibling ``/api/webhooks/deliveries`` endpoint. The Settings →
        Deploy "Recent Executions" panel in ``static/js/settings-deploy.js``
        does ``Array.isArray(res.body)`` on the response — wrapping the
        list in ``{"history": [...]}`` made the panel render the
        "unexpected response" error reported in issue #137.
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
