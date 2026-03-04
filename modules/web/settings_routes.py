from flask import request, jsonify


def register_settings_routes(app, managers, require_web_auth, auth_manager,
                             settings_manager, dns_manager):
    """Register settings-related routes"""

    @app.route('/api/settings', methods=['GET', 'POST'])
    @app.route('/api/web/settings', methods=['GET', 'POST'])
    @auth_manager.require_role('admin')
    def api_settings():
        """Get or update settings"""
        if request.method == 'GET':
            try:
                settings = settings_manager.load_settings()
                return jsonify(settings)
            except Exception as e:
                return jsonify({'error': f"Failed to load settings: {e}"}), 500

        try:
            data = request.json
            if settings_manager.save_settings(data):
                return jsonify({'message': 'Settings updated'})
            return jsonify({'error': 'Update failed'}), 500
        except Exception as e:
            return jsonify({'error': f"Failed to update settings: {e}"}), 500

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

        if auth_manager.create_user(username, password, role):
            return jsonify({'message': 'User created'})
        return jsonify({'error': 'User creation failed'}), 500

    @app.route('/api/users/<string:username>', methods=['DELETE', 'PUT'])
    @app.route('/api/web/settings/users/<string:username>',
               methods=['DELETE', 'PUT'])
    @auth_manager.require_role('admin')
    def api_user_edit(username):
        """Edit or delete user"""
        if request.method == 'DELETE':
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
            return jsonify({'error': str(e)}), 500

    @app.route('/api/dns/<string:provider>/accounts/<string:account_id>',
               methods=['DELETE'])
    @app.route('/api/dns-providers/accounts/<string:account_id>',
               methods=['DELETE'])
    @app.route('/api/web/settings/accounts/<string:account_id>',
               methods=['DELETE'])
    @auth_manager.require_role('admin')
    def api_dns_account_delete(account_id, provider=None):
        """Route for deleting a DNS provider account"""
        if dns_manager.delete_account(provider, account_id):
            return jsonify({'message': 'Account deleted'})
        return jsonify({'error': 'Failure to delete account'}), 500
