import json
import logging
import os
import re
import tempfile
import zipfile
import concurrent.futures
from datetime import datetime
from functools import wraps
from pathlib import Path
from collections import defaultdict
from time import time
from flask import render_template, request, jsonify, send_file, send_from_directory, redirect, url_for, after_this_request, Response, stream_with_context

logger = logging.getLogger(__name__)

def register_settings_routes(app, managers, require_web_auth, auth_manager, settings_manager, dns_manager, _is_localhost):
    # Web-specific settings endpoints (no auth required for initial setup)
    @app.route('/api/web/settings', methods=['GET', 'POST'])
    def web_settings():
        """Web interface settings endpoint"""
        if request.method == 'GET':
            try:
                settings = settings_manager.load_settings()
                
                # Check if setup is completed
                setup_completed = settings.get('setup_completed', False)
                
                # For initial setup, return minimal safe settings
                if not setup_completed:
                    return jsonify({
                        'setup_completed': False,
                        'email': settings.get('email', ''),
                        'dns_provider': settings.get('dns_provider', 'cloudflare'),
                        'auto_renew': settings.get('auto_renew', True),
                        'domains': []
                    })
                
                # For completed setup, require auth (session cookie or Bearer token)
                # Allow bypass when auth is disabled (setup mode)
                authenticated = False
                if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
                    authenticated = True
                if not authenticated:
                    session_id = request.cookies.get('certmate_session')
                    if session_id and auth_manager.validate_session(session_id):
                        authenticated = True
                if not authenticated:
                    auth_header = request.headers.get('Authorization', '')
                    if auth_header.startswith('Bearer ') and auth_manager.validate_api_token(auth_header[7:]):
                        authenticated = True
                if not authenticated:
                    return jsonify({'error': 'Authentication required'}), 401
                
                # Return full settings (with sensitive data fully masked)
                safe_settings = dict(settings)
                if 'api_bearer_token' in safe_settings:
                    safe_settings['api_bearer_token'] = '********'
                
                return jsonify(safe_settings)
                
            except Exception as e:
                logger.error(f"Error getting web settings: {e}")
                return jsonify({'error': 'Failed to load settings'}), 500
        
        elif request.method == 'POST':
            try:
                new_settings = request.json
                if not new_settings:
                    return jsonify({'error': 'No settings provided'}), 400
                
                current_settings = settings_manager.load_settings()
                setup_completed = current_settings.get('setup_completed', False)

                if setup_completed:
                    # Require auth for updates after setup
                    # Allow bypass when auth is disabled (setup mode)
                    authenticated = False
                    if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
                        authenticated = True
                    if not authenticated:
                        session_id = request.cookies.get('certmate_session')
                        if session_id and auth_manager.validate_session(session_id):
                            authenticated = True
                    if not authenticated:
                        auth_header = request.headers.get('Authorization', '')
                        if auth_header.startswith('Bearer ') and auth_manager.validate_api_token(auth_header[7:]):
                            authenticated = True
                    if not authenticated:
                        return jsonify({'error': 'Authentication required'}), 401
                else:
                    # Initial setup: allow if auth is disabled (setup mode),
                    # or from localhost, or with valid token
                    if not (not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users()):
                        client_ip = request.remote_addr or ''
                        auth_header = request.headers.get('Authorization', '')
                        has_valid_token = False
                        if auth_header.startswith('Bearer '):
                            has_valid_token = auth_manager.validate_api_token(auth_header[7:])
                        if not _is_localhost(client_ip) and not has_valid_token:
                            logger.warning(f"Setup attempt from non-local IP: {client_ip}")
                            return jsonify({'error': 'Initial setup only allowed from localhost'}), 403
                
                # Strip masked/sentinel api_bearer_token from incoming data.
                # The GET endpoint masks it as '********', so if the UI sends
                # it back unchanged we must preserve the real token.
                incoming_token = new_settings.get('api_bearer_token', '')
                if not incoming_token or incoming_token == '********':
                    new_settings.pop('api_bearer_token', None)

                # Merge with existing settings
                merged_settings = {**current_settings, **new_settings}
                
                # Mark setup as completed if not already
                if not setup_completed and all(key in merged_settings and merged_settings[key] 
                                             for key in ['email', 'dns_provider']):
                    merged_settings['setup_completed'] = True
                
                # Save settings
                success = settings_manager.save_settings(merged_settings, "web_update")
                
                if success:
                    return jsonify({'message': 'Settings updated successfully'})
                else:
                    return jsonify({'error': 'Failed to save settings'}), 500
                    
            except Exception as e:
                logger.error(f"Error updating web settings: {e}")
                return jsonify({'error': 'Failed to update settings'}), 500

    # DNS Provider Account Management endpoints for web interface
    @app.route('/api/dns/<string:provider>/accounts', methods=['GET', 'POST'])
    @auth_manager.require_role('viewer')
    def web_dns_provider_accounts(provider):
        """Manage DNS provider accounts"""
        if request.method == 'POST':
            user = getattr(request, 'current_user', {})
            if ROLE_HIERARCHY.get(user.get('role'), -1) < ROLE_HIERARCHY['admin']:
                return jsonify({'error': 'admin privileges required', 'code': 'INSUFFICIENT_ROLE'}), 403
        if request.method == 'GET':
            try:
                accounts = dns_manager.list_dns_provider_accounts(provider)
                return jsonify(accounts)
            except Exception as e:
                logger.error(f"Error listing DNS accounts for {provider}: {e}")
                return jsonify({'error': 'Failed to list DNS accounts'}), 500
        
        elif request.method == 'POST':
            try:
                data = request.json
                account_id = data.get('account_id')
                account_config = data.get('config', {})
                
                if not account_id:
                    return jsonify({'error': 'Account ID is required'}), 400
                
                success = dns_manager.create_dns_account(provider, account_id, account_config)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} created/updated successfully'})
                else:
                    return jsonify({'error': 'Failed to create/update DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error creating DNS account for {provider}: {e}")
                return jsonify({'error': 'Failed to create DNS account'}), 500

    @app.route('/api/dns/<string:provider>/accounts/<string:account_id>', methods=['GET', 'PUT', 'DELETE'])
    @auth_manager.require_role('viewer')
    def web_dns_provider_account(provider, account_id):
        """Manage specific DNS provider account"""
        # Validate account_id to prevent path traversal
        if '..' in account_id or '/' in account_id or '\\' in account_id or '\x00' in account_id:
            return jsonify({'error': 'Invalid account ID'}), 400
        if '..' in provider or '/' in provider or '\\' in provider or '\x00' in provider:
            return jsonify({'error': 'Invalid provider'}), 400
        if request.method in ('PUT', 'DELETE'):
            user = getattr(request, 'current_user', {})
            if ROLE_HIERARCHY.get(user.get('role'), -1) < ROLE_HIERARCHY['admin']:
                return jsonify({'error': 'admin privileges required', 'code': 'INSUFFICIENT_ROLE'}), 403
        if request.method == 'GET':
            try:
                config, _ = dns_manager.get_dns_provider_account_config(provider, account_id)
                if config:
                    return jsonify(config)
                else:
                    return jsonify({'error': 'Account not found'}), 404
            except Exception as e:
                logger.error(f"Error getting DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to get DNS account'}), 500
        
        elif request.method == 'PUT':
            try:
                account_config = request.json
                if not account_config:
                    return jsonify({'error': 'Account configuration is required'}), 400
                
                success = dns_manager.create_dns_account(provider, account_id, account_config)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} updated successfully'})
                else:
                    return jsonify({'error': 'Failed to update DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error updating DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to update DNS account'}), 500
        
        elif request.method == 'DELETE':
            try:
                success = dns_manager.delete_dns_account(provider, account_id)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} deleted successfully'})
                else:
                    return jsonify({'error': 'Failed to delete DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error deleting DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to delete DNS account'}), 500

