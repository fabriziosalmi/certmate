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

def register_auth_routes(app, managers, require_web_auth, auth_manager, _check_login_rate_limit, _record_login_attempt):
    # Authentication endpoints for local login
    @app.route('/login', methods=['GET'])
    def login_page():
        """Login page"""
        # Check if local auth is enabled and has users
        if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
            # Redirect to main page if local auth not set up
            return redirect(url_for('index'))
        return render_template('login.html')
    
    @app.route('/api/auth/login', methods=['POST'])
    def api_login():
        """Login endpoint for local authentication"""
        try:
            # Rate limiting - prevent brute force attacks
            client_ip = request.remote_addr or 'unknown'
            allowed, retry_after = _check_login_rate_limit(client_ip)
            if not allowed:
                logger.warning(f"Login rate limit exceeded for IP: {client_ip}")
                response = jsonify({
                    'error': 'Too many login attempts. Please try again later.',
                    'retry_after': retry_after
                })
                response.headers['Retry-After'] = str(retry_after)
                return response, 429
            
            data = request.json
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return jsonify({'error': 'Username and password are required'}), 400
            
            # Check if local auth is enabled
            if not auth_manager.is_local_auth_enabled():
                return jsonify({'error': 'Local authentication is not enabled'}), 403
            
            # Record attempt before authentication
            _record_login_attempt(client_ip)
            
            # Authenticate user
            user_info = auth_manager.authenticate_user(username, password)
            
            if not user_info:
                return jsonify({'error': 'Invalid username or password'}), 401
            
            # Create session
            session_id = auth_manager.create_session(username)
            
            response = jsonify({
                'message': 'Login successful',
                'user': user_info
            })
            
            # Set session cookie with security flags
            # secure=True requires HTTPS (disabled for local dev, enable in production)
            # samesite='Strict' prevents CSRF attacks
            response.set_cookie(
                'certmate_session',
                session_id,
                httponly=True,
                secure=request.is_secure,  # Auto-enable on HTTPS
                samesite='Strict',
                path='/',
                max_age=8 * 60 * 60  # 8 hours
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': 'Login failed'}), 500
    
    @app.route('/api/auth/logout', methods=['POST'])
    def api_logout():
        """Logout endpoint"""
        try:
            session_id = request.cookies.get('certmate_session')
            if session_id:
                auth_manager.invalidate_session(session_id)
            
            response = jsonify({'message': 'Logged out successfully'})
            response.delete_cookie(
                'certmate_session',
                path='/',
                secure=request.is_secure,
                httponly=True,
                samesite='Strict'
            )
            return response
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return jsonify({'error': 'Logout failed'}), 500
    
    @app.route('/api/auth/me', methods=['GET'])
    def api_current_user():
        """Get current user info"""
        try:
            session_id = request.cookies.get('certmate_session')
            if session_id:
                user_info = auth_manager.validate_session(session_id)
                if user_info:
                    return jsonify({'user': user_info})
            
            return jsonify({'user': None}), 401
        except Exception as e:
            logger.error(f"Get current user error: {e}")
            return jsonify({'error': 'Failed to get user info'}), 500
    
    @app.route('/api/auth/token', methods=['GET'])
    @auth_manager.require_role('viewer')
    def api_get_token():
        """Get API bearer token (for settings page reveal button)"""
        try:
            settings = settings_manager.load_settings()
            token = settings.get('api_bearer_token', '')
            return jsonify({'token': token})
        except Exception as e:
            logger.error(f"Get token error: {e}")
            return jsonify({'error': 'Failed to get token'}), 500

    # Scoped API key management (admin only)
    @app.route('/api/keys', methods=['GET'])
    @auth_manager.require_role('admin')
    def api_list_keys():
        """List all scoped API keys (metadata only, no secrets)."""
        try:
            keys = auth_manager.list_api_keys()
            return jsonify({'keys': keys})
        except Exception as e:
            logger.error(f"Error listing API keys: {e}")
            return jsonify({'error': 'Failed to list API keys'}), 500

    @app.route('/api/keys', methods=['POST'])
    @auth_manager.require_role('admin')
    def api_create_key():
        """Create a new scoped API key. Returns the plaintext token once."""
        try:
            data = request.get_json(silent=True) or {}
            name = data.get('name', '').strip()
            role = data.get('role', 'viewer')
            expires_at = data.get('expires_at')

            if not name:
                return jsonify({'error': 'Key name is required'}), 400
            if len(name) > 64:
                return jsonify({'error': 'Key name must be 64 characters or less'}), 400
            if role not in ('viewer', 'operator', 'admin'):
                return jsonify({'error': 'Role must be viewer, operator, or admin'}), 400

            created_by = getattr(request, 'current_user', {}).get('username', 'unknown')
            success, result = auth_manager.create_api_key(
                name=name, role=role, expires_at=expires_at, created_by=created_by
            )

            if success:
                audit_logger = managers.get('audit')
                if audit_logger:
                    audit_logger.log_operation(
                        operation='create',
                        resource_type='api_key',
                        resource_id=result['id'],
                        status='success',
                        user=created_by,
                        ip_address=request.remote_addr
                    )
                return jsonify(result), 201
            return jsonify({'error': result}), 400
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            return jsonify({'error': 'Failed to create API key'}), 500

    @app.route('/api/keys/<string:key_id>', methods=['DELETE'])
    @auth_manager.require_role('admin')
    def api_revoke_key(key_id):
        """Revoke an API key."""
        try:
            success, message = auth_manager.revoke_api_key(key_id)
            if success:
                audit_logger = managers.get('audit')
                if audit_logger:
                    revoked_by = getattr(request, 'current_user', {}).get('username', 'unknown')
                    audit_logger.log_operation(
                        operation='revoke',
                        resource_type='api_key',
                        resource_id=key_id,
                        status='success',
                        user=revoked_by,
                        ip_address=request.remote_addr
                    )
                return jsonify({'message': message})
            return jsonify({'error': message}), 404
        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return jsonify({'error': 'Failed to revoke API key'}), 500

    # User management endpoints (admin only)
    @app.route('/api/users', methods=['GET', 'POST'])
    @auth_manager.require_admin
    def api_users():
        """List or create users"""
        if request.method == 'GET':
            try:
                users = auth_manager.list_users()
                return jsonify({'users': users})
            except Exception as e:
                logger.error(f"Error listing users: {e}")
                return jsonify({'error': 'Failed to list users'}), 500
        
        elif request.method == 'POST':
            try:
                data = request.json
                username = data.get('username', '').strip()
                password = data.get('password', '')
                role = data.get('role', 'user')
                email = data.get('email', '').strip() or None
                
                if not username or not password:
                    return jsonify({'error': 'Username and password are required'}), 400
                
                if role not in ['admin', 'user']:
                    return jsonify({'error': 'Role must be admin or user'}), 400
                
                success, message = auth_manager.create_user(username, password, role, email)
                
                if success:
                    return jsonify({'message': message})
                else:
                    return jsonify({'error': message}), 400
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return jsonify({'error': 'Failed to create user'}), 500
    
    @app.route('/api/users/<string:username>', methods=['GET', 'PUT', 'DELETE'])
    @auth_manager.require_admin
    def api_user(username):
        """Get, update, or delete a specific user"""
        if request.method == 'GET':
            try:
                users = auth_manager.list_users()
                if username not in users:
                    return jsonify({'error': 'User not found'}), 404
                return jsonify({'user': {username: users[username]}})
            except Exception as e:
                logger.error(f"Error getting user: {e}")
                return jsonify({'error': 'Failed to get user'}), 500
        
        elif request.method == 'PUT':
            try:
                data = request.json
                password = data.get('password')
                role = data.get('role')
                email = data.get('email')
                enabled = data.get('enabled')
                
                if role and role not in ['admin', 'user']:
                    return jsonify({'error': 'Role must be admin or user'}), 400
                
                success, message = auth_manager.update_user(
                    username, password=password, role=role, email=email, enabled=enabled
                )
                
                if success:
                    return jsonify({'message': message})
                else:
                    return jsonify({'error': message}), 400
            except Exception as e:
                logger.error(f"Error updating user: {e}")
                return jsonify({'error': 'Failed to update user'}), 500
        
        elif request.method == 'DELETE':
            try:
                success, message = auth_manager.delete_user(username)
                
                if success:
                    return jsonify({'message': message})
                else:
                    return jsonify({'error': message}), 400
            except Exception as e:
                logger.error(f"Error deleting user: {e}")
                return jsonify({'error': 'Failed to delete user'}), 500
    
    @app.route('/api/auth/config', methods=['GET', 'POST'])
    @auth_manager.require_role('viewer')
    def api_auth_config():
        """Get or update authentication configuration"""
        if request.method == 'POST':
            user = getattr(request, 'current_user', {})
            if ROLE_HIERARCHY.get(user.get('role'), -1) < ROLE_HIERARCHY['admin']:
                return jsonify({'error': 'admin privileges required', 'code': 'INSUFFICIENT_ROLE'}), 403
        if request.method == 'GET':
            try:
                return jsonify({
                    'local_auth_enabled': auth_manager.is_local_auth_enabled(),
                    'has_users': auth_manager.has_any_users()
                })
            except Exception as e:
                logger.error(f"Error getting auth config: {e}")
                return jsonify({'error': 'Failed to get auth config'}), 500
        
        elif request.method == 'POST':
            try:
                data = request.json
                enable = data.get('local_auth_enabled', False)
                
                # Require at least one admin user before enabling local auth
                if enable and not auth_manager.has_any_users():
                    return jsonify({'error': 'Create at least one admin user before enabling local auth'}), 400
                
                if auth_manager.enable_local_auth(enable):
                    return jsonify({'message': f'Local authentication {"enabled" if enable else "disabled"}'})
                else:
                    return jsonify({'error': 'Failed to update auth config'}), 500
            except Exception as e:
                logger.error(f"Error updating auth config: {e}")
                return jsonify({'error': 'Failed to update auth config'}), 500

