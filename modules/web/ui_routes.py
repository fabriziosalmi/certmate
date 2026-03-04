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

def register_ui_routes(app, managers, require_web_auth):
    # Static file routes — serve images from static/img/ for well-known paths
    _img_dir = os.path.join(app.root_path, 'static', 'img')

    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon"""
        return send_from_directory(_img_dir, 'favicon.ico')

    @app.route('/certmate_logo.png')
    def logo():
        """Serve logo"""
        return send_from_directory(_img_dir, 'certmate_logo.png')

    @app.route('/certmate_logo_256.png')
    def logo_256():
        """Serve logo (256px)"""
        return send_from_directory(_img_dir, 'certmate_logo_256.png')

    @app.route('/apple-touch-icon.png')
    def apple_touch_icon():
        """Serve Apple touch icon"""
        return send_from_directory(_img_dir, 'apple-touch-icon.png')

    @app.route('/redoc/')
    @app.route('/redoc')
    def redoc():
        """Serve ReDoc API documentation UI"""
        # ReDoc uses external CDNs — override CSP for this route only
        html = '''<!DOCTYPE html>
<html><head><title>CertMate API - ReDoc</title>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
<style>body{margin:0;padding:0;}</style></head>
<body><redoc spec-url="/api/swagger.json"></redoc>
<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body></html>'''
        response = app.make_response((html, 200, {'Content-Type': 'text/html'}))
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.redoc.ly; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "worker-src blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )
        return response

    # ACME HTTP-01 challenge endpoint (no auth — ACME servers must reach it)
    @app.route('/.well-known/acme-challenge/<token>')
    def acme_challenge(token):
        """Serve HTTP-01 ACME challenge response files."""
        if not re.match(r'^[A-Za-z0-9_-]+$', token):
            return 'Invalid token', 400
        challenge_dir = Path(app.config.get('DATA_DIR', 'data')) / 'acme-challenges' / '.well-known' / 'acme-challenge'
        challenge_file = challenge_dir / token
        # Prevent path traversal
        try:
            challenge_file = challenge_file.resolve()
            if not str(challenge_file).startswith(str(challenge_dir.resolve())):
                return 'Invalid token', 400
        except (OSError, ValueError):
            return 'Invalid token', 400
        if not challenge_file.exists():
            return 'Not found', 404
        return challenge_file.read_text(), 200, {'Content-Type': 'text/plain'}

    # Main web interface routes
    @app.route('/')
    @require_web_auth
    def index():
        """Main dashboard page"""
        try:
            settings = settings_manager.load_settings()
            certificates = []

            # Get all domains from settings
            domains_from_settings = settings.get('domains', [])

            # Also check for certificates that exist on disk but might not be in settings
            cert_dirs = []
            cert_dir = certificate_manager.cert_dir
            if cert_dir.exists():
                cert_dirs = [d for d in cert_dir.iterdir() if d.is_dir()]

            # Create a set of all domains to check (from settings and disk)
            all_domains = set()

            # Add domains from settings
            for domain_config in domains_from_settings:
                if isinstance(domain_config, str):
                    domain_name = domain_config
                elif isinstance(domain_config, dict):
                    domain_name = domain_config.get('domain')
                else:
                    continue
                if domain_name:
                    all_domains.add(domain_name)

            # Add domains from disk (for backward compatibility with existing certificates)
            for cert_dir_path in cert_dirs:
                all_domains.add(cert_dir_path.name)

            # Get certificate info for all domains
            for domain_name in all_domains:
                if domain_name:
                    cert_info = certificate_manager.get_certificate_info(domain_name)
                    if cert_info:
                        certificates.append(cert_info)

            return render_template('index.html', certificates=certificates)
        except Exception as e:
            logger.error(f"Failed to load settings for index page: {e}")
            return render_template('index.html', certificates=[])

    @app.route('/settings')
    @require_web_auth
    def settings_page():
        """Settings configuration page"""
        return render_template('settings.html')

    @app.route('/help')
    @require_web_auth
    def help_page():
        """Help and documentation page"""
        return render_template('help.html')

    @app.route('/client-certificates')
    @require_web_auth
    def client_certificates_page():
        """Redirect to unified certificates page with client tab"""
        return redirect('/#client')

    @app.route('/activity')
    @require_web_auth
    def activity_page():
        """Activity timeline page"""
        return render_template('activity.html')

