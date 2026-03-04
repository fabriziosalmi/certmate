"""
CertMate - Modular SSL Certificate Management Application
Main application entry point with modular architecture
"""
__version__ = '2.2.0'
import os
import sys
import logging
from flask import Flask, request

# Import new modular components
from modules.core import configure_structured_logging, get_certmate_logger
from modules.core.factory import create_app

# Configure structured JSON logging
json_logging = os.getenv('CERTMATE_LOG_JSON', 'true').lower() == 'true'
log_level = getattr(logging, os.getenv('CERTMATE_LOG_LEVEL', 'INFO').upper(), logging.INFO)
configure_structured_logging(level=log_level, json_output=json_logging)
logger = get_certmate_logger('app')

# Global app instance for WSGI servers
try:
    app, container = create_app()
except Exception as e:
    logger.error(f"Failed to initialize CertMate app: {e}")
    sys.exit(1)

# =============================================
# COMPATIBILITY LAYER FOR TESTS
# =============================================
class _LegacyAppWrapper:
    def __init__(self, flask_app, di_container):
        self.app = flask_app
        self.managers = di_container.managers
        self.scheduler = di_container.scheduler
        self.cert_dir = di_container.cert_dir
        self.data_dir = di_container.data_dir
        self.backup_dir = di_container.backup_dir
        self.logs_dir = di_container.logs_dir
        
    def get_app(self):
        return self.app

certmate_app = _LegacyAppWrapper(app, container)

# Directory variables (for test compatibility)
CERT_DIR = certmate_app.cert_dir
DATA_DIR = certmate_app.data_dir
BACKUP_DIR = certmate_app.backup_dir
LOGS_DIR = certmate_app.logs_dir

# Settings file path for test compatibility
SETTINGS_FILE = certmate_app.data_dir / "settings.json"

# Function aliases for test compatibility
def require_auth(f):
    from functools import wraps
    from flask import request
    import secrets
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return {'error': 'Authorization header required', 'code': 'AUTH_HEADER_MISSING'}, 401
            
            try:
                scheme, token = auth_header.split(' ', 1)
                if scheme.lower() != 'bearer':
                    return {'error': 'Invalid authorization scheme. Use Bearer token', 'code': 'INVALID_AUTH_SCHEME'}, 401
                if not token.strip():
                    return {'error': 'Invalid authorization header format', 'code': 'INVALID_AUTH_FORMAT'}, 401
            except ValueError:
                return {'error': 'Invalid authorization header format', 'code': 'INVALID_AUTH_FORMAT'}, 401
            
            settings = load_settings()
            expected_token = settings.get('api_bearer_token')
            
            if not expected_token:
                return {'error': 'Server config error: no API token configured', 'code': 'SERVER_CONFIG_ERROR'}, 500
                
            is_valid, validation_error = validate_api_token(expected_token)
            if not is_valid:
                return {'error': 'Server security config error', 'code': 'WEAK_SERVER_TOKEN'}, 500
            
            if not secrets.compare_digest(token, expected_token):
                return {'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}, 401
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return {'error': 'Authentication failed', 'code': 'AUTH_ERROR'}, 401
    return decorated_function

def load_settings():
    return certmate_app.managers['settings'].load_settings()

def save_settings(settings, backup_reason="manual"):
    return certmate_app.managers['settings'].save_settings(settings, backup_reason)

def safe_file_read(file_path, is_json=False, default=None):
    return certmate_app.managers['file_ops'].safe_file_read(file_path, is_json, default)

def safe_file_write(file_path, data, is_json=True):
    return certmate_app.managers['file_ops'].safe_file_write(file_path, data, is_json)

def get_certificate_info(domain):
    return certmate_app.managers['certificates'].get_certificate_info(domain)

def create_certificate(domain, email, dns_provider=None, dns_config=None, account_id=None, staging=False):
    try:
        result = certmate_app.managers['certificates'].create_certificate(
            domain, email, dns_provider, dns_config, account_id, staging
        )
        if isinstance(result, dict) and result.get('success'):
            return True, f"Certificate created successfully for {domain}"
        else:
            return False, f"Certificate creation failed for {domain}"
    except Exception as e:
        error_msg = str(e)
        if "subprocess" in error_msg.lower() and "failed" in error_msg.lower():
            error_msg = f"Subprocess error: {error_msg}"
        return False, error_msg

def create_certificate_legacy(domain, email, cloudflare_token):
    try:
        result = certmate_app.managers['certificates'].create_certificate_legacy(domain, email, cloudflare_token)
        if isinstance(result, tuple):
            return result
        elif isinstance(result, dict) and result.get('success'):
            return True, f"Certificate created successfully for {domain}"
        else:
            return False, f"Certificate creation failed for {domain}"
    except Exception as e:
        return False, str(e)

def renew_certificate(domain):
    if not domain:
        return False, "Domain cannot be empty"
    try:
        result = certmate_app.managers['certificates'].renew_certificate(domain)
        if isinstance(result, dict) and result.get('success'):
            return True, "Certificate renewed successfully"
        else:
            return False, "Renewal failed: Certificate not found"
    except Exception as e:
        error_msg = str(e)
        if "Renewal failed:" in error_msg:
            return False, error_msg
        elif "Exception:" in error_msg:
            return False, error_msg
        else:
            return False, f"Exception: {error_msg}"

def check_renewals():
    return certmate_app.managers['certificates'].check_renewals()

def migrate_dns_providers_to_multi_account(settings):
    return certmate_app.managers['settings'].migrate_dns_providers_to_multi_account(settings)

def migrate_domains_format(settings):
    return certmate_app.managers['settings'].migrate_domains_format(settings)

def get_domain_dns_provider(domain, settings=None):
    return certmate_app.managers['settings'].get_domain_dns_provider(domain, settings)

def get_dns_provider_account_config(provider, account_id=None, settings=None):
    if settings is None:
        settings = load_settings()
    return certmate_app.managers['dns'].get_dns_provider_account_config(provider, account_id, settings)

def list_dns_provider_accounts(provider, settings=None):
    if settings is None:
        settings = load_settings()
    return certmate_app.managers['dns'].list_dns_provider_accounts(provider, settings)

def suggest_dns_provider_for_domain(domain, settings=None):
    return certmate_app.managers['dns'].suggest_dns_provider_for_domain(domain, settings)

# Import validation functions from modules.core.utils for test compatibility
from modules.core.utils import (
    validate_email, validate_domain, validate_api_token, validate_dns_provider_account
)

# Import DNS configuration functions for test compatibility  
from modules.core.utils import (
    create_cloudflare_config, create_azure_config, create_google_config,
    create_powerdns_config, create_digitalocean_config, create_linode_config,
    create_gandi_config, create_ovh_config, create_namecheap_config,
    create_arvancloud_config, create_acme_dns_config,
    create_multi_provider_config
)

# Import metrics functions for test compatibility
from modules.core.metrics import (
    metrics_collector, generate_metrics_response, get_metrics_summary, is_prometheus_available
)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='CertMate SSL Certificate Management')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='Set logging level')
    
    args = parser.parse_args()

    if args.debug and os.getenv('FLASK_ENV') == 'production':
        print("ERROR: Debug mode cannot be enabled in production")
        sys.exit(1)

    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    try:
        print(f"🚀 Starting CertMate on {args.host}:{args.port}")
        print(f"📊 Debug mode: {'enabled' if args.debug else 'disabled'}")
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\\n🛑 Shutting down CertMate...")
        if container.scheduler:
            try:
                container.scheduler.shutdown()
                print("📅 Background scheduler stopped")
            except Exception as e:
                pass
        sys.exit(0)
