from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flask_restx import Api, Resource, fields, Namespace
from functools import wraps
import os
import json
import subprocess
import tempfile
import time
import zipfile
import shutil
from datetime import datetime, timedelta
import threading
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from pathlib import Path
import ssl
import socket
from urllib.parse import urlparse
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import fcntl  # For file locking
import re
import secrets
import atexit
import string

# Import custom modules
from modules.utils import (
    DeploymentStatusCache, generate_secure_token, validate_email, validate_domain, validate_api_token,
    validate_dns_provider_account, 
    create_cloudflare_config, create_azure_config, create_google_config,
    create_powerdns_config, create_digitalocean_config, create_linode_config,
    create_gandi_config, create_ovh_config, create_namecheap_config,
    create_multi_provider_config
)

# Backup constants
BACKUP_RETENTION_DAYS = 30  # Keep backups for 30 days
MAX_BACKUPS_PER_TYPE = 50   # Maximum number of backups to keep per type

def safe_file_read(file_path, is_json=False, default=None):
    """Safely read a file with proper error handling and file locking"""
    try:
        # Validate file path to prevent path traversal
        file_path = Path(file_path).resolve()
        
        # Ensure the file is within allowed directories
        allowed_dirs = [DATA_DIR.resolve(), CERT_DIR.resolve(), BACKUP_DIR.resolve()]
        if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in allowed_dirs):
            logger.error(f"Access denied: file outside allowed directories: {file_path}")
            return default
        
        if not file_path.exists():
            return default
            
        with open(file_path, 'r', encoding='utf-8') as f:
            # Use file locking for safety
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                content = f.read()
                if is_json:
                    return json.loads(content) if content.strip() else default
                return content
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                
    except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return default
    except Exception as e:
        logger.error(f"Unexpected error reading file {file_path}: {e}")
        return default

def safe_file_write(file_path, data, is_json=True):
    """Safely write data to a file with proper error handling and atomic operations"""
    try:
        # Validate file path to prevent path traversal
        file_path = Path(file_path).resolve()
        
        # Ensure the file is within allowed directories
        allowed_dirs = [DATA_DIR.resolve(), CERT_DIR.resolve(), BACKUP_DIR.resolve()]
        if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in allowed_dirs):
            logger.error(f"Access denied: file outside allowed directories: {file_path}")
            return False
        
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use temporary file for atomic writes
        temp_file = Path(f"{file_path}.tmp")
        
        with open(temp_file, 'w', encoding='utf-8') as f:
            # Use file locking for safety
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                if is_json:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                else:
                    f.write(str(data))
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        
        # Atomic move
        temp_file.rename(file_path)
        
        # Set proper permissions
        os.chmod(file_path, 0o600)
        
        return True
        
    except (PermissionError, OSError) as e:
        logger.error(f"Error writing file {file_path}: {e}")
        # Clean up temp file if it exists
        if temp_file.exists():
            temp_file.unlink(missing_ok=True)
        return False
    except Exception as e:
        logger.error(f"Unexpected error writing file {file_path}: {e}")
        # Clean up temp file if it exists
        if temp_file.exists():
            temp_file.unlink(missing_ok=True)
        return False


# Initialize Flask app
app = Flask(__name__)
# Generate a secure random secret key if not provided
default_secret = os.urandom(32).hex() if not os.getenv('SECRET_KEY') else 'your-secret-key-here'
app.secret_key = os.getenv('SECRET_KEY', default_secret)
CORS(app)

# Initialize Flask-RESTX
api = Api(
    app,
    version='1.1.12',
    title='CertMate API',
    description='SSL Certificate Management API',
    doc='/docs/',
    prefix='/api'
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Directories with proper error handling
try:
    CERT_DIR = Path("certificates")
    DATA_DIR = Path("data")
    BACKUP_DIR = Path("backups") # New backup directory
    LOGS_DIR = Path("logs")
    
    # Create directories if they don't exist
    for directory in [CERT_DIR, DATA_DIR, BACKUP_DIR, LOGS_DIR]:
        directory.mkdir(exist_ok=True)
        logger.info(f"Ensured directory exists: {directory}")
    
    # Create backup subdirectories
    (BACKUP_DIR / "settings").mkdir(exist_ok=True)
    (BACKUP_DIR / "certificates").mkdir(exist_ok=True)
    logger.info(f"Backup directories created: {BACKUP_DIR}")
    
    # Test write permissions
    for directory in [CERT_DIR, DATA_DIR, BACKUP_DIR, LOGS_DIR]:
        if not os.access(directory, os.W_OK):
            logger.error(f"No write permission for directory: {directory}")
        
except Exception as e:
    logger.error(f"Failed to create required directories: {e}")
    # Use temporary directories as fallback
    CERT_DIR = Path(tempfile.mkdtemp(prefix="certmate_certs_"))
    DATA_DIR = Path(tempfile.mkdtemp(prefix="certmate_data_"))
    BACKUP_DIR = Path(tempfile.mkdtemp(prefix="certmate_backups_"))
    logger.warning(f"Using temporary directories - data may not persist")

# Settings file
SETTINGS_FILE = DATA_DIR / "settings.json"

# Initialize scheduler with error handling
try:
    scheduler = BackgroundScheduler()
    scheduler.start()
    logger.info("Background scheduler started successfully")
except Exception as e:
    logger.error(f"Failed to start background scheduler: {e}")
    scheduler = None

def load_settings():
    """Load settings from file with improved error handling"""
    default_settings = {
        'cloudflare_token': '',
        'domains': [],
        'email': '',
        'auto_renew': True,
        'api_bearer_token': os.getenv('API_BEARER_TOKEN') or generate_secure_token(),
        'setup_completed': False,  # Track if initial setup is done
        'dns_provider': 'cloudflare',
        'dns_providers': {}  # Start with empty DNS providers - only add what's actually configured
    }
    
    # Only create full template for first-time setup
    first_time_template = {
        'cloudflare_token': '',
        'domains': [],
        'email': '',
        'auto_renew': True,
        'api_bearer_token': os.getenv('API_BEARER_TOKEN') or generate_secure_token(),
        'setup_completed': False,
        'dns_provider': 'cloudflare',
        'dns_providers': {
            'cloudflare': {'api_token': ''},
            'route53': {'access_key_id': '', 'secret_access_key': '', 'region': 'us-east-1'},
            'azure': {'subscription_id': '', 'resource_group': '', 'tenant_id': '', 'client_id': '', 'client_secret': ''},
            'google': {'project_id': '', 'service_account_key': ''},
            'powerdns': {'api_url': '', 'api_key': ''},
            'digitalocean': {'api_token': ''},
            'linode': {'api_key': ''},
            'gandi': {'api_token': ''},
            'ovh': {'endpoint': '', 'application_key': '', 'application_secret': '', 'consumer_key': ''},
            'namecheap': {'username': '', 'api_key': ''}
        }
    }
    
    if not SETTINGS_FILE.exists():
        # First time setup - create with full template for web UI
        logger.info("Creating initial settings file with full provider template for first-time setup")
        save_settings(first_time_template)
        return first_time_template
    
    try:
        settings = safe_file_read(SETTINGS_FILE, is_json=True)
        if settings is None:
            logger.warning("Failed to read settings, using defaults")
            return default_settings
            
        # Only merge essential missing keys, NOT the full dns_providers template
        essential_keys = ['cloudflare_token', 'domains', 'email', 'auto_renew', 'api_bearer_token', 'setup_completed', 'dns_provider']
        for key in essential_keys:
            if key not in settings:
                settings[key] = default_settings[key]
        
        # Ensure dns_providers exists but don't overwrite with empty template
        if 'dns_providers' not in settings:
            settings['dns_providers'] = {}
                
        # Validate critical settings
        if settings.get('api_bearer_token') in ['change-this-token', 'certmate-api-token-12345', '']:
            logger.warning("Insecure API token detected, generating new one")
            settings['api_bearer_token'] = generate_secure_token()
            save_settings(settings)
            
        return settings
        
    except Exception as e:
        logger.error(f"Error loading settings: {e}")
        return default_settings

def save_settings(settings, backup_reason="auto_save"):
    """Save settings to file with improved error handling, validation, and automatic backup"""
    try:
        # Create backup before saving if settings file exists
        if SETTINGS_FILE.exists():
            current_settings = safe_file_read(SETTINGS_FILE, is_json=True)
            if current_settings:
                create_settings_backup(current_settings, backup_reason)
        
        # Validate critical settings before saving
        if 'email' in settings and settings['email']:
            is_valid, email_or_error = validate_email(settings['email'])
            if not is_valid:
                logger.error(f"Invalid email in settings: {email_or_error}")
                return False
            settings['email'] = email_or_error
            
        if 'api_bearer_token' in settings:
            is_valid, token_or_error = validate_api_token(settings['api_bearer_token'])
            if not is_valid:
                logger.error(f"Invalid API token: {token_or_error}")
                return False
                
        # Validate domains
        if 'domains' in settings:
            validated_domains = []
            for domain_entry in settings['domains']:
                if isinstance(domain_entry, str):
                    is_valid, domain_or_error = validate_domain(domain_entry)
                    if is_valid:
                        validated_domains.append(domain_or_error)
                    else:
                        logger.warning(f"Invalid domain skipped: {domain_or_error}")
                elif isinstance(domain_entry, dict) and 'domain' in domain_entry:
                    is_valid, domain_or_error = validate_domain(domain_entry['domain'])
                    if is_valid:
                        domain_entry['domain'] = domain_or_error
                        validated_domains.append(domain_entry)
                    else:
                        logger.warning(f"Invalid domain in object skipped: {domain_or_error}")
            settings['domains'] = validated_domains
        
        # Save settings
        result = safe_file_write(SETTINGS_FILE, settings)
        
        if result:
            logger.info(f"Settings saved successfully (backup reason: {backup_reason})")
        
        return result
        
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return False

def require_auth(f):
    """Enhanced decorator to require bearer token authentication"""
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
                    return {'error': 'Invalid authorization header format. Use: Bearer <token>', 'code': 'INVALID_AUTH_FORMAT'}, 401
            except ValueError:
                return {'error': 'Invalid authorization header format. Use: Bearer <token>', 'code': 'INVALID_AUTH_FORMAT'}, 401
            
            settings = load_settings()
            expected_token = settings.get('api_bearer_token')
            
            if not expected_token:
                return {'error': 'Server configuration error: no API token configured', 'code': 'SERVER_CONFIG_ERROR'}, 500
                
            # Validate token strength
            is_valid, validation_error = validate_api_token(expected_token)
            if not is_valid:
                logger.error(f"Server has weak API token: {validation_error}")
                return {'error': 'Server security configuration error', 'code': 'WEAK_SERVER_TOKEN'}, 500
            
            if not secrets.compare_digest(token, expected_token):
                logger.warning(f"Invalid token attempt from {request.remote_addr}")
                return {'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}, 401
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return {'error': 'Authentication failed', 'code': 'AUTH_ERROR'}, 401
    return decorated_function


def get_certificate_info(domain):
    """Get certificate information for a domain"""
    if not domain:
        return None
    
    cert_path = CERT_DIR / domain
    if not cert_path.exists():
        return {
            'domain': domain,
            'exists': False,
            'expiry_date': None,
            'days_left': None,
            'days_until_expiry': None,
            'needs_renewal': False,
            'dns_provider': None
        }
    
    cert_file = cert_path / "cert.pem"
    if not cert_file.exists():
        return {
            'domain': domain,
            'exists': False,
            'expiry_date': None,
            'days_left': None,
            'days_until_expiry': None,
            'needs_renewal': False,
            'dns_provider': None
        }
    
    # Get DNS provider info from settings
    settings = load_settings()
    dns_provider = get_domain_dns_provider(domain, settings)
    
    try:
        # Get certificate expiry using openssl
        result = subprocess.run([
            'openssl', 'x509', '-in', str(cert_file), '-noout', '-dates'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            not_after = None
            for line in lines:
                if line.startswith('notAfter='):
                    not_after = line.split('=', 1)[1]
                    break
            
            if not_after:
                # Parse the date
                from datetime import datetime
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days
                    
                    return {
                        'domain': domain,
                        'exists': True,
                        'expiry_date': expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                        'days_left': days_left,
                        'days_until_expiry': days_left,
                        'needs_renewal': days_left < 30,
                        'dns_provider': dns_provider
                    }
                except Exception as e:
                    logger.error(f"Error parsing certificate date: {e}")
    except Exception as e:
        logger.error(f"Error getting certificate info: {e}")
    
    return {
        'domain': domain,
        'exists': False,
        'expiry_date': None,
        'days_left': None,
        'days_until_expiry': None,
        'needs_renewal': False,
        'dns_provider': dns_provider
    }

def create_certificate(domain, email, dns_provider=None, dns_config=None, account_id=None, staging=False):
    """Create SSL certificate using Let's Encrypt with configurable DNS challenge
    
    Args:
        domain: Domain name for certificate
        email: Contact email for Let's Encrypt
        dns_provider: DNS provider name (e.g., 'cloudflare')
        dns_config: Explicit DNS configuration (overrides account lookup)
        account_id: Specific account ID to use for the DNS provider
        staging: Use Let's Encrypt staging environment for testing
    """
    # Track if we set Route53 environment variables for cleanup
    route53_env_set = False
    
    try:
        # Enhanced input validation
        if not domain or not isinstance(domain, str):
            return False, "Invalid domain provided"
            
        # Validate domain format and security
        is_valid_domain, domain_error = validate_domain(domain)
        if not is_valid_domain:
            return False, f"Domain validation failed: {domain_error}"
        domain = domain_error  # validated domain
        
        # Validate email
        is_valid_email, email_error = validate_email(email)
        if not is_valid_email:
            return False, f"Email validation failed: {email_error}"
        email = email_error  # validated email
        
        # Load settings to get DNS provider configuration
        settings = load_settings()
        
        # Use provided DNS provider or fall back to settings
        if not dns_provider:
            dns_provider = settings.get('dns_provider', 'cloudflare')
        
        # Get DNS provider account configuration
        if not dns_config:
            account_config, used_account_id = get_dns_provider_account_config(
                dns_provider, account_id, settings
            )
            if not account_config:
                return False, f"DNS provider '{dns_provider}' account '{account_id or 'default'}' not configured"
            
            dns_config = account_config
            logger.info(f"Using {dns_provider} account '{used_account_id}' for domain {domain}")
        else:
            # If explicit config provided, validate it
            is_valid, validation_error = validate_dns_provider_account(dns_provider, account_id or 'explicit', dns_config)
            if not is_valid:
                return False, f"DNS configuration validation failed: {validation_error}"
        
        # Create config file based on DNS provider
        config_file = None
        dns_plugin = None
        dns_args = []
        
        if dns_provider == 'cloudflare':
            token = dns_config.get('api_token') or settings.get('cloudflare_token', '')  # Backward compatibility
            if not token:
                return False, "Cloudflare API token not configured"
            config_file = create_cloudflare_config(token)
            dns_plugin = 'cloudflare'
            dns_args = ['--dns-cloudflare-credentials', str(config_file), '--dns-cloudflare-propagation-seconds', '60']
            
        elif dns_provider == 'route53':
            access_key = dns_config.get('access_key_id', '')
            secret_key = dns_config.get('secret_access_key', '')
            region = dns_config.get('region', 'us-east-1')  # Default region
            if not access_key or not secret_key:
                return False, "AWS Route53 credentials not configured"
            
            # Route53 plugin uses environment variables, not a credentials file
            os.environ['AWS_ACCESS_KEY_ID'] = access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
            os.environ['AWS_DEFAULT_REGION'] = region
            route53_env_set = True
            
            dns_plugin = 'route53'
            dns_args = []  # Route53 plugin doesn't use credentials file arguments
            
        elif dns_provider == 'azure':
            subscription_id = dns_config.get('subscription_id', '')
            resource_group = dns_config.get('resource_group', '')
            tenant_id = dns_config.get('tenant_id', '')
            client_id = dns_config.get('client_id', '')
            client_secret = dns_config.get('client_secret', '')
            if not all([subscription_id, resource_group, tenant_id, client_id, client_secret]):
                return False, "Azure DNS credentials not fully configured"
            config_file = create_azure_config(subscription_id, resource_group, tenant_id, client_id, client_secret)
            dns_plugin = 'azure'
            dns_args = ['--dns-azure-credentials', str(config_file)]
            
        elif dns_provider == 'google':
            project_id = dns_config.get('project_id', '')
            service_account_key = dns_config.get('service_account_key', '')
            if not project_id or not service_account_key:
                return False, "Google Cloud DNS credentials not configured"
            config_file = create_google_config(project_id, service_account_key)
            dns_plugin = 'google'
            dns_args = ['--dns-google-credentials', str(config_file)]
            
        elif dns_provider == 'powerdns':
            api_url = dns_config.get('api_url', '')
            api_key = dns_config.get('api_key', '')
            if not api_url or not api_key:
                return False, "PowerDNS credentials not configured"
            config_file = create_powerdns_config(api_url, api_key)
            dns_plugin = 'powerdns'
            dns_args = ['--dns-powerdns-credentials', str(config_file)]
            
        elif dns_provider == 'digitalocean':
            api_token = dns_config.get('api_token', '')
            if not api_token:
                return False, "DigitalOcean API token not configured"
            config_file = create_digitalocean_config(api_token)
            dns_plugin = 'digitalocean'
            dns_args = ['--dns-digitalocean-credentials', str(config_file)]
            
        elif dns_provider == 'linode':
            api_key = dns_config.get('api_key', '')
            if not api_key:
                return False, "Linode API key not configured"
            config_file = create_linode_config(api_key)
            dns_plugin = 'linode'
            dns_args = ['--dns-linode-credentials', str(config_file)]
            
        elif dns_provider == 'gandi':
            api_token = dns_config.get('api_token', '')
            if not api_token:
                return False, "Gandi API token not configured"
            config_file = create_gandi_config(api_token)
            dns_plugin = 'gandi'
            dns_args = ['--dns-gandi-credentials', str(config_file)]
            
        elif dns_provider == 'ovh':
            endpoint = dns_config.get('endpoint', '')
            application_key = dns_config.get('application_key', '')
            application_secret = dns_config.get('application_secret', '')
            consumer_key = dns_config.get('consumer_key', '')
            if not all([endpoint, application_key, application_secret, consumer_key]):
                return False, "OVH credentials not fully configured"
            config_file = create_ovh_config(endpoint, application_key, application_secret, consumer_key)
            dns_plugin = 'ovh'
            dns_args = ['--dns-ovh-credentials', str(config_file)]
            
        elif dns_provider == 'namecheap':
            username = dns_config.get('username', '')
            api_key = dns_config.get('api_key', '')
            if not username or not api_key:
                return False, "Namecheap credentials not configured"
            config_file = create_namecheap_config(username, api_key)
            dns_plugin = 'namecheap'
            dns_args = ['--dns-namecheap-credentials', str(config_file)]
            
        else:
            # Try to use individual plugins for additional providers
            if not dns_config:
                return False, f"DNS provider '{dns_provider}' requires configuration"
            
            try:
                config_file = create_multi_provider_config(dns_provider, dns_config)
                if config_file is None:
                    # Provider doesn't have individual plugin - not supported in this version
                    return False, f"DNS provider '{dns_provider}' is not supported. Please use one of the supported providers: cloudflare, route53, azure, google, powerdns, digitalocean, linode, gandi, ovh, namecheap, vultr, dnsmadeeasy, nsone, rfc2136, hetzner, porkbun, godaddy, he-ddns, dynudns"
                
                # Determine the plugin name based on provider
                plugin_map = {
                    'vultr': 'vultr',
                    'dnsmadeeasy': 'dnsmadeeasy',
                    'nsone': 'nsone',
                    'rfc2136': 'rfc2136',
                    'hetzner': 'hetzner',
                    'porkbun': 'porkbun',
                    'godaddy': 'godaddy',
                    'he-ddns': 'he-ddns',
                    'dynudns': 'dynudns'
                }
                
                dns_plugin = plugin_map.get(dns_provider, dns_provider)
                dns_args = [f'--dns-{dns_plugin}-credentials', str(config_file)]
                logger.info(f"Using certbot-dns-{dns_plugin} for provider: {dns_provider}")
                
            except Exception as e:
                logger.error(f"Failed to configure DNS provider {dns_provider}: {e}")
                return False, f"Failed to configure DNS provider '{dns_provider}': {str(e)}"
        
        # Create local directories for certbot
        letsencrypt_dir = Path("letsencrypt")
        config_dir = letsencrypt_dir / "config"
        work_dir = letsencrypt_dir / "work"
        logs_dir = letsencrypt_dir / "logs"
        
        # Create directories if they don't exist
        config_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare certbot command with local directories
        cmd = [
            'certbot', 'certonly',
            '--config-dir', str(config_dir),
            '--work-dir', str(work_dir),
            '--logs-dir', str(logs_dir),
            f'--dns-{dns_plugin}',
            *dns_args,
            '--email', email,
            '--agree-tos',
            '--non-interactive',
            '--cert-name', domain,
            '-d', domain,
            '-d', f'*.{domain}'  # Include wildcard
        ]
        
        # Add staging flag if requested
        if staging:
            cmd.append('--staging')
        
        logger.info(f"Creating certificate for {domain} using {dns_provider} DNS provider")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Clean up sensitive environment variables for Route53
        if route53_env_set:
            os.environ.pop('AWS_ACCESS_KEY_ID', None)
            os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
            os.environ.pop('AWS_DEFAULT_REGION', None)
        
        if result.returncode == 0:
            # Copy certificates to our directory
            src_dir = config_dir / "live" / domain
            dest_dir = CERT_DIR / domain
            dest_dir.mkdir(exist_ok=True)
            
            # Copy certificate files
            files_to_copy = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']
            for file_name in files_to_copy:
                src_file = src_dir / file_name
                dest_file = dest_dir / file_name
                if src_file.exists():
                    with open(src_file, 'rb') as src, open(dest_file, 'wb') as dest:
                        dest.write(src.read())
            
            logger.info(f"Certificate created successfully for {domain}")
            
            # Create automatic backup after successful certificate creation
            backup_path = create_certificates_backup(f"new_cert_{domain}")
            if backup_path:
                logger.info(f"Certificate backup created after new certificate for {domain}")
            
            return True, "Certificate created successfully"
        else:
            error_msg = result.stderr or result.stdout
            logger.error(f"Certificate creation failed: {error_msg}")
            return False, f"Certificate creation failed: {error_msg}"
    
    except Exception as e:
        # Clean up sensitive environment variables for Route53 in case of exception
        if route53_env_set:
            os.environ.pop('AWS_ACCESS_KEY_ID', None)
            os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
            os.environ.pop('AWS_DEFAULT_REGION', None)
            
        error_msg = str(e)
        logger.error(f"Exception during certificate creation: {error_msg}")
        return False, f"Exception: {error_msg}"

# Legacy function for backward compatibility
def create_certificate_legacy(domain, email, cloudflare_token):
    """Legacy function for backward compatibility"""
    dns_config = {'api_token': cloudflare_token}
    return create_certificate(domain, email, 'cloudflare', dns_config)

def renew_certificate(domain):
    """Renew a certificate"""
    try:
        cmd = ['certbot', 'renew', '--cert-name', domain, '--quiet']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Copy renewed certificates
            src_dir = Path(f"/etc/letsencrypt/live/{domain}")
            dest_dir = CERT_DIR / domain
            
            files_to_copy = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']
            for file_name in files_to_copy:
                src_file = src_dir / file_name
                dest_file = dest_dir / file_name
                if src_file.exists():
                    with open(src_file, 'rb') as src, open(dest_file, 'wb') as dest:
                        dest.write(src.read())
            
            logger.info(f"Certificate renewed successfully for {domain}")
            return True, "Certificate renewed successfully"
        else:
            error_msg = result.stderr or "Renewal failed: Certificate not found"
            logger.error(f"Certificate renewal failed for {domain}: {error_msg}")
            return False, f"Renewal failed: {error_msg}"
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Exception during certificate renewal for {domain}: {error_msg}")
        return False, f"Exception: {error_msg}"

def check_renewals():
    """Check and renew certificates that are about to expire"""
    settings = load_settings()
    if not settings.get('auto_renew', True):
        return
    
    # Migrate settings format if needed
    settings = migrate_domains_format(settings)
    
    logger.info("Checking for certificates that need renewal")
    
    for domain_entry in settings.get('domains', []):
        # Handle both old format (string) and new format (object)
        if isinstance(domain_entry, str):
            domain = domain_entry
        elif isinstance(domain_entry, dict):
            domain = domain_entry.get('domain')
        else:
            continue  # Skip invalid entries
            
        if domain:
            cert_info = get_certificate_info(domain)
            if cert_info and cert_info['needs_renewal']:
                logger.info(f"Renewing certificate for {domain}")
                success, message = renew_certificate(domain)

# Schedule renewal check every day at 2 AM (only if scheduler is available)
if scheduler:
    try:
        scheduler.add_job(
            func=check_renewals,
            trigger="cron",
            hour=2,
            minute=0,
            id='renewal_check'
        )
        logger.info("Automatic renewal check scheduled for 2 AM daily")
    except Exception as e:
        logger.error(f"Failed to schedule renewal check: {e}")
else:
    logger.warning("Background scheduler not available - automatic renewals disabled")

# Define API models
# DNS Provider models
cloudflare_model = api.model('CloudflareConfig', {
    'api_token': fields.String(description='Cloudflare API token')
})

route53_model = api.model('Route53Config', {
    'access_key_id': fields.String(description='AWS Access Key ID'),
    'secret_access_key': fields.String(description='AWS Secret Access Key'),
    'region': fields.String(description='AWS Region', default='us-east-1')
})

azure_model = api.model('AzureConfig', {
    'subscription_id': fields.String(description='Azure Subscription ID'),
    'resource_group': fields.String(description='Azure Resource Group'),
    'tenant_id': fields.String(description='Azure Tenant ID'),
    'client_id': fields.String(description='Azure Client ID'),
    'client_secret': fields.String(description='Azure Client Secret')
})

google_model = api.model('GoogleConfig', {
    'project_id': fields.String(description='Google Cloud Project ID'),
    'service_account_key': fields.String(description='Google Service Account JSON Key')
})

powerdns_model = api.model('PowerDNSConfig', {
    'api_url': fields.String(description='PowerDNS API URL'),
    'api_key': fields.String(description='PowerDNS API Key')
})

digitalocean_model = api.model('DigitalOceanConfig', {
    'api_token': fields.String(description='DigitalOcean API token')
})

linode_model = api.model('LinodeConfig', {
    'api_key': fields.String(description='Linode API key')
})

gandi_model = api.model('GandiConfig', {
    'api_token': fields.String(description='Gandi API token')
})

ovh_model = api.model('OvhConfig', {
    'endpoint': fields.String(description='OVH API endpoint'),
    'application_key': fields.String(description='OVH application key'),
    'application_secret': fields.String(description='OVH application secret'),
    'consumer_key': fields.String(description='OVH consumer key')
})

namecheap_model = api.model('NamecheapConfig', {
    'username': fields.String(description='Namecheap username'),
    'api_key': fields.String(description='Namecheap API key')
})

# Tier 3 DNS Providers (Additional individual plugins)
hetzner_model = api.model('HetznerConfig', {
    'api_token': fields.String(description='Hetzner DNS API token')
})

porkbun_model = api.model('PorkbunConfig', {
    'api_key': fields.String(description='Porkbun API key'),
    'secret_key': fields.String(description='Porkbun secret key')
})

godaddy_model = api.model('GoDaddyConfig', {
    'api_key': fields.String(description='GoDaddy API key'),
    'secret': fields.String(description='GoDaddy API secret')
})

he_ddns_model = api.model('HurricaneElectricConfig', {
    'username': fields.String(description='Hurricane Electric username'),
    'password': fields.String(description='Hurricane Electric password')
})

dynudns_model = api.model('DynuConfig', {
    'token': fields.String(description='Dynu API token')
})

# Multi-provider model for certbot-dns-multi (117+ providers)
multi_provider_model = api.model('MultiProviderConfig', {
    'provider': fields.String(description='DNS provider name (e.g., hetzner, porkbun, vultr)'),
    'config': fields.Raw(description='Provider-specific configuration (flexible key-value pairs)')
})

dns_providers_model = api.model('DNSProviders', {
    'cloudflare': fields.Nested(cloudflare_model),
    'route53': fields.Nested(route53_model),
    'azure': fields.Nested(azure_model),
    'google': fields.Nested(google_model),
    'powerdns': fields.Nested(powerdns_model),
    'digitalocean': fields.Nested(digitalocean_model),
    'linode': fields.Nested(linode_model),
    'gandi': fields.Nested(gandi_model),
    'ovh': fields.Nested(ovh_model),
    'namecheap': fields.Nested(namecheap_model),
    'vultr': fields.Nested(linode_model),  # Same API structure as Linode
    'dnsmadeeasy': fields.Nested(digitalocean_model),  # Simple API token
    'nsone': fields.Nested(digitalocean_model),  # Simple API token
    'rfc2136': fields.Nested(powerdns_model),  # Server URL and key
    # Tier 3 providers
    'hetzner': fields.Nested(hetzner_model),
    'porkbun': fields.Nested(porkbun_model),
    'godaddy': fields.Nested(godaddy_model),
    'he-ddns': fields.Nested(he_ddns_model),
    'dynudns': fields.Nested(dynudns_model),
    # Support for any other provider via certbot-dns-multi
    'multi': fields.Raw(description='Configuration for any DNS provider via certbot-dns-multi')
})

certificate_model = api.model('Certificate', {
    'domain': fields.String(required=True, description='Domain name'),
    'exists': fields.Boolean(description='Whether certificate exists'),
    'expiry_date': fields.String(description='Certificate expiry date'),
    'days_left': fields.Integer(description='Days until expiry'),
    'days_until_expiry': fields.Integer(description='Days until expiry (alias for days_left)'),
    'needs_renewal': fields.Boolean(description='Whether certificate needs renewal'),
    'dns_provider': fields.String(description='DNS provider used for the certificate')
})

settings_model = api.model('Settings', {
    'cloudflare_token': fields.String(description='Cloudflare API token (deprecated, use dns_providers)'),
    'domains': fields.List(fields.Raw, description='List of domains (can be strings or objects)'),
    'email': fields.String(description='Email for Let\'s Encrypt'),
    'auto_renew': fields.Boolean(description='Enable auto-renewal'),
    'api_bearer_token': fields.String(description='API bearer token for authentication'),
    'dns_provider': fields.String(description='Active DNS provider', enum=['cloudflare', 'route53', 'azure', 'google', 'powerdns', 'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap', 'vultr', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner', 'porkbun', 'godaddy', 'he-ddns', 'dynudns']),
    'dns_providers': fields.Nested(dns_providers_model, description='DNS provider configurations')
})

create_cert_model = api.model('CreateCertificate', {
    'domain': fields.String(required=True, description='Domain name to create certificate for'),
    'dns_provider': fields.String(description='DNS provider to use (optional, uses default from settings)', enum=['cloudflare', 'route53', 'azure', 'google', 'powerdns', 'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap', 'vultr', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner', 'porkbun', 'godaddy', 'he-ddns', 'dynudns']),
    'account_id': fields.String(description='DNS provider account ID to use (optional, uses default account if not specified)')
})

# Cache models
cache_entry_model = api.model('CacheEntry', {
    'domain': fields.String(description='Domain name'),
    'age': fields.Integer(description='Age of cache entry in seconds'),
    'remaining': fields.Integer(description='Remaining TTL in seconds'),
    'status': fields.String(description='Deployment status', enum=['deployed', 'not-deployed'])
})

cache_stats_model = api.model('CacheStats', {
    'total_entries': fields.Integer(description='Total number of cached entries'),
    'current_ttl': fields.Integer(description='Current TTL setting in seconds'),
    'entries': fields.List(fields.Nested(cache_entry_model), description='List of cached entries')
})

cache_clear_response_model = api.model('CacheClearResponse', {
    'success': fields.Boolean(description='Whether cache was cleared successfully'),
    'message': fields.String(description='Status message'),
    'cleared_entries': fields.Integer(description='Number of entries that were cleared')
})

# Define namespaces
ns_certificates = Namespace('certificates', description='Certificate operations')
ns_settings = Namespace('settings', description='Settings operations')
ns_health = Namespace('health', description='Health check')
ns_backups = Namespace('backups', description='Backup and restore operations')
ns_cache = Namespace('cache', description='Cache management operations')

api.add_namespace(ns_certificates)
api.add_namespace(ns_settings)
api.add_namespace(ns_health)
api.add_namespace(ns_backups)
api.add_namespace(ns_cache)

# Health check endpoint
@ns_health.route('')
class HealthCheck(Resource):
    def get(self):
        """Health check endpoint"""
        return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}

# Settings endpoints
@ns_settings.route('')
class Settings(Resource):
    @api.doc(security='Bearer')
    @api.marshal_with(settings_model)
    @require_auth
    def get(self):
        """Get current settings"""
        settings = load_settings()
        # Don't return sensitive data - mask credentials
        safe_settings = {
            'domains': settings.get('domains', []),
            'email': settings.get('email', ''),
            'auto_renew': settings.get('auto_renew', True),
            'dns_provider': settings.get('dns_provider', 'cloudflare'),
            'has_cloudflare_token': bool(settings.get('cloudflare_token')),  # Backward compatibility
            'has_api_bearer_token': bool(settings.get('api_bearer_token')),
            'dns_providers': {}
        }
        
        # Add masked DNS provider info
        dns_providers = settings.get('dns_providers', {})
        for provider, config in dns_providers.items():
            safe_settings['dns_providers'][provider] = {}
            for key, value in config.items():
                # Mask sensitive values
                if value:
                    if key in ['api_token', 'secret_access_key', 'client_secret', 'api_key', 'service_account_key']:
                        safe_settings['dns_providers'][provider][key] = '***masked***'
                    else:
                        safe_settings['dns_providers'][provider][key] = value
                else:
                    safe_settings['dns_providers'][provider][key] = ''
        
        return safe_settings
    
    @api.doc(security='Bearer')
    @api.expect(settings_model)
    @require_auth
    def post(self):
        """Update settings"""
        data = request.get_json()
        settings = load_settings()
        
        # Update basic settings
        if 'cloudflare_token' in data:
            settings['cloudflare_token'] = data['cloudflare_token']
            # Also update the new structure for backward compatibility
            if 'dns_providers' not in settings:
                settings['dns_providers'] = {}
            if 'cloudflare' not in settings['dns_providers']:
                settings['dns_providers']['cloudflare'] = {}
            settings['dns_providers']['cloudflare']['api_token'] = data['cloudflare_token']
            
        if 'domains' in data:
            settings['domains'] = data['domains']
        if 'email' in data:
            settings['email'] = data['email']
        if 'auto_renew' in data:
            settings['auto_renew'] = data['auto_renew']
        if 'api_bearer_token' in data:
            settings['api_bearer_token'] = data['api_bearer_token']
        if 'dns_provider' in data:
            settings['dns_provider'] = data['dns_provider']
        
        # Update DNS provider configurations
        if 'dns_providers' in data:
            if 'dns_providers' not in settings:
                settings['dns_providers'] = {}
            
            for provider, config in data['dns_providers'].items():
                if provider not in settings['dns_providers']:
                    settings['dns_providers'][provider] = {}
                
                # Only update non-masked values
                for key, value in config.items():
                    if value and value != '***masked***':
                        settings['dns_providers'][provider][key] = value
        
        if save_settings(settings):
            return {'success': True, 'message': 'Settings saved successfully'}
        else:
            return {'success': False, 'message': 'Failed to save settings'}, 500

# DNS Providers endpoint
@ns_settings.route('/dns-providers')
class DNSProviders(Resource):
    @api.doc(security='Bearer')
    @require_auth
    def get(self):
        """Get available DNS providers and their configuration status"""
        settings = load_settings()
        settings = migrate_dns_providers_to_multi_account(settings)  # Ensure migration
        dns_providers = settings.get('dns_providers', {})
        current_provider = settings.get('dns_provider', 'cloudflare')
        default_accounts = settings.get('default_accounts', {})
        
        def get_provider_status(provider_name, provider_config):
            """Helper to check if a provider is configured in multi-account format"""
            if not provider_config:
                return False, 0
            
            if isinstance(provider_config, dict):
                # Count accounts
                account_count = 0
                has_configured_account = False
                
                for account_id, account_config in provider_config.items():
                    if isinstance(account_config, dict):
                        # Check if this looks like an account config
                        if 'name' in account_config or any(key in account_config for key in [
                            'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                        ]):
                            account_count += 1
                            # Check if account has credentials
                            if any(account_config.get(key) for key in [
                                'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                            ]):
                                has_configured_account = True
                
                # Fallback: check if it's old single-account format
                if account_count == 0 and any(key in provider_config for key in [
                    'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                ]):
                    account_count = 1
                    has_configured_account = True
                
                return has_configured_account, account_count
            
            return False, 0
        
        providers_status = {
            'current_provider': current_provider,
            'default_accounts': default_accounts,
            'multi_account_enabled': True,
            'available_providers': {
                'cloudflare': {
                    'name': 'Cloudflare',
                    'description': 'Cloudflare DNS provider using API tokens',
                    'configured': get_provider_status('cloudflare', dns_providers.get('cloudflare', {}))[0],
                    'account_count': get_provider_status('cloudflare', dns_providers.get('cloudflare', {}))[1],
                    'required_fields': ['api_token']
                },
                'route53': {
                    'name': 'AWS Route53',
                    'description': 'Amazon Web Services Route53 DNS provider',
                    'configured': get_provider_status('route53', dns_providers.get('route53', {}))[0],
                    'account_count': get_provider_status('route53', dns_providers.get('route53', {}))[1],
                    'required_fields': ['access_key_id', 'secret_access_key'],
                    'optional_fields': ['region']
                },
                'azure': {
                    'name': 'Azure DNS',
                    'description': 'Microsoft Azure DNS provider',
                    'configured': get_provider_status('azure', dns_providers.get('azure', {}))[0],
                    'account_count': get_provider_status('azure', dns_providers.get('azure', {}))[1],
                    'required_fields': ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret']
                },
                'google': {
                    'name': 'Google Cloud DNS',
                    'description': 'Google Cloud Platform DNS provider',
                    'configured': get_provider_status('google', dns_providers.get('google', {}))[0],
                    'account_count': get_provider_status('google', dns_providers.get('google', {}))[1],
                    'required_fields': ['project_id', 'service_account_key']
                },
                'powerdns': {
                    'name': 'PowerDNS',
                    'description': 'PowerDNS API provider',
                    'configured': get_provider_status('powerdns', dns_providers.get('powerdns', {}))[0],
                    'account_count': get_provider_status('powerdns', dns_providers.get('powerdns', {}))[1],
                    'required_fields': ['api_url', 'api_key']
                },
                'digitalocean': {
                    'name': 'DigitalOcean',
                    'description': 'DigitalOcean DNS provider',
                    'configured': get_provider_status('digitalocean', dns_providers.get('digitalocean', {}))[0],
                    'account_count': get_provider_status('digitalocean', dns_providers.get('digitalocean', {}))[1],
                    'required_fields': ['api_token']
                },
                'linode': {
                    'name': 'Linode',
                    'description': 'Linode DNS provider',
                    'configured': get_provider_status('linode', dns_providers.get('linode', {}))[0],
                    'account_count': get_provider_status('linode', dns_providers.get('linode', {}))[1],
                    'required_fields': ['api_key']
                },
                'gandi': {
                    'name': 'Gandi',
                    'description': 'Gandi DNS provider',
                    'configured': get_provider_status('gandi', dns_providers.get('gandi', {}))[0],
                    'account_count': get_provider_status('gandi', dns_providers.get('gandi', {}))[1],
                    'required_fields': ['api_token']
                },
                'ovh': {
                    'name': 'OVH',
                    'description': 'OVH DNS provider',
                    'configured': get_provider_status('ovh', dns_providers.get('ovh', {}))[0],
                    'account_count': get_provider_status('ovh', dns_providers.get('ovh', {}))[1],
                    'required_fields': ['endpoint', 'application_key', 'application_secret', 'consumer_key']
                },
                'namecheap': {
                    'name': 'Namecheap',
                    'description': 'Namecheap DNS provider',
                    'configured': get_provider_status('namecheap', dns_providers.get('namecheap', {}))[0],
                    'account_count': get_provider_status('namecheap', dns_providers.get('namecheap', {}))[1],
                    'required_fields': ['username', 'api_key']
                },
                # RFC2136 and additional individual plugins
                'rfc2136': {
                    'name': 'RFC2136',
                    'description': 'RFC2136 DNS Update Protocol',
                    'configured': get_provider_status('rfc2136', dns_providers.get('rfc2136', {}))[0],
                    'account_count': get_provider_status('rfc2136', dns_providers.get('rfc2136', {}))[1],
                    'required_fields': ['nameserver', 'tsig_key', 'tsig_secret'],
                    'optional_fields': ['tsig_algorithm']
                },
                'vultr': {
                    'name': 'Vultr',
                    'description': 'Vultr DNS provider',
                    'configured': get_provider_status('vultr', dns_providers.get('vultr', {}))[0],
                    'account_count': get_provider_status('vultr', dns_providers.get('vultr', {}))[1],
                    'required_fields': ['api_key']
                },
                'dnsmadeeasy': {
                    'name': 'DNS Made Easy',
                    'description': 'DNS Made Easy provider',
                    'configured': get_provider_status('dnsmadeeasy', dns_providers.get('dnsmadeeasy', {}))[0],
                    'account_count': get_provider_status('dnsmadeeasy', dns_providers.get('dnsmadeeasy', {}))[1],
                    'required_fields': ['api_key', 'secret_key']
                },
                'nsone': {
                    'name': 'NS1',
                    'description': 'NS1 DNS provider',
                    'configured': get_provider_status('nsone', dns_providers.get('nsone', {}))[0],
                    'account_count': get_provider_status('nsone', dns_providers.get('nsone', {}))[1],
                    'required_fields': ['api_key']
                },
                'hetzner': {
                    'name': 'Hetzner',
                    'description': 'Hetzner DNS provider',
                    'configured': get_provider_status('hetzner', dns_providers.get('hetzner', {}))[0],
                    'account_count': get_provider_status('hetzner', dns_providers.get('hetzner', {}))[1],
                    'required_fields': ['api_token']
                },
                'porkbun': {
                    'name': 'Porkbun',
                    'description': 'Porkbun DNS provider',
                    'configured': get_provider_status('porkbun', dns_providers.get('porkbun', {}))[0],
                    'account_count': get_provider_status('porkbun', dns_providers.get('porkbun', {}))[1],
                    'required_fields': ['api_key', 'secret_key']
                },
                'godaddy': {
                    'name': 'GoDaddy',
                    'description': 'GoDaddy DNS provider',
                    'configured': get_provider_status('godaddy', dns_providers.get('godaddy', {}))[0],
                    'account_count': get_provider_status('godaddy', dns_providers.get('godaddy', {}))[1],
                    'required_fields': ['api_key', 'secret']
                },
                'he-ddns': {
                    'name': 'Hurricane Electric',
                    'description': 'Hurricane Electric DNS provider',
                    'configured': get_provider_status('he-ddns', dns_providers.get('he-ddns', {}))[0],
                    'account_count': get_provider_status('he-ddns', dns_providers.get('he-ddns', {}))[1],
                    'required_fields': ['username', 'password']
                },
                'dynudns': {
                    'name': 'Dynu',
                    'description': 'Dynu DNS provider',
                    'configured': get_provider_status('dynudns', dns_providers.get('dynudns', {}))[0],
                    'account_count': get_provider_status('dynudns', dns_providers.get('dynudns', {}))[1],
                    'required_fields': ['token']
                }
            }
        }
        
        return providers_status

# Cache management endpoints
@ns_cache.route('/stats')
class CacheStats(Resource):
    @api.doc(security='Bearer')
    @api.marshal_with(cache_stats_model)
    @require_auth
    def get(self):
        """Get cache statistics"""
        try:
            stats = deployment_cache.get_stats()
            return stats
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {'message': f'Failed to get cache stats: {str(e)}'}, 500

@ns_cache.route('/clear')
class CacheClear(Resource):
    @api.doc(security='Bearer')
    @api.marshal_with(cache_clear_response_model)
    @require_auth
    def post(self):
        """Clear deployment status cache"""
        try:
            cleared_count = deployment_cache.clear()
            return {
                'success': True,
                'message': 'Cache cleared successfully',
                'cleared_entries': cleared_count
            }
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return {
                'success': False,
                'message': f'Failed to clear cache: {str(e)}',
                'cleared_entries': 0
            }, 500

# Certificate endpoints
@ns_certificates.route('')
class CertificateList(Resource):
    @api.doc(security='Bearer')
    @api.marshal_list_with(certificate_model)
    @require_auth
    def get(self):
        """Get all certificates"""
        try:
            settings = load_settings()
            certificates = []
            
            # Get all domains from settings
            domains_from_settings = settings.get('domains', [])
            
            # Also check for certificates that exist on disk but might not be in settings
            cert_dirs = []
            if CERT_DIR.exists():
                cert_dirs = [d for d in CERT_DIR.iterdir() if d.is_dir()]
            
            # Create a set of all domains to check (from settings and disk)
            all_domains = set()
            
            # Add domains from settings
            for domain_config in domains_from_settings:
                domain_name = domain_config.get('domain') if isinstance(domain_config, dict) else domain_config
                if domain_name:
                    all_domains.add(domain_name)
            
            # Add domains from disk
            for cert_dir in cert_dirs:
                all_domains.add(cert_dir.name)
            
            # Get certificate info for all domains
            for domain_name in all_domains:
                if domain_name:  # Ensure domain_name is not empty
                    cert_info = get_certificate_info(domain_name)
                    if cert_info:
                        certificates.append(cert_info)
            
            logger.info(f"Found {len(certificates)} certificates")
            return certificates
        except Exception as e:
            logger.error(f"Error fetching certificates: {e}")
            # Return empty array on error to ensure frontend compatibility
            return []

@ns_certificates.route('/create')
class CreateCertificate(Resource):
    @api.doc(security='Bearer')
    @api.expect(create_cert_model)
    @require_auth
    def post(self):
        """Create a new certificate"""
        data = request.get_json()
        domain = data.get('domain')
        dns_provider = data.get('dns_provider')  # Optional, uses default from settings
        account_id = data.get('account_id')      # Optional, uses default account
        
        if not domain:
            return {'success': False, 'message': 'Domain is required'}, 400
        
        settings = load_settings()
        email = settings.get('email')
        
        if not email:
            return {'success': False, 'message': 'Email not configured in settings'}, 400
        
        # Determine DNS provider with proper inheritance and smart suggestions
        if not dns_provider:
            # Check if domain already exists in settings with specific DNS provider
            existing_dns_provider = get_domain_dns_provider(domain, settings)
            if existing_dns_provider and existing_dns_provider != settings.get('dns_provider', 'cloudflare'):
                # Domain has a specific DNS provider configured
                dns_provider = existing_dns_provider
            else:
                # Use smart suggestion based on domain patterns
                suggested_provider, confidence = suggest_dns_provider_for_domain(domain, settings)
                if confidence >= 70:
                    dns_provider = suggested_provider
                    logger.info(f"Smart DNS provider suggestion for {domain}: {suggested_provider} (confidence: {confidence}%)")
                else:
                    # Use global default
                    dns_provider = settings.get('dns_provider', 'cloudflare')
                    logger.info(f"Using global default DNS provider for {domain}: {dns_provider}")
        
        # Determine account_id with proper inheritance
        if not account_id:
            # Try to get default account for this DNS provider
            default_accounts = settings.get('default_accounts', {})
            account_id = default_accounts.get(dns_provider)
            
            # If no default account is configured, use 'default' or first available account
            if not account_id:
                dns_providers = settings.get('dns_providers', {})
                provider_accounts = dns_providers.get(dns_provider, {})
                if isinstance(provider_accounts, dict):
                    available_accounts = list(provider_accounts.keys())
                    if available_accounts:
                        account_id = available_accounts[0]
                        logger.info(f"Using first available account '{account_id}' for {dns_provider}")
                    else:
                        account_id = 'default'
                else:
                    account_id = 'default'
        
        # Validate that the DNS provider account exists and is properly configured
        account_config, used_account_id = get_dns_provider_account_config(dns_provider, account_id, settings)
        if not account_config:
            return {
                'success': False, 
                'message': f'DNS provider account "{account_id}" not found or not configured for {dns_provider}. Please configure the DNS provider settings first.'
            }, 400
        
        # Use the validated account_id
        account_id = used_account_id
        
        try:
            success, message = create_certificate(domain, email, dns_provider, dns_config=account_config, account_id=used_account_id)
            
            if success:
                # Automatically add the domain to the settings if it's not already there
                current_domains = settings.get('domains', [])
                domain_exists = False
                
                for existing_domain in current_domains:
                    if isinstance(existing_domain, dict):
                        if existing_domain.get('domain') == domain:
                            domain_exists = True
                            break
                    elif existing_domain == domain:
                        domain_exists = True
                        break
                
                if not domain_exists:
                    # Add domain with DNS provider info, ensuring all required fields are present
                    domain_config = {
                        'domain': domain,
                        'dns_provider': dns_provider,
                        'account_id': account_id or 'default'
                    }
                    
                    # Validate the domain config before adding
                    if domain_config['domain'] and domain_config['dns_provider']:
                        current_domains.append(domain_config)
                        settings['domains'] = current_domains
                        
                        # Save the updated settings
                        save_result = save_settings(settings, f"auto_add_domain_{domain}")
                        if save_result:
                            logger.info(f"Domain {domain} automatically added to settings after certificate creation with DNS provider {dns_provider} and account {account_id}")
                        else:
                            logger.error(f"Failed to save settings after adding domain {domain}")
                    else:
                        logger.error(f"Invalid domain configuration for {domain}: missing required fields")
                
                return {
                    'success': True, 
                    'message': f'Certificate created successfully for {domain}',
                    'domain': domain,
                    'dns_provider': dns_provider,
                    'account_id': account_id
                }
            else:
                return {'success': False, 'message': message}, 400
                
        except Exception as e:
            logger.error(f"Certificate creation failed: {str(e)}")
            return {'success': False, 'message': f'Certificate creation failed: {str(e)}'}, 500

@ns_certificates.route('/<string:domain>/download')
class DownloadCertificate(Resource):
    @api.doc(security='Bearer')
    @require_auth
    def get(self, domain):
        """Download certificate as ZIP file"""
        cert_dir = CERT_DIR / domain
        if not cert_dir.exists():
            return {'error': 'Certificate not found'}, 404
        
        # Create temporary ZIP file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            with zipfile.ZipFile(tmp_file.name, 'w') as zip_file:
                for file_name in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
                    file_path = cert_dir / file_name
                    if file_path.exists():
                        zip_file.write(file_path, file_name)
            
            return send_file(tmp_file.name, as_attachment=True, download_name=f'{domain}-certificates.zip')

@ns_certificates.route('/<string:domain>/renew')
class RenewCertificate(Resource):
    @api.doc(security='Bearer')
    @require_auth
    def post(self, domain):
        """Renew a certificate"""
        settings = load_settings()
        
        # Check if domain exists in settings
        domain_exists = False
        for domain_config in settings.get('domains', []):
            if isinstance(domain_config, dict) and domain_config.get('domain') == domain:
                domain_exists = True
                break
            elif isinstance(domain_config, str) and domain_config == domain:
                domain_exists = True
                break
        
        if not domain_exists:
            return {'success': False, 'message': 'Domain not found in settings'}, 404
        
        # Renew certificate in background
        def renew_cert_async():
            success, message = renew_certificate(domain)
            logger.info(f"Certificate renewal for {domain}: {'Success' if success else 'Failed'}")
        
        thread = threading.Thread(target=renew_cert_async)
        thread.start()
        
        return {'success': True, 'message': f'Certificate renewal started for {domain}'}

# Special download endpoint for easy automation
@app.route('/<string:domain>/tls')
@require_auth
def download_tls(domain):
    """Download certificate via simple URL with bearer token auth"""
    cert_dir = CERT_DIR / domain
    if not cert_dir.exists():
        return jsonify({'error': 'Certificate not found'}), 404
    
    # Create temporary ZIP file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
        with zipfile.ZipFile(tmp_file.name, 'w') as zip_file:
            for file_name in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
                file_path = cert_dir / file_name
                if file_path.exists():
                    zip_file.write(file_path, file_name)
        
        return send_file(tmp_file.name, as_attachment=True, download_name=f'{domain}-tls.zip')

# Configure API security
api.authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Add "Bearer " before your token'
    }
}

# Web interface routes
@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'favicon.ico')

@app.route('/')
def index():
    """Main dashboard"""
    settings = load_settings()
    certificates = []
    
    # Get all domains from settings
    domains_from_settings = settings.get('domains', [])
    
    # Also check for certificates that exist on disk but might not be in settings
    cert_dirs = []
    if CERT_DIR.exists():
        cert_dirs = [d for d in CERT_DIR.iterdir() if d.is_dir()]
    
    # Create a set of all domains to check (from settings and disk)
    all_domains = set()
    
    # Add domains from settings
    for domain_config in domains_from_settings:
        domain_name = domain_config.get('domain') if isinstance(domain_config, dict) else domain_config
        if domain_name:
            all_domains.add(domain_name)
    
    # Add domains from disk
    for cert_dir in cert_dirs:
        all_domains.add(cert_dir.name)
    
    # Get certificate info for all domains
    for domain_name in all_domains:
        if domain_name:
            cert_info = get_certificate_info(domain_name)
            if cert_info:
                certificates.append(cert_info)
    
    # Get API token for frontend use
    api_token = settings.get('api_bearer_token', 'token-not-configured')
    return render_template('index.html', certificates=certificates, api_token=api_token)

@app.route('/settings')
def settings_page():
    """Settings page"""
    settings = load_settings()
    # Get API token for frontend use
    api_token = settings.get('api_bearer_token', 'token-not-configured')
    return render_template('settings.html', settings=settings, api_token=api_token)

@app.route('/help')
def help_page():
    """Help and documentation page"""
    return render_template('help.html')

# Health check for Docker
@app.route('/health')
def health_check():
    """Enhanced health check endpoint for Docker and monitoring"""
    try:
        status = 'healthy'
        checks = {}
        
        # Check directory access
        checks['directories'] = {
            'cert_dir_writable': os.access(CERT_DIR, os.W_OK),
            'data_dir_writable': os.access(DATA_DIR, os.W_OK)
        }
        
        # Check settings file
        checks['settings'] = {
            'file_exists': SETTINGS_FILE.exists(),
            'readable': SETTINGS_FILE.exists() and os.access(SETTINGS_FILE, os.R_OK)
        }
        
        # Check scheduler
        checks['scheduler'] = {
            'available': scheduler is not None,
            'running': scheduler.running if scheduler else False
        }
        
        # Determine overall status
        if not all([
            checks['directories']['cert_dir_writable'],
            checks['directories']['data_dir_writable'],
            checks['settings']['readable']
        ]):
            status = 'degraded'
            
        return jsonify({
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'checks': checks
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }), 500

# Web-specific settings endpoints (no auth required for initial setup)
@app.route('/api/web/settings', methods=['GET', 'POST'])
def web_settings():
    """Web interface settings endpoint (no auth required for initial setup)"""
    logger.info(f"[SETTINGS DEBUG] {request.method} /api/web/settings called")
    
    if request.method == 'GET':
        try:
            settings = load_settings()
            logger.info(f"[SETTINGS DEBUG] Loaded settings, has {len(settings.get('domains', []))} domains")
            
            # Ensure migration is applied for DNS providers
            settings = migrate_dns_providers_to_multi_account(settings)
            
            # Prepare safe settings for UI
            safe_settings = {
                'domains': settings.get('domains', []),
                'email': settings.get('email', ''),
                'auto_renew': settings.get('auto_renew', True),
                'dns_provider': settings.get('dns_provider', 'cloudflare'),
                'dns_providers': settings.get('dns_providers', {}),
                'api_bearer_token': settings.get('api_bearer_token', ''),
                'cache_ttl': settings.get('cache_ttl', 300),
                'has_cloudflare_token': bool(settings.get('cloudflare_token')),
                'has_api_bearer_token': bool(settings.get('api_bearer_token'))
            }
            
            logger.info(f"[SETTINGS DEBUG] Returning safe_settings with DNS provider: {safe_settings['dns_provider']}")
            return jsonify(safe_settings)
            
        except Exception as e:
            logger.error(f"[SETTINGS DEBUG] Error in GET settings: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
           

            logger.info(f"[SETTINGS DEBUG] POST data received: {list(data.keys()) if data else 'None'}")
            
            if not data:
                logger.error("[SETTINGS DEBUG] No JSON data received")
                return jsonify({'error': 'No data received'}), 400
            
            settings = load_settings()
            logger.info(f"[SETTINGS DEBUG] Current settings loaded")
            
            # Update basic settings
            if 'email' in data:
                settings['email'] = data['email']
                logger.info(f"[SETTINGS DEBUG] Updated email")
            
            if 'domains' in data:
                settings['domains'] = data['domains']
                logger.info(f"[SETTINGS DEBUG] Updated domains: {len(data['domains'])}")
            
            if 'auto_renew' in data:
                settings['auto_renew'] = data['auto_renew']
                logger.info(f"[SETTINGS DEBUG] Updated auto_renew: {data['auto_renew']}")
            
            if 'dns_provider' in data:
                settings['dns_provider'] = data['dns_provider']
                logger.info(f"[SETTINGS DEBUG] Updated DNS provider: {data['dns_provider']}")
            
            if 'dns_providers' in data:
                settings['dns_providers'] = {**settings.get('dns_providers', {}), **data['dns_providers']}
                logger.info(f"[SETTINGS DEBUG] Updated DNS providers config")
            
            if 'api_bearer_token' in data and data['api_bearer_token']:
                settings['api_bearer_token'] = data['api_bearer_token']
                logger.info(f"[SETTINGS DEBUG] Updated API bearer token")
            
            if 'cache_ttl' in data:
                settings['cache_ttl'] = data['cache_ttl']
                logger.info(f"[SETTINGS DEBUG] Updated cache TTL: {data['cache_ttl']}")
                # Update the deployment cache TTL
                deployment_cache.set_ttl(data['cache_ttl'])
            
            # Legacy cloudflare token support
            if 'cloudflare_token' in data and data['cloudflare_token']:
                settings['cloudflare_token'] = data['cloudflare_token']
                logger.info(f"[SETTINGS DEBUG] Updated legacy cloudflare token")
            
            logger.info(f"[SETTINGS DEBUG] Saving settings...")
            if save_settings(settings):
                logger.info(f"[SETTINGS DEBUG] Settings saved successfully")
                return jsonify({'success': True, 'message': 'Settings saved successfully'})
            else:
                logger.error(f"[SETTINGS DEBUG] Failed to save settings")
                return jsonify({'success': False, 'message': 'Failed to save settings'}), 500
                
        except Exception as e:
            logger.error(f"[SETTINGS DEBUG] Error in POST settings: {e}")
            return jsonify({'error': str(e)}), 500

# DNS Provider Account Management endpoints for web interface (no auth required for initial setup)
@app.route('/api/dns/<string:provider>/accounts', methods=['GET', 'POST'])
def web_dns_provider_accounts(provider):
    """Web interface DNS provider accounts endpoint"""
    logger.info(f"[DNS DEBUG] {request.method} /api/dns/{provider}/accounts called")
    
    if request.method == 'GET':
        try:
            settings = load_settings()
            settings = migrate_dns_providers_to_multi_account(settings)
            
            accounts = list_dns_provider_accounts(provider, settings)
            
            logger.info(f"[DNS DEBUG] Found {len(accounts)} accounts for {provider}")
            return jsonify({'accounts': accounts})
            
        except Exception as e:
            logger.error(f"[DNS DEBUG] Error getting accounts for {provider}: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            logger.info(f"[DNS DEBUG] Adding account for {provider}: {list(data.keys()) if data else 'None'}")
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            account_id = data.get('account_id')
            account_config = data.get('config', {})
            
            if not account_id:
                return jsonify({'error': 'account_id is required'}, 400)
            
            if not account_config.get('name'):
                account_config['name'] = account_id.title()
            
            # Validate the account configuration
            is_valid, validation_error = validate_dns_provider_account(provider, account_id, account_config)
            if not is_valid:
                return {'error': f'Account validation failed: {validation_error}'}, 400
            
            # Load current settings
            settings = load_settings()
            settings = migrate_dns_providers_to_multi_account(settings)
            
            # Initialize provider if not exists
            if 'dns_providers' not in settings:
                settings['dns_providers'] = {}
            if provider not in settings['dns_providers']:
                settings['dns_providers'][provider] = {}
            
            # Add the account
            settings['dns_providers'][provider][account_id] = account_config
            
            # Set as default if requested or if it's the first account
            if (data.get('set_as_default') or 
                len(settings['dns_providers'][provider]) == 1):
                if 'default_accounts' not in settings:
                    settings['default_accounts'] = {}
                settings['default_accounts'][provider] = account_id
            
            # Save settings
            save_settings(settings)
            
            logger.info(f"[DNS DEBUG] Account {account_id} added for {provider}")
            return jsonify({
                'success': True,
                'message': f'Account added successfully',
                'account_id': account_id
            })
            
        except Exception as e:
            logger.error(f"[DNS DEBUG] Error adding account for {provider}: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/dns/<string:provider>/accounts/<string:account_id>', methods=['GET', 'PUT', 'DELETE'])
def web_dns_provider_account(provider, account_id):
    """Web interface individual DNS provider account endpoint"""
    logger.info(f"[DNS DEBUG] {request.method} /api/dns/{provider}/accounts/{account_id} called")
    
    if request.method == 'GET':
        try:
            account_config, _ = get_dns_provider_account_config(provider, account_id)
            if not account_config:
                return jsonify({'error': 'Account not found'}), 404
            
            # Return masked version for security
            safe_config = {
                'name': account_config.get('name', account_id.title()),
                'description': account_config.get('description', ''),
                'account_id': account_id,
                'provider': provider,
                'configured': bool(any(account_config.get(key) for key in [
                    'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                ]))
            }
            
            return safe_config
        except Exception as e:
            logger.error(f"[DNS DEBUG] Error getting account {account_id} for {provider}: {e}")
            return jsonify({'error': 'Failed to get DNS provider account'}, 500)

    @api.doc(security='Bearer')
    @require_auth
    def put(self, provider, account_id):
        """Update an existing account configuration"""
        try:
            data = request.get_json()
            logger.info(f"[DNS DEBUG] Updating account {account_id} for {provider}")
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Validate account data
            is_valid, error_msg = validate_dns_provider_account(provider, account_id, data)
            if not is_valid:
                logger.error(f"[DNS DEBUG] Validation failed: {error_msg}")
                return jsonify({'error': error_msg}), 400
            
            # Load current settings
            settings = load_settings()
            settings = migrate_dns_providers_to_multi_account(settings)
            
            # Check if account exists
            if (provider not in settings.get('dns_providers', {}) or 
                account_id not in settings['dns_providers'][provider]):
                return jsonify({'error': 'Account not found'}), 404
            
            # Update account
            settings['dns_providers'][provider][account_id] = {
                **settings['dns_providers'][provider][account_id],
                **data
            }
            
            # Set as default if requested
            if data.get('set_as_default'):
                if 'default_accounts' not in settings:
                    settings['default_accounts'] = {}
                settings['default_accounts'][provider] = account_id
            
            # Save settings
            save_settings(settings)
            
            logger.info(f"[DNS DEBUG] Account {account_id} updated for {provider}")
            return jsonify({
                'success': True,
                'message': f'Account updated successfully'
            })
            
        except Exception as e:
            logger.error(f"[DNS DEBUG] Error updating account {account_id} for {provider}: {e}")
            return jsonify({'error': str(e)}), 500
    
    @api.doc(security='Bearer')
    @require_auth
    def delete(self, provider, account_id):
        """Delete an account configuration"""
        try:
            # Load current settings
            settings = load_settings()
            settings = migrate_dns_providers_to_multi_account(settings)
            
            # Check if account exists
            if (provider not in settings.get('dns_providers', {}) or 
                account_id not in settings['dns_providers'][provider]):
                return jsonify({'error': 'Account not found'}), 404
            
            # Don't allow deletion if this is the only account
            provider_accounts = list_dns_provider_accounts(provider, settings)
            if len(provider_accounts) <= 1:
                return jsonify({'error': 'Cannot delete the only account for this provider'}), 400
            
            # Remove account
            del settings['dns_providers'][provider][account_id]
            
            # Update default if this was the default
            if (settings.get('default_accounts', {}).get(provider) == account_id):
                remaining_accounts = list(settings['dns_providers'][provider].keys())
                if remaining_accounts:
                    settings['default_accounts'][provider] = remaining_accounts[0]
                else:
                    if provider in settings['default_accounts']:
                        del settings['default_accounts'][provider]
            
            # Save settings
            save_settings(settings)
            
            logger.info(f"[DNS DEBUG] Account {account_id} deleted for {provider}")
            return jsonify({
                'success': True,
                'message': f'Account deleted successfully'
            })
            
        except Exception as e:
            logger.error(f"[DNS DEBUG] Error deleting account {account_id} for {provider}: {e}")
            return jsonify({'error': str(e)}), 500


def create_settings_backup(settings_data, backup_reason="manual"):
    """Create a backup of settings data with timestamp and metadata"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"settings_{timestamp}_{backup_reason}.json"
        backup_path = BACKUP_DIR / "settings" / backup_filename
        
        # Create backup metadata
        backup_metadata = {
            "timestamp": timestamp,
            "datetime": datetime.now().isoformat(),
            "reason": backup_reason,
            "original_file": str(SETTINGS_FILE),
            "backup_version": "1.0"
        }
        
        # Create backup with metadata
        backup_data = {
            "metadata": backup_metadata,
            "settings": settings_data
        }
        
        # Write backup file
        success = safe_file_write(backup_path, backup_data, is_json=True)
        
        if success:
            logger.info(f"Settings backup created: {backup_filename} (reason: {backup_reason})")
            
            # Cleanup old backups
            cleanup_old_settings_backups()
            return str(backup_path)
        else:
            logger.error(f"Failed to create settings backup: {backup_filename}")
            return None
            
    except Exception as e:
        logger.error(f"Error creating settings backup: {e}")
        return None

def create_certificates_backup(backup_reason="manual"):
    """Create a zip backup of all certificates"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"certificates_{timestamp}_{backup_reason}.zip"
        backup_path = BACKUP_DIR / "certificates" / backup_filename
        
        # Only create backup if certificates directory exists and has content
        if not CERT_DIR.exists() or not any(CERT_DIR.iterdir()):
            logger.info("No certificates to backup")
            return None
            
        # Create zip file
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all certificate files
            for cert_dir in CERT_DIR.iterdir():
                if cert_dir.is_dir():
                    for cert_file in cert_dir.rglob('*'):
                        if cert_file.is_file():
                            # Store with relative path
                            arcname = cert_file.relative_to(CERT_DIR)
                            zipf.write(cert_file, arcname)
            
            # Add backup metadata
            metadata = {
                "timestamp": timestamp,
                "datetime": datetime.now().isoformat(),
                "reason": backup_reason,
                "backup_version": "1.0",
                "total_domains": len([d for d in CERT_DIR.iterdir() if d.is_dir()])
            }
            
            # Add metadata as a file in the zip
            zipf.writestr("backup_metadata.json", json.dumps(metadata, indent=2))
        
        logger.info(f"Certificates backup created: {backup_filename} (reason: {backup_reason})")
        
        # Cleanup old backups
        cleanup_old_certificate_backups()
        return str(backup_path)
        
    except Exception as e:
        logger.error(f"Error creating certificates backup: {e}")
        return None

def cleanup_old_settings_backups():
    """Remove old settings backups based on retention policy"""
    try:
        settings_backup_dir = BACKUP_DIR / "settings"
        if not settings_backup_dir.exists():
            return
            
        # Get all backup files sorted by modification time
        backup_files = sorted(
            [f for f in settings_backup_dir.glob("*.json") if f.is_file()],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        # Remove files older than retention period
        cutoff_time = time.time() - (BACKUP_RETENTION_DAYS * 24 * 60 * 60)
        removed_count = 0
        
        for backup_file in backup_files:
            if backup_file.stat().st_mtime < cutoff_time:
                try:
                    backup_file.unlink()
                    removed_count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove old backup {backup_file}: {e}")
        
        # Also enforce maximum backup count
        if len(backup_files) > MAX_BACKUPS_PER_TYPE:
            files_to_remove = backup_files[MAX_BACKUPS_PER_TYPE:]
            for backup_file in files_to_remove:
                try:
                    if backup_file.exists():  # File might have been removed above
                        backup_file.unlink()
                        removed_count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove excess backup {backup_file}: {e}")
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} old settings backups")
            
    except Exception as e:
        logger.error(f"Error during settings backup cleanup: {e}")

def cleanup_old_certificate_backups():
    """Remove old certificate backups based on retention policy"""
    try:
        cert_backup_dir = BACKUP_DIR / "certificates"
        if not cert_backup_dir.exists():
            return
            
        # Get all backup files sorted by modification time
        backup_files = sorted(
            [f for f in cert_backup_dir.glob("*.zip") if f.is_file()],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        # Remove files older than retention period
        cutoff_time = time.time() - (BACKUP_RETENTION_DAYS * 24 * 60 * 60)
        removed_count = 0
        
        for backup_file in backup_files:
            if backup_file.stat().st_mtime < cutoff_time:
                try:
                    backup_file.unlink()
                    removed_count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove old backup {backup_file}: {e}")
        
        # Also enforce maximum backup count
        if len(backup_files) > MAX_BACKUPS_PER_TYPE:
            files_to_remove = backup_files[MAX_BACKUPS_PER_TYPE:]
            for backup_file in files_to_remove:
                try:
                    if backup_file.exists():  # File might have been removed above
                        backup_file.unlink()
                        removed_count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove excess backup {backup_file}: {e}")
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} old certificate backups")
            
    except Exception as e:
        logger.error(f"Error during certificate backup cleanup: {e}")

def list_backups():
    """List all available backups with metadata"""
    try:
        backups = {
            "settings": [],
            "certificates": []
        }
        
        # List settings backups
        settings_backup_dir = BACKUP_DIR / "settings"
        if settings_backup_dir.exists():
            for backup_file in sorted(settings_backup_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    # Try to read metadata from backup
                    backup_data = safe_file_read(backup_file, is_json=True)
                    if backup_data and "metadata" in backup_data:
                        metadata = backup_data["metadata"]
                    else:
                        # Fallback metadata from filename and file stats
                        metadata = {
                            "timestamp": backup_file.stem.split("_")[1:3],
                            "reason": backup_file.stem.split("_")[-1] if len(backup_file.stem.split("_")) > 3 else "unknown"
                        }
                    
                    backups["settings"].append({
                        "filename": backup_file.name,
                        "path": str(backup_file),
                        "size": backup_file.stat().st_size,
                        "created": datetime.fromtimestamp(backup_file.stat().st_mtime).isoformat(),
                        "metadata": metadata
                    })
                except Exception as e:
                    logger.warning(f"Error processing settings backup {backup_file}: {e}")
        
        # List certificate backups
        cert_backup_dir = BACKUP_DIR / "certificates"
        if cert_backup_dir.exists():
            for backup_file in sorted(cert_backup_dir.glob("*.zip"), key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    # Try to read metadata from zip
                    metadata = {}
                    try:
                        with zipfile.ZipFile(backup_file, 'r') as zipf:
                            if "backup_metadata.json" in zipf.namelist():
                                metadata = json.loads(zipf.read("backup_metadata.json").decode('utf-8'))
                    except:
                        # Fallback metadata
                        metadata = {
                            "timestamp": backup_file.stem.split("_")[1:3],
                            "reason": backup_file.stem.split("_")[-1] if len(backup_file.stem.split("_")) > 3 else "unknown"
                        }
                    
                    backups["certificates"].append({
                        "filename": backup_file.name,
                        "path": str(backup_file),
                        "size": backup_file.stat().st_size,
                        "created": datetime.fromtimestamp(backup_file.stat().st_mtime).isoformat(),
                        "metadata": metadata
                    })
                except Exception as e:
                    logger.warning(f"Error processing certificate backup {backup_file}: {e}")
        
        return backups
        
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        return {"settings": [], "certificates": []}

# =============================================
# BACKUP MANAGEMENT API ENDPOINTS
# =============================================

backup_metadata_model = api.model('BackupMetadata', {
    'filename': fields.String(description='Backup filename'),
    'size': fields.Integer(description='File size in bytes'),
    'created': fields.String(description='Creation timestamp'),
    'metadata': fields.Raw(description='Backup metadata')
})

backup_list_model = api.model('BackupList', {
    'settings': fields.List(fields.Nested(backup_metadata_model), description='Settings backups'),
    'certificates': fields.List(fields.Nested(backup_metadata_model), description='Certificate backups')
})

@ns_backups.route('')
class BackupList(Resource):
    @api.doc(security='Bearer')
    @api.marshal_with(backup_list_model)
    @require_auth
    def get(self):
        """List all available backups"""
        try:
            backups = list_backups()
            return backups
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return {'message': 'Failed to list backups'}, 500

@ns_backups.route('/create')
class BackupCreate(Resource):
    @api.doc(security='Bearer')
    @api.expect(api.model('BackupCreateRequest', {
        'type': fields.String(required=True, enum=['settings', 'certificates', 'both'], description='Type of backup to create'),
        'reason': fields.String(description='Reason for backup creation', default='manual')
    }))
    @require_auth
    def post(self):
        """Create manual backup"""
        try:
            data = request.get_json()
            backup_type = data.get('type', 'both')
            reason = data.get('reason', 'manual')
            
            created_backups = []
            
            if backup_type in ['settings', 'both']:
                # Create settings backup
                current_settings = load_settings()
                backup_path = create_settings_backup(current_settings, reason)
                if backup_path:
                    created_backups.append({
                        'type': 'settings',
                        'path': backup_path,
                        'filename': Path(backup_path).name
                    })
            
            if backup_type in ['certificates', 'both']:
                # Create certificates backup
                backup_path = create_certificates_backup(reason)
                if backup_path:
                    created_backups.append({
                        'type': 'certificates', 
                        'path': backup_path,
                        'filename': Path(backup_path).name
                    })
            
            if created_backups:
                return {
                    'success': True,
                    'message': f'Backup(s) created successfully',
                    'backups': created_backups
                }
            else:
                return {
                    'success': False,
                    'message': 'No backups were created'
                }, 400
                
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return {'success': False, 'message': f'Failed to create backup: {str(e)}'}, 500

@ns_backups.route('/download/<backup_type>/<filename>')
class BackupDownload(Resource):
    @api.doc(security='Bearer')
    @require_auth
    def get(self, backup_type, filename):
        """Download a specific backup file"""
        try:
            if backup_type not in ['settings', 'certificates']:
                return {'message': 'Invalid backup type'}, 400
            
            backup_path = BACKUP_DIR / backup_type / filename
            
            if not backup_path.exists():
                return {'message': 'Backup file not found'}, 404
            
            # Verify file is within backup directory (security check)
            if not str(backup_path.resolve()).startswith(str(BACKUP_DIR.resolve())):
                return {'message': 'Access denied'}, 403
            
            return send_file(
                backup_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
            
        except Exception as e:
            logger.error(f"Error downloading backup: {e}")
            return {'message': f'Failed to download backup: {str(e)}'}, 500

@ns_backups.route('/restore/settings')
class BackupRestoreSettings(Resource):
    @api.doc(security='Bearer')
    @api.expect(api.model('RestoreSettingsRequest', {
        'filename': fields.String(required=True, description='Settings backup filename to restore'),
        'create_backup_before_restore': fields.Boolean(description='Create backup before restoring', default=True)
    }))
    @require_auth
    def post(self):
        """Restore settings from backup"""
        try:
            data = request.get_json()
            filename = data.get('filename')
            create_backup = data.get('create_backup_before_restore', True)
            
            if not filename:
                return {'message': 'Filename is required'}, 400
            
            backup_path = BACKUP_DIR / "settings" / filename
            
            if not backup_path.exists():
                return {'message': 'Backup file not found'}, 404
            
            # Verify file is within backup directory (security check)
            if not str(backup_path.resolve()).startswith(str((BACKUP_DIR / "settings").resolve())):
                return {'message': 'Access denied'}, 403
            
            # Create backup of current settings before restore
            if create_backup:
                current_settings = load_settings()
                backup_path_current = create_settings_backup(current_settings, f"before_restore_{filename}")
                if backup_path_current:
                    logger.info(f"Created backup before restore: {backup_path_current}")
            
            # Load backup data
            backup_data = safe_file_read(backup_path, is_json=True)
            if not backup_data:
                return {'message': 'Failed to read backup file'}, 500
            
            # Extract settings from backup data
            if 'settings' in backup_data:
                restored_settings = backup_data['settings']
            else:
                # Assume the entire file is settings (for older backups)
                restored_settings = backup_data
            
            # Validate and save restored settings
            if save_settings(restored_settings, f"restore_from_{filename}"):
                logger.info(f"Settings restored from backup: {filename}")
                return {
                    'success': True,
                    'message': 'Settings restored successfully',
                    'restored_from': filename
                }
            else:
                return {'message': 'Failed to save restored settings'}, 500
                
        except Exception as e:
            logger.error(f"Error restoring settings: {e}")
            return {'message': f'Failed to restore settings: {str(e)}'}, 500

@ns_backups.route('/cleanup')
class BackupCleanup(Resource):
    @api.doc(security='Bearer')
    @api.expect(api.model('CleanupRequest', {
        'type': fields.String(enum=['settings', 'certificates', 'both'], description='Type of backups to cleanup', default='both'),
        'force': fields.Boolean(description='Force cleanup even if within retention period', default=False)
    }))
    @require_auth
    def post(self):
        """Clean up old backups"""
        try:
            data = request.get_json() or {}
            cleanup_type = data.get('type', 'both')
            force = data.get('force', False)
            
            cleaned_files = []
            
            if cleanup_type in ['settings', 'both']:
                cleanup_old_settings_backups()
                cleaned_files.append('settings')
            
            if cleanup_type in ['certificates', 'both']:
                cleanup_old_certificate_backups()
                cleaned_files.append('certificates')
            
            return {
                'success': True,
                'message': f'Cleanup completed for: {", ".join(cleaned_files)}',
                'cleaned_types': cleaned_files
            }
            
        except Exception as e:
            logger.error(f"Error during backup cleanup: {e}")
            return {'message': f'Failed to cleanup backups: {str(e)}'}, 500

# =============================================
# WEB INTERFACE BACKUP ENDPOINTS
# =============================================

@app.route('/api/web/backups')
@require_auth
def web_list_backups():
    """Web interface endpoint to list backups"""
    try:
        backups = list_backups()
        return jsonify(backups)
    except Exception as e:
        logger.error(f"Error listing backups for web: {e}")
        return jsonify({'error': 'Failed to list backups'}), 500

@app.route('/api/web/backups/create', methods=['POST'])
@require_auth
def web_create_backup():
    """Web interface endpoint to create backup"""
    try:
        data = request.get_json() or {}
        backup_type = data.get('type', 'both')
        reason = data.get('reason', 'manual_web')
        
        created_backups = []
        
        if backup_type in ['settings', 'both']:
            current_settings = load_settings()
            backup_path = create_settings_backup(current_settings, reason)
            if backup_path:
                created_backups.append({
                    'type': 'settings',
                    'filename': Path(backup_path).name
                })
        
        if backup_type in ['certificates', 'both']:
            backup_path = create_certificates_backup(reason)
            if backup_path:
                created_backups.append({
                    'type': 'certificates',
                    'filename': Path(backup_path).name
                })
        
        if created_backups:
            return jsonify({
                'success': True,
                'message': 'Backup(s) created successfully',
                'backups': created_backups
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No backups were created'
            }), 400
            
    except Exception as e:
        logger.error(f"Error creating backup via web: {e}")
        return jsonify({'error': f'Failed to create backup: {str(e)}'}), 500

@app.route('/api/web/backups/download/<backup_type>/<filename>')
@require_auth
def web_download_backup(backup_type, filename):
    """Web interface endpoint to download backup"""
    try:
        if backup_type not in ['settings', 'certificates']:
            return jsonify({'error': 'Invalid backup type'}), 400
        
        backup_path = BACKUP_DIR / backup_type / filename
        
        if not backup_path.exists():
            return jsonify({'error': 'Backup file not found'}), 404
        
        # Security check
        if not str(backup_path.resolve()).startswith(str(BACKUP_DIR.resolve())):
            return jsonify({'error': 'Access denied'}), 403
        
        return send_file(
            backup_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        logger.error(f"Error downloading backup via web: {e}")
        return jsonify({'error': f'Failed to download backup: {str(e)}'}), 500

# =============================================
# WEB INTERFACE CACHE ENDPOINTS
# =============================================

@app.route('/api/web/cache/stats')
def web_cache_stats():
    """Web interface endpoint to get cache statistics"""
    try:
        stats = deployment_cache.get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting cache stats for web: {e}")
        return jsonify({'error': 'Failed to get cache statistics'}), 500

@app.route('/api/web/cache/clear', methods=['POST'])
def web_cache_clear():
    """Web interface endpoint to clear cache"""
    try:
        cleared_count = deployment_cache.clear()
        return jsonify({
            'success': True,
            'message': 'Cache cleared successfully',
            'cleared_entries': cleared_count
        })
    except Exception as e:
        logger.error(f"Error clearing cache for web: {e}")
        return jsonify({
            'success': False,
            'message': f'Failed to clear cache: {str(e)}',
            'cleared_entries': 0
        }), 500

# Web Certificate API Routes (for form-based frontend)
@app.route('/api/web/certificates')
@require_auth
def web_list_certificates():
    """Web interface endpoint to list certificates"""
    try:
        settings = load_settings()
        certificates = []
        
        for domain_config in settings.get('domains', []):
            domain_name = domain_config.get('domain') if isinstance(domain_config, dict) else domain_config
            cert_info = get_certificate_info(domain_name)
            if cert_info:
                certificates.append(cert_info)
        
        return jsonify(certificates)
    except Exception as e:
        logger.error(f"Error fetching certificates via web: {e}")
        # Return empty array on error to ensure frontend compatibility
        return jsonify([])

@app.route('/api/web/certificates/create', methods=['POST'])
@require_auth
def web_create_certificate():
    """Web interface endpoint to create certificate"""
    try:
        # Handle both form data and JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        domain = data.get('domain')
        dns_provider = data.get('dns_provider')  # Optional, uses default from settings
        account_id = data.get('account_id')      # Optional, uses default account
        
        if not domain:
            return jsonify({'success': False, 'message': 'Domain is required'}), 400
        
        settings = load_settings()
        email = settings.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email not configured in settings'}), 400
        
        # Determine DNS provider
        if not dns_provider:
            dns_provider = settings.get('dns_provider', 'cloudflare')
        
        # Validate that the specified account exists (if provided)
        if account_id:
            account_config, _ = get_dns_provider_account_config(dns_provider, account_id, settings)
            if not account_config:
                return jsonify({
                    'success': False, 
                    'message': f'DNS provider account "{account_id}" not found for {dns_provider}'
                }), 400
        
        # Create certificate in background
        def create_cert_async():
            success, message = create_certificate(domain, email, dns_provider, account_id=account_id)
            logger.info(f"Certificate creation for {domain}: {'Success' if success else 'Failed'}")
        
        thread = threading.Thread(target=create_cert_async)
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': f'Certificate creation started for {domain}',
            'domain': domain,
            'dns_provider': dns_provider,
            'account_id': account_id
        })
        
    except Exception as e:
        logger.error(f"Certificate creation failed via web: {str(e)}")
        return jsonify({'success': False, 'message': f'Certificate creation failed: {str(e)}'}), 500

@app.route('/api/web/certificates/<string:domain>/download')
@require_auth
def web_download_certificate(domain):
    """Web interface endpoint to download certificate as ZIP file"""
    try:
        cert_dir = CERT_DIR / domain
        if not cert_dir.exists():
            return jsonify({'error': 'Certificate not found'}), 404
        
        # Create temporary ZIP file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            with zipfile.ZipFile(tmp_file.name, 'w') as zip_file:
                for file_name in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
                    file_path = cert_dir / file_name
                    if file_path.exists():
                        zip_file.write(file_path, file_name)
            
            return send_file(tmp_file.name, as_attachment=True, download_name=f'{domain}-certificates.zip')
            
    except Exception as e:
        logger.error(f"Error downloading certificate via web: {e}")
        return jsonify({'error': f'Failed to download certificate: {str(e)}'}), 500

@app.route('/api/web/certificates/<string:domain>/renew', methods=['POST'])
@require_auth
def web_renew_certificate(domain):
    """Web interface endpoint to renew certificate"""
    try:
        settings = load_settings()
        
        # Check if domain exists in settings
        domain_exists = False
        for domain_config in settings.get('domains', []):
            if isinstance(domain_config, dict) and domain_config.get('domain') == domain:
                domain_exists = True
                break
            elif isinstance(domain_config, str) and domain_config == domain:
                domain_exists = True
                break
        
        if not domain_exists:
            return jsonify({'success': False, 'message': 'Domain not found in settings'}), 404
        
        # Renew certificate in background
        def renew_cert_async():
            success, message = renew_certificate(domain)
            logger.info(f"Certificate renewal for {domain}: {'Success' if success else 'Failed'}")
        
        thread = threading.Thread(target=renew_cert_async)
        thread.start()
        
        return jsonify({'success': True, 'message': f'Certificate renewal started for {domain}'})
        
    except Exception as e:
        logger.error(f"Certificate renewal failed via web: {str(e)}")
        return jsonify({'success': False, 'message': f'Certificate renewal failed: {str(e)}'}), 500

def migrate_domains_format(settings):
    """Migrate old domain format (string) to new format (object with dns_provider)"""
    try:
        if 'domains' not in settings:
            return settings
            
        domains = settings['domains']
        default_provider = settings.get('dns_provider', 'cloudflare')
        migrated_domains = []
        
        for domain_entry in domains:
            if isinstance(domain_entry, str):
                # Old format: just a string
                migrated_domains.append({
                    'domain': domain_entry,
                    'dns_provider': default_provider
                })
            elif isinstance(domain_entry, dict):
                # New format: already an object
                if 'domain' in domain_entry:
                    # Ensure dns_provider is set if missing
                    if 'dns_provider' not in domain_entry:
                        domain_entry['dns_provider'] = default_provider
                    migrated_domains.append(domain_entry)
            else:
                # Invalid format, skip
                logger.warning(f"Invalid domain entry format: {domain_entry}")
                
        settings['domains'] = migrated_domains
        return settings
        
    except Exception as e:
        logger.error(f"Error during domain format migration: {e}")
        return settings

def migrate_dns_providers_to_multi_account(settings):
    """Migrate old single-account DNS provider configurations to multi-account format"""
    try:
        dns_providers = settings.get('dns_providers', {})
        
        # Check if migration is needed
        needs_migration = False
        for provider_name, provider_config in dns_providers.items():
            if provider_config and isinstance(provider_config, dict):
                # Check if this is an old single-account configuration
                # Look for credential keys that indicate old format
                old_config_keys = {
                    'cloudflare': ['api_token'],
                    'route53': ['access_key_id', 'secret_access_key', 'region'],
                    'azure': ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret'],
                    'google': ['project_id', 'service_account_key'],
                    'powerdns': ['api_url', 'api_key'],
                    'digitalocean': ['api_token'],
                    'linode': ['api_key'],
                    'gandi': ['api_token'],
                    'ovh': ['endpoint', 'application_key', 'application_secret', 'consumer_key'],
                    'namecheap': ['username', 'api_key'],
                    'rfc2136': ['nameserver', 'tsig_key', 'tsig_secret']
                }
                
                provider_keys = old_config_keys.get(provider_name, ['api_token', 'api_key', 'username'])
                
                # Check if this provider has old-style configuration (direct credential keys)
                # Skip if already has 'accounts' structure or account-like sub-objects
                if 'accounts' not in provider_config:
                    has_old_config = any(key in provider_config for key in provider_keys)
                    has_account_objects = any(
                        isinstance(v, dict) and ('name' in v or any(k in v for k in provider_keys))
                        for k, v in provider_config.items()
                        if k not in provider_keys
                    )
                    
                    if has_old_config and not has_account_objects:
                        needs_migration = True
                        break
        
        if not needs_migration:
            return settings
            
        logger.info("Migrating DNS providers to multi-account format")
        
        # Migrate each provider
        for provider_name, provider_config in dns_providers.items():
            if not provider_config or not isinstance(provider_config, dict):
                continue
                
            # Skip if already in multi-account format
            if 'accounts' in provider_config:
                continue
                
            # Define credential keys for each provider
            old_config_keys = {
                'cloudflare': ['api_token'],
                'route53': ['access_key_id', 'secret_access_key', 'region'],
                'azure': ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret'],
                'google': ['project_id', 'service_account_key'],
                'powerdns': ['api_url', 'api_key'],
                'digitalocean': ['api_token'],
                'linode': ['api_key'],
                'gandi': ['api_token'],
                'ovh': ['endpoint', 'application_key', 'application_secret', 'consumer_key'],
                'namecheap': ['username', 'api_key'],
                'rfc2136': ['nameserver', 'tsig_key', 'tsig_secret', 'api_key'],
                'vultr': ['api_key'],
                'hetzner': ['api_token'],
                'porkbun': ['api_key', 'secret_key'],
                'godaddy': ['api_key', 'secret'],
                'he-ddns': ['username', 'password']
            }
            
            provider_keys = old_config_keys.get(provider_name, ['api_token', 'api_key', 'username'])
            
            # Check if this provider has old-style configuration
            has_old_config = any(key in provider_config for key in provider_keys)
            
            # Check if it already has account-like objects
            has_account_objects = any(
                isinstance(v, dict) and ('name' in v or any(k in v for k in provider_keys))
                for k, v in provider_config.items()
                if k not in provider_keys
            )
            
            if not has_old_config or has_account_objects:
                continue
                
            # Extract old configuration keys
            old_config = {}
            remaining_config = {}
            
            for key, value in provider_config.items():
                if key in provider_keys:
                    old_config[key] = value
                else:
                    remaining_config[key] = value
                    
            # Create new multi-account structure
            new_config = {
                'accounts': {
                    'default': {
                        'name': f'Default {provider_name.title()} Account',
                        'description': 'Migrated from single-account configuration',
                        **old_config
                    }
                },
                **remaining_config
            }
                    
            dns_providers[provider_name] = new_config
            
        # Update default accounts if not set
        if 'default_accounts' not in settings:
            settings['default_accounts'] = {}
            
        # Set default account for each configured provider
        for provider_name, provider_config in dns_providers.items():
            if provider_config and isinstance(provider_config, dict) and 'accounts' in provider_config:
                if provider_name not in settings['default_accounts']:
                    # Use the first account as default
                    first_account_id = next(iter(provider_config['accounts'].keys()), None)
                    if first_account_id:
                        settings['default_accounts'][provider_name] = first_account_id
                        
        logger.info("DNS provider migration completed successfully")
        return settings
        
    except Exception as e:
        logger.error(f"Error during DNS provider migration: {e}")
        return settings

def get_domain_dns_provider(domain, settings):
    """Get the DNS provider for a specific domain
    
    Args:
        domain: The domain name to check
        settings: Current settings dict
        
    Returns:
        str: DNS provider name (e.g., 'cloudflare', 'route53')
    """
    try:
        # Check if domain has specific DNS provider configured
        domains = settings.get('domains', [])
        
        for domain_entry in domains:
            if isinstance(domain_entry, dict):
                # New format: {domain: "example.com", dns_provider: "route53", account_id: "prod"}
                if domain_entry.get('domain') == domain:
                    return domain_entry.get('dns_provider', settings.get('dns_provider', 'cloudflare'))
            elif isinstance(domain_entry, str) and domain_entry == domain:
                # Old format: just domain string, use global DNS provider
                return settings.get('dns_provider', 'cloudflare')
        
        # Domain not found in list, use global default
        return settings.get('dns_provider', 'cloudflare')
        
    except Exception as e:
        logger.error(f"Error getting DNS provider for domain {domain}: {e}")
        return 'cloudflare'  # Safe fallback

def get_dns_provider_account_config(provider, account_id=None, settings=None):
    """Get DNS provider account configuration
    
    Args:
        provider: DNS provider name (e.g., 'cloudflare')
        account_id: Specific account ID (optional, uses default if not provided)
        settings: Settings dict (optional, loads current if not provided)
        
    Returns:
        tuple: (account_config_dict, used_account_id)
    """
    try:
        if not settings:
            settings = load_settings()
            
        # Ensure migration is applied
        settings = migrate_dns_providers_to_multi_account(settings)
        
        dns_providers = settings.get('dns_providers', {})
        provider_config = dns_providers.get(provider, {})
        
        if not isinstance(provider_config, dict) or not provider_config:
            return None, None
        
        # Check if this is multi-account format (has 'accounts' key)
        if 'accounts' in provider_config:
            accounts = provider_config['accounts']
            if not isinstance(accounts, dict):
                return None, None
            
            # If account_id is specified, look for it directly
            if account_id:
                if account_id in accounts:
                    account_config = accounts[account_id]
                    if isinstance(account_config, dict):
                        return account_config, account_id
                else:
                    # Specific account requested but not found
                    return None, None
            
            # If no account_id specified, try to use default account
            default_accounts = settings.get('default_accounts', {})
            default_account_id = default_accounts.get(provider)
            
            if default_account_id and default_account_id in accounts:
                account_config = accounts[default_account_id]
                if isinstance(account_config, dict):
                    return account_config, default_account_id
            
            # If we get here and no account_id was specified, try to use the first available account
            for acc_id, acc_config in accounts.items():
                if isinstance(acc_config, dict) and any(key in acc_config for key in [
                    'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                ]):
                    logger.info(f"Using first available account '{acc_id}' for provider {provider}")
                    return acc_config, acc_id
            
            return None, None
        else:
            # Check if this is old single-account format (has direct config keys)
            if any(key in provider_config for key in [
                'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
            ]):
                # This is old single-account format
                return provider_config, 'default'
            
            # If we get here, it's multi-account format but structured differently
            # Try to find account configs directly under provider
            if account_id:
                # Look for specific account
                if account_id in provider_config:
                    acc_config = provider_config[account_id]
                    if isinstance(acc_config, dict) and any(key in acc_config for key in [
                        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                    ]):
                        return acc_config, account_id
                # Specific account requested but not found
                return None, None
            else:
                # No specific account requested - try default or first available
                default_accounts = settings.get('default_accounts', {})
                default_account_id = default_accounts.get(provider)
                
                # Try default account first
                if default_account_id and default_account_id in provider_config:
                    acc_config = provider_config[default_account_id]
                    if isinstance(acc_config, dict) and any(key in acc_config for key in [
                        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                    ]):
                        return acc_config, default_account_id
                
                # Fall back to first available account
                for acc_id, acc_config in provider_config.items():
                    if isinstance(acc_config, dict) and any(key in acc_config for key in [
                        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                    ]):
                        logger.info(f"Using first available account '{acc_id}' for provider {provider}")
                        return acc_config, acc_id
            
            return None, None
                
    except Exception as e:
        logger.error(f"Error getting DNS provider account config for {provider}: {e}")
        return None, None

def list_dns_provider_accounts(provider, settings=None):
    """List all accounts for a DNS provider
    
    Args:
        provider: DNS provider name
        settings: Settings dict (optional, loads current if not provided)
        
    Returns:
        list: List of account configurations with metadata
    """
    try:
        if not settings:
            settings = load_settings()
            
        # Ensure migration is applied
        settings = migrate_dns_providers_to_multi_account(settings)
        
        dns_providers = settings.get('dns_providers', {})
        provider_config = dns_providers.get(provider, {})
        
        accounts = []
        
        if 'accounts' in provider_config:
            # Multi-account format
            for account_id, account_config in provider_config['accounts'].items():
                accounts.append({
                    'account_id': account_id,
                    'name': account_config.get('name', account_id.title()),
                    'description': account_config.get('description', ''),
                    'configured': bool(any(account_config.get(key) for key in [
                        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                    ]))
                })
        elif provider_config:
            # Legacy single-account format
            accounts.append({
                'account_id': 'default',
                'name': f'Default {provider.title()} Account',
                'description': 'Legacy single-account configuration',
                'configured': bool(any(provider_config.get(key) for key in [
                    'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                ]))
            })
            
        return accounts
        
    except Exception as e:
        logger.error(f"Error listing DNS provider accounts for {provider}: {e}")
        return []

def suggest_dns_provider_for_domain(domain, settings=None):
    """Suggest DNS provider based on domain patterns and existing configuration
    
    Args:
        domain: Domain name to analyze
        settings: Current settings (optional)
        
    Returns:
        tuple: (suggested_provider, confidence_level)
    """
    if not domain:
        return None, 0
    
    # Load settings if not provided
    if settings is None:
        settings = load_settings()
    
    # Check if domain already exists in settings
    existing_domains = settings.get('domains', [])
    for domain_config in existing_domains:
        if isinstance(domain_config, dict):
            if domain_config.get('domain') == domain:
                return domain_config.get('dns_provider'), 100  # High confidence
        elif domain_config == domain:
            # Old format, use global provider
            return settings.get('dns_provider', 'cloudflare'), 80
    
    # Pattern-based suggestions
    domain_lower = domain.lower()
    
    # AWS/Route53 patterns
    if any(pattern in domain_lower for pattern in ['aws', 'amazon', 'route53', 'test.certmate.org']):
        return 'route53', 70
    
    # Cloudflare patterns
    if any(pattern in domain_lower for pattern in ['cf-', 'cloudflare', 'audiolibri.org']):
        return 'cloudflare', 70
    
    # DigitalOcean patterns
    if any(pattern in domain_lower for pattern in ['do-', 'digitalocean']):
        return 'digitalocean', 70
    
    # Default to global setting
    return settings.get('dns_provider', 'cloudflare'), 30

# Initialize global deployment cache
deployment_cache = DeploymentStatusCache()

def update_cache_settings():
    """Update cache settings from configuration"""
    try:
        settings = load_settings()
        cache_ttl = settings.get('cache_ttl', 300)
        deployment_cache.set_ttl(cache_ttl)
        logger.info(f"Updated deployment cache TTL to {cache_ttl} seconds")
    except Exception as e:
        logger.error(f"Error updating cache settings: {e}")

# Initialize cache settings
update_cache_settings()
