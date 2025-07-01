from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from flask_restx import Api, Resource, fields, Namespace
from functools import wraps
import os
import json
import subprocess
import tempfile
import zipfile
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

def safe_file_read(file_path, is_json=False, default=None):
    """Safely read a file with proper error handling and file locking"""
    try:
        if not Path(file_path).exists():
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
        # Ensure parent directory exists
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
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

def validate_email(email):
    """Validate email address format"""
    if not email or not isinstance(email, str):
        return False, "Email is required"
    
    email = email.strip().lower()
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    if len(email) > 254:
        return False, "Email too long"
    
    return True, email

def validate_domain(domain):
    """Validate domain name format"""
    if not domain or not isinstance(domain, str):
        return False, "Domain is required"
    
    domain = domain.strip().lower()
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc or domain
    
    # Basic domain validation
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
    
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    if len(domain) > 253:
        return False, "Domain too long"
    
    if '..' in domain:
        return False, "Domain cannot contain consecutive dots"
    
    return True, domain

def validate_api_token(token):
    """Validate API token strength and format"""
    if not token or not isinstance(token, str):
        return False, "API token is required"
    
    token = token.strip()
    
    if len(token) < 32:
        return False, "API token must be at least 32 characters long"
    
    if len(token) > 500:
        return False, "API token too long"
    
    # Check for weak patterns
    weak_patterns = [
        'password', '12345', 'admin', 'test', 'demo', 'change-this',
        'default', 'secret', 'token', 'key', 'api'
    ]
    
    token_lower = token.lower()
    for pattern in weak_patterns:
        if pattern in token_lower:
            return False, f"API token contains weak pattern: {pattern}"
    
    return True, token

# Initialize Flask app
app = Flask(__name__)
# Generate a secure random secret key if not provided
default_secret = os.urandom(32).hex() if not os.getenv('SECRET_KEY') else 'your-secret-key-here'
app.secret_key = os.getenv('SECRET_KEY', default_secret)
CORS(app)

# Initialize Flask-RESTX
api = Api(
    app,
    version='1.0',
    title='CertMate API',
    description='SSL Certificate Management API with Cloudflare DNS Challenge',
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
    CERT_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    
    # Verify directory permissions
    if not os.access(CERT_DIR, os.W_OK):
        logger.error(f"No write permission for certificates directory: {CERT_DIR}")
    if not os.access(DATA_DIR, os.W_OK):
        logger.error(f"No write permission for data directory: {DATA_DIR}")
        
except Exception as e:
    logger.error(f"Failed to create required directories: {e}")
    # Use temporary directories as fallback
    CERT_DIR = Path(tempfile.mkdtemp(prefix="certmate_certs_"))
    DATA_DIR = Path(tempfile.mkdtemp(prefix="certmate_data_"))
    logger.warning(f"Using temporary directories - certificates may not persist")

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
        # First time setup - create with secure defaults
        logger.info("Creating initial settings file with secure defaults")
        save_settings(default_settings)
        return default_settings
    
    try:
        settings = safe_file_read(SETTINGS_FILE, is_json=True)
        if settings is None:
            logger.warning("Failed to read settings, using defaults")
            return default_settings
            
        # Validate and merge with defaults
        for key, default_value in default_settings.items():
            if key not in settings:
                settings[key] = default_value
                
        # Validate critical settings
        if settings.get('api_bearer_token') in ['change-this-token', 'certmate-api-token-12345', '']:
            logger.warning("Insecure API token detected, generating new one")
            settings['api_bearer_token'] = generate_secure_token()
            save_settings(settings)
            
        return settings
        
    except Exception as e:
        logger.error(f"Error loading settings: {e}")
        return default_settings

def save_settings(settings):
    """Save settings to file with improved error handling and validation"""
    try:
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
        
        return safe_file_write(SETTINGS_FILE, settings)
        
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

def create_cloudflare_config(token):
    """Create Cloudflare credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "cloudflare.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_cloudflare_api_token = {token}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_route53_config(access_key_id, secret_access_key):
    """Create AWS Route53 credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "route53.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_route53_access_key_id = {access_key_id}\n")
        f.write(f"dns_route53_secret_access_key = {secret_access_key}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_azure_config(subscription_id, resource_group, tenant_id, client_id, client_secret):
    """Create Azure DNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "azure.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_azure_subscription_id = {subscription_id}\n")
        f.write(f"dns_azure_resource_group = {resource_group}\n")
        f.write(f"dns_azure_tenant_id = {tenant_id}\n")
        f.write(f"dns_azure_client_id = {client_id}\n")
        f.write(f"dns_azure_client_secret = {client_secret}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_google_config(project_id, service_account_key):
    """Create Google Cloud DNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Create service account JSON file
    sa_file = config_dir / "google-service-account.json"
    with open(sa_file, 'w') as f:
        f.write(service_account_key)
    sa_file.chmod(0o600)
    
    # Create credentials file
    config_file = config_dir / "google.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_google_project_id = {project_id}\n")
        f.write(f"dns_google_service_account_key = {str(sa_file)}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_powerdns_config(api_url, api_key):
    """Create PowerDNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "powerdns.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_powerdns_api_url = {api_url}\n")
        f.write(f"dns_powerdns_api_key = {api_key}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_digitalocean_config(api_token):
    """Create DigitalOcean DNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "digitalocean.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_digitalocean_token = {api_token}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_linode_config(api_key):
    """Create Linode DNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "linode.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_linode_key = {api_key}\n")
        f.write("dns_linode_version = 4\n")  # Use API v4
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_gandi_config(api_token):
    """Create Gandi DNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "gandi.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_gandi_token = {api_token}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_ovh_config(endpoint, application_key, application_secret, consumer_key):
    """Create OVH DNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "ovh.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_ovh_endpoint = {endpoint}\n")
        f.write(f"dns_ovh_application_key = {application_key}\n")
        f.write(f"dns_ovh_application_secret = {application_secret}\n")
        f.write(f"dns_ovh_consumer_key = {consumer_key}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_namecheap_config(username, api_key):
    """Create Namecheap DNS credentials file"""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "namecheap.ini"
    with open(config_file, 'w') as f:
        f.write(f"dns_namecheap_username = {username}\n")
        f.write(f"dns_namecheap_api_key = {api_key}\n")
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file

def create_multi_provider_config(provider, config_data):
    """Create configuration for additional DNS providers using individual plugins where available
    
    This function supports additional providers beyond the core Tier 1 providers.
    For
    direct API implementation should be used instead.
    """
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Map providers to their individual plugin configuration files
    plugin_configs = {
        'vultr': 'vultr.ini',
        'dnsmadeeasy': 'dnsmadeeasy.ini',
        'nsone': 'nsone.ini',
        'rfc2136': 'rfc2136.ini',
        'hetzner': 'hetzner.ini',
        'porkbun': 'porkbun.ini',
        'godaddy': 'godaddy.ini',
        'he-ddns': 'he-ddns.ini',
        'dynudns': 'dynudns.ini'
    }
    
    if provider not in plugin_configs:
        # Provider doesn't have an individual plugin
        # Return None to indicate fallback to direct API should be used
        return None
    
    config_file = config_dir / plugin_configs[provider]
    
    # Create provider-specific configuration
    if provider == 'vultr':
        api_key = config_data.get('api_key')
        if not api_key:
            raise ValueError("Vultr API key required")
        
        config_content = f"dns_vultr_api_key = {api_key}\n"
        
    elif provider == 'dnsmadeeasy':
        api_key = config_data.get('api_key')
        secret_key = config_data.get('secret_key')
        if not api_key or not secret_key:
            raise ValueError("DNS Made Easy API key and secret key required")
            
        config_content = f"dns_dnsmadeeasy_api_key = {api_key}\n"
        config_content += f"dns_dnsmadeeasy_secret_key = {secret_key}\n"
        
    elif provider == 'nsone':
        api_key = config_data.get('api_key')
        if not api_key:
            raise ValueError("NS1 API key required")
            
        config_content = f"dns_nsone_api_key = {api_key}\n"
        
    elif provider == 'rfc2136':
        nameserver = config_data.get('nameserver')
        tsig_key = config_data.get('tsig_key')
        tsig_secret = config_data.get('tsig_secret')
        tsig_algorithm = config_data.get('tsig_algorithm', 'HMAC-SHA512')
        
        if not nameserver or not tsig_key or not tsig_secret:
            raise ValueError("RFC2136 nameserver, TSIG key and secret required")
            
        config_content = f"dns_rfc2136_nameserver = {nameserver}\n"
        config_content += f"dns_rfc2136_name = {tsig_key}\n"
        config_content += f"dns_rfc2136_secret = {tsig_secret}\n"
        config_content += f"dns_rfc2136_algorithm = {tsig_algorithm}\n"
        
    elif provider == 'hetzner':
        api_token = config_data.get('api_token')
        if not api_token:
            raise ValueError("Hetzner DNS API token required")
            
        config_content = f"dns_hetzner_api_token = {api_token}\n"
        
    elif provider == 'porkbun':
        api_key = config_data.get('api_key')
        secret_key = config_data.get('secret_key')
        if not api_key or not secret_key:
            raise ValueError("Porkbun API key and secret key required")
            
        config_content = f"dns_porkbun_api_key = {api_key}\n"
        config_content += f"dns_porkbun_secret_key = {secret_key}\n"
        
    elif provider == 'godaddy':
        api_key = config_data.get('api_key')
        secret = config_data.get('secret')
        if not api_key or not secret:
            raise ValueError("GoDaddy API key and secret required")
            
        config_content = f"dns_godaddy_key = {api_key}\n"
        config_content += f"dns_godaddy_secret = {secret}\n"
        
    elif provider == 'he-ddns':
        username = config_data.get('username')
        password = config_data.get('password')
        if not username or not password:
            raise ValueError("Hurricane Electric username and password required")
            
        config_content = f"dns_he_ddns_username = {username}\n"
        config_content += f"dns_he_ddns_password = {password}\n"
        
    elif provider == 'dynudns':
        token = config_data.get('token')
        if not token:
            raise ValueError("Dynu API token required")
            
        config_content = f"dns_dynudns_token = {token}\n"
        
    else:
        # This shouldn't happen given our check above, but just in case
        return None
    
    # Write the configuration file
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    # Set proper permissions
    config_file.chmod(0o600)
    return config_file
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
            if not access_key or not secret_key:
                return False, "AWS Route53 credentials not configured"
            config_file = create_route53_config(access_key, secret_key)
            dns_plugin = 'route53'
            dns_args = ['--dns-route53-credentials', str(config_file)]
            
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
            return True, "Certificate created successfully"
        else:
            error_msg = result.stderr or result.stdout
            logger.error(f"Certificate creation failed: {error_msg}")
            return False, f"Certificate creation failed: {error_msg}"
    
    except Exception as e:
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

# Define namespaces
ns_certificates = Namespace('certificates', description='Certificate operations')
ns_settings = Namespace('settings', description='Settings operations')
ns_health = Namespace('health', description='Health check')

api.add_namespace(ns_certificates)
api.add_namespace(ns_settings)
api.add_namespace(ns_health)

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

# Certificate endpoints
@ns_certificates.route('')
class CertificateList(Resource):
    @api.doc(security='Bearer')
    @api.marshal_list_with(certificate_model)
    @require_auth
    def get(self):
        """Get all certificates"""
        settings = load_settings()
        certificates = []
        
        for domain_config in settings.get('domains', []):
            domain_name = domain_config.get('domain') if isinstance(domain_config, dict) else domain_config
            cert_info = get_certificate_info(domain_name)
            if cert_info:
                certificates.append(cert_info)
        
        return certificates

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
        
        # Determine DNS provider
        if not dns_provider:
            dns_provider = settings.get('dns_provider', 'cloudflare')
        
        # Validate that the specified account exists (if provided)
        if account_id:
            account_config, _ = get_dns_provider_account_config(dns_provider, account_id, settings)
            if not account_config:
                return {
                    'success': False, 
                    'message': f'DNS provider account "{account_id}" not found for {dns_provider}'
                }, 400
        
        try:
            success, message = create_certificate(domain, email, dns_provider, account_id=account_id)
            
            if success:
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
@app.route('/')
def index():
    """Main dashboard"""
    settings = load_settings()
    certificates = []
    
    for domain_config in settings.get('domains', []):
        domain_name = domain_config.get('domain') if isinstance(domain_config, dict) else domain_config
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
            
            return jsonify({'account': account_config})
            
        except Exception as e:
            logger.error(f"[DNS DEBUG] Error getting account {account_id} for {provider}: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
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
    
    elif request.method == 'DELETE':
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

@app.route('/api/web/cache/stats')
def web_cache_stats():
    """Get cache statistics for the web interface"""
    try:
        # For now, return placeholder stats - implement actual cache stats later
        stats = {
            'entries': 0,
            'current_ttl': 300,
            'hits': 0,
            'misses': 0
        }
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/web/cache/clear', methods=['POST'])
def web_cache_clear():
    """Clear deployment status cache for the web interface"""
    try:
        # For now, return success - implement actual cache clearing later
        logger.info("Cache clear requested from web interface")
        return jsonify({'success': True, 'message': 'Cache cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'error': str(e)}), 500

# Web-specific certificates endpoint (no auth required for initial setup)
@app.route('/api/web/certificates')
def web_certificates():
    """Web interface certificates endpoint (no auth required)"""
    settings = load_settings()
    
    # Migrate settings format if needed
    settings = migrate_domains_format(settings)
    
    certificates = []
    
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
            certificates.append(cert_info)
    
    return jsonify(certificates)

@app.route('/api/web/certificates/create', methods=['POST'])
def web_create_certificate():
    """Web interface create certificate endpoint (no auth required)"""
    data = request.get_json()
    domain = data.get('domain')
    dns_provider_override = data.get('dns_provider')  # Optional DNS provider override
    
    if not domain:
        return jsonify({'success': False, 'message': 'Domain is required'}), 400
    
    settings = load_settings()
    
    # Migrate settings format if needed
    settings = migrate_domains_format(settings) 
    
    email = settings.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email not configured in settings'}), 400
    
    # Determine DNS provider to use
    dns_provider = dns_provider_override or settings.get('dns_provider', 'cloudflare')
    
    # Validate DNS provider configuration
    dns_config = settings.get('dns_providers', {}).get(dns_provider, {})
    
    if dns_provider == 'cloudflare':
        # Support legacy cloudflare_token setting
        token = dns_config.get('api_token') or settings.get('cloudflare_token', '')
        if not token:
            return jsonify({'success': False, 'message': f'{dns_provider.title()} token not configured in settings'}), 400
        dns_config = {'api_token': token}
    elif dns_provider == 'route53':
        if not dns_config.get('access_key_id') or not dns_config.get('secret_access_key'):
            return jsonify({'success': False, 'message': 'AWS Route53 credentials not configured in settings'}), 400
    elif dns_provider == 'azure':
        required_fields = ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret']
        if not all(dns_config.get(field) for field in required_fields):
            return jsonify({'success': False, 'message': 'Azure DNS credentials not configured in settings'}), 400
    elif dns_provider == 'google':
        if not dns_config.get('credentials_file') and not dns_config.get('credentials_json'):
            return jsonify({'success': False, 'message': 'Google Cloud DNS credentials not configured in settings'}), 400
    elif dns_provider == 'powerdns':
        if not dns_config.get('api_url') or not dns_config.get('api_key'):
            return jsonify({'success': False, 'message': 'PowerDNS API credentials not configured in settings'}), 400
    elif dns_provider == 'digitalocean':
        if not dns_config.get('api_token'):
            return jsonify({'success': False, 'message': 'DigitalOcean API token not configured in settings'}), 400
    elif dns_provider == 'linode':
        if not dns_config.get('api_key'):
            return jsonify({'success': False, 'message': 'Linode API key not configured in settings'}), 400
    elif dns_provider == 'gandi':
        if not dns_config.get('api_token'):
            return jsonify({'success': False, 'message': 'Gandi API token not configured in settings'}), 400
    elif dns_provider == 'ovh':
        if not all(dns_config.get(field) for field in ['endpoint', 'application_key', 'application_secret', 'consumer_key']):
            return jsonify({'success': False, 'message': 'OVH credentials not fully configured in settings'}), 400
    elif dns_provider == 'namecheap':
        if not all(dns_config.get(field) for field in ['username', 'api_key']):
            return jsonify({'success': False, 'message': 'Namecheap credentials not fully configured in settings'}), 400
    
    # Add domain to settings if not already there (using new format)
    domains = settings.get('domains', [])
    domain_exists = False
    
    for domain_entry in domains:
        if isinstance(domain_entry, str):
            if domain_entry == domain:
                domain_exists = True
                break
        elif isinstance(domain_entry, dict):
            if domain_entry.get('domain') == domain:
                domain_exists = True
                # Update DNS provider if it changed
                if domain_entry.get('dns_provider') != dns_provider:
                    domain_entry['dns_provider'] = dns_provider
                break
    
    if not domain_exists:
        domains.append({
            'domain': domain,
            'dns_provider': dns_provider
        })
        settings['domains'] = domains
        save_settings(settings)
    
    # Create certificate using new multi-provider function
    success, message = create_certificate(domain, email, dns_provider, dns_config)
    logger.info(f"Certificate creation for {domain} using {dns_provider}: {'Success' if success else 'Failed'} - {message}")
    
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'message': message}), 500

@app.route('/api/web/certificates/<domain>/renew', methods=['POST'])
def web_renew_certificate(domain):
    """Web interface renew certificate endpoint (no auth required)"""
    settings = load_settings()
    
    # Migrate settings format if needed
    settings = migrate_domains_format(settings)
    
    # Check if domain exists in settings (handle both old and new formats)
    domain_found = False
    for domain_entry in settings.get('domains', []):
        if isinstance(domain_entry, str):
            if domain_entry == domain:
                domain_found = True
                break
        elif isinstance(domain_entry, dict):
            if domain_entry.get('domain') == domain:
                domain_found = True
                break
    
    if not domain_found:
        return jsonify({'success': False, 'message': 'Domain not found in settings'}), 404
    
    # Renew certificate in background
    def renew_cert_async():
        success, message = renew_certificate(domain)
        logger.info(f"Certificate renewal for {domain}: {'Success' if success else 'Failed'}")
    
    thread = threading.Thread(target=renew_cert_async)
    thread.start()
    
    return jsonify({'success': True, 'message': f'Certificate renewal started for {domain}'})

@app.route('/api/web/certificates/<domain>/download')
def web_download_certificate(domain):
    """Web interface download certificate endpoint (no auth required)"""
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

def check_ssl_certificate(domain, port=443, timeout=10):
    """Check SSL certificate for a domain"""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the domain
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate info
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Check if certificate is valid for this domain
                san_extension = None
                try:
                    san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san_names = [name.value for name in san_extension.value]
                except:
                    san_names = []
                
                # Get subject common name
                subject_cn = None
                for attribute in cert.subject:
                    if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                        subject_cn = attribute.value
                        break
                
                # Check if domain matches certificate
                certificate_domains = []
                if subject_cn:
                    certificate_domains.append(subject_cn)
                certificate_domains.extend(san_names)
                
                domain_match = any(
                    domain == cert_domain or 
                    (cert_domain.startswith('*.') and domain.endswith(cert_domain[2:]))
                    for cert_domain in certificate_domains
                )
                
                return {
                    'deployed': True,
                    'reachable': True,
                    'certificate_match': domain_match,
                    'certificate_domains': certificate_domains,
                    'issuer': cert.issuer.rfc4514_string(),
                    'expires_at': cert.not_valid_after_utc.isoformat(),
                    'method': 'ssl-direct',
                    'timestamp': datetime.now().isoformat()
                }
                
    except socket.timeout:
        return {
            'deployed': False,
            'reachable': False,
            'certificate_match': False,
            'error': 'timeout',
            'method': 'ssl-direct',
            'timestamp': datetime.now().isoformat()
        }
    except socket.gaierror:
        return {
            'deployed': False,
            'reachable': False,
            'certificate_match': False,
            'error': 'dns_resolution_failed',
            'method': 'ssl-direct',
            'timestamp': datetime.now().isoformat()
        }
    except ssl.SSLError as e:
        return {
            'deployed': False,
            'reachable': True,
            'certificate_match': False,
            'error': f'ssl_error: {str(e)}',
            'method': 'ssl-direct',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'deployed': False,
            'reachable': False,
            'certificate_match': False,
            'error': f'unknown: {str(e)}',
            'method': 'ssl-direct',
            'timestamp': datetime.now().isoformat()
        }

@ns_certificates.route('/<string:domain>/deployment-status')
class CertificateDeploymentStatus(Resource):
    def get(self, domain):
        """Check deployment status of a certificate for a domain"""
        try:
            logger.info(f"Checking deployment status for domain: {domain}")
            
            # Check SSL certificate deployment
            deployment_status = check_ssl_certificate(domain)
            
            # If we have a certificate for this domain, compare with deployed cert
            cert_dir = CERT_DIR / domain
            if cert_dir.exists():
                cert_file = cert_dir / "cert.pem"
                if cert_file.exists():
                    try:
                        # Load our certificate
                        with open(cert_file, 'rb') as f:
                            our_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                        
                        # If the domain has SSL but doesn't match, check if it's our certificate
                        if deployment_status['reachable'] and not deployment_status['certificate_match']:
                            # Additional verification - check certificate fingerprints or other identifiers
                            deployment_status['has_local_cert'] = True
                            deployment_status['local_cert_expires'] = our_cert.not_valid_after_utc.isoformat()
                        else:
                            deployment_status['has_local_cert'] = True
                            deployment_status['local_cert_expires'] = our_cert.not_valid_after_utc.isoformat()
                            
                    except Exception as e:
                        logger.error(f"Error reading local certificate for {domain}: {e}")
                        deployment_status['has_local_cert'] = False
                else:
                    deployment_status['has_local_cert'] = False
            else:
                deployment_status['has_local_cert'] = False
            
            return deployment_status
            
        except Exception as e:
            logger.error(f"Error checking deployment status for {domain}: {e}")
            return {
                'deployed': False,
                'reachable': False,
                'certificate_match': False,
                'error': f'check_failed: {str(e)}',
                'method': 'ssl-direct',
                'timestamp': datetime.now().isoformat()
            }, 500

def get_domain_dns_provider(domain, settings):
    """Get the DNS provider used for a specific domain"""
    domains = settings.get('domains', [])
    
    # Handle both old format (list of strings) and new format (list of objects)
    for domain_entry in domains:
        if isinstance(domain_entry, str):
            # Old format - just domain name, use default provider
            if domain_entry == domain:
                return settings.get('dns_provider', 'cloudflare')
        elif isinstance(domain_entry, dict):
            # New format - domain object with provider info
            if domain_entry.get('domain') == domain:
                return domain_entry.get('dns_provider', settings.get('dns_provider', 'cloudflare'))
    
    # If domain not found, return default provider
    return settings.get('dns_provider', 'cloudflare')

def migrate_domains_format(settings):
    """Migrate domains from old format (list of strings) to new format (list of objects)"""
    domains = settings.get('domains', [])
    migrated_domains = []
    needs_migration = False
    
    for domain_entry in domains:
        if isinstance(domain_entry, str):
            # Old format - convert to new format
            migrated_domains.append({
                'domain': domain_entry,
                'dns_provider': settings.get('dns_provider', 'cloudflare')
            })
            needs_migration = True
        elif isinstance(domain_entry, dict):
            # Already new format
            migrated_domains.append(domain_entry)
        else:
            # Invalid format, skip
            logger.warning(f"Invalid domain entry format: {domain_entry}")
    
    if needs_migration:
        settings['domains'] = migrated_domains
        save_settings(settings)
        logger.info("Migrated domains to new format")
    
    return settings

# Input validation utilities
def validate_domain(domain):
    """Validate domain name format and security"""
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string"
    
    domain = domain.strip().lower()
    
    # Basic format validation
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    # Length checks
    if len(domain) > 253:
        return False, "Domain name too long"
    
    # Check for dangerous characters
    if any(char in domain for char in [' ', '\n', '\r', '\t', ';', '&', '|', '`']):
        return False, "Domain contains invalid characters"
    
    return True, domain

def validate_email(email):
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False, "Email must be a non-empty string"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email.strip()):
        return False, "Invalid email format"
    
    return True, email.strip().lower()

def validate_api_token(token):
    """Validate API token strength"""
    if not token or not isinstance(token, str):
        return False, "Token must be a non-empty string"
    
    if len(token) < 32:
        return False, "Token must be at least 32 characters long"
    
    if token in ['change-this-token', 'certmate-api-token-12345']:
        return False, "Please use a secure, unique token"
    
    return True, token

def generate_secure_token():
    """Generate a secure random token for API authentication"""
    return secrets.token_urlsafe(32)

def migrate_dns_providers_to_multi_account(settings):
    """Migrate existing single-account DNS providers to multi-account structure
    
    This function ensures backward compatibility by converting old format:
    dns_providers: { "cloudflare": {"api_token": "..."} }
    
    To new format:
    dns_providers: { "cloudflare": {"default": {"name": "Default Account", "api_token": "..."}} }
    default_accounts: { "cloudflare": "default" }
    """
    if 'dns_providers' not in settings:
        return settings
        
    # Check if migration is needed
    needs_migration = False
    dns_providers = settings['dns_providers']
    
    for provider, config in dns_providers.items():
        if isinstance(config, dict) and any(key in config for key in [
            'api_token', 'access_key_id', 'secret_access_key', 'api_key', 'api_url',
            'subscription_id', 'project_id', 'username', 'token', 'secret'
        ]):
            # This is old single-account format
            needs_migration = True
            break
    
    if not needs_migration:
        return settings
    
    logger.info("Migrating DNS providers to multi-account structure")
    
    # Initialize new structures
    if 'default_accounts' not in settings:
        settings['default_accounts'] = {}
    
    migrated_providers = {}
    
    for provider, config in dns_providers.items():
        if isinstance(config, dict):
            # Check if this is already multi-account format
            if any(isinstance(v, dict) and ('name' in v or 'api_token' in v or 'access_key_id' in v) for v in config.values()):
                # Already in multi-account format or mixed format
                migrated_providers[provider] = config
                continue
            
            # Check if this is single-account format that needs migration
            credentials_found = any(key in config for key in [
                'api_token', 'access_key_id', 'secret_access_key', 'api_key', 'api_url',
                'subscription_id', 'project_id', 'username', 'token', 'secret'
            ])
            
            if credentials_found:
                # Migrate to multi-account format
                migrated_providers[provider] = {
                    'default': {
                        'name': 'Default Account',
                        'description': f'Migrated from single-account configuration',
                        **config
                    }
                }
                settings['default_accounts'][provider] = 'default'
                logger.info(f"Migrated {provider} to multi-account format")
            else:
                # Empty or invalid config, keep as is
                migrated_providers[provider] = config
        else:
            # Non-dict config, keep as is
            migrated_providers[provider] = config
    
    settings['dns_providers'] = migrated_providers
    return settings

def validate_dns_provider_account(provider, account_id, config):
    """Validate DNS provider account configuration
    
    Args:
        provider: DNS provider name (e.g., 'cloudflare')
        account_id: Account identifier (e.g., 'production')
        config: Account configuration dict
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not isinstance(config, dict):
        return False, "Account configuration must be a dictionary"
    
    # Validate account metadata
    if 'name' not in config or not config['name'].strip():
        return False, "Account name is required"
    
    # Provider-specific validation
    if provider == 'cloudflare':
        if 'api_token' not in config or not config['api_token']:
            return False, "Cloudflare API token is required"
        # Basic token format validation
        token = config['api_token']
        if len(token) < 10:
            return False, "Cloudflare API token appears to be too short"
            
    elif provider == 'route53':
        required_fields = ['access_key_id', 'secret_access_key']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"AWS Route53 {field} is required"
        # Basic AWS key format validation
        if len(config['access_key_id']) < 16:
            return False, "AWS access key ID appears to be too short"
        if len(config['secret_access_key']) < 32:
            return False, "AWS secret access key appears to be too short"
            
    elif provider == 'azure':
        required_fields = ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"Azure {field} is required"
                
    elif provider == 'google':
        required_fields = ['project_id', 'service_account_key']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"Google Cloud {field} is required"
        # Validate service account key is valid JSON
        try:
            json.loads(config['service_account_key'])
        except (json.JSONDecodeError, TypeError):
            return False, "Google Cloud service account key must be valid JSON"
            
    elif provider == 'powerdns':
        required_fields = ['api_url', 'api_key']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"PowerDNS {field} is required"
        # Validate URL format
        try:
            parsed = urlparse(config['api_url'])
            if not parsed.scheme or not parsed.netloc:
                return False, "PowerDNS API URL must be a valid URL"
        except Exception:
            return False, "PowerDNS API URL format is invalid"
            
    elif provider in ['digitalocean', 'linode', 'gandi', 'vultr', 'hetzner', 'nsone', 'dnsmadeeasy']:
        if 'api_key' not in config and 'api_token' not in config:
            return False, f"{provider.title()} API key/token is required"
        
        token_key = 'api_key' if 'api_key' in config else 'api_token'
        if not config.get(token_key):
            return False, f"{provider.title()} {token_key} cannot be empty"
            
    elif provider == 'ovh':
        required_fields = ['endpoint', 'application_key', 'application_secret', 'consumer_key']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"OVH {field} is required"
                
    elif provider == 'namecheap':
        required_fields = ['username', 'api_key']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"Namecheap {field} is required"
                
    elif provider == 'rfc2136':
        required_fields = ['nameserver', 'tsig_key', 'tsig_secret']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"RFC2136 {field} is required"
                
    elif provider == 'porkbun':
        required_fields = ['api_key', 'secret_key']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"Porkbun {field} is required"
                
    elif provider == 'godaddy':
        required_fields = ['api_key', 'secret']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"GoDaddy {field} is required"
                
    elif provider == 'he-ddns':
        required_fields = ['username', 'password']
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"Hurricane Electric {field} is required"
                
    elif provider == 'dynudns':
        if 'token' not in config or not config['token']:
            return False, "Dynu API token is required"
    
    return True, "Valid"

def get_dns_provider_account_config(provider, account_id=None, settings=None):
    """Get DNS provider account configuration
    
    Args:
        provider: DNS provider name
        account_id: Account identifier (if None, uses default)
        settings: Settings dict (if None, loads from file)
        
    Returns:
        tuple: (account_config, account_id_used)
    """
    if settings is None:
        settings = load_settings()
    
    # Ensure migration is applied
    settings = migrate_dns_providers_to_multi_account(settings)
    
    dns_providers = settings.get('dns_providers', {})
    if provider not in dns_providers:
        return None, None
    
    provider_config = dns_providers[provider]
    
    # Handle both old and new formats
    if not isinstance(provider_config, dict):
        return None, None
    
    # If account_id is not specified, use default
    if account_id is None:
        default_accounts = settings.get('default_accounts', {})
        account_id = default_accounts.get(provider, 'default')
    
    # Check if this is multi-account format
    if account_id in provider_config and isinstance(provider_config[account_id], dict):
        account_config = provider_config[account_id]
        # Check if this looks like an account config (has name or credentials)
        if 'name' in account_config or any(key in account_config for key in [
            'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
        ]):
            return account_config, account_id
    
    # Fallback for old single-account format or if account not found
    # Check if provider_config has direct credentials (old format)
    if any(key in provider_config for key in [
        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
    ]):
        # This is old format, wrap it
        return {
            'name': 'Default Account',
            **provider_config
        }, 'default'
    
    # Try 'default' account if not already tried
    if account_id != 'default' and 'default' in provider_config:
        default_config = provider_config['default']
        if isinstance(default_config, dict):
            return default_config, 'default'
    
    return None, None

def list_dns_provider_accounts(provider, settings=None):
    """List all accounts for a DNS provider
    
    Args:
        provider: DNS provider name
        settings: Settings dict (if None, loads from file)
        
    Returns:
        dict: {account_id: account_info, ...}
    """
    if settings is None:
        settings = load_settings()
    
    # Ensure migration is applied
    settings = migrate_dns_providers_to_multi_account(settings)
    
    dns_providers = settings.get('dns_providers', {})
    if provider not in dns_providers:
        return {}
    
    provider_config = dns_providers[provider]
    if not isinstance(provider_config, dict):
        return {}
    
    accounts = {}
    for account_id, config in provider_config.items():
        if isinstance(config, dict):
            # Check if this looks like an account config
            if 'name' in config or any(key in config for key in [
                'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
            ]):
                accounts[account_id] = {
                    'name': config.get('name', 'Unnamed Account'),
                    'description': config.get('description', '')
                }
    
    # Fallback for old single-account format
    if not accounts and any(key in provider_config for key in [
        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
    ]):
        accounts['default'] = {
            'name': 'Default Account',
            'description': 'Migrated from single-account configuration'
        }
    
    return accounts

# Multi-Account DNS Management endpoints
@ns_settings.route('/dns-providers/<string:provider>/accounts')
class DNSProviderAccounts(Resource):
    @api.doc(security='Bearer')
    @require_auth
    def get(self, provider):
        """Get all accounts for a specific DNS provider"""
        try:
            accounts = list_dns_provider_accounts(provider)
            settings = load_settings()
            default_accounts = settings.get('default_accounts', {})
            default_account = default_accounts.get(provider)
            
            return {
                'provider': provider,
                'accounts': accounts,
                'default_account': default_account,
                'total_accounts': len(accounts)
            }
        except Exception as e:
            logger.error(f"Error getting DNS provider accounts: {str(e)}")
            return {'error': 'Failed to get DNS provider accounts'}, 500

    @api.doc(security='Bearer')
    @require_auth
    def post(self, provider):
        """Add a new account for a DNS provider"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No data provided'}, 400
            
            account_id = data.get('account_id')
            account_config = data.get('config', {})
            
            if not account_id:
                return {'error': 'account_id is required'}, 400
            
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
            
            return {
                'message': f'Account {account_id} added successfully to {provider}',
                'account_id': account_id,
                'provider': provider
            }, 201
            
        except Exception as e:
            logger.error(f"Error adding DNS provider account: {str(e)}")
            return {'error': 'Failed to add DNS provider account'}, 500

@ns_settings.route('/dns-providers/<string:provider>/accounts/<string:account_id>')
class DNSProviderAccount(Resource):
    @api.doc(security='Bearer')
    @require_auth
    def get(self, provider, account_id):
        """Get a specific account configuration (masked)"""
        try:
            account_config, _ = get_dns_provider_account_config(provider, account_id)
            if not account_config:
                return {'error': 'Account not found'}, 404
            
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
            logger.error(f"Error getting DNS provider account: {str(e)}")
            return {'error': 'Failed to get DNS provider account'}, 500

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
            
            # Remove the account
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
