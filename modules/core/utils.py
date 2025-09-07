"""
This module contains self-contained utility functions for the CertMate application.

These functions handle tasks like data validation, security token generation,
and the creation of configuration files for certbot DNS plugins. They do not
depend on the Flask application context or global configuration variables.
"""
import dataclasses
import re
import secrets
import string
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# =============================================
# MODULE-LEVEL CONSTANTS
# =============================================

# Constants for API token validation
_MIN_TOKEN_LENGTH = 32  # Increased minimum for better security
_MAX_TOKEN_LENGTH = 512
_MIN_UNIQUE_CHARS = 12  # Increased for better entropy
_WEAK_TOKEN_PATTERNS = {
    'password', '12345', 'admin', 'test', 'demo', 'change-this',
    'default', 'secret', 'token', 'key', 'api', 'qwerty', 'example',
    'your_token_here', 'your_super_secure_api_token_here_change_this'
}

# A mapping of DNS providers to their required credential fields for validation.
_DNS_PROVIDER_CREDENTIALS = {
    'cloudflare': ['api_token'],
    'route53': ['access_key_id', 'secret_access_key'],
    'azure': ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret'],
    'google': ['project_id', 'service_account_key'],
    'powerdns': ['api_url', 'api_key'],
    'digitalocean': ['api_token'],
    'linode': ['api_key'],
    'gandi': ['api_token'],
    'ovh': ['endpoint', 'application_key', 'application_secret', 'consumer_key'],
    'namecheap': ['username', 'api_key'],
    'arvancloud': ['api_key'],
    'acme-dns': ['api_url', 'username', 'password', 'subdomain'],
    'vultr': ['api_key'],
    'dnsmadeeasy': ['api_key', 'secret_key'],
    'nsone': ['api_key'],
    'rfc2136': ['nameserver', 'tsig_key', 'tsig_secret'],
    'hetzner': ['api_token'],
    'porkbun': ['api_key', 'secret_key'],
    'godaddy': ['api_key', 'secret'],
    'he-ddns': ['username', 'password'],
    'dynudns': ['token']
}

# A mapping of multi-provider names to their certbot plugin .ini filename.
_MULTI_PROVIDER_PLUGIN_FILES = {
    'vultr': 'vultr.ini', 'dnsmadeeasy': 'dnsmadeeasy.ini', 'nsone': 'nsone.ini',
    'rfc2136': 'rfc2136.ini', 'hetzner': 'hetzner.ini', 'porkbun': 'porkbun.ini',
    'godaddy': 'godaddy.ini', 'he-ddns': 'he-ddns.ini', 'dynudns': 'dynudns.ini'
}

# A data-driven template for building multi-provider config files.
# Maps the final .ini key to the key from the input config_data dictionary.
# A tuple value indicates an optional key: (input_key, default_value)
_MULTI_PROVIDER_TEMPLATE_MAP = {
    'vultr': {'dns_vultr_api_key': 'api_key'},
    'dnsmadeeasy': {'dns_dnsmadeeasy_api_key': 'api_key', 'dns_dnsmadeeasy_secret_key': 'secret_key'},
    'nsone': {'dns_nsone_api_key': 'api_key'},
    'rfc2136': {
        'dns_rfc2136_nameserver': 'nameserver',
        'dns_rfc2136_name': 'tsig_key',
        'dns_rfc2136_secret': 'tsig_secret',
        'dns_rfc2136_algorithm': ('tsig_algorithm', 'HMAC-SHA512')
    },
    'hetzner': {'dns_hetzner_api_token': 'api_token'},
    'porkbun': {'dns_porkbun_api_key': 'api_key', 'dns_porkbun_secret_key': 'secret_key'},
    'godaddy': {'dns_godaddy_key': 'api_key', 'dns_godaddy_secret': 'secret'},
    'he-ddns': {'dns_he_ddns_username': 'username', 'dns_he_ddns_password': 'password'},
    'dynudns': {'dns_dynudns_token': 'token'},
}


# =============================================
# VALIDATION FUNCTIONS
# =============================================

def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate email address format with enhanced structural and domain checks.
    """
    if not email or not isinstance(email, str):
        return False, "Email address is required and must be a string."

    email = email.strip()
    if len(email) > 254:
        return False, "Email address is too long (maximum 254 characters)."
    if email.count('@') != 1:
        return False, "Invalid email format (must contain exactly one '@' symbol)."

    local_part, domain_part = email.split('@', 1)

    if not local_part or len(local_part) > 64:
        return False, "Invalid email format (local part is missing or too long)."
    if not re.fullmatch(r"^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+$", local_part):
         return False, "Invalid characters in the local part of the email."

    if not domain_part:
        return False, "Invalid email format (domain part is missing)."
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}$'
    )
    if not domain_pattern.fullmatch(domain_part):
        return False, "Invalid domain name format in email address."
        
    return True, email.lower()


def validate_domain(domain: str) -> Tuple[bool, str]:
    """
    Validate a domain name with enhanced structural checks for RFC compliance.
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain is required and must be a string."
    
    domain = domain.strip().lower()
    
    if domain.startswith(('http://', 'https://')):
        try:
            domain = urlparse(domain).netloc
            if not domain:
                return False, "Could not extract a valid domain from the provided URL."
        except Exception:
            return False, "Invalid URL format provided."
            
    domain_to_validate = domain[2:] if domain.startswith('*.') else domain

    if len(domain_to_validate) > 253 or '..' in domain_to_validate:
        return False, "Domain is too long or contains consecutive dots."

    labels = domain_to_validate.split('.')
    if len(labels) < 2:
        return False, "Invalid domain format (e.g., must be like 'example.com')."
    
    label_pattern = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
    
    for i, label in enumerate(labels):
        if not label:
            return False, "Domain labels cannot be empty."
        if len(label) > 63:
            return False, f"Domain label '{label}' is too long (maximum 63 characters)."
        
        is_last_label = (i == len(labels) - 1)
        if is_last_label and (not label.isalpha() or len(label) < 2):
            return False, f"Invalid Top-Level Domain (TLD): '{label}'."
        if not is_last_label and not label_pattern.fullmatch(label):
             return False, f"Invalid format for domain label: '{label}'."

    return True, domain


def validate_api_token(token: str) -> Tuple[bool, str]:
    """
    Validate an API token for strength, format, and complexity.
    Enhanced security validation with cryptographic strength checks.
    """
    if not token or not isinstance(token, str):
        return False, "API token is required and must be a string."
    
    token = token.strip()
    
    # Check minimum and maximum length
    if not (_MIN_TOKEN_LENGTH <= len(token) <= _MAX_TOKEN_LENGTH):
        return False, f"API token length must be between {_MIN_TOKEN_LENGTH} and {_MAX_TOKEN_LENGTH} characters."
    
    # Check for weak patterns (case insensitive)
    token_lower = token.lower()
    for pattern in _WEAK_TOKEN_PATTERNS:
        if pattern in token_lower:
            return False, f"API token must not contain weak patterns like '{pattern}'."
    
    # Check character variety for entropy
    unique_chars = len(set(token))
    if unique_chars < _MIN_UNIQUE_CHARS:
        return False, f"API token lacks character variety (must have at least {_MIN_UNIQUE_CHARS} unique characters)."
    
    # Additional security checks
    # Check for repeating patterns
    if len(token) >= 6:
        for i in range(len(token) - 5):
            pattern = token[i:i+3]
            if token.count(pattern) > 2:
                return False, "API token contains too many repeating patterns."
    
    # Check character type distribution for better entropy
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    
    char_types = sum([has_upper, has_lower, has_digit])
    if char_types < 2:
        return False, "API token must contain at least 2 character types (uppercase, lowercase, digits)."
    
    return True, token


# =============================================
# SECURITY & TOKEN FUNCTIONS
# =============================================

def generate_secure_token(length: int = 40) -> str:
    """
    Generate a cryptographically secure, random string for API authentication.
    Enhanced to ensure compliance with stronger validation requirements.
    """
    if not isinstance(length, int) or length < _MIN_TOKEN_LENGTH:
        raise ValueError(f"Token length must be an integer of at least {_MIN_TOKEN_LENGTH} characters for security.")
    
    # Ensure we have a good mix of character types for better entropy
    alphabet_upper = string.ascii_uppercase
    alphabet_lower = string.ascii_lowercase
    alphabet_digits = string.digits
    alphabet_all = alphabet_upper + alphabet_lower + alphabet_digits
    
    # Generate token with guaranteed character type diversity
    token_parts = []
    
    # Ensure at least one character from each type
    token_parts.append(secrets.choice(alphabet_upper))
    token_parts.append(secrets.choice(alphabet_lower))
    token_parts.append(secrets.choice(alphabet_digits))
    
    # Fill the rest with random characters
    for _ in range(length - 3):
        token_parts.append(secrets.choice(alphabet_all))
    
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(token_parts)
    
    return ''.join(token_parts)


# =============================================
# CERTBOT CONFIGURATION FILE CREATORS
# =============================================

def _create_config_file(plugin_name: str, content: str) -> Path:
    """Generic helper to create a config file in the right directory."""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / f"{plugin_name}.ini"
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    config_file.chmod(0o600)
    return config_file

def create_cloudflare_config(token: str) -> Path:
    """Create Cloudflare credentials file."""
    return _create_config_file("cloudflare", f"dns_cloudflare_api_token = {token}\n")

def create_route53_config(access_key_id: str, secret_access_key: str) -> Path:
    """Create AWS Route53 credentials file."""
    content = f"dns_route53_access_key_id = {access_key_id}\ndns_route53_secret_access_key = {secret_access_key}\n"
    return _create_config_file("route53", content)

def create_azure_config(subscription_id: str, resource_group: str, tenant_id: str, client_id: str, client_secret: str) -> Path:
    """Create Azure DNS credentials file."""
    content = (
        f"dns_azure_subscription_id = {subscription_id}\n"
        f"dns_azure_resource_group = {resource_group}\n"
        f"dns_azure_tenant_id = {tenant_id}\n"
        f"dns_azure_client_id = {client_id}\n"
        f"dns_azure_client_secret = {client_secret}\n"
    )
    return _create_config_file("azure", content)

def create_google_config(project_id: str, service_account_key: str) -> Path:
    """Create Google Cloud DNS credentials file."""
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    sa_file = config_dir / "google-service-account.json"
    with open(sa_file, 'w', encoding='utf-8') as f:
        f.write(service_account_key)
    sa_file.chmod(0o600)
    
    content = f"dns_google_project_id = {project_id}\ndns_google_service_account_key = {str(sa_file)}\n"
    return _create_config_file("google", content)

def create_powerdns_config(api_url: str, api_key: str) -> Path:
    """Create PowerDNS credentials file."""
    content = f"dns_powerdns_api_url = {api_url}\ndns_powerdns_api_key = {api_key}\n"
    return _create_config_file("powerdns", content)

def create_digitalocean_config(api_token: str) -> Path:
    """Create DigitalOcean DNS credentials file."""
    return _create_config_file("digitalocean", f"dns_digitalocean_token = {api_token}\n")

def create_linode_config(api_key: str) -> Path:
    """Create Linode DNS credentials file."""
    content = f"dns_linode_key = {api_key}\ndns_linode_version = 4\n"
    return _create_config_file("linode", content)

def create_gandi_config(api_token: str) -> Path:
    """Create Gandi DNS credentials file."""
    return _create_config_file("gandi", f"dns_gandi_token = {api_token}\n")

def create_ovh_config(endpoint: str, application_key: str, application_secret: str, consumer_key: str) -> Path:
    """Create OVH DNS credentials file."""
    content = (
        f"dns_ovh_endpoint = {endpoint}\n"
        f"dns_ovh_application_key = {application_key}\n"
        f"dns_ovh_application_secret = {application_secret}\n"
        f"dns_ovh_consumer_key = {consumer_key}\n"
    )
    return _create_config_file("ovh", content)

def create_namecheap_config(username: str, api_key: str) -> Path:
    """Create Namecheap DNS credentials file."""
    content = f"dns_namecheap_username = {username}\ndns_namecheap_api_key = {api_key}\n"
    return _create_config_file("namecheap", content)

def create_arvancloud_config(api_key: str) -> Path:
    """Create ArvanCloud DNS credentials file."""
    content = f"dns_arvancloud_api_key = {api_key}\n"
    return _create_config_file("arvancloud", content)

def create_acme_dns_config(api_url: str, username: str, password: str, subdomain: str) -> Path:
    """Create ACME-DNS credentials file."""
    content = f"""{{
    "{subdomain}": {{
        "username": "{username}",
        "password": "{password}",
        "fulldomain": "{subdomain}",
        "subdomain": "{subdomain}",
        "allowfrom": []
    }}
}}"""
    return _create_config_file("acme-dns", content)

def create_multi_provider_config(provider: str, config_data: Dict[str, Any]) -> Optional[Path]:
    """
    Creates a certbot DNS plugin configuration file from a provider and data.
    """
    if provider not in _MULTI_PROVIDER_PLUGIN_FILES:
        return None

    is_valid, _ = validate_dns_provider_account(provider, '', config_data)
    if not is_valid:
        return None

    try:
        template = _MULTI_PROVIDER_TEMPLATE_MAP[provider]
        config_lines = []
        for ini_key, source in template.items():
            value = config_data.get(*source) if isinstance(source, tuple) else config_data[source]
            config_lines.append(f"{ini_key} = {value}")

        return _create_config_file(provider, "\n".join(config_lines) + "\n")
    except (KeyError, Exception):
        return None


# =============================================
# DNS PROVIDER HELPERS
# =============================================

def validate_dns_provider_account(provider: str, account_id: str, account_config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates a DNS provider's account configuration dictionary.
    """
    try:
        if provider not in _DNS_PROVIDER_CREDENTIALS:
            return False, f"Unsupported DNS provider: '{provider}'."

        if not isinstance(account_config, dict):
            return False, f"Account configuration must be a dictionary, but got {type(account_config).__name__}."
        
        required_fields = _DNS_PROVIDER_CREDENTIALS[provider]
        missing_fields = [f for f in required_fields if not str(account_config.get(f) or '').strip()]
            
        if missing_fields:
            return False, f"Missing or empty required fields: {', '.join(sorted(missing_fields))}."
        
        return True, "Valid configuration."
    except Exception as e:
        return False, f"An unexpected error occurred during validation: {e}"


# =============================================
# CACHE SYSTEM CLASS
# =============================================

@dataclasses.dataclass
class _CacheEntry:
    """Internal dataclass to represent a single, structured cache entry."""
    result: Any
    expires_at: float
    timestamp: float
    ttl: int


class DeploymentStatusCache:
    """
    A simple, thread-safe, in-memory, time-based cache.
    """
    def __init__(self, default_ttl: int = 300):
        self._cache: Dict[str, _CacheEntry] = {}
        self._default_ttl: int = default_ttl
        self._lock = threading.Lock()

    def get(self, domain: str) -> Optional[Any]:
        """Get a cached result for a domain, returning None if expired or not found."""
        with self._lock:
            entry = self._cache.get(domain)
            if entry and time.time() <= entry.expires_at:
                return entry.result
        return None
        
    def set(self, domain: str, result: Any, ttl: Optional[int] = None) -> None:
        """Cache a result for a domain with a specific or default TTL."""
        effective_ttl = ttl if ttl is not None else self._default_ttl
        entry = _CacheEntry(
            result=result,
            timestamp=time.time(),
            expires_at=time.time() + effective_ttl,
            ttl=effective_ttl
        )
        with self._lock:
            self._cache[domain] = entry
        
    def clear(self) -> int:
        """Clear all entries from the cache, returning the number of cleared items."""
        with self._lock:
            cleared_count = len(self._cache)
            self._cache.clear()
        return cleared_count
    
    def _clean_expired(self) -> None:
        """Internal method to remove all expired entries. Assumes lock is already held."""
        current_time = time.time()
        expired_keys = [k for k, v in self._cache.items() if current_time > v.expires_at]
        for key in expired_keys:
            del self._cache[key]
        
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the cache's current state, cleaning expired entries first."""
        with self._lock:
            self._clean_expired()
            entries = []
            current_time = time.time()
            for domain, entry in self._cache.items():
                deployed = False
                if isinstance(entry.result, dict):
                    deployed = bool(entry.result.get('deployed', False))
                entries.append({
                    'domain': domain,
                    'age': int(current_time - entry.timestamp),
                    'remaining': int(entry.expires_at - current_time),
                    'status': 'deployed' if deployed else 'not-deployed'
                })
            
            return {
                'total_entries': len(self._cache),
                'current_ttl': self._default_ttl,
                'entries': sorted(entries, key=lambda x: x['domain'])
            }
        
    def set_ttl(self, ttl: int) -> bool:
        """Set the default TTL for new cache entries."""
        if isinstance(ttl, (int, float)) and 30 <= ttl <= 3600:
            with self._lock:
                self._default_ttl = int(ttl)
            return True
        return False