"""
Constants module for CertMate
Centralized location for shared constants across the application
"""

# Standard certificate files produced by Certbot
CERTIFICATE_FILES = ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem')

# Maximum validity period for client certificates (in days)
MAX_CERTIFICATE_VALIDITY_DAYS = 3650  # ~10 years

# Minimum validity period for certificates
MIN_CERTIFICATE_VALIDITY_DAYS = 1

# Default renewal threshold (days before expiry to trigger renewal)
DEFAULT_RENEWAL_THRESHOLD_DAYS = 30

# Rate limiting defaults
DEFAULT_LOGIN_RATE_LIMIT = 5  # attempts
DEFAULT_LOGIN_RATE_WINDOW = 60  # seconds

# Session defaults
DEFAULT_SESSION_TIMEOUT_HOURS = 24

# API defaults
DEFAULT_CACHE_TTL = 300  # seconds


def get_domain_name(domain_config):
    """Extract domain name from either string or dict format.
    
    Args:
        domain_config: Either a string domain name or a dict with 'domain' key
        
    Returns:
        str or None: The domain name, or None if not found
    """
    if isinstance(domain_config, str):
        return domain_config
    elif isinstance(domain_config, dict):
        return domain_config.get('domain')
    return None
