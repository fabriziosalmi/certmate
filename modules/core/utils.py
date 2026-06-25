"""
This module contains self-contained utility functions for the CertMate application.

These functions handle tasks like data validation, security token generation,
and the creation of configuration files for certbot DNS plugins. They do not
depend on the Flask application context or global configuration variables.
"""
import dataclasses
import json
import re
import secrets
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse


def utc_now() -> datetime:
    """Drop-in replacement for the deprecated datetime.utcnow(): a UTC-now
    timestamp returned as a *naive* datetime, preserving on-disk format
    compatibility with timestamps written by older versions of CertMate."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_now_iso() -> str:
    """ISO-8601 string of the current UTC time, naive shape (no offset)."""
    return utc_now().isoformat()

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
    'infomaniak': ['api_token'],
    'acme-dns': ['api_url', 'username', 'password', 'subdomain'],
    'duckdns': ['api_token'],
    'vultr': ['api_key'],
    'dnsmadeeasy': ['api_key', 'secret_key'],
    'nsone': ['api_key'],
    'rfc2136': ['nameserver', 'tsig_key', 'tsig_secret'],
    'hetzner': ['api_token'],
    'hetzner-cloud': ['api_token'],
    'porkbun': ['api_key', 'secret_key'],
    'godaddy': ['api_key', 'secret'],
    'he-ddns': ['username', 'password'],
    'dynudns': ['token'],
    'edgedns': ['client_token', 'client_secret', 'access_token', 'host'],
    'desec': ['api_token'],
    'scaleway': ['application_token'],
    'solidserver': ['host', 'username', 'password', 'dns_name'],
    # Admin-supplied hook scripts (#286): the auth hook is the only hard
    # requirement; the cleanup hook is optional.
    'custom-script': ['auth_hook']
}

# A mapping of multi-provider names to their certbot plugin .ini filename.
_MULTI_PROVIDER_PLUGIN_FILES = {
    'vultr': 'vultr.ini', 'dnsmadeeasy': 'dnsmadeeasy.ini', 'nsone': 'nsone.ini',
    'rfc2136': 'rfc2136.ini', 'hetzner': 'hetzner.ini', 'hetzner-cloud': 'hetzner-cloud.ini',
    'porkbun': 'porkbun.ini', 'godaddy': 'godaddy.ini', 'he-ddns': 'he-ddns.ini',
    'dynudns': 'dynudns.ini', 'desec': 'desec.ini', 'scaleway': 'scaleway.ini'
}

# A data-driven template for building multi-provider config files.
# Maps the final .ini key to the key from the input config_data dictionary.
# A tuple value indicates an optional key: (input_key, default_value)
_MULTI_PROVIDER_TEMPLATE_MAP = {
    'vultr': {'dns_vultr_api_key': 'api_key'},
    'dnsmadeeasy': {'dns_dnsmadeeasy_api_key': 'api_key', 'dns_dnsmadeeasy_secret_key': 'secret_key'},
    'nsone': {'dns_nsone_api_key': 'api_key'},
    'rfc2136': {
        'dns_rfc2136_server': 'nameserver',
        'dns_rfc2136_name': 'tsig_key',
        'dns_rfc2136_secret': 'tsig_secret',
        'dns_rfc2136_algorithm': ('tsig_algorithm', 'HMAC-SHA512')
    },
    'hetzner': {'dns_hetzner_api_token': 'api_token'},
    'hetzner-cloud': {'dns_hetzner_cloud_api_token': 'api_token'},
    'porkbun': {'dns_porkbun_api_key': 'api_key', 'dns_porkbun_secret_key': 'secret_key'},
    'godaddy': {'dns_godaddy_key': 'api_key', 'dns_godaddy_secret': 'secret'},
    'he-ddns': {'dns_he_ddns_username': 'username', 'dns_he_ddns_password': 'password'},
    'dynudns': {'dns_dynudns_token': 'token'},
    'desec': {'dns_desec_token': 'api_token'},
    'scaleway': {'dns_scaleway_application_token': 'application_token'},
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


def find_covering_zone(fqdn: str, zones: List[str]) -> Optional[str]:
    """Return the longest zone in *zones* that covers *fqdn*, or None.

    Used by providers that need an explicit DNS-zone identity at cert
    issuance time (Azure DNS is the only one today; the certbot plugins
    for Cloudflare, Route53, Google etc. walk parent labels themselves
    so CertMate does not pre-resolve a zone for them).

    Semantics:

    * Leading ``*.`` is stripped from the FQDN — the ACME TXT challenge
      for a wildcard lives under the bare apex, not the wildcard form.
    * Comparison is case-insensitive and tolerant of trailing dots.
    * Longest-match wins. For ``api.staging.example.com`` with zones
      ``staging.example.com`` and ``example.com`` both present, the
      result is ``staging.example.com`` — the operator's intent is the
      most specific zone the IdP actually hosts.
    * **TLD guard**: candidate zones with fewer than two labels (e.g.
      ``com``, ``tv``) are silently skipped. Discovery layers never
      surface a bare TLD because providers don't host the root, but the
      guard is defence-in-depth so a misconfigured zone list cannot
      lead CertMate to attempt a TLD-wide match. Multi-label public
      suffixes (``co.uk``, ``com.br``) are NOT special-cased — they
      pass the gate and are matched structurally like any other
      ≥2-label zone. An operator who legitimately runs a hosted zone
      at that level still gets the correct longest match.
    """
    if not fqdn or not zones:
        return None
    name = fqdn.strip().lower().rstrip('.')
    if name.startswith('*.'):
        name = name[2:]
    if not name:
        return None

    best: Optional[str] = None
    best_len = -1
    for raw in zones:
        if not raw or not isinstance(raw, str):
            continue
        zone = raw.strip().lower().rstrip('.')
        if not zone or zone.count('.') < 1:
            # <2 labels — TLD guard
            continue
        if name == zone or name.endswith('.' + zone):
            if len(zone) > best_len:
                best = zone
                best_len = len(zone)
    return best


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
# CERTIFICATE KEY OPTIONS
# =============================================

# RSA key sizes accepted by certbot's --rsa-key-size; matches LE/ZeroSSL
# guidance and the upstream cryptography defaults. 1024 is excluded
# (insecure) and 8192 is excluded (no real-world need, slow handshakes).
KEY_TYPE_RSA = 'rsa'
KEY_TYPE_ECDSA = 'ecdsa'
VALID_KEY_TYPES = frozenset({KEY_TYPE_RSA, KEY_TYPE_ECDSA})
VALID_RSA_KEY_SIZES = frozenset({2048, 3072, 4096})
# secp521r1 is intentionally excluded: certbot accepts it but Let's Encrypt
# rejects it as of 2026, and most consumers (browsers, load balancers) only
# implement secp256r1/secp384r1.
VALID_ELLIPTIC_CURVES = frozenset({'secp256r1', 'secp384r1'})


def validate_key_options(
    key_type: Optional[str],
    key_size: Optional[int],
    elliptic_curve: Optional[str],
) -> Tuple[bool, str]:
    """Validate the cert key-shape inputs that flow from API/UI to certbot.

    Returns ``(True, '')`` on success and ``(False, message)`` on failure.

    All three inputs may be ``None`` to mean "use the default" — this function
    treats ``None`` for ``key_type`` as a request to skip validation entirely
    so callers can hand it untouched API payloads. When ``key_type`` is set,
    ``key_size`` and ``elliptic_curve`` are mutually exclusive (one applies to
    RSA, the other to ECDSA).
    """
    if key_type is None:
        # Caller hasn't picked a type; size/curve must also be absent or we
        # have an inconsistent shape (e.g. {'key_size': 4096} with no type).
        if key_size is not None or elliptic_curve is not None:
            return False, "key_size/elliptic_curve require key_type to be set"
        return True, ''

    if key_type not in VALID_KEY_TYPES:
        return False, f"key_type must be one of {sorted(VALID_KEY_TYPES)}, got {key_type!r}"

    if key_type == KEY_TYPE_RSA:
        if elliptic_curve is not None:
            return False, "elliptic_curve is not valid for key_type='rsa'"
        if key_size is None:
            return False, "key_size is required when key_type='rsa'"
        if key_size not in VALID_RSA_KEY_SIZES:
            return False, f"key_size must be one of {sorted(VALID_RSA_KEY_SIZES)}, got {key_size!r}"
        return True, ''

    # key_type == 'ecdsa'
    if key_size is not None:
        return False, "key_size is not valid for key_type='ecdsa'"
    if elliptic_curve is None:
        return False, "elliptic_curve is required when key_type='ecdsa'"
    if elliptic_curve not in VALID_ELLIPTIC_CURVES:
        return False, f"elliptic_curve must be one of {sorted(VALID_ELLIPTIC_CURVES)}, got {elliptic_curve!r}"
    return True, ''


# =============================================
# CERTBOT STDERR SANITIZER
# =============================================

# Matches a single line of the form `key = value` where `key` carries a
# credential-bearing name fragment. certbot-dns-azure and a few other
# plugins echo the credentials file line-by-line on parse error, so the
# offending value would otherwise round-trip into a 422 JSON response.
# Anchored on word-start so substrings like "monkeysecret" don't fire
# but `dns_azure_sp_client_secret = ...` does.
_CERTBOT_STDERR_CREDENTIAL_LINE_RE = re.compile(
    # NB: digits in the character class — provider names like
    # ``route53`` carry digits, and stripping them from the alphabet
    # would skip ``dns_route53_access_key_id`` entirely.
    r'(?im)^\s*([A-Za-z0-9_]*(?:secret|token|password|key|credential|hmac|api_bearer)[A-Za-z0-9_]*)\s*=\s*.+$'
)

# Matches absolute paths to per-provider credential .ini files
# (letsencrypt/config/<provider>.ini and friends). The path itself is
# not a credential, but operator-side troubleshooting hints already
# point operators at the path via the log, and stripping it from the
# client-facing error message is consistent with the general policy of
# not echoing internal paths.
_CERTBOT_CONFIG_PATH_RE = re.compile(
    r'(?i)(?:[\w\-./]+/)?letsencrypt/config/[A-Za-z0-9_\-.]+\.ini'
)

# Hard cap on the sanitized stderr we surface to API clients. Certbot's
# verbose mode can emit several KB; the client doesn't need the full
# trace (which is in the application log), and a huge payload is its
# own DoS shape.
_CERTBOT_STDERR_MAX_BYTES = 4096


def classify_renewal_error(reason: str) -> tuple:
    """Map a renewal failure reason to a (user_message, code) pair.

    The renew endpoints used to return an opaque ``"Certificate renewal failed"``
    with HTTP 500, hiding diagnosable conditions. The most common one is a
    *broken renewal configuration*: certbot's ``renewal/<domain>.conf`` bakes
    absolute paths and expects the ``live/`` cert to be a symlink, so after the
    data directory moves (e.g. a cert created on the host then mounted into the
    container, or a relocated volume) certbot reports a ``parsefail`` and skips
    the lineage. That is not a server fault — it is actionable: reissue.

    Returns the clean broken-config message (no host paths leaked) with code
    ``RENEWAL_CONFIG_BROKEN`` for that case, else a generic pair the caller can
    pad with the sanitized reason.
    """
    low = (reason or '').lower()
    broken_markers = ('parsefail', 'renewal configuration', 'is broken', 'to be a symlink')
    if any(marker in low for marker in broken_markers):
        return (
            "This certificate's renewal configuration is broken: its certbot "
            "config references paths that no longer exist. Use Edit & Reissue "
            "to regenerate the certificate.",
            'RENEWAL_CONFIG_BROKEN',
        )
    if 'not configured' in low and ('account' in low or 'dns provider' in low):
        return (
            "The DNS provider account this certificate uses is no longer "
            "configured. Re-add it in Settings → DNS, then retry the renewal.",
            'DNS_ACCOUNT_NOT_CONFIGURED',
        )
    return ('Certificate renewal failed', 'RENEWAL_FAILED')


def sanitize_certbot_stderr(stderr_text: str) -> str:
    """Strip credential material from a certbot stderr blob before it
    is sent to an API client.

    What gets stripped:

    * Lines of the form ``<name>_secret = ...``, ``<name>_token = ...``,
      ``<name>_password = ...``, ``<name>_key = ...``, ``<name>_credential = ...``,
      ``<name>_hmac = ...`` and ``api_bearer = ...``. Some certbot plugins
      (notably ``certbot-dns-azure``) echo the offending config line
      verbatim when they fail to parse, which round-tripped the secret
      value into the API response.
    * Credential file paths (``letsencrypt/config/<provider>.ini``) are
      replaced with ``<credential file>``. Not secret per se but
      consistent with not echoing internal paths to API consumers.

    What is preserved:

    * ACME server errors, plugin error narration, DNS verification
      failures, hint URLs, exit codes — everything an operator needs
      to figure out why a renewal failed.

    The full unredacted stderr is still written to the application log
    (``logger.error``) at the call site; this helper only sanitises the
    copy that flows into the API response.
    """
    if not stderr_text:
        return ''
    text = str(stderr_text)
    text = _CERTBOT_STDERR_CREDENTIAL_LINE_RE.sub(lambda m: f'{m.group(1)} = [REDACTED]', text)
    text = _CERTBOT_CONFIG_PATH_RE.sub('<credential file>', text)
    if len(text) > _CERTBOT_STDERR_MAX_BYTES:
        text = text[:_CERTBOT_STDERR_MAX_BYTES] + '\n[…truncated — see application log for full output]'
    return text


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
    
    # Generate tokens until we get one that passes validation
    max_attempts = 100  # Prevent infinite loops
    for attempt in range(max_attempts):
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
        
        token = ''.join(token_parts)
        
        # Check if the generated token passes validation
        is_valid, _ = validate_api_token(token)
        if is_valid:
            return token
    
    # Fallback: if we can't generate a valid token after max_attempts,
    # raise an exception rather than return an invalid token
    raise RuntimeError(f"Failed to generate a valid token after {max_attempts} attempts")


# =============================================
# CERTBOT CONFIGURATION FILE CREATORS
# =============================================

def _create_config_file(plugin_name: str, content: str) -> Path:
    """Generic helper to create a per-operation credentials file.

    The filename carries a random suffix so two concurrent operations on the
    SAME provider (e.g. renewing a.com and b.com, both Cloudflare) no longer
    write — and then delete in their ``finally`` — the same shared
    ``<plugin>.ini``, which raced one certbot run's credentials out from under
    another. Each caller deletes its own unique file. The directory is
    unchanged so the certbot-stderr path sanitizer still redacts these paths.
    """
    config_dir = Path("letsencrypt/config")
    config_dir.mkdir(parents=True, exist_ok=True)

    config_file = config_dir / f"{plugin_name}-{secrets.token_hex(8)}.ini"
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

def create_azure_config(subscription_id: str, resource_group: str, tenant_id: str, client_id: str, client_secret: str, zone_domain: Union[str, List[str]]) -> Path:
    """Create Azure DNS credentials file for certbot-dns-azure (terrycain).

    The plugin (certbot-dns-azure >= 2.x) expects:

    * ``dns_azure_sp_client_id`` / ``dns_azure_sp_client_secret`` /
      ``dns_azure_tenant_id`` — service principal credentials. Note the
      ``sp_`` prefix; the older bare ``dns_azure_client_id`` keys that
      certmate used previously are ignored and the plugin reports
      "No authentication methods have been configured for Azure DNS".
    * ``dns_azure_zoneN = <zone>:<azure-resource-id>`` — at least one
      zone mapping. ``subscription_id`` and ``resource_group`` are NOT
      top-level keys; they live inside the resource id of the zone line.

    See ``certbot_dns_azure/_internal/dns_azure.py:_validate_credentials``
    in v2.5.0 for the validation that drives this format.

    ``zone_domain`` accepts two shapes:

    * **str** — legacy single-zone usage. Writes one ``dns_azure_zone1``
      line. Kept for callers (and tests) that haven't migrated to the
      list form.
    * **list[str]** — one ``dns_azure_zoneN`` per entry, in the order
      given. The cert-issuance path passes the deduplicated longest-first
      list returned by ``resolve_zones_for_domains`` so the plugin's
      longest-prefix match selects the most specific hosted zone per
      ACME challenge — that's what enables nested-subdomain wildcards
      against a parent hosted zone (e.g. ``*.example2.example.com``
      issued under hosted zone ``example.com``).
    """
    zone_resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    if isinstance(zone_domain, str):
        zone_list = [zone_domain]
    else:
        zone_list = [z for z in (zone_domain or []) if z]
    if not zone_list:
        raise ValueError(
            "create_azure_config requires at least one zone (received empty list)"
        )
    zone_lines = ''.join(
        f"dns_azure_zone{idx} = {zone}:{zone_resource_id}\n"
        for idx, zone in enumerate(zone_list, start=1)
    )
    content = (
        f"dns_azure_sp_client_id = {client_id}\n"
        f"dns_azure_sp_client_secret = {client_secret}\n"
        f"dns_azure_tenant_id = {tenant_id}\n"
        f"dns_azure_environment = AzurePublicCloud\n"
        f"{zone_lines}"
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

def create_edgedns_config(client_token: str, client_secret: str, access_token: str, host: str) -> Path:
    """Create Akamai Edge DNS credentials file for certbot-plugin-edgedns.

    The plugin (akamai/certbot-plugin-edgedns v0.1.x) uses certbot's standard
    ``dns_common.CredentialsConfiguration``: a flat INI with no section header
    and keys prefixed by the plugin namespace (``edgedns_``). It does NOT
    consume a raw Akamai ``.edgerc`` file at this path — that path is reserved
    for the optional ``edgedns_edgerc_path`` indirection.

    Source: certbot_plugin_edgedns/edgedns.py:_validate_credentials reads
    self.credentials.conf('client_token') etc., which dns_common translates to
    the ``edgedns_<key>`` lookup against the INI.
    """
    content = (
        f"edgedns_client_token = {client_token}\n"
        f"edgedns_client_secret = {client_secret}\n"
        f"edgedns_access_token = {access_token}\n"
        f"edgedns_host = {host}\n"
    )
    return _create_config_file("edgedns", content)

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

def create_infomaniak_config(api_token: str) -> Path:
    """Create Infomaniak DNS credentials file."""
    return _create_config_file("infomaniak", f"dns_infomaniak_token = {api_token}\n")

def create_duckdns_config(api_token: str) -> Path:
    """Create DuckDNS credentials file.

    DuckDNS uses a single per-account token that grants write access to every
    subdomain owned by the account. The token is passed to certbot via the
    ``dns_duckdns_token`` INI key.
    """
    return _create_config_file("duckdns", f"dns_duckdns_token = {api_token}\n")


def create_acme_dns_config(api_url: str, username: str, password: str, subdomain: str) -> Path:
    """Create ACME-DNS credentials file."""
    config = {
        subdomain: {
            "username": username,
            "password": password,
            "fulldomain": subdomain,
            "subdomain": subdomain,
            "allowfrom": []
        }
    }
    content = json.dumps(config, indent=4)
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
    A simple, thread-safe, in-memory, time-based cache with max size limit.
    """
    MAX_ENTRIES = 10000  # Prevent unbounded memory growth

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
            # Evict expired entries if approaching size limit
            if len(self._cache) >= self.MAX_ENTRIES:
                self._clean_expired()
            # If still at limit after cleanup, evict oldest entry
            if len(self._cache) >= self.MAX_ENTRIES:
                oldest_key = min(self._cache, key=lambda k: self._cache[k].timestamp)
                del self._cache[oldest_key]
            self._cache[domain] = entry
        
    def clear(self) -> int:
        """Clear all entries from the cache, returning the number of cleared items."""
        with self._lock:
            cleared_count = len(self._cache)
            self._cache.clear()
        return cleared_count

    def clear_prefix(self, prefix: str) -> int:
        """Remove every entry whose key starts with ``prefix``, returning the count removed."""
        with self._lock:
            matching_keys = [k for k in self._cache if k.startswith(prefix)]
            for key in matching_keys:
                del self._cache[key]
        return len(matching_keys)

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
        
    def remove(self, domain: str) -> None:
        """Remove a specific domain from the cache."""
        with self._lock:
            self._cache.pop(domain, None)

    def set_ttl(self, ttl: int) -> bool:
        """Set the default TTL for new cache entries."""
        if isinstance(ttl, (int, float)) and 30 <= ttl <= 3600:
            with self._lock:
                self._default_ttl = int(ttl)
            return True
        return False