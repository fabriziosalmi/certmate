"""
Constants module for CertMate
Centralized location for shared constants across the application
"""
from pathlib import Path
from typing import Iterator

# Standard certificate files produced by Certbot
CERTIFICATE_FILES = ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem')

# Directory names that may legitimately appear under the cert storage root
# (because it's often a volume mount point) but are NEVER a CertMate cert
# directory. Listed here so enumeration paths can filter them out without
# bespoke checks in each call site.
_FILESYSTEM_ARTIFACT_DIR_NAMES = frozenset({'lost+found'})


def iter_cert_domain_dirs(cert_dir: Path) -> Iterator[Path]:
    """Yield subdirectories of ``cert_dir`` that are real CertMate cert stores.

    A cert directory is identified by the presence of ``cert.pem`` — the
    canonical marker for an issued certificate. This filter excludes:

    * filesystem artifacts like ``lost+found`` (ext-family roots)
    * hidden directories (``.cache``, ``.git``, ...)
    * other subdirectories that happen to share the cert root (mount points
      often collect unrelated folders such as ``certs``, ``config``, ``tmp``)

    Callers that want the raw directory list (e.g. backup) should iterate
    directly with their own policy.

    Reported on issue #99 by @SpeeDFireCZE: running CertMate against a cert
    root that is also a mount point caused orphan directories to appear as
    "Not Found" certificates in the dashboard.
    """
    if not cert_dir.exists():
        return
    for path in cert_dir.iterdir():
        if not path.is_dir():
            continue
        name = path.name
        if not name or name.startswith('.'):
            continue
        if name in _FILESYSTEM_ARTIFACT_DIR_NAMES:
            continue
        if not (path / 'cert.pem').exists():
            continue
        yield path

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
