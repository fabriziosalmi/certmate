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

# Default renewal threshold (days before expiry to trigger renewal).
# Read by certificates.py, digest.py and metrics.py as the fallback when
# settings.json carries no renewal_threshold_days.
DEFAULT_RENEWAL_THRESHOLD_DAYS = 30

# Default session lifetime, in hours. Overridden by SESSION_TIMEOUT_HOURS.
# Read by AuthManager, which is also what both cookie mint sites ask for their
# max_age — so the server record and the browser cookie cannot drift apart.
#
# This said 24 while the code used 8 and nothing read the file (#590). The
# value here is now the one shipped installs have always run.
DEFAULT_SESSION_TIMEOUT_HOURS = 8

# Shape of settings.json, bumped ONLY when that shape changes — unlike
# `certmate_version`, which is the product version and moves on every release
# (#669). A file whose schema is NEWER than this is refused rather than read:
# an older process writing to a shape it does not understand is the failure
# rollback actually produces, and it is silent.
SETTINGS_SCHEMA_VERSION = 1

# Shape of each certificate's metadata.json, on the same terms as
# SETTINGS_SCHEMA_VERSION above: bumped only when the shape changes, never with
# the product version. The file records key custody — private_key_state, the
# CSR fingerprint, the CA a private-CA certificate cannot renew without — so a
# downgrade that reads it, understands the fields it knows and writes back the
# rest as absent is a silent data loss on exactly the record that says which
# private key belongs to which certificate.
#
# Enforced at the WRITE, not at startup: there is one of these files per
# domain, and refusing to start over one certificate would turn a data-loss
# risk into an outage. Reading a newer file stays allowed. See
# CertificateManager._save_metadata.
METADATA_SCHEMA_VERSION = 1

# Shape of the HTTP interface, on the same terms as the two schema versions
# above: bumped only when the surface changes, never with the product version.
#
# `certmate_version` and the Swagger document's `version` are both the RELEASE
# number, which moves on every patch whether or not anything a caller depends
# on moved with it — so neither can answer "will my client still work". A
# client that pinned the release number would refuse a patch that changed
# nothing; one that ignored it had nothing else to read.
#
# Bump the MINOR when the surface grows in a way a caller can ignore: a new
# endpoint, a new field on a response, a new optional request field. Bump the
# MAJOR when something a caller may depend on goes away or changes meaning: an
# endpoint removed, a response field removed or retyped, a request field that
# becomes required, a status code that changes for an existing condition.
#
# Deprecating something does NOT bump either — that is the point of deprecating
# rather than removing. It is announced with the Deprecation and Sunset headers
# (see modules/api/deprecation.py) and the removal is what bumps the major.
# 2.0 because `code` was retyped: on failures raised by the HTTP layer it was
# the status INTEGER while every application error used a string symbol, so one
# API answered in two types under one field name and a client had to check the
# type before it could branch. It is a string everywhere now, and the number a
# caller may have been reading is in `status` on those same responses — a
# one-line migration, and the version is how they learn to make it. By the rule
# above this is a retype, and a retype is a MAJOR; picking the comfortable
# number instead would make the rule decorative.
#
# 2.1 for the bounded issuance queue: the async create/renew/reissue endpoints
# can now answer 429 with code ISSUANCE_QUEUE_FULL when too much issuance is
# already outstanding, where they used to accept it. MINOR rather than MAJOR
# because it is a new code on a status those endpoints could already return —
# every /api/ path goes through the rate limiter, which answers 429 — so a
# client that handles 429 at all needs no change, and one that does not was
# already exposed. What is new is a condition, not a type or a shape.
API_CONTRACT_VERSION = '2.1'

# Protocols the deployment probe can speak. A domain fact, not an API one: the
# service validates against it and modules/api/tls_probe drives it (#672 — it
# lived in the API layer, which core could not reach without importing api and
# deepening #668).
PROBE_PROTOCOLS = ('https-tls', 'tls', 'smtp-starttls')

# Default deployment-status cache TTL, in seconds. Read by CacheManager as the
# fallback when settings.json carries no cache_ttl.
DEFAULT_CACHE_TTL = 300

# Login rate-limiting defaults deliberately do NOT live here. There is no
# single pair any more: routes.py runs two buckets with four values (5 attempts
# / 60s per IP, 10 / 300s per username), and a lone DEFAULT_LOGIN_RATE_LIMIT
# could only misdescribe them. They stay next to the algorithm that reads
# them.


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
