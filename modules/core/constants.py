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
# What each version was is below; the rule for choosing the next one is
# last, immediately above the constant, because that is where the person
# changing the surface is looking. It used to sit above the history, and
# every version added pushed it further from the line it governs until
# tests/test_the_contract_says_when_it_changes.py stopped finding it.
#
# 2.0 because `code` was retyped: on failures raised by the HTTP layer it was
# the status INTEGER while every application error used a string symbol, so one
# API answered in two types under one field name and a client had to check the
# type before it could branch. It is a string everywhere now, and the number a
# caller may have been reading is in `status` on those same responses — a
# one-line migration, and the version is how they learn to make it. By the rule
# below this is a retype, and a retype is a MAJOR; picking the comfortable
# number instead would make the rule decorative.
#
# 2.1 for the bounded issuance queue: the async create/renew/reissue endpoints
# can now answer 429 with code ISSUANCE_QUEUE_FULL when too much issuance is
# already outstanding, where they used to accept it. MINOR rather than MAJOR
# because it is a new code on a status those endpoints could already return —
# every /api/ path goes through the rate limiter, which answers 429 — so a
# client that handles 429 at all needs no change, and one that does not was
# already exposed. What is new is a condition, not a type or a shape.
#
# 2.2 for `expired` and `seconds_left` on every certificate-info response.
# MINOR because nothing changed type or disappeared: `days_left` and
# `days_until_expiry` keep their meaning, whole days, truncated. What is new
# is that a client no longer has to derive validity from them, which it could
# not do correctly: under 24 hours truncates to 0, so `days_until_expiry <= 0`
# called a valid certificate expired, and CertMate's own dashboard did exactly
# that in six places (#829). Both new fields are None on the branch where the
# certificate could not be parsed, because unknown is not the same as fine.
#
# 2.3 for POST /api/client-certs/ca/reset: the client-certificate CA can be
# rebuilt with a subject the operator chooses, and that is a new endpoint. By
# the rule below a new endpoint is a MINOR, and this one arrived without moving
# the number at all: the surface grew and a client polling this version had no
# way to learn it. Nothing compared the route table with the version, which is
# why tests/test_the_contract_moves_with_the_surface.py now does.
#
# 2.4 for `revocation` on every GET /api/inventory record (and a `revocation`
# count in its summary): the last verified OCSP/CRL answer for the certificate,
# or None when it was never checked. None is not "good" — nothing was asked.
# A new response field is a MINOR by the rule below. The route-table snapshot
# in tests/test_the_contract_moves_with_the_surface.py cannot see a new field,
# so this one moved by reading the rule, not because a test demanded it.
#
# 2.5 for POST /api/certificates/check-caa: what the CAA records say about
# issuing a set of names from a given CA, so the create form can warn before
# the order instead of after the CA refuses it. A new endpoint is a MINOR. It
# advises and never gates — the create endpoint does not consult it.
#
# 2.6 for GET /api/inventory/domains: when each tracked domain's registration
# expires, from RDAP or WHOIS, and a `domain_registration` section in the
# inventory config and scan responses. A new endpoint and new response fields,
# so a MINOR. `not_published` is a status, not a missing field: some
# registries (.de, .eu) do not publish expiry, and that is the answer.
#
# 2.7 for PATCH /api/keys/<key_id>: an operator confirms an API key that was
# created while the instance was in setup mode. New endpoint, so a MINOR.
# The same change refuses POST /api/keys, and any user after the first, with
# 409 SETUP_BOOTSTRAP_ONLY while in setup mode. That is a new answer to an
# existing request, which the rule below would call MAJOR. It is a security
# fix instead: a key minted in setup mode was minted by whoever could reach
# the instance, and it outlived setup, so no client could rely on it safely.
#
# 2.8 for POST /api/probe: read the certificate a host is serving right now,
# with the verified revocation answer. The inventory could only probe what its
# configuration named, and deployment-status only a managed domain, so a tool
# that wanted CertMate to answer "what is being served at this host" had no way
# to ask and reimplemented the probe — badly, in at least one case, with a
# revocation status that was assumed rather than checked. A new endpoint is a
# MINOR. A scoped key probes only what its scope covers.
#
# 2.9 for GET /api/inventory/health: what the name-level checks last found —
# SPF, DMARC, MX, the blocklists and the HSTS header — plus a `domain_health`
# section in the inventory config and scan responses. A new endpoint and new
# response fields, so a MINOR. `unknown` is a status a caller must not read as
# a pass: a blocklist that refused the query (every public resolver gets that
# from Spamhaus) has said nothing about the address, and the tool these checks
# came from reported exactly that case as "not listed".
#
# 2.10 for `security_headers` and `disclosure` on GET /api/inventory/health,
# and `check_headers` in place of `check_hsts` in the `domain_health` config.
# New response fields are a MINOR. The config key is read both ways on the way
# in, so an instance configured before this does not silently start making a
# request it had turned off; `check_hsts` is no longer written back, because
# the switch now covers three checks over one request and a name that says
# only one of them would be a lie about what turning it off stops.
#
# 2.11 for `weak_tls` on GET /api/inventory/health, and `check_weak_tls` in the
# `domain_health` config. A new response field is a MINOR. It is the only check
# that opens connections a host did not invite — two handshakes per name,
# offering TLS 1.0 and 1.1 — so it is off by default and the field is absent
# until an operator turns it on. `unknown` there means this build could not
# make the offer, which is not the same as the host refusing it.
#
# 2.12 for `dns_resolver` in the inventory configuration: which nameservers
# this instance asks for its own lookups, used by the name-level checks and by
# CAA. A new field on GET and POST /api/inventory/config, so a MINOR. It
# exists because the blocklist check told operators to "point CertMate at a
# resolver of your own" and there was no way to (#881) — advice for something
# the product did not let you do.
#
# 2.13 for `csr` on POST /api/certificates/<domain>/reissue: a new OPTIONAL
# request field, so a MINOR. It exists because the documented way to rotate a
# CSR-only certificate's key — submit the new CSR the same way, same domain —
# did not work: create answers 409 for a domain that already has one and
# points at reissue, and reissue took no CSR. The only path was delete then
# create, with no certificate in between, on the feature people choose
# precisely because they keep the private key elsewhere (#876 item 6).
#
# 2.14 for filters on GET /api/activity — `operation`, `resource_type`,
# `resource_id`, `user`, `status` — and the `complete` field on its response.
# Optional query parameters and a new response field, so a MINOR.
#
# `complete` is the part worth reading twice. The search walks back until it
# has `limit` MATCHES rather than filtering a tail, because "matches among the
# last hundred" would answer "there are none" for anything older — including
# the bootstrap entries docs/compliance.md sends operators to look for. False
# means it stopped early or could not read the log; only `complete: true` with
# an empty result means there are none.
#
# 2.15 for POST /api/web/update-check and `enabled` on its GET response. A new
# endpoint and a new response field, so a MINOR.
#
# It exists because 2.13's update check shipped with no way to turn it on:
# `UpdateCheck.save_config` was there, nothing called it, and the only route
# was the GET the footer asks. Off by default is the contract; no way to opt in
# is not an opt-in. Both verbs take a bearer token like their neighbour
# /api/web/settings — an instance provisioned over the API could otherwise
# write every other setting and not this one.
#
# 2.16 for the additions in the peer-review sweep. All MINOR — a caller that
# ignores every one of them is unaffected:
#
#   GET /api/client-certs/ca              the CA certificate a relying party
#                                         has to trust. Two comments in
#                                         private_ca.py justified the 0600
#                                         file mode by saying it "is served
#                                         over HTTP by certmate", and nothing
#                                         served it: the only /ca route was
#                                         POST /ca/reset.
#   csr, country, state                   new optional fields on
#                                         POST /api/client-certs/create.
#                                         `generate_key: false` needed a CSR
#                                         and had nowhere to put one, so it
#                                         could only ever 400; C and ST were
#                                         the literals "CH"/"Switzerland" for
#                                         every operator. Both default to what
#                                         was issued before.
#   alias_dns_provider                    new optional field on
#                                         POST /api/certificates/create. PATCH
#                                         and reissue have always read it;
#                                         create accepted it in the body and
#                                         dropped it.
#   client_ca_subject                     now accepted by POST /api/settings,
#                                         which docs/api.md has told operators
#                                         to use since contract 2.3.
#   chain_available                       new field on the probe/discovery
#                                         response: false when the runtime
#                                         cannot read the served chain, so a
#                                         leaf-only result is not read as "no
#                                         intermediate served".
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
API_CONTRACT_VERSION = '2.16'

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
