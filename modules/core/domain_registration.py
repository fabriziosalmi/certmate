"""Domain registration expiry — when does the domain itself lapse?

A certificate that renews on time is worth nothing on a domain whose
registration expired: the name stops resolving, or resolves to a parking page,
and every certificate under it with it. For an agency the two dates are the
same kind of risk, so CertMate reads the second one too.

Where the answer comes from, in order:

1. **RDAP** (RFC 9082/9083), at the server the IANA bootstrap file
   (``https://data.iana.org/rdap/dns.json``) lists for the TLD. The expiry is
   the ``expiration`` event; the registrar is the entity with the ``registrar``
   role. Every gTLD has RDAP; many ccTLDs do too.
2. **WHOIS** (port 43), only for a TLD the bootstrap lists no RDAP server for.
   That is not a corner case: ``.it``, ``.eu``, ``.de``, ``.es``, ``.ch``,
   ``.at``, ``.io`` and ``.co`` had none when this was written. The server is
   the one IANA's own WHOIS names for the TLD.

What is never done is guessing. Several registries do not publish an expiry
date at all — DENIC (``.de``) and EURid (``.eu``) answer that the domain is
registered and nothing more — and that is reported as ``not_published``, not as
a missing value that looks like an error or a date that was never stated.

Statuses:

* ``ok`` — registered, and the registry published when it expires.
* ``not_published`` — registered, but the registry does not publish expiry.
* ``not_registered`` — the registry says the name does not exist.
* ``unavailable`` — no answer could be obtained; ``error`` says why.

The registrable domain (``example.co.uk`` for ``www.shop.example.co.uk``) comes
from the Public Suffix List snapshot bundled with ``tldextract``, read offline:
no list is downloaded at runtime and nothing is written to disk.

Every lookup is failure-isolated and bounded by a timeout. WHOIS goes through
the probe's SSRF guard like every other socket CertMate opens towards a name it
did not choose; RDAP URLs come from the IANA bootstrap and must be ``https``.
"""

import json
import logging
import re
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from .utils import utc_now_iso

logger = logging.getLogger(__name__)

STATUS_OK = 'ok'
STATUS_NOT_PUBLISHED = 'not_published'
STATUS_NOT_REGISTERED = 'not_registered'
STATUS_UNAVAILABLE = 'unavailable'

SOURCE_RDAP = 'rdap'
SOURCE_WHOIS = 'whois'

BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
IANA_WHOIS = 'whois.iana.org'
BOOTSTRAP_MAX_AGE = timedelta(days=1)
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RDAP_BYTES = 1024 * 1024
MAX_WHOIS_BYTES = 64 * 1024

# --------------------------------------------------------------------------- #
# Registrable domain
# --------------------------------------------------------------------------- #

_extractor = None
_extractor_lock = threading.Lock()


def _get_extractor():
    """tldextract with its bundled Public Suffix List snapshot, offline.

    ``suffix_list_urls=()`` stops it fetching the list; ``cache_dir=None``
    stops it writing one, which matters on a read-only root filesystem.
    Private-registry suffixes (github.io, ...) are left out on purpose: the
    question is who registered the name at a registry, and that is GitHub.
    """
    global _extractor
    with _extractor_lock:
        if _extractor is None:
            import tldextract
            _extractor = tldextract.TLDExtract(
                cache_dir=None, suffix_list_urls=(), include_psl_private_domains=False)
        return _extractor


def registrable_domain(name):
    """The name a registry registered for *name*, or None.

    ``www.shop.example.co.uk`` -> ``example.co.uk``; ``*.example.it`` ->
    ``example.it``. None for an IP address, a bare public suffix, or a name
    under no known suffix (``localhost``, an internal zone).
    """
    if not name or not isinstance(name, str):
        return None
    host = name.strip().lower().rstrip('.')
    if host.startswith('*.'):
        host = host[2:]
    if not host or '/' in host or ' ' in host:
        return None
    result = _get_extractor()(host)
    registered = getattr(result, 'top_domain_under_public_suffix', None)
    if registered is None:  # tldextract < 5.3
        registered = result.registered_domain
    return registered or None


# --------------------------------------------------------------------------- #
# Transports (injectable, so the parsing is testable against real payloads)
# --------------------------------------------------------------------------- #

class LookupError_(Exception):
    """A lookup failed; the message is safe to surface to an operator."""


def http_get_json(url, *, timeout):
    """GET *url* as RDAP JSON. Returns ``(status_code, parsed_or_None)``."""
    import requests

    if not url.startswith('https://'):
        raise LookupError_(f'refusing a non-https RDAP URL: {url}')
    try:
        with requests.Session() as session:
            session.max_redirects = 3
            resp = session.get(url, timeout=timeout, stream=True, headers={
                'Accept': 'application/rdap+json, application/json',
                'User-Agent': 'CertMate-domain-registration',
            })
            body = resp.raw.read(MAX_RDAP_BYTES + 1, decode_content=True)
    except requests.RequestException as e:
        raise LookupError_(f'{e.__class__.__name__} fetching {url}') from e
    if len(body) > MAX_RDAP_BYTES:
        raise LookupError_(f'{url} returned more than {MAX_RDAP_BYTES} bytes')
    if resp.status_code != 200:
        return resp.status_code, None
    try:
        return 200, json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as e:
        raise LookupError_(f'{url} did not return JSON: {e}') from e


def whois_query(server, query, *, timeout, allow_private=False):
    """Ask *server* on port 43 about *query*. Returns the decoded answer."""
    from .cert_probe import _resolve_and_guard

    family, connect_ip, reason = _resolve_and_guard(server, 43, allow_private)
    if reason is not None:
        raise LookupError_(f'{server}: {reason}')
    chunks, total = [], 0
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((connect_ip, 43))
            sock.sendall(query.encode('idna') + b'\r\n')
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_WHOIS_BYTES:
                    raise LookupError_(f'{server} returned more than {MAX_WHOIS_BYTES} bytes')
    except socket.timeout as e:
        raise LookupError_(f'{server} timed out') from e
    except (OSError, UnicodeError) as e:
        raise LookupError_(f'{server}: {e.__class__.__name__}: {e}') from e
    return b''.join(chunks).decode('utf-8', 'replace')


# --------------------------------------------------------------------------- #
# RDAP
# --------------------------------------------------------------------------- #

def parse_rdap(payload):
    """Pull expiry, registrar and status out of an RDAP domain object."""
    # A registry's JSON is input, not a contract: anything that is not the
    # expected shape is skipped rather than allowed to raise out of lookup().
    def _objects(key):
        value = payload.get(key)
        return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []

    expires_at = None
    for event in _objects('events'):
        if str(event.get('eventAction') or '').lower() == 'expiration':
            expires_at = _normalise_date(event.get('eventDate'))
            break
    registrar = None
    for entity in _objects('entities'):
        roles = entity.get('roles')
        if isinstance(roles, list) and 'registrar' in roles:
            registrar = _vcard_fn(entity) or entity.get('handle')
            break
    status = payload.get('status')
    return {
        'expires_at': expires_at,
        'registrar': registrar,
        'registry_status': [str(s) for s in status] if isinstance(status, list) else [],
    }


def _vcard_fn(entity):
    vcard = entity.get('vcardArray')
    if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) > 3 and prop[0] == 'fn':
            return str(prop[3]).strip() or None
    return None


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #

# Field names registries use for the expiry, most specific first. Only these
# are read: a date on any other line (created, changed) is not an expiry.
_WHOIS_EXPIRY_FIELDS = (
    'registry expiry date', 'registrar registration expiration date',
    'expire date', 'expiry date', 'expiration date', 'expiration time',
    'expires on', 'expires', 'paid-till', 'renewal date', 'expire',
)
# An answer that says the name is free. Matched as whole lines or prefixes.
_WHOIS_NOT_FOUND = re.compile(
    r'^\s*(status:\s*(available|free)\b|no match\b|not found\b|no entries found\b|'
    r'no data found\b|domain not found\b|% no such domain\b)',
    re.IGNORECASE | re.MULTILINE)
_WHOIS_DOMAIN_LINE = re.compile(r'^\s*domain(?: name)?:\s*\S+', re.IGNORECASE | re.MULTILINE)

_DATE_FORMATS = (
    '%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y.%m.%d', '%d.%m.%Y', '%d-%b-%Y',
    '%Y/%m/%d', '%d/%m/%Y', '%Y%m%d',
)


def parse_whois(text):
    """Classify a WHOIS answer and pull the expiry out of it.

    Returns ``(status, fields)`` where status is ok / not_published /
    not_registered, or raises LookupError_ for an answer that names an expiry
    in a form this does not understand — a date misread is worse than none.
    """
    if _WHOIS_NOT_FOUND.search(text):
        return STATUS_NOT_REGISTERED, {'expires_at': None, 'registrar': None, 'registry_status': []}

    fields = {}
    for line in text.splitlines():
        if ':' not in line or line.lstrip().startswith(('%', '#', '>>>')):
            continue
        key, _, value = line.partition(':')
        key, value = key.strip().lower(), value.strip()
        if key and value and key not in fields:
            fields[key] = value

    expires_raw = next((fields[k] for k in _WHOIS_EXPIRY_FIELDS if k in fields), None)
    registrar = _whois_registrar(text, fields)
    status = [s for s in re.split(r'[,\s]+', fields.get('status', '')) if s][:1]

    if expires_raw is None:
        if not _WHOIS_DOMAIN_LINE.search(text):
            raise LookupError_('the WHOIS answer names no domain and no expiry')
        return STATUS_NOT_PUBLISHED, {'expires_at': None, 'registrar': registrar,
                                      'registry_status': status}
    expires_at = _normalise_date(expires_raw)
    if expires_at is None:
        raise LookupError_(f'unrecognised expiry date {expires_raw!r}')
    return STATUS_OK, {'expires_at': expires_at, 'registrar': registrar,
                       'registry_status': status}


def _whois_registrar(text, fields):
    """The registrar, from a one-line field or from a ``Registrar`` block.

    ``Registrar: Example Ltd`` (gTLD style), or a heading followed by indented
    ``Organization:`` / ``Name:`` lines (.it, .eu).
    """
    inline = fields.get('registrar')
    if inline and not inline.endswith(':'):
        return inline
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().rstrip(':').lower() == 'registrar':
            for follow in lines[i + 1:i + 6]:
                if not follow.strip():
                    break
                key, _, value = follow.partition(':')
                if key.strip().lower() in ('organization', 'organisation', 'name') and value.strip():
                    return value.strip()
    return None


def _normalise_date(value):
    """An ISO-8601 UTC ``...Z`` string for a registry date, or None."""
    if not value:
        return None
    text = str(value).strip()
    iso = text.replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        dt = None
        cleaned = re.sub(r'\s*\(.*\)$', '', text).split(' UTC')[0].strip()
        cleaned = re.sub(r'T(\d\d:\d\d:\d\d)(\.\d+)?Z?$', r' \1', cleaned)
        for fmt in _DATE_FORMATS:
            try:
                dt = datetime.strptime(cleaned, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #

class RegistrationClient:
    """Looks up a registrable domain's registration. Never raises.

    Holds the IANA bootstrap (cached on disk under ``cache_dir`` for a day, and
    reused stale when IANA cannot be reached) and the WHOIS server per TLD.
    Transports are injectable so tests can feed real captured answers.
    """

    def __init__(self, cache_dir=None, *, timeout=DEFAULT_TIMEOUT_SECONDS,
                 http_get=http_get_json, whois=whois_query, clock=time.time):
        self.cache_path = Path(cache_dir) / 'rdap-bootstrap.json' if cache_dir else None
        self.timeout = timeout
        self._http_get = http_get
        self._whois = whois
        self._clock = clock
        self._bootstrap = None
        self._bootstrap_at = 0.0
        self._whois_servers = {}
        self._lock = threading.Lock()

    # -- bootstrap -------------------------------------------------------- #

    def rdap_base_urls(self, tld):
        """The RDAP base URLs IANA lists for *tld*, or [] when it has none."""
        services = self._load_bootstrap()
        return services.get(tld.lower(), [])

    def _load_bootstrap(self):
        with self._lock:
            fresh = self._clock() - self._bootstrap_at < BOOTSTRAP_MAX_AGE.total_seconds()
            if self._bootstrap is not None and fresh:
                return self._bootstrap
            cached = self._read_cached_bootstrap()
            if cached and self._clock() - cached[0] < BOOTSTRAP_MAX_AGE.total_seconds():
                self._bootstrap, self._bootstrap_at = cached[1], cached[0]
                return self._bootstrap
            try:
                status, payload = self._http_get(BOOTSTRAP_URL, timeout=self.timeout)
                if status != 200 or not isinstance(payload, dict):
                    raise LookupError_(f'IANA RDAP bootstrap answered HTTP {status}')
                services = _index_bootstrap(payload)
            except LookupError_ as e:
                if cached:
                    logger.warning('RDAP bootstrap refresh failed (%s); using the copy from %s',
                                   e, datetime.fromtimestamp(cached[0], timezone.utc).isoformat())
                    self._bootstrap, self._bootstrap_at = cached[1], self._clock()
                    return self._bootstrap
                raise
            self._bootstrap, self._bootstrap_at = services, self._clock()
            self._write_cached_bootstrap(services)
            return services

    def _read_cached_bootstrap(self):
        if not self.cache_path or not self.cache_path.exists():
            return None
        try:
            data = json.loads(self.cache_path.read_text(encoding='utf-8'))
            return float(data['fetched_at']), dict(data['services'])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _write_cached_bootstrap(self, services):
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix('.tmp')
            tmp.write_text(json.dumps({'fetched_at': self._clock(), 'services': services}),
                           encoding='utf-8')
            tmp.replace(self.cache_path)
        except OSError as e:
            logger.warning('Could not cache the RDAP bootstrap: %s', e)

    # -- whois server ----------------------------------------------------- #

    def whois_server(self, tld):
        """The WHOIS server IANA names for *tld*, or None."""
        tld = tld.lower()
        if tld in self._whois_servers:
            return self._whois_servers[tld]
        answer = self._whois(IANA_WHOIS, tld, timeout=self.timeout)
        match = re.search(r'^whois:\s*(\S+)', answer, re.IGNORECASE | re.MULTILINE)
        server = match.group(1).strip().lower() if match else None
        self._whois_servers[tld] = server
        return server

    # -- lookup ----------------------------------------------------------- #

    def lookup(self, domain):
        """Registration of *domain* (already registrable). Never raises."""
        domain = domain.strip().lower().rstrip('.')
        tld = domain.rsplit('.', 1)[-1]
        try:
            bases = self.rdap_base_urls(tld)
            if bases:
                return self._lookup_rdap(domain, bases)
            server = self.whois_server(tld)
            if not server:
                return _result(domain, STATUS_UNAVAILABLE, error=(
                    f'.{tld} has neither an RDAP service in the IANA bootstrap '
                    'nor a WHOIS server'))
            return self._lookup_whois(domain, server)
        except LookupError_ as e:
            return _result(domain, STATUS_UNAVAILABLE, error=str(e))

    def _lookup_rdap(self, domain, bases):
        url = bases[0].rstrip('/') + '/domain/' + quote(domain)
        status, payload = self._http_get(url, timeout=self.timeout)
        if status == 404:
            return _result(domain, STATUS_NOT_REGISTERED, source=SOURCE_RDAP)
        if status == 429:
            return _result(domain, STATUS_UNAVAILABLE, source=SOURCE_RDAP,
                           error=f'{url} is rate-limiting (HTTP 429); retried on the next sweep')
        if status != 200 or not isinstance(payload, dict):
            return _result(domain, STATUS_UNAVAILABLE, source=SOURCE_RDAP,
                           error=f'{url} answered HTTP {status}')
        parsed = parse_rdap(payload)
        state = STATUS_OK if parsed['expires_at'] else STATUS_NOT_PUBLISHED
        return _result(domain, state, source=SOURCE_RDAP, **parsed)

    def _lookup_whois(self, domain, server):
        answer = self._whois(server, domain, timeout=self.timeout)
        state, parsed = parse_whois(answer)
        return _result(domain, state, source=SOURCE_WHOIS, **parsed)


def _index_bootstrap(payload):
    services = {}
    for entry in payload.get('services') or []:
        if not (isinstance(entry, list) and len(entry) == 2):
            continue
        tlds, urls = entry
        https = [u for u in urls if isinstance(u, str) and u.startswith('https://')]
        for tld in tlds:
            if https:
                services[str(tld).lower()] = https
    if not services:
        raise LookupError_('the IANA RDAP bootstrap listed no services')
    return services


def _result(domain, status, *, source=None, expires_at=None, registrar=None,
            registry_status=None, error=None):
    return {
        'domain': domain,
        'status': status,
        'expires_at': expires_at,
        'registrar': registrar,
        'registry_status': list(registry_status or []),
        'source': source,
        'error': error,
        'checked_at': utc_now_iso(),
    }


# --------------------------------------------------------------------------- #
# The scheduled sweep
# --------------------------------------------------------------------------- #

DEFAULT_REGISTRATION_CONFIG = {
    'enabled': False,
    # Also follow the domains of certificates discovery found (probed or in
    # CT logs), not only the ones CertMate manages.
    'include_inventory': True,
    'extra_domains': [],
}

# How many registries one sweep may ask. Registries rate-limit, some sharply
# (NIC.it answers a burst with a temporary ban), and the answer changes once a
# year: a large estate is covered over several days rather than in one burst.
MAX_LOOKUPS_PER_RUN = 100
# Pause between lookups, for the same reason.
LOOKUP_INTERVAL_SECONDS = 1.0


def is_due(stored, now):
    """Whether a stored registration should be asked again at *now*.

    A registration changes on renewal, so most answers stay true for a long
    time. Asked again: never-asked and failed lookups after 6 hours; a domain
    expiring within 60 days daily, because that is when renewal happens and an
    alert must stop once it has; everything else weekly.
    """
    if stored is None:
        return True
    checked = _parse_utc(stored.get('checked_at'))
    if checked is None:
        return True
    age = now - checked
    if stored.get('status') == STATUS_UNAVAILABLE:
        return age >= timedelta(hours=6)
    expires = _parse_utc(stored.get('expires_at'))
    if expires is not None and expires - now <= timedelta(days=60):
        return age >= timedelta(days=1)
    return age >= timedelta(days=7)


def _parse_utc(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class DomainRegistrationManager:
    """Settings-backed daily check of every tracked domain's registration.

    The tracked set is recomputed on every run from what CertMate manages
    (settings and the certificate directory, including each certificate's
    SANs), optionally what discovery found, and any extra domains the operator
    lists. Each name is reduced to its registrable domain, so fifty hosts under
    example.com cost one lookup. :meth:`run_check` never raises.
    """

    def __init__(self, settings_manager, inventory, cert_dir, client=None,
                 *, sleep=time.sleep, now=None):
        self.settings_manager = settings_manager
        self.inventory = inventory
        self.cert_dir = Path(cert_dir)
        self.client = client or RegistrationClient(inventory.inventory_dir)
        self._sleep = sleep
        self._now = now or (lambda: datetime.now(timezone.utc))

    def get_config(self):
        settings = self.settings_manager.load_settings() or {}
        config = dict(DEFAULT_REGISTRATION_CONFIG)
        config.update(settings.get('domain_registration') or {})
        return config

    def save_config(self, config):
        """Validate and persist. Raises ValueError on a name with no registry."""
        extra = []
        for raw in config.get('extra_domains') or []:
            name = str(raw).strip()
            if not name:
                continue
            if registrable_domain(name) is None:
                raise ValueError(f'{name!r} is not under a public suffix, so no registry holds it')
            extra.append(name.lower())
        clean = {
            'enabled': bool(config.get('enabled', False)),
            'include_inventory': bool(config.get('include_inventory', True)),
            'extra_domains': extra,
        }
        self.settings_manager.update(
            lambda s: s.__setitem__('domain_registration', clean),
            'domain_registration_save',
        )
        return clean

    def tracked_domains(self, config=None, settings=None):
        """Every registrable domain to follow, sorted."""
        from .inventory_sources import collect_domain_sources

        settings = settings if settings is not None else (self.settings_manager.load_settings() or {})
        config = config or self.get_config()
        names = set()
        for domain in collect_domain_sources(settings, self.cert_dir):
            names.add(domain)
            names.update(self._metadata_sans(domain))
        if config.get('include_inventory', True):
            for record in self.inventory.list_all():
                if record.get('subject_cn'):
                    names.add(record['subject_cn'])
                names.update(record.get('san_dns') or [])
        names.update(config.get('extra_domains') or [])
        return sorted({r for r in (registrable_domain(n) for n in names) if r})

    def _metadata_sans(self, domain):
        path = self.cert_dir / domain / 'metadata.json'
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return []
        sans = data.get('san_domains') if isinstance(data, dict) else None
        return [s for s in sans if isinstance(s, str)] if isinstance(sans, list) else []

    def run_check(self, *, force=False, max_lookups=MAX_LOOKUPS_PER_RUN):
        """Look up every tracked domain that is due.

        A single lookup never raises (``RegistrationClient.lookup`` turns every
        failure into ``unavailable``), so one bad registry cannot stop the
        sweep. Anything else — the settings or the inventory unreadable — is
        left to the caller: the scheduler wrapper logs it and records the run,
        the scan endpoint reports it.
        """
        config = self.get_config()
        if not config.get('enabled') and not force:
            return {'skipped': True, 'reason': 'disabled', 'results': []}
        tracked = self.tracked_domains(config)
        pruned = self.inventory.prune_registrations(tracked)
        now = self._now()
        due = [d for d in tracked if force or is_due(self.inventory.get_registration(d), now)]
        results = []
        for i, domain in enumerate(due[:max_lookups]):
            if i:
                self._sleep(LOOKUP_INTERVAL_SECONDS)
            result = self.client.lookup(domain)
            self.inventory.record_registration(result)
            results.append({'domain': domain, 'status': result['status'],
                            'error': result.get('error')})
        deferred = max(0, len(due) - max_lookups)
        logger.info("Domain registration check: %d tracked, %d looked up, %d deferred, %d forgotten.",
                    len(tracked), len(results), deferred, pruned)
        return {'skipped': False, 'results': results, 'summary': {
            'tracked': len(tracked), 'looked_up': len(results),
            'deferred': deferred, 'forgotten': pruned}}
