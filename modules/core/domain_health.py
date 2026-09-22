"""The other things that take a site down, and that a certificate cannot fix.

A certificate that renews on time and a domain that does not lapse still leave
an agency answering for a site that stopped receiving mail, or one whose IP
landed on a blocklist. These are the checks that were living in a separate
tool, brought in beside the certificate and the registration, because they are
about the same thing: the name, and whether it still works.

Five checks, each of which can say *it does not know*:

* **SPF** — a ``v=spf1`` TXT record on the domain. Absent is a finding; more
  than one is a misconfiguration every receiver treats as permerror.
* **DMARC** — a ``v=DMARC1`` TXT at ``_dmarc``. The policy (``p=``) is
  reported as published, not judged: ``p=none`` is a deliberate first step for
  many, and calling it a failure would be an opinion, not a check.
* **MX** — whether the domain accepts mail at all. A domain with no MX is not
  broken, it just does not receive; a domain whose MX vanished usually is.
* **Blocklists (RBL)** — the domain's addresses against a list of DNSBLs.
  This is the one that most often lies, in two ways. A public resolver gets
  its queries *refused* by Spamhaus and friends (the ``127.255.255.x``
  answers), and reading a refusal as "not listed" is how a tool reports clean
  while knowing nothing. Worse, a refusal that travels back through a
  forwarder often arrives as plain NXDOMAIN, which is indistinguishable from
  "not listed" — so each list is asked about its own test point first, and a
  list that cannot answer that is not asked about anything else.
* **HSTS** — the ``Strict-Transport-Security`` header the host serves. Read
  over the connection the probe already knows how to make safely.

Everything is offline-testable: each check takes its resolver or fetcher, so
the parsing is exercised against real answers rather than live DNS.
"""

import ipaddress
import json
import logging
import re
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Check outcomes. `unknown` is a first-class answer: it means the check could
# not be completed, and it is never rendered as a pass.
OK = 'ok'
WARNING = 'warning'
FAILING = 'failing'
UNKNOWN = 'unknown'

DEFAULT_RBLS = (
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org',
    'dnsbl-1.uceprotect.net',
)

# A DNSBL answers with a 127.0.0.x code. 127.255.255.x is not a listing: it is
# the list telling you your resolver is not allowed to ask — the usual answer
# to a query that came through a public resolver such as 8.8.8.8. Spamhaus
# documents .252 (malformed query), .254 (public resolver) and .255 (too many
# queries), and says outright that these "must not be taken to imply that the
# object of the query is listed".
RBL_REFUSED_PREFIX = '127.255.255.'

# ...but that is only the polite refusal. A query that travels through a
# forwarder can come back NXDOMAIN instead, which at the DNS level is
# indistinguishable from "not listed" — and that is the answer a resolver
# behind Tailscale's MagicDNS, a corporate forwarder or a caching proxy often
# gets. Measured on a developer laptop: every public resolver answers the
# test point below with 127.255.255.254, and the system resolver forwarding to
# one answers NXDOMAIN. Both mean "you learned nothing"; only one says so.
#
# The way to tell them apart is the list's own test point. By long convention
# every DNSBL keeps 127.0.0.2 permanently listed and 127.0.0.1 permanently
# unlisted, precisely so a client can confirm it is reaching the list at all.
# A list that does not report 127.0.0.2 as listed is not answering us, and its
# answer about any real address is worth nothing.
RBL_SELFTEST_LISTED = '2.0.0.127'      # 127.0.0.2, reversed. Always listed.
RBL_SELFTEST_UNLISTED = '1.0.0.127'    # 127.0.0.1, reversed. Never listed.
# Spamhaus PBL: "this is consumer/dynamic space", which is a policy statement
# about the address range, not a reputation finding about this host.
RBL_POLICY_CODES = frozenset({'127.0.0.10', '127.0.0.11'})

# A name behind a CDN can answer with a dozen addresses, and each one costs a
# query per list.
MAX_ADDRESSES = 4

DEFAULT_TIMEOUT_SECONDS = 5.0

# Worst-first, for rolling several checks into one answer for a name.
_SEVERITY = {FAILING: 0, WARNING: 1, UNKNOWN: 2, OK: 3}

DEFAULT_HEALTH_CONFIG = {
    'enabled': False,
    'include_inventory': True,
    'check_mail': True,
    'check_blocklists': True,
    'check_hsts': True,
    'extra_domains': [],
}

# These records change rarely; once a day is plenty, and the interval keeps a
# re-run on the same day from asking every list again.
RECHECK_AFTER_HOURS = 20
MAX_NAMES_PER_RUN = 200


def _result(status, detail, **extra):
    return dict({'status': status, 'detail': detail}, **extra)


# --------------------------------------------------------------------------- #
# Mail: SPF, DMARC, MX
# --------------------------------------------------------------------------- #

def check_spf(domain, txt_records):
    """*txt_records* is the domain's TXT strings, already joined per record."""
    if txt_records is None:
        return _result(UNKNOWN, 'the TXT lookup did not complete')
    spf = [r for r in txt_records if r.lower().startswith('v=spf1')]
    if not spf:
        return _result(FAILING, 'no v=spf1 record, so anyone can send mail as this domain')
    if len(spf) > 1:
        return _result(FAILING,
                       f'{len(spf)} v=spf1 records; receivers treat more than one as permerror',
                       record=spf[0])
    record = spf[0]
    if re.search(r'\ball\b', record) is None:
        return _result(WARNING, 'the record has no "all" mechanism, so it says nothing '
                                'about senders it does not list', record=record)
    if re.search(r'\+all\b', record):
        return _result(FAILING, '"+all" authorises every sender, which is the same as '
                                'publishing no SPF at all', record=record)
    return _result(OK, 'published', record=record)


def check_dmarc(domain, txt_records):
    """*txt_records* is the TXT strings at ``_dmarc.<domain>``."""
    if txt_records is None:
        return _result(UNKNOWN, 'the TXT lookup at _dmarc did not complete')
    dmarc = [r for r in txt_records if r.lower().startswith('v=dmarc1')]
    if not dmarc:
        return _result(FAILING, 'no DMARC record, so a receiver has no instruction '
                                'for mail that fails authentication')
    record = dmarc[0]
    policy = re.search(r'\bp\s*=\s*(none|quarantine|reject)\b', record, re.IGNORECASE)
    if not policy:
        return _result(FAILING, 'the DMARC record has no p= policy', record=record)
    # The policy is reported, not marked. p=none is where most deployments
    # start, and calling it a failure would be an opinion about someone's
    # rollout rather than a check.
    return _result(OK, f'published, p={policy.group(1).lower()}',
                   record=record, policy=policy.group(1).lower())


def check_mx(domain, mx_records):
    if mx_records is None:
        return _result(UNKNOWN, 'the MX lookup did not complete')
    if not mx_records:
        return _result(WARNING, 'no MX record: this domain receives no mail')
    return _result(OK, f'{len(mx_records)} mail exchanger'
                       f'{"s" if len(mx_records) != 1 else ""}', hosts=list(mx_records))


# --------------------------------------------------------------------------- #
# Blocklists
# --------------------------------------------------------------------------- #

def rbl_query_name(ip):
    """``1.2.3.4`` -> ``4.3.2.1``; IPv6 -> its reversed nibbles."""
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return '.'.join(reversed(address.exploded.split('.')))
    return '.'.join(reversed(address.packed.hex()))


def classify_rbl_answer(codes):
    """What a DNSBL's answer means.

    One of ``'listed'``, ``'refused'``, ``'policy'`` or ``'not_listed'``.
    ``'refused'`` and ``'not_listed'`` are the pair worth keeping apart: an
    empty answer means the list was asked and had nothing, a ``127.255.255.x``
    answer means it declined to answer at all.
    """
    codes = [str(c) for c in codes or []]
    if not codes:
        return 'not_listed'
    if any(c.startswith(RBL_REFUSED_PREFIX) for c in codes):
        return 'refused'
    if all(c in RBL_POLICY_CODES for c in codes):
        return 'policy'
    return 'listed'


def list_is_answering(rbl, lookup):
    """Is this list actually answering *us*, or only appearing to?

    Two questions, because a resolver can fail in both directions:

    * the test point that is always listed must come back listed. If it does
      not — NXDOMAIN, a refusal code, a failed lookup — then nothing this list
      says about a real address can be trusted, and in particular its silence
      about that address is not "not listed";
    * the test point that is never listed must come back clean. A list that
      reports even that one is answering everything, which a hijacked or
      wildcarding resolver does, and its "listed" verdicts are worthless too.

    Returns True only when both hold.
    """
    listed = lookup(f'{RBL_SELFTEST_LISTED}.{rbl}')
    if listed is None or classify_rbl_answer(listed) not in ('listed', 'policy'):
        return False
    clean = lookup(f'{RBL_SELFTEST_UNLISTED}.{rbl}')
    return clean is None or classify_rbl_answer(clean) != 'listed'


def usable_lists(lookup, lists=DEFAULT_RBLS, cache=None):
    """The lists worth asking, and why each of the others is not.

    *cache* is an optional dict shared across a sweep: the answer is about the
    list and the resolver, not about the domain, so it is the same for every
    name checked in one run.
    """
    cache = cache if cache is not None else {}
    usable, unusable = [], []
    for rbl in lists:
        if rbl not in cache:
            cache[rbl] = list_is_answering(rbl, lookup)
        if cache[rbl]:
            usable.append(rbl)
        else:
            unusable.append(rbl)
    return usable, unusable


def check_blocklists(domain, addresses, lookup, cache=None):
    """Check each address against each list that is actually answering us.

    *lookup* is ``callable(query_name) -> [codes] | None``: the A records the
    list answered with, or None when the query failed (which is not the same
    as an empty answer — an empty answer is "not listed").

    Every list is self-tested first. Without that, the check is only as honest
    as the resolver: a forwarder that turns a refusal into NXDOMAIN would make
    every domain look clean, which is the failure this whole module exists to
    avoid, one level deeper than the refusal codes.
    """
    if addresses is None:
        return _result(UNKNOWN, 'the address lookup did not complete')
    if not addresses:
        return _result(UNKNOWN, 'the domain resolves to no address')

    lists, unusable = usable_lists(lookup, cache=cache)
    unanswered = [f'{rbl}: did not answer its own test point, so its answers '
                  f'about this domain would mean nothing' for rbl in unusable]
    listings = []
    # Only answers that carry information count. A refusal is not a check that
    # came back clean, and counting it as one is the whole defect this module
    # was written to avoid.
    answered = 0
    for address in addresses[:MAX_ADDRESSES]:
        try:
            reversed_name = rbl_query_name(address)
        except ValueError:
            continue
        for rbl in lists:
            codes = lookup(f'{reversed_name}.{rbl}')
            if codes is None:
                unanswered.append(f'{rbl} ({address}): the lookup failed')
                continue
            verdict = classify_rbl_answer(codes)
            if verdict == 'refused':
                unanswered.append(f'{rbl} ({address}): refused this resolver')
                continue
            answered += 1
            if verdict == 'listed':
                listings.append({'address': address, 'list': rbl, 'codes': list(codes)})
            # 'policy' and 'not_listed' are both "no reputation finding here".

    if listings:
        where = ', '.join(sorted({entry['list'] for entry in listings}))
        return _result(FAILING, f'listed on {where}', listings=listings,
                       unanswered=unanswered)
    if not answered:
        return _result(UNKNOWN,
                       'no blocklist answered usefully — the resolver CertMate uses is '
                       'almost always the reason, because the large lists refuse public '
                       'resolvers; point it at a resolver of your own',
                       unanswered=unanswered)
    if unanswered:
        return _result(WARNING,
                       f'not listed where it could be checked, but '
                       f'{len(unanswered)} lookup(s) went unanswered',
                       unanswered=unanswered)
    return _result(OK, f'not listed on {len(lists)} blocklist'
                       f'{"s" if len(lists) != 1 else ""}')


# --------------------------------------------------------------------------- #
# HSTS
# --------------------------------------------------------------------------- #

_MAX_AGE = re.compile(r'max-age\s*=\s*"?(\d+)"?', re.IGNORECASE)
# Six months, the floor the HSTS preload list requires.
HSTS_SHORT_MAX_AGE = 15552000


def check_hsts(header):
    """*header* is the Strict-Transport-Security value, '' when absent, or
    None when the page could not be fetched."""
    if header is None:
        return _result(UNKNOWN, 'the site could not be reached over HTTPS')
    if not header.strip():
        return _result(FAILING, 'no Strict-Transport-Security header: a first visit '
                                'over http can be intercepted')
    max_age = _MAX_AGE.search(header)
    if not max_age:
        return _result(FAILING, 'the header carries no max-age, so browsers ignore it',
                       header=header)
    seconds = int(max_age.group(1))
    if seconds == 0:
        return _result(FAILING, 'max-age=0 tells browsers to forget the policy',
                       header=header, max_age=seconds)
    if seconds < HSTS_SHORT_MAX_AGE:
        return _result(WARNING, f'max-age is {seconds}s, under the six months the '
                                f'preload list requires', header=header, max_age=seconds)
    return _result(OK, f'max-age {seconds}s', header=header, max_age=seconds,
                   includes_subdomains='includesubdomains' in header.lower(),
                   preload='preload' in header.lower())


# --------------------------------------------------------------------------- #
# Live lookups
# --------------------------------------------------------------------------- #

def dns_lookups(timeout=DEFAULT_TIMEOUT_SECONDS):
    """Return ``(txt, mx, addresses, rbl)`` callables backed by dnspython.

    Each returns None when the lookup failed, and an empty list when the name
    exists with no such record — the difference between "could not ask" and
    "asked, nothing there", which every check above depends on.
    """
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    def query(name, rdtype):
        try:
            return list(resolver.resolve(name, rdtype))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException:
            return None

    def txt(name):
        answers = query(name, 'TXT')
        if answers is None:
            return None
        out = []
        for rdata in answers:
            strings = getattr(rdata, 'strings', None) or []
            out.append(b''.join(strings).decode('utf-8', 'replace'))
        return out

    def mx(name):
        answers = query(name, 'MX')
        if answers is None:
            return None
        return [str(r.exchange).rstrip('.') for r in answers]

    def addresses(name):
        found = []
        for rdtype in ('A', 'AAAA'):
            answers = query(name, rdtype)
            if answers is None:
                if not found:
                    return None
                continue
            found += [str(r) for r in answers]
        return found

    def rbl(name):
        answers = query(name, 'A')
        if answers is None:
            return None
        return [str(r) for r in answers]

    return txt, mx, addresses, rbl


def fetch_hsts_header(host, *, timeout=DEFAULT_TIMEOUT_SECONDS, allow_private=False):
    """The Strict-Transport-Security header *host* serves, '' if none, None if
    it could not be reached.

    Through the probe's SSRF guard and pinned to the validated address, like
    every other connection CertMate opens towards a name it did not choose.
    Unlike the probe, this one *verifies* the certificate: a browser ignores
    HSTS served over a connection it did not trust, so reporting a header read
    from an untrusted one would describe a policy nobody applies.
    """
    import http.client
    import ssl

    from .cert_probe import _resolve_and_guard

    if any(c in host for c in '\r\n \t'):
        # Never reachable through the inventory, which holds validated names,
        # but this string is about to become a request line.
        return None

    family, connect_ip, reason = _resolve_and_guard(host, 443, allow_private)
    if reason is not None:
        logger.info("HSTS check skipped for %s: %s", host, reason)
        return None

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    request = (f'HEAD / HTTP/1.1\r\nHost: {host}\r\n'
               f'User-Agent: CertMate-domain-health\r\nConnection: close\r\n\r\n')
    try:
        # Connect to the address the guard validated, with SNI = the name, so
        # a DNS rebind between check and handshake changes nothing.
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((connect_ip, 443))
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(request.encode('ascii'))
                response = http.client.HTTPResponse(tls, method='HEAD')
                response.begin()
                try:
                    return response.getheader('Strict-Transport-Security') or ''
                finally:
                    response.close()
    except (OSError, ssl.SSLError, http.client.HTTPException,
            ValueError, TypeError, UnicodeError) as e:
        logger.info("HSTS check could not reach %s: %s", host, e.__class__.__name__)
        return None


# --------------------------------------------------------------------------- #
# Running the checks for one name, and for everything tracked
# --------------------------------------------------------------------------- #

def worst_status(checks):
    """The status a name gets from the checks that ran on it."""
    statuses = [c.get('status') for c in (checks or {}).values() if isinstance(c, dict)]
    if not statuses:
        return UNKNOWN
    return min(statuses, key=lambda s: _SEVERITY.get(s, _SEVERITY[UNKNOWN]))


def check_name(name, *, lookups=None, hsts_fetcher=None, mail=True,
               blocklists=True, hsts=True, is_registrable=True, rbl_cache=None):
    """Run the applicable checks for one name and return ``{check: result}``.

    Mail and blocklist checks only apply to a registrable domain: DMARC falls
    back to the organisational domain, so asking ``_dmarc.www.example.com``
    alone would report "no DMARC" for a domain that publishes one. HSTS is the
    opposite — it belongs to the host that serves the site.
    """
    txt, mx_lookup, addresses, rbl = lookups if lookups else dns_lookups()
    checks = {}
    if mail and is_registrable:
        checks['spf'] = check_spf(name, txt(name))
        checks['dmarc'] = check_dmarc(name, txt(f'_dmarc.{name}'))
        checks['mx'] = check_mx(name, mx_lookup(name))
    if blocklists and is_registrable:
        checks['blocklists'] = check_blocklists(name, addresses(name), rbl,
                                                cache=rbl_cache)
    if hsts:
        fetch = hsts_fetcher or fetch_hsts_header
        checks['hsts'] = check_hsts(fetch(name))
    return checks


def is_due(record, now, *, after_hours=RECHECK_AFTER_HOURS):
    """True when *name* has never been checked, or was checked long enough ago."""
    if not record or not record.get('checked_at'):
        return True
    try:
        checked = datetime.fromisoformat(record['checked_at'])
    except (TypeError, ValueError):
        return True
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    return now - checked >= timedelta(hours=after_hours)


class DomainHealthManager:
    """Settings-backed daily sweep of the name-level checks.

    The tracked set is recomputed on every run, the same way the registration
    check does it, so a domain CertMate stopped managing stops being asked
    about. :meth:`run_check` never lets one name's failure stop the sweep.
    """

    def __init__(self, settings_manager, inventory, cert_dir,
                 *, lookups=None, hsts_fetcher=None, now=None, sleep=time.sleep):
        self.settings_manager = settings_manager
        self.inventory = inventory
        self.cert_dir = Path(cert_dir)
        self._lookups = lookups
        self._hsts_fetcher = hsts_fetcher
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._sleep = sleep

    def get_config(self):
        settings = self.settings_manager.load_settings() or {}
        config = dict(DEFAULT_HEALTH_CONFIG)
        config.update(settings.get('domain_health') or {})
        return config

    def save_config(self, config):
        """Validate and persist. Raises ValueError on an unusable extra name."""
        extra = []
        for raw in config.get('extra_domains') or []:
            name = str(raw).strip().lower()
            if not name:
                continue
            if any(c in name for c in '\r\n \t/') or '.' not in name:
                raise ValueError(f'{name!r} is not a domain name')
            extra.append(name)
        clean = {
            'enabled': bool(config.get('enabled', False)),
            'include_inventory': bool(config.get('include_inventory', True)),
            'check_mail': bool(config.get('check_mail', True)),
            'check_blocklists': bool(config.get('check_blocklists', True)),
            'check_hsts': bool(config.get('check_hsts', True)),
            'extra_domains': extra,
        }
        self.settings_manager.update(
            lambda s: s.__setitem__('domain_health', clean),
            'domain_health_save',
        )
        return clean

    def tracked_names(self, config=None, settings=None):
        """Every name to check, as ``{name: is_registrable}``.

        Both scopes come out of the same sweep: the hosts CertMate serves (for
        HSTS) and the registrable domains behind them (for mail and
        blocklists). A name that is both — an apex CertMate also serves — gets
        every check in one row.
        """
        from .domain_registration import registrable_domain
        from .inventory_sources import collect_domain_sources

        settings = settings if settings is not None else (self.settings_manager.load_settings() or {})
        config = config or self.get_config()
        hosts = set()
        for domain in collect_domain_sources(settings, self.cert_dir):
            hosts.add(domain)
            hosts.update(self._metadata_sans(domain))
        if config.get('include_inventory', True):
            for record in self.inventory.list_all():
                if record.get('subject_cn'):
                    hosts.add(record['subject_cn'])
                hosts.update(record.get('san_dns') or [])
        hosts.update(config.get('extra_domains') or [])

        tracked = {}
        for raw in hosts:
            host = str(raw).strip().lower().lstrip('*.')
            # A wildcard certificate names no host that serves anything; its
            # registrable domain is still worth checking.
            if not host or any(c in host for c in '\r\n \t/'):
                continue
            tracked.setdefault(host, False)
            registrable = registrable_domain(host)
            if registrable:
                tracked[registrable] = True
        return dict(sorted(tracked.items()))

    def _metadata_sans(self, domain):
        path = self.cert_dir / domain / 'metadata.json'
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return []
        sans = data.get('san_domains') if isinstance(data, dict) else None
        return [s for s in sans if isinstance(s, str)] if isinstance(sans, list) else []

    def check_one(self, name, is_registrable, config, rbl_cache=None):
        """One name, never raising: an unexpected failure becomes ``unknown``."""
        try:
            return check_name(
                name,
                lookups=self._lookups,
                hsts_fetcher=self._hsts_fetcher,
                mail=config.get('check_mail', True),
                blocklists=config.get('check_blocklists', True),
                hsts=config.get('check_hsts', True),
                is_registrable=is_registrable,
                rbl_cache=rbl_cache,
            )
        except Exception as e:  # noqa: BLE001 - one bad name must not stop the sweep
            logger.warning("Domain health check failed for %s: %s: %s",
                           name, e.__class__.__name__, e)
            return {'error': _result(UNKNOWN, f'the check did not complete: '
                                              f'{e.__class__.__name__}')}

    def run_check(self, *, force=False, max_names=MAX_NAMES_PER_RUN):
        """Check every tracked name that is due. Returns a summary."""
        config = self.get_config()
        if not config.get('enabled') and not force:
            return {'skipped': True, 'reason': 'disabled', 'results': []}
        tracked = self.tracked_names(config)
        pruned = self.inventory.prune_domain_health(tracked)
        now = self._now()
        due = [(n, r) for n, r in tracked.items()
               if force or is_due(self.inventory.get_domain_health(n), now)]
        results = []
        # Whether a list answers us is about the list and the resolver, not
        # about the domain, so it is decided once for the whole sweep.
        rbl_cache = {}
        for name, is_registrable in due[:max_names]:
            checks = self.check_one(name, is_registrable, config, rbl_cache)
            status = worst_status(checks)
            self.inventory.record_domain_health(name, status, checks)
            results.append({'name': name, 'status': status,
                            'checks': {k: v.get('status') for k, v in checks.items()}})
        deferred = max(0, len(due) - max_names)
        logger.info("Domain health check: %d tracked, %d checked, %d deferred, %d forgotten.",
                    len(tracked), len(results), deferred, pruned)
        return {'skipped': False, 'results': results, 'summary': {
            'tracked': len(tracked), 'checked': len(results),
            'deferred': deferred, 'forgotten': pruned}}
