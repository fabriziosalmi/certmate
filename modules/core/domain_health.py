"""The other things that take a site down, and that a certificate cannot fix.

A certificate that renews on time and a domain that does not lapse still leave
an agency answering for a site that stopped receiving mail, or one whose IP
landed on a blocklist. These are the checks that were living in a separate
tool, brought in beside the certificate and the registration, because they are
about the same thing: the name, and whether it still works.

Seven checks, each of which can say *it does not know*:

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
* **Security headers** — whether the browser is told to refuse framing, MIME
  sniffing and unsanctioned script. A missing header is a warning; one that
  looks like protection and is not enforced is a finding, because it answers
  "are we covered?" with a yes.
* **Disclosure** — whether the response names the software and *version*
  answering it. ``nginx/1.24.0`` tells an attacker which CVEs to try;
  ``cloudflare`` does not, which is why this is a version pattern and not a
  presence check.

The last three share one request. An eighth check, whether the host still
accepts TLS 1.0 or 1.1, lives in ``weak_tls.py``: it is the only one that
opens a connection a host did not invite, so it is opt-in and kept separate.

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
    # Named for what it now covers. `check_hsts` is still read on the way in,
    # because an instance configured before the other two headers existed
    # would otherwise silently start making a request it had turned off.
    'check_headers': True,
    # Off by default: it is the only check that opens connections a host did
    # not invite, two per name, and an operator should choose that.
    'check_weak_tls': False,
    'extra_domains': [],
}

# These records change rarely; once a day is plenty, and the interval keeps a
# re-run on the same day from asking every list again.
RECHECK_AFTER_HOURS = 20
MAX_NAMES_PER_RUN = 200


# `all` is a mechanism, and a mechanism is a whole token. Matching it as a bare
# word made `v=spf1 include:all.example.net` look like a record that ends in
# `all` — a dot is a word boundary — so a record with no all-mechanism at all
# reported `ok`. The qualifier is optional and may be +, -, ~ or ?.
_ALL_MECHANISM = re.compile(r'(?:^|\s)[-+~?]?all(?:\s|$)', re.IGNORECASE)
_PLUS_ALL = re.compile(r'(?:^|\s)\+?all(?:\s|$)', re.IGNORECASE)


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
    if _ALL_MECHANISM.search(record) is None:
        return _result(WARNING, 'the record has no "all" mechanism, so it says nothing '
                                'about senders it does not list', record=record)
    if _PLUS_ALL.search(record):
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


def not_covered_reason(address):
    """Why a DNSBL cannot answer about *address*, or None if it can.

    Two kinds, and neither is a gap in coverage — both are the boundary of
    what these lists answer about at all:

    * **Not a public address.** A DNSBL lists hosts that send mail on the
      internet. It has nothing to say about 10.0.0.0/8, and an empty answer
      about one is not "clean". Worse, asking is not free: the query carries
      an internal address to four third parties, which is a piece of the
      estate's topology they had no reason to receive. `is_global` rather
      than `is_private`, because the latter answers False for 100.64.0.0/10 —
      carrier-grade NAT, which is not public and not private by that test.

    * **IPv6.** The self-test points are 127.0.0.2 and 127.0.0.1, so they
      prove a list answers about IPv4 and nothing more.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None          # handled by the caller, which skips it
    if not ip.is_global:
        return (f'{address}: not a public address, so a blocklist has nothing '
                f'to say about it and is not asked')
    if ip.version == 6:
        return f'{address}: IPv6, which these lists are not self-tested for'
    return None


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
    # A negative control that did not come back proves nothing either: the
    # point of it is to catch a list (or resolver) that answers everything,
    # and an unanswered query cannot rule that out.
    return clean is not None and classify_rbl_answer(clean) != 'listed'


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

    # The test points are 127.0.0.2 and 127.0.0.1, which say whether a list
    # answers about **IPv4**. They say nothing about IPv6, and most DNSBLs
    # either do not list IPv6 at all or use a separate zone for it — so an
    # empty answer about an AAAA address is indistinguishable from "this list
    # does not serve IPv6", which is the false-clean this module exists to
    # prevent, one level below the refusal codes. Until there is a self-test
    # that proves otherwise, an IPv6 address is not asked about.
    #
    # Kept apart from `unanswered` on purpose. A list that refused is a hole in
    # coverage of something we should have been able to check; an IPv6 address
    # is a boundary of what these lists answer about at all. Counting the
    # second as the first would put nearly every healthy dual-stack domain —
    # which is most of them — at a permanent warning, and a warning that is
    # always on is one nobody reads.
    not_covered = [r for r in (not_covered_reason(a)
                               for a in addresses[:MAX_ADDRESSES]) if r]
    # Only answers that carry information count. A refusal is not a check that
    # came back clean, and counting it as one is the whole defect this module
    # was written to avoid.
    answered = 0
    for address in addresses[:MAX_ADDRESSES]:
        if not_covered_reason(address):
            continue
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

    extra = {'unanswered': unanswered, 'not_covered': not_covered}
    if listings:
        where = ', '.join(sorted({entry['list'] for entry in listings}))
        return _result(FAILING, f'listed on {where}', listings=listings, **extra)
    if not answered:
        if not_covered and not unanswered:
            return _result(UNKNOWN,
                           'nothing about this domain could be asked: ' +
                           '; '.join(not_covered), **extra)
        return _result(UNKNOWN,
                       'no blocklist answered usefully — the resolver CertMate uses is '
                       'almost always the reason, because the large lists refuse public '
                       'resolvers. Name one of your own under dns_resolver in the '
                       'discovery configuration, or in CERTMATE_DNS_RESOLVERS',
                       **extra)
    if unanswered:
        return _result(WARNING,
                       f'not listed where it could be checked, but '
                       f'{len(unanswered)} lookup(s) went unanswered', **extra)
    detail = (f'not listed on {len(lists)} blocklist'
              f'{"s" if len(lists) != 1 else ""}')
    if not_covered:
        detail += (f'; {len(not_covered)} address(es) these lists do not '
                   f'cover were not asked about')
    return _result(OK, detail, **extra)


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
# The other response headers
# --------------------------------------------------------------------------- #
#
# Three things a browser does with what a site sends, beyond HSTS: refuse to
# frame it, refuse to guess a content type for it, and refuse to run script
# the site did not sanction. And one thing the site says that only helps an
# attacker: which software, at which version, is answering.

# A version is digits-and-dots after the product name: `nginx/1.24.0`,
# `Apache/2.4.58`. `nginx` or `cloudflare` on their own name the product and
# disclose nothing an attacker could look up a CVE for, which is why this is
# a pattern and not a presence check — the tool these checks came from
# reported `Server: cloudflare` as "Server Version Disclosed".
_VERSION_IN_HEADER = re.compile(r'\d+\.\d+')

# Only these two are honoured. ALLOW-FROM was dropped by every modern browser,
# so a site relying on it is not protected and does not know it.
_VALID_FRAME_OPTIONS = frozenset({'deny', 'sameorigin'})

_DISCLOSING_HEADERS = ('x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
                       'x-generator')


def _header(headers, name):
    """A header's value, case-insensitively, or None. HTTP header names are
    case-insensitive and servers disagree about which case they use."""
    if not headers:
        return None
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def check_security_headers(served):
    """What the browser is told to refuse. *served* is a
    :func:`fetch_response_headers` result, or None.

    A header that looks like protection and is not enforced is worse than a
    missing one, because it answers the question "are we covered?" with a yes,
    so those are findings and the absences are warnings.
    """
    if served is None:
        return _result(UNKNOWN, 'the site could not be reached over HTTPS')
    if served.get('stopped_at_redirect'):
        return _result(UNKNOWN,
                       'the host only redirects, so these headers belong to the '
                       'name it redirects to, not to this one')

    headers = served['headers']
    csp = _header(headers, 'content-security-policy')
    csp_report_only = _header(headers, 'content-security-policy-report-only')
    frame_options = (_header(headers, 'x-frame-options') or '').strip().lower()
    nosniff = (_header(headers, 'x-content-type-options') or '').strip().lower()
    framed_by_csp = bool(csp and 'frame-ancestors' in csp.lower())

    broken, missing = [], []
    if frame_options and frame_options not in _VALID_FRAME_OPTIONS:
        broken.append(f'X-Frame-Options: {frame_options} is not a value browsers '
                      f'honour, so the site is not protected from framing')
    elif not frame_options and not framed_by_csp:
        missing.append('no X-Frame-Options and no CSP frame-ancestors, so the page '
                       'can be framed')
    if not csp and csp_report_only:
        broken.append('only Content-Security-Policy-Report-Only: violations are '
                      'reported and nothing is blocked')
    elif not csp and not csp_report_only:
        missing.append('no Content-Security-Policy')
    if nosniff and nosniff != 'nosniff':
        broken.append(f'X-Content-Type-Options: {nosniff} is not "nosniff", so it '
                      f'does nothing')
    elif not nosniff:
        missing.append('no X-Content-Type-Options: nosniff')

    present = {'content_security_policy': csp, 'x_frame_options': frame_options or None,
               'x_content_type_options': nosniff or None,
               'frame_ancestors_in_csp': framed_by_csp}
    if broken:
        return _result(FAILING, '; '.join(broken), broken=broken, missing=missing,
                       headers=present, checked_host=served['final_host'])
    if missing:
        return _result(WARNING, '; '.join(missing), broken=[], missing=missing,
                       headers=present, checked_host=served['final_host'])
    return _result(OK, 'framing, sniffing and script sources are all restricted',
                   broken=[], missing=[], headers=present,
                   checked_host=served['final_host'])


def check_disclosure(served):
    """What the response volunteers about the software behind it.

    Never a failure: knowing the version does not let anyone in, it only
    saves them the reconnaissance. It is worth telling an operator about
    because it is usually one line of configuration.
    """
    if served is None:
        return _result(UNKNOWN, 'the site could not be reached over HTTPS')
    headers = served['headers']
    leaks = []
    server = _header(headers, 'server')
    if server and _VERSION_IN_HEADER.search(server):
        leaks.append(f'Server: {server}')
    for name in _DISCLOSING_HEADERS:
        value = _header(headers, name)
        if value:
            leaks.append(f'{name}: {value}')
    if leaks:
        return _result(WARNING, f'the response names the software running it: '
                                f'{"; ".join(leaks)}', disclosed=leaks,
                       checked_host=served['final_host'])
    return _result(OK, 'the response does not name its software version',
                   disclosed=[], checked_host=served['final_host'])


# --------------------------------------------------------------------------- #
# Live lookups
# --------------------------------------------------------------------------- #

def dns_lookups(timeout=DEFAULT_TIMEOUT_SECONDS, nameservers=None):
    """Return ``(txt, mx, addresses, rbl)`` callables backed by dnspython.

    Each returns None when the lookup failed, and an empty list when the name
    exists with no such record — the difference between "could not ask" and
    "asked, nothing there", which every check above depends on.

    *nameservers* replaces the system's, which is how an operator acts on the
    advice a refused blocklist gives (see ``dns_resolver.py``).
    """
    import dns.exception
    import dns.resolver

    from .dns_resolver import build

    resolver = build(timeout, nameservers)

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
        found, failed = [], 0
        for rdtype in ('A', 'AAAA'):
            answers = query(name, rdtype)
            if answers is None:
                # Resolvers time out on AAAA alone often enough that one
                # failure must not decide the answer; ask both, and only
                # report "could not look" when neither came back.
                failed += 1
                continue
            found += [str(r) for r in answers]
        return None if failed == 2 else found

    def rbl(name):
        answers = query(name, 'A')
        if answers is None:
            return None
        return [str(r) for r in answers]

    return txt, mx, addresses, rbl


def _one_response(host, *, timeout, allow_private):
    """One HEAD to *host*, returning ``(status, headers)`` or ``(None, None)``.

    Through the probe's SSRF guard and pinned to the validated address, like
    every other connection CertMate opens towards a name it did not choose.
    Unlike the probe, this one *verifies* the certificate: a browser ignores
    the policies these headers carry when it did not trust the connection, so
    reporting them from an untrusted one would describe a policy nobody
    applies.
    """
    import http.client
    import ssl

    from .cert_probe import _resolve_and_guard

    if any(c in host for c in '\r\n \t'):
        # Never reachable through the inventory, which holds validated names,
        # but this string is about to become a request line.
        return None, None

    family, connect_ip, reason = _resolve_and_guard(host, 443, allow_private)
    if reason is not None:
        logger.info("Header check skipped for %s: %s", host, reason)
        return None, None

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
                    return response.status, dict(response.getheaders())
                finally:
                    response.close()
    except (OSError, ssl.SSLError, http.client.HTTPException,
            ValueError, TypeError, UnicodeError) as e:
        logger.info("Header check could not reach %s: %s", host, e.__class__.__name__)
        return None, None


def _redirect_target(headers, from_host):
    """The https host a 3xx points at, or None if it is not one to follow.

    Only https, and only a name under the same registrable domain: an apex
    that redirects to ``www`` is the case worth following, and following a
    redirect off the estate would be reading someone else's headers and
    calling them this domain's.
    """
    from urllib.parse import urlsplit

    from .domain_registration import registrable_domain

    location = _header(headers, 'location')
    if not location:
        return None
    parts = urlsplit(location.strip())
    if parts.scheme != 'https' or not parts.hostname:
        return None
    target = parts.hostname.lower()
    if target == from_host.lower():
        return None
    if registrable_domain(target) != registrable_domain(from_host):
        return None
    return target


def fetch_response_headers(host, *, timeout=DEFAULT_TIMEOUT_SECONDS,
                           allow_private=False, max_redirects=3):
    """What *host* serves, as ``{'headers': {...}, 'final_host': str}``, or None.

    Redirects within the same registrable domain are followed, because the
    apex of most estates is a 301 to ``www`` and the protective headers live
    on the page, not on the redirect. HSTS is the exception and is read from
    the *first* response: a browser records it from whatever the host sent,
    including a 301, so taking it from the last hop would miss an apex that
    sets it and a ``www`` that does not.
    """
    status, headers = _one_response(host, timeout=timeout, allow_private=allow_private)
    if headers is None:
        return None
    first_hsts = _header(headers, 'strict-transport-security')
    seen = {host.lower()}
    current = host
    for _ in range(max_redirects):
        if not (status and 300 <= status < 400):
            break
        target = _redirect_target(headers, current)
        if target is None or target in seen:
            break
        seen.add(target)
        next_status, next_headers = _one_response(
            target, timeout=timeout, allow_private=allow_private)
        if next_headers is None:
            # The hop failed. What we have is the redirect's own headers,
            # which say nothing about the page, so this is not an answer.
            return {'headers': headers, 'final_host': current,
                    'first_hsts': first_hsts, 'stopped_at_redirect': True}
        status, headers, current = next_status, next_headers, target
    at_redirect = bool(status and 300 <= status < 400)
    return {'headers': headers, 'final_host': current, 'first_hsts': first_hsts,
            'stopped_at_redirect': at_redirect}


def fetch_hsts_header(host, **kwargs):
    """The Strict-Transport-Security header *host* itself serves, '' if none,
    None if it could not be reached."""
    served = fetch_response_headers(host, **kwargs)
    if served is None:
        return None
    return served['first_hsts'] or ''


# --------------------------------------------------------------------------- #
# Running the checks for one name, and for everything tracked
# --------------------------------------------------------------------------- #

def worst_status(checks):
    """The status a name gets from the checks that ran on it."""
    statuses = [c.get('status') for c in (checks or {}).values() if isinstance(c, dict)]
    if not statuses:
        return UNKNOWN
    return min(statuses, key=lambda s: _SEVERITY.get(s, _SEVERITY[UNKNOWN]))


def check_name(name, *, lookups=None, headers_fetcher=None, mail=True,
               blocklists=True, headers=True, weak_tls=False, is_registrable=True,
               rbl_cache=None, tls_capability=None, weak_tls_prober=None):
    """Run the applicable checks for one name and return ``{check: result}``.

    Mail and blocklist checks only apply to a registrable domain: DMARC falls
    back to the organisational domain, so asking ``_dmarc.www.example.com``
    alone would report "no DMARC" for a domain that publishes one. The header
    checks are the opposite — they belong to the host that serves the site.

    The three header checks share **one** request. They are separate answers
    because they are separate jobs to do, but a site should not be asked three
    times to produce them.
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
    if headers:
        fetch = headers_fetcher or fetch_response_headers
        served = fetch(name)
        checks['hsts'] = check_hsts(None if served is None
                                    else served['first_hsts'] or '')
        checks['security_headers'] = check_security_headers(served)
        checks['disclosure'] = check_disclosure(served)
    if weak_tls:
        # Imported here, not at the top: weak_tls imports this module for the
        # status vocabulary, and only the sweeps that ask for the check should
        # pay for loading it.
        from . import weak_tls as weak_tls_module
        checks['weak_tls'] = weak_tls_module.check(
            name, prober=weak_tls_prober, capability=tls_capability)
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
                 *, lookups=None, headers_fetcher=None, now=None, sleep=time.sleep):
        self.settings_manager = settings_manager
        self.inventory = inventory
        self.cert_dir = Path(cert_dir)
        self._lookups = lookups
        self._headers_fetcher = headers_fetcher
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._sleep = sleep

    def get_config(self):
        settings = self.settings_manager.load_settings() or {}
        config = dict(DEFAULT_HEALTH_CONFIG)
        config.update(settings.get('domain_health') or {})
        return config

    def _configured_lookups(self):
        """Lookups through whichever nameservers this instance is set to use.

        Built per sweep rather than held, so changing the setting takes effect
        on the next run instead of on the next restart.
        """
        from .dns_resolver import configured_nameservers

        settings = self.settings_manager.load_settings() or {}
        return dns_lookups(nameservers=configured_nameservers(settings))

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
            'check_headers': bool(config.get('check_headers',
                                             config.get('check_hsts', True))),
            'check_weak_tls': bool(config.get('check_weak_tls', False)),
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

    def check_one(self, name, is_registrable, config, rbl_cache=None,
                  tls_capability=None):
        """One name, never raising: an unexpected failure becomes ``unknown``."""
        try:
            return check_name(
                name,
                lookups=self._lookups or self._configured_lookups(),
                headers_fetcher=self._headers_fetcher,
                mail=config.get('check_mail', True),
                blocklists=config.get('check_blocklists', True),
                headers=config.get('check_headers', config.get('check_hsts', True)),
                weak_tls=config.get('check_weak_tls', False),
                tls_capability=tls_capability,
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
        # Whether this build can offer an old TLS version is a fact about the
        # runtime, the same for every host, so it is established once.
        tls_capability = {}
        for name, is_registrable in due[:max_names]:
            checks = self.check_one(name, is_registrable, config, rbl_cache,
                                    tls_capability)
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
