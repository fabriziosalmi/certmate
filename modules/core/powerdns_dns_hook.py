#!/usr/bin/env python3
"""Certbot manual DNS hook for PowerDNS.

PowerDNS DNS-01 used to go through ``certbot-dns-powerdns``. Its last release
(0.2.1, 2021) requires ``dns-lexicon<=3.5.6``, which no environment holding
CertMate's pins can install, so PowerDNS was a "Separate install" nobody could
complete. The release that does install (0.1.1) looks for the zone of
``sub.example.com`` by asking for ``sub.example.com`` first and moves on to
``example.com`` only on a 422; current PowerDNS answers 404 for a zone it does
not have, so the plugin stopped at the first guess. The record is written here
instead, through the PowerDNS HTTP API, the way the Azure hook writes its own.

The API is spoken directly rather than through ``dns-lexicon``. Lexicon's
``Client`` guesses the zone again from the record name with ``tldextract`` and
reads the Public Suffix List over the network on every call; for a name under no
public suffix (``corp.lan``, ``example.internal``: the zones a private ACME CA
issues for) it guesses wrong even when told the zone (``delegated``), measured on
lexicon 3.25.1: ``corp.lan`` became ``corp.lan.lan``. The zone found below is the
one PowerDNS itself answered for, and nothing guesses it again.

Run by certbot as ``--manual-auth-hook`` / ``--manual-cleanup-hook``::

    powerdns_dns_hook.py --config <file> --action auth|cleanup

``<file>`` is the 0600 JSON CertMate writes for the operation and removes when it
ends: ``api_url``, ``api_key`` and, optionally, ``server_id`` (``localhost`` when
absent, as in PowerDNS). certbot passes the challenge in the environment
(``CERTBOT_DOMAIN``, ``CERTBOT_VALIDATION``); how long to wait for the record to
be visible comes from ``CERTMATE_DNS_PROPAGATION_SECONDS``, as for Azure.

* The zone is asked of PowerDNS, longest name first, from the challenge name
  itself down to the registered domain. 404 and 422 mean "not this one"; a 401
  or 403 is an answer about the key, or about a proxy in front of the API, and
  stops the lookup with its own message instead of ending as "zone not found".
* One name can carry several values (a wildcard and its apex are validated on
  the same ``_acme-challenge`` name), so a value is added to the record set,
  never written over it, and cleanup removes only its own value.
* Cleanup never fails the issuance: a record left behind is a warning.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from .pinned_https import UnsafeDestination, refuse_metadata_endpoint
except ImportError:  # run by certbot as a script: this directory is on sys.path, the package is not
    from pinned_https import UnsafeDestination, refuse_metadata_endpoint

CHALLENGE_LABEL = '_acme-challenge'
TXT_TTL_SECONDS = 60
MAX_WAIT_SECONDS = 3600
# Every request is bounded: a hung API must not hold certbot (and the issuance
# thread waiting on it) until certbot's own 30-minute limit.
REQUEST_TIMEOUT_SECONDS = 30
NOT_THIS_ZONE = (404, 422)
REFUSED = (401, 403)
_ERROR_SNIPPET = 300


class PowerDNSHookError(RuntimeError):
    pass


def _require(config, *keys):
    missing = [key for key in keys if not str(config.get(key) or '').strip()]
    if missing:
        raise PowerDNSHookError(
            f"Missing PowerDNS credential fields: {', '.join(missing)}")


def _normalize(name):
    return (name or '').strip().lower().removeprefix('*.').rstrip('.')


def _registered_domain(name):
    """The registered domain of *name*, or None for a name under no public suffix.

    The same reading as ``domain_registration.registrable_domain``: the Public
    Suffix List bundled with ``tldextract``, offline (``suffix_list_urls=()``)
    and without a cache directory. Not imported from there: certbot runs this
    file as a script, which sees the installed packages but not CertMate's own.
    """
    import tldextract
    result = tldextract.TLDExtract(
        cache_dir=None, suffix_list_urls=(), include_psl_private_domains=False)(name)
    registered = getattr(result, 'top_domain_under_public_suffix', None)
    if registered is None:  # tldextract < 5.3
        registered = result.registered_domain
    return registered or None


def zone_candidates(domain):
    """Where the TXT record for *domain*'s challenge may live, longest name first.

    From ``_acme-challenge.<domain>`` (a zone of its own is a common way to hand
    the challenge to a separate server) down to the registered domain. A name
    under no public suffix (``corp.lan``) stops at its last two labels, so a bare
    top-level label is never asked for.
    """
    name = _normalize(domain)
    if not name:
        raise PowerDNSHookError('no domain to find a PowerDNS zone for')
    labels = f'{CHALLENGE_LABEL}.{name}'.split('.')
    floor = _registered_domain(name)
    lowest = len(floor.split('.')) if floor else min(2, len(labels))
    return ['.'.join(labels[index:]) for index in range(len(labels) - lowest + 1)]


def api_base(config):
    """``<api_url>/api/v1/servers/<server_id>``, as lexicon's PowerDNS provider built it.

    The URL is admin-set; as for the alias hook's requests, it must be http(s)
    (urllib also opens ``file://``) and never a cloud-metadata or link-local
    address.
    """
    url = str(config['api_url']).strip().rstrip('/')
    if urllib.parse.urlsplit(url).scheme.lower() not in ('http', 'https'):
        raise PowerDNSHookError(f'PowerDNS API URL must use http or https: {url[:64]}')
    try:
        refuse_metadata_endpoint(url)
    except UnsafeDestination as exc:
        raise PowerDNSHookError(str(exc)) from exc
    if not url.endswith('/api/v1'):
        url += '/api/v1'
    server_id = str(config.get('server_id') or '').strip() or 'localhost'
    return f"{url}/servers/{urllib.parse.quote(server_id, safe='')}"


def _zone_url(base, zone):
    return f"{base}/zones/{urllib.parse.quote(zone + '.', safe='.')}"


class _HTTPStatus(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


def _request(method, url, api_key, payload=None):
    """``(status, parsed JSON or None)``; a non-2xx answer raises ``_HTTPStatus``."""
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    request = urllib.request.Request(  # noqa: S310 - http(s) only, checked in api_base
        url, data=data, method=method,
        headers={'X-API-Key': api_key, 'Accept': 'application/json',
                 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(  # noqa: S310  # nosec B310 - http(s) only, checked in api_base
                request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            raw = response.read().decode('utf-8')
            return response.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', errors='replace')[:_ERROR_SNIPPET]
        raise _HTTPStatus(exc.code, body) from exc
    except urllib.error.URLError as exc:
        raise PowerDNSHookError(f'PowerDNS API at {url} could not be reached: {exc.reason}') from exc


def _refused(status, zone, body):
    who = ('the API key' if status == 401
           else 'the API key, or a proxy in front of the PowerDNS API')
    return PowerDNSHookError(
        f"PowerDNS refused the request for zone {zone} (HTTP {status}): check {who}. "
        f"A refusal is not a missing zone, so the lookup stops here. {body}".strip())


def find_zone(base, api_key, domain):
    """``(zone, zone data)`` for the zone PowerDNS holds the challenge record of *domain* in."""
    tried = []
    for zone in zone_candidates(domain):
        try:
            _, data = _request('GET', _zone_url(base, zone), api_key)
        except _HTTPStatus as exc:
            if exc.status in NOT_THIS_ZONE:
                tried.append(f'{zone} ({exc.status})')
                continue
            if exc.status in REFUSED:
                raise _refused(exc.status, zone, exc.body) from None
            raise PowerDNSHookError(
                f'PowerDNS answered HTTP {exc.status} for zone {zone}: {exc.body}') from None
        return zone, data or {}
    raise PowerDNSHookError(
        f"No PowerDNS zone holds {CHALLENGE_LABEL}.{_normalize(domain)}; "
        f"asked for: {', '.join(tried)}")


def _quoted(value):
    return f'"{value}"'


def _txt_rrset(zone_data, fqdn):
    for rrset in zone_data.get('rrsets') or []:
        if rrset.get('type') == 'TXT' and _normalize(rrset.get('name')) == fqdn:
            return rrset
    return None


def _patch(base, api_key, zone, rrset):
    try:
        _request('PATCH', _zone_url(base, zone), api_key, {'rrsets': [rrset]})
    except _HTTPStatus as exc:
        if exc.status in REFUSED:
            raise _refused(exc.status, zone, exc.body) from None
        raise PowerDNSHookError(
            f'PowerDNS refused the change to zone {zone} (HTTP {exc.status}): {exc.body}') from None


def _notify_secondaries(base, api_key, zone, zone_data):
    """Ask a primary zone's secondaries to transfer now, as lexicon's provider did.

    A secondary the CA happens to ask must already have the record. Failing to
    notify is not failing the challenge: secondaries still refresh on their own.
    """
    if zone_data.get('kind') not in ('Master', 'Primary'):
        return
    try:
        _request('PUT', f'{_zone_url(base, zone)}/notify', api_key)
    except (_HTTPStatus, PowerDNSHookError) as exc:
        print(f'PowerDNS: notifying the secondaries of {zone} failed: {exc}', file=sys.stderr)


def add_txt(base, api_key, domain, validation):
    zone, zone_data = find_zone(base, api_key, domain)
    fqdn = f'{CHALLENGE_LABEL}.{_normalize(domain)}'
    existing = _txt_rrset(zone_data, fqdn)
    records = [{'content': record['content'], 'disabled': record.get('disabled', False)}
               for record in (existing or {}).get('records') or []]
    if any(record['content'] == _quoted(validation) for record in records):
        return zone
    _patch(base, api_key, zone, {
        'name': fqdn + '.', 'type': 'TXT', 'changetype': 'REPLACE',
        'ttl': (existing or {}).get('ttl') or TXT_TTL_SECONDS,
        'records': [*records, {'content': _quoted(validation), 'disabled': False}]})
    _notify_secondaries(base, api_key, zone, zone_data)
    return zone


def remove_txt(base, api_key, domain, validation):
    zone, zone_data = find_zone(base, api_key, domain)
    fqdn = f'{CHALLENGE_LABEL}.{_normalize(domain)}'
    existing = _txt_rrset(zone_data, fqdn)
    if existing is None:
        return zone
    records = existing.get('records') or []
    remaining = [{'content': record['content'], 'disabled': record.get('disabled', False)}
                 for record in records if record.get('content') != _quoted(validation)]
    if len(remaining) == len(records):
        return zone
    if remaining:
        change = {'name': fqdn + '.', 'type': 'TXT', 'changetype': 'REPLACE',
                  'ttl': existing.get('ttl') or TXT_TTL_SECONDS, 'records': remaining}
    else:
        change = {'name': fqdn + '.', 'type': 'TXT', 'changetype': 'DELETE'}
    _patch(base, api_key, zone, change)
    _notify_secondaries(base, api_key, zone, zone_data)
    return zone


def _wait_seconds():
    try:
        seconds = int(os.environ.get('CERTMATE_DNS_PROPAGATION_SECONDS') or 0)
    except ValueError:
        return 0
    return max(0, min(MAX_WAIT_SECONDS, seconds))


def run(config, action, environ=None):
    environ = os.environ if environ is None else environ
    domain = environ.get('CERTBOT_DOMAIN')
    validation = environ.get('CERTBOT_VALIDATION')
    if not domain or not validation:
        if action == 'cleanup':
            return
        raise PowerDNSHookError('CERTBOT_DOMAIN and CERTBOT_VALIDATION must be set')
    _require(config, 'api_url', 'api_key')
    base = api_base(config)
    if action == 'auth':
        add_txt(base, config['api_key'], domain, validation)
        time.sleep(_wait_seconds())
    else:
        remove_txt(base, config['api_key'], domain, validation)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--action', choices=['auth', 'cleanup'], required=True)
    args = parser.parse_args(argv)

    try:
        with open(args.config, encoding='utf-8') as f:
            config = json.load(f)
        if not isinstance(config, dict):
            raise PowerDNSHookError('the hook config is not a JSON object')
        run(config, args.action)
    except (PowerDNSHookError, OSError, ValueError) as exc:
        if args.action == 'cleanup':
            # Same rule as the Azure and alias hooks: a failed cleanup must not
            # fail the issuance that already succeeded or failed on its own.
            print(f'PowerDNS cleanup failed: {exc}', file=sys.stderr)
            return 0
        print(f'PowerDNS challenge failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
