"""CAA — does the domain's DNS allow the chosen CA to issue for it?

A CAA record (RFC 8659) names the CAs allowed to issue for a domain. A CA must
check it before issuing and must refuse when it is not named, so a CAA record
that does not name the CA CertMate is about to use turns into a failed
issuance or, worse, a failed renewal weeks later with an ACME error the
operator has to decode.

This module answers the question CertMate can answer ahead of the CA: given
the CA and the names on the certificate, what do the CAA records say? It is
used two ways, and deliberately never to block anything:

* **warn** — before issuance, so the create form can say "the CAA record for
  example.com only allows pki.goog" while the operator can still change the CA
  or the record;
* **explain** — after certbot fails, so the error says which record refused
  and what to add, instead of only relaying the CA's message.

It never blocks because CertMate's resolver is not the CA's. Split-horizon
DNS, a record changed a minute ago, a CNAME only one side can follow: the CA's
view is the one that decides, and refusing an issuance the CA would have
accepted is a worse failure than a warning that turns out to be wrong.

The lookup follows RFC 8659 section 3: query the name, and if it has no CAA
records climb one label at a time towards the TLD; the first non-empty set is
the one that applies. A wildcard name uses its ``issuewild`` properties when
the set has any, ``issue`` otherwise. RFC 8657's ``validationmethods``
parameter is honoured, because a record can allow a CA for ``dns-01`` only and
a CA will then refuse an ``http-01`` order. ``accounturi`` is reported but not
enforced here: CertMate does not always know its ACME account URI before the
order, and guessing would make the warning wrong in both directions.

The issuer domain names each CA recognises are the ones it declares in the
CCADB "CAA Identifiers" report, which is what the root programs hold it to.
"""

import logging

logger = logging.getLogger(__name__)

# CertMate ca_provider key -> the CAA issuer domain names that CA recognises.
# Source: CCADB AllCAAIdentifiersReport (retrieved 2026-09-22). ZeroSSL has no
# row of its own: it issues from Sectigo's hierarchy and honours Sectigo's
# identifiers. A private CA is absent on purpose — whether it checks CAA, and
# for which name, is its operator's decision, not something CertMate can know.
CA_IDENTIFIERS = {
    'letsencrypt': ('letsencrypt.org',),
    'letsencrypt_staging': ('letsencrypt.org',),
    'google': ('pki.goog',),
    'actalis': ('actalis.it',),
    'sslcom': ('ssl.com',),
    'zerossl': ('sectigo.com', 'comodo.com', 'comodoca.com', 'usertrust.com',
                'trust-provider.com', 'entrust.net', 'affirmtrust.com'),
    'digicert': ('digicert.com', 'www.digicert.com', 'digicert.ne.jp',
                 'cybertrust.ne.jp', 'thawte.com', 'geotrust.com',
                 'rapidssl.com', 'symantec.com', 'digitalcertvalidation.com',
                 'quovadisglobal.com', 'amazon.com', 'amazontrust.com',
                 'awstrust.com', 'amazonaws.com'),
}
# ZeroSSL issues from the Sectigo hierarchy; the CCADB identifiers apply to
# both providers, so keep their CAA advice in sync.
CA_IDENTIFIERS['sectigo'] = CA_IDENTIFIERS['zerossl']

# Property tags a CA understands. An unknown tag with the critical flag set
# obliges the CA to refuse (RFC 8659 section 4.1), so it is reported as such.
_KNOWN_TAGS = {'issue', 'issuewild', 'iodef', 'contactemail', 'contactphone',
               'issuemail', 'issuevmc'}
_CRITICAL_FLAG = 0x80

STATUS_ALLOWED = 'allowed'          # a record names this CA (or restricts nothing relevant)
STATUS_NO_POLICY = 'no_policy'      # no CAA records anywhere up the tree: any CA may issue
STATUS_FORBIDDEN = 'forbidden'      # records exist and none authorises this CA
STATUS_UNKNOWN = 'unknown'          # the lookup failed; the CA may fail the same way
STATUS_NOT_APPLICABLE = 'not_applicable'  # private CA, or a CA with no known identifiers

_SEVERITY = [STATUS_FORBIDDEN, STATUS_UNKNOWN, STATUS_ALLOWED, STATUS_NO_POLICY,
             STATUS_NOT_APPLICABLE]

DEFAULT_TIMEOUT_SECONDS = 3.0


class LookupFailed(Exception):
    """The CAA query could not be answered (SERVFAIL, timeout, no resolver)."""


def _dnspython_resolver(timeout, nameservers=None):
    """Return ``resolve(name) -> [(flags, tag, value)]`` backed by dnspython.

    An empty list means the name has no CAA records (NOERROR/NODATA or
    NXDOMAIN) — the signal to climb. Anything else that goes wrong raises
    :class:`LookupFailed`. A CNAME at the name is followed by the resolver,
    which is what RFC 8659 asks for.
    """
    import dns.exception
    import dns.resolver

    from .dns_resolver import build

    resolver = build(timeout, nameservers)

    def resolve(name):
        try:
            answer = resolver.resolve(name, 'CAA')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.NoResolverConfiguration) as e:
            raise LookupFailed(f'{e.__class__.__name__} for {name}') from e
        except dns.exception.DNSException as e:
            raise LookupFailed(f'{e.__class__.__name__} for {name}: {e}') from e
        out = []
        for rdata in answer:
            tag = rdata.tag.decode('ascii', 'replace') if isinstance(rdata.tag, bytes) else str(rdata.tag)
            value = rdata.value.decode('utf-8', 'replace') if isinstance(rdata.value, bytes) else str(rdata.value)
            out.append((int(rdata.flags), tag, value))
        return out

    return resolve


# What check() builds its resolver with. A module attribute rather than a
# direct call so the test suite can swap it for an offline one (conftest.py)
# while _dnspython_resolver itself stays reachable for the one test that asks
# the real DNS.
resolver_factory = _dnspython_resolver


def _candidate_names(name):
    """The names RFC 8659 climbs through: the name itself, then each parent,
    stopping before the root (the TLD is included)."""
    labels = name.rstrip('.').split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels))]


def _parse_issue_value(value):
    """Split an issue/issuewild value into (issuer_domain, {param: value}).

    ``"letsencrypt.org; validationmethods=dns-01"`` ->
    ``('letsencrypt.org', {'validationmethods': 'dns-01'})``. An empty issuer
    domain (``";"``) is a record that authorises no CA at all.
    """
    parts = [p.strip() for p in value.split(';')]
    issuer = parts[0].lower().rstrip('.') if parts else ''
    params = {}
    for part in parts[1:]:
        if '=' in part:
            key, _, val = part.partition('=')
            params[key.strip().lower()] = val.strip()
    return issuer, params


def _format_record(flags, tag, value):
    return f'{flags} {tag} "{value}"'


def check_domain(name, identifiers, *, challenge_type=None, resolve):
    """CAA verdict for one certificate name against one CA's identifiers."""
    wildcard = name.startswith('*.')
    lookup_name = name[2:] if wildcard else name
    lookup_name = lookup_name.rstrip('.').lower()

    relevant_name, records = None, []
    for candidate in _candidate_names(lookup_name):
        try:
            found = resolve(candidate)
        except LookupFailed as e:
            return {
                'domain': name, 'status': STATUS_UNKNOWN, 'relevant_name': candidate,
                'records': [], 'reason': (
                    f'the CAA lookup for {candidate} failed ({e}); a CA that gets '
                    'the same answer refuses to issue'),
            }
        if found:
            relevant_name, records = candidate, found
            break

    if relevant_name is None:
        return {'domain': name, 'status': STATUS_NO_POLICY, 'relevant_name': None,
                'records': [], 'reason': 'no CAA records, so any CA may issue'}

    shown = [_format_record(*r) for r in records]
    base = {'domain': name, 'relevant_name': relevant_name, 'records': shown}

    for flags, tag, _value in records:
        if tag.lower() not in _KNOWN_TAGS and flags & _CRITICAL_FLAG:
            return dict(base, status=STATUS_FORBIDDEN, reason=(
                f'{relevant_name} carries a critical CAA property "{tag}" that no CA '
                'is required to understand, and a CA must refuse when it does not'))

    issue = [(t.lower(), v) for _f, t, v in records if t.lower() == 'issue']
    issuewild = [(t.lower(), v) for _f, t, v in records if t.lower() == 'issuewild']
    props = issuewild if (wildcard and issuewild) else issue
    kind = 'issuewild' if (wildcard and issuewild) else 'issue'

    if not props:
        return dict(base, status=STATUS_ALLOWED, reason=(
            f'{relevant_name} has CAA records but none restricts which CA may '
            f'issue {"a wildcard" if wildcard else "a certificate"}'))

    wanted = {i.lower() for i in identifiers}
    method_mismatch = None
    for _tag, value in props:
        issuer, params = _parse_issue_value(value)
        if issuer not in wanted:
            continue
        methods = params.get('validationmethods')
        if methods and challenge_type:
            allowed_methods = {m.strip().lower() for m in methods.split(',')}
            if challenge_type.lower() not in allowed_methods:
                method_mismatch = (issuer, methods)
                continue
        reason = f'{relevant_name} {kind} names {issuer}'
        if 'accounturi' in params:
            reason += (f', restricted to the ACME account {params["accounturi"]} '
                       '(not checked here: the CA will refuse any other account)')
        return dict(base, status=STATUS_ALLOWED, reason=reason)

    if method_mismatch:
        issuer, methods = method_mismatch
        return dict(base, status=STATUS_FORBIDDEN, reason=(
            f'{relevant_name} allows {issuer} only for {methods}, and this '
            f'certificate is validated with {challenge_type}'))

    named = sorted({_parse_issue_value(v)[0] or '(no CA)' for _t, v in props})
    return dict(base, status=STATUS_FORBIDDEN, reason=(
        f'{relevant_name} {kind} allows only {", ".join(named)}'))


def check(ca_provider, domains, *, challenge_type=None, resolve=None,
          timeout=DEFAULT_TIMEOUT_SECONDS, ca_name=None, nameservers=None):
    """CAA verdict for issuing *domains* from *ca_provider*. Never raises.

    Returns ``{'status', 'ca_provider', 'identifiers', 'domains': [...],
    'message'}`` where ``status`` is the most severe per-domain status
    (forbidden > unknown > allowed > no_policy) and ``message`` is one
    sentence an operator can act on, or None when there is nothing to say.
    """
    names = []
    for d in domains or []:
        d = str(d).strip()
        if d and d.lower() not in (n.lower() for n in names):
            names.append(d)

    identifiers = CA_IDENTIFIERS.get(ca_provider or '')
    if not identifiers:
        return {'status': STATUS_NOT_APPLICABLE, 'ca_provider': ca_provider,
                'identifiers': [], 'domains': [], 'message': None}

    if resolve is None:
        try:
            resolve = resolver_factory(timeout, nameservers)
        except ImportError as e:
            # dnspython reaches the image transitively, through the DNS
            # plugins; if one day it does not, say so rather than fail.
            logger.warning('CAA check unavailable: %s', e)
            return {'status': STATUS_UNKNOWN, 'ca_provider': ca_provider,
                    'identifiers': list(identifiers), 'domains': [],
                    'message': f'CAA could not be checked: {e}'}

    # No catch-all here: every dnspython failure, including a malformed name
    # (dns.name.EmptyLabel, IDNA errors), is a DNSException that the resolver
    # turns into LookupFailed, which check_domain reports as `unknown`.
    results = [check_domain(name, identifiers, challenge_type=challenge_type,
                            resolve=resolve)
               for name in names]

    status = STATUS_NO_POLICY
    for candidate in _SEVERITY:
        if any(r['status'] == candidate for r in results):
            status = candidate
            break

    return {
        'status': status,
        'ca_provider': ca_provider,
        'identifiers': list(identifiers),
        'domains': results,
        'message': _message(status, ca_name or ca_provider, identifiers, results),
        'suggested_record': _suggested_record(status, identifiers, results),
    }


def _suggested_record(status, identifiers, results):
    """The record that would let this CA issue, in zone-file form, or None."""
    if status != STATUS_FORBIDDEN:
        return None
    first = next(r for r in results if r['status'] == STATUS_FORBIDDEN)
    target = first['relevant_name'] or first['domain'].lstrip('*.')
    tag = 'issuewild' if first['domain'].startswith('*.') else 'issue'
    return f'{target}. CAA 0 {tag} "{identifiers[0]}"'


def _message(status, ca_label, identifiers, results):
    if status == STATUS_FORBIDDEN:
        bad = [r for r in results if r['status'] == STATUS_FORBIDDEN]
        first = bad[0]
        more = f' (and {len(bad) - 1} more name{"s" if len(bad) > 2 else ""})' if len(bad) > 1 else ''
        return (
            f'CAA: {first["reason"]}, so {ca_label} ({identifiers[0]}) will refuse '
            f'{first["domain"]}{more}. Add a record such as '
            f'{_suggested_record(STATUS_FORBIDDEN, identifiers, results)} '
            f'or choose a CA the record names.')
    if status == STATUS_UNKNOWN:
        first = next(r for r in results if r['status'] == STATUS_UNKNOWN)
        return f'CAA could not be checked for {first["domain"]}: {first["reason"]}.'
    return None


def explain_failure(ca_provider, domains, *, challenge_type=None, resolve=None,
                    timeout=DEFAULT_TIMEOUT_SECONDS, ca_name=None,
                    nameservers=None):
    """A sentence to append to an issuance/renewal error, or None.

    Only a CAA record that refuses this CA earns an explanation: an ``unknown``
    lookup after a failure is noise next to the CA's own message, and an
    ``allowed`` one means CAA is not why it failed.
    """
    result = check(ca_provider, domains, challenge_type=challenge_type,
                   nameservers=nameservers,
                   resolve=resolve, timeout=timeout, ca_name=ca_name)
    if result['status'] == STATUS_FORBIDDEN:
        return result['message']
    return None
