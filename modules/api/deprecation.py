"""Marking an endpoint as going away, in a shape a client can act on.

There was no deprecation mechanism at all: no `Deprecation` header, no `Sunset`
header, no `deprecated` flag in the Swagger document, no per-endpoint marker.
An endpoint or a field could therefore be removed abruptly — breaking whatever
was calling it, with the first notice being a 404 — or kept forever because
removing it was the only alternative.

Both of those are choices nobody wants to make. The standard shape lets a
client warn instead of fail, which is what makes removal possible later:

* **RFC 8594** `Sunset: <HTTP-date>` — the earliest date the endpoint may stop
  answering.
* **RFC 9745** `Deprecation: @<unix seconds>` — when it *became* deprecated. An
  `@`-prefixed integer rather than a date string; that is the spec, not a
  shortcut.
* `Link: <...>; rel="deprecation"` — where to read what to do instead.

This module shipped with `DEPRECATIONS` empty, before anything needed it, so
that the shape existed before the release where something had to go. It is not
empty any more: `/api/dns-providers/accounts` is a second address for the same
operation as `/api/dns/accounts`, at the same role, through a different
implementation, and two public addresses that can drift apart is one too many.

Deprecating does not bump the contract version. That is the point of
deprecating rather than removing, and the rule is written beside
API_CONTRACT_VERSION in modules/core/constants.py: the removal is what bumps
the major.

`tests/test_the_contract_says_when_it_changes.py` checks the shape against an
example entry rather than against production data, so the mechanism stays
tested while nothing uses it.
"""
import datetime
import logging

logger = logging.getLogger(__name__)

# endpoint name -> what to tell a caller. Empty on purpose; see the module
# docstring.
#
# Shape:
#   'certificates_certificate_list': {
#       'since': '2026-09-08',        # when it became deprecated
#       'sunset': '2027-03-08',       # earliest it may stop answering
#       'link': 'https://.../docs/api.md#certificates',
#       'note': 'Use GET /api/v2/certificates.',
#   }
DEPRECATIONS = {
    # /api/dns-providers/accounts duplicates /api/dns/accounts: same role, same
    # behaviour, a different implementation, both public. Nothing in the
    # product calls it - not the dashboard, which uses /api/dns/accounts, not
    # the SDK, which uses the same, not the templates - so the cost of it is
    # not that somebody depends on it, but that two implementations of one
    # operation can answer differently and nobody would know which one a
    # caller reached.
    #
    # Keyed by these names and not by `api_dns_accounts`, which the dashboard's
    # own /api/web/settings/accounts shares: see the note above the routes in
    # modules/web/settings_routes.py.
    'api_dns_accounts_deprecated': {
        'since': '2026-09-18',
        'sunset': '2027-03-18',
        'link': 'https://github.com/fabriziosalmi/certmate/blob/main/docs/api.md#dns-provider-accounts',
        'note': 'Use GET/POST /api/dns/accounts, or /api/dns/<provider>/accounts.',
    },
    'api_dns_account_detail_deprecated': {
        'since': '2026-09-18',
        'sunset': '2027-03-18',
        'link': 'https://github.com/fabriziosalmi/certmate/blob/main/docs/api.md#dns-provider-accounts',
        'note': 'Use PUT/DELETE /api/dns/<provider>/accounts/<account_id>.',
    },
}


def _http_date(day):
    """An RFC 1123 date at midnight UTC, which is what Sunset takes."""
    parsed = datetime.datetime.strptime(day, '%Y-%m-%d').replace(
        tzinfo=datetime.timezone.utc)
    return parsed.strftime('%a, %d %b %Y %H:%M:%S GMT')


def _unix_at(day):
    parsed = datetime.datetime.strptime(day, '%Y-%m-%d').replace(
        tzinfo=datetime.timezone.utc)
    return int(parsed.timestamp())


def deprecation_headers(entry):
    """The headers announcing one deprecation, or {} for a malformed entry.

    Never raises. A typo in a date must not turn a working endpoint into a
    500: the endpoint still answers, and the announcement is what is lost.
    """
    if not isinstance(entry, dict) or not entry.get('since'):
        return {}
    headers = {}
    try:
        headers['Deprecation'] = f"@{_unix_at(entry['since'])}"
        if entry.get('sunset'):
            headers['Sunset'] = _http_date(entry['sunset'])
    except (TypeError, ValueError) as e:
        logger.error(
            "Malformed deprecation entry (%s); the endpoint still answers but "
            "callers are not being told it is going away: %s", entry, e)
        return {}
    if entry.get('link'):
        headers['Link'] = f'<{entry["link"]}>; rel="deprecation"'
    return headers


def apply_deprecation_headers(app):
    """Announce, on every response, that its endpoint is going away.

    Applied at the app rather than per route: a decorator would have to be
    remembered on the endpoint being deprecated, which is the one moment
    nobody is thinking about the mechanism.
    """
    from flask import request

    @app.after_request
    def _announce(response):
        entry = DEPRECATIONS.get(request.endpoint)
        if entry:
            for name, value in deprecation_headers(entry).items():
                response.headers.setdefault(name, value)
        return response
