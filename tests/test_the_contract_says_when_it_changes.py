"""A client needs a version that moves when the interface does, and not before.

The only version a caller could read was the release number — in the Swagger
document and in `/health`. It moves on every patch whether or not anything a
caller depends on moved with it, so it cannot answer *"will my client still
work"*. A client that pinned it would refuse a patch that changed nothing; one
that ignored it had nothing else to read.

`API_CONTRACT_VERSION` is that other thing. It is sent on **every** response as
`X-CertMate-API-Version` — a header rather than only a field, so a client learns
it from any response including the error it is trying to understand, without a
second call — and reported by `/health` as `api_contract_version` for anything
that already polls there.

The rule is written where the constant is: **minor** when the surface grows in
a way a caller can ignore, **major** when something a caller may depend on goes
away or changes meaning. Deprecating does neither — that is the point of
deprecating rather than removing.

Which is the second half. There was no deprecation mechanism at all: no
`Deprecation` header, no `Sunset`, no marker. So an endpoint could be removed
abruptly, with a 404 as the first notice, or kept forever because removing it
was the only alternative.

`DEPRECATIONS` is empty, and that is the honest state — nothing is deprecated
today. The mechanism ships before it is needed on purpose: the alternative is
inventing it under time pressure in the release where something has to go,
which is the release where it gets skipped. These tests exercise it against an
example entry so it stays tested while nothing uses it.
"""
import datetime
import pathlib

import pytest
from flask import Flask

from modules.api.deprecation import (
    DEPRECATIONS, apply_deprecation_headers, deprecation_headers,
)
from modules.core.constants import API_CONTRACT_VERSION

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent

EXAMPLE = {
    'since': '2026-09-08',
    'sunset': '2027-03-08',
    'link': 'https://example.invalid/docs/api.md#certificates',
    'note': 'Use GET /api/v2/certificates.',
}


# --- the contract version ------------------------------------------------

def test_it_is_not_the_release_number():
    """The whole point. If these were the same value, the new one would move
    on every patch and answer nothing the old one did not."""
    from modules import __version__
    assert API_CONTRACT_VERSION != __version__


def test_it_looks_like_a_two_part_version():
    major, _, minor = API_CONTRACT_VERSION.partition('.')
    assert major.isdigit() and minor.isdigit(), (
        f'{API_CONTRACT_VERSION!r} is not major.minor, so "bump the major" is '
        f'not an instruction anyone can follow'
    )


def test_the_rule_for_bumping_it_is_written_down():
    """A version with no stated rule is a number that drifts. The rule lives
    beside the constant, where the next person to change the surface is."""
    source = (REPO / 'modules' / 'core' / 'constants.py').read_text()
    block = source.split('API_CONTRACT_VERSION')[0][-2000:]
    for expected in ('MINOR', 'MAJOR', 'endpoint removed'):
        assert expected in block, (
            f'the constant does not say what a {expected} bump means'
        )


def test_every_response_carries_it(app_client):
    response = app_client.get('/health')
    assert response.headers['X-CertMate-API-Version'] == API_CONTRACT_VERSION


def test_an_error_response_carries_it_too(app_client):
    """The case a header buys over a field: a client trying to understand a
    failure learns which interface produced it, without a second call."""
    response = app_client.get('/no-such-route-at-all')
    assert response.status_code == 404
    assert response.headers['X-CertMate-API-Version'] == API_CONTRACT_VERSION


def test_health_reports_it_as_a_field(app_client):
    body = app_client.get('/health').get_json()
    assert body['api_contract_version'] == API_CONTRACT_VERSION
    assert body['version'] != body['api_contract_version'], (
        'health reports the same number twice, so one of them is redundant'
    )


# --- deprecation ---------------------------------------------------------

def test_nothing_is_deprecated_today():
    """The honest state, asserted so that adding an entry is a deliberate act
    that shows up in a diff next to this line."""
    assert DEPRECATIONS == {}


def test_the_headers_follow_the_specs():
    headers = deprecation_headers(EXAMPLE)

    # RFC 9745: an @-prefixed unix timestamp, not a date string.
    assert headers['Deprecation'] == '@%d' % int(
        datetime.datetime(2026, 9, 8, tzinfo=datetime.timezone.utc).timestamp())
    # RFC 8594: an HTTP-date.
    assert headers['Sunset'] == 'Mon, 08 Mar 2027 00:00:00 GMT'
    assert headers['Link'] == (
        '<https://example.invalid/docs/api.md#certificates>; '
        'rel="deprecation"')


def test_a_deprecation_without_a_sunset_still_announces_itself():
    """Not every deprecation has a removal date yet, and saying "this is going
    away" is worth more than saying nothing until the date is chosen."""
    headers = deprecation_headers({'since': '2026-09-08'})
    assert 'Deprecation' in headers
    assert 'Sunset' not in headers


@pytest.mark.parametrize('entry', [
    {}, None, 'a string', {'sunset': '2027-03-08'},          # no `since`
    {'since': 'not-a-date'},
    {'since': '2026-09-08', 'sunset': 'whenever'},
])
def test_a_malformed_entry_produces_no_headers_rather_than_an_error(entry):
    """CONTROL, and the one that matters: a typo in a date must not turn a
    working endpoint into a 500. The endpoint still answers; what is lost is
    the announcement."""
    assert deprecation_headers(entry) == {}


def test_a_deprecated_endpoint_announces_itself(monkeypatch):
    app = Flask(__name__)

    @app.route('/old')
    def old_thing():
        return {'ok': True}

    monkeypatch.setitem(DEPRECATIONS, 'old_thing', EXAMPLE)
    apply_deprecation_headers(app)

    response = app.test_client().get('/old')
    assert response.status_code == 200, 'deprecated is not gone'
    assert response.headers['Deprecation'].startswith('@')
    assert response.headers['Sunset']


def test_an_endpoint_that_is_not_deprecated_says_nothing(monkeypatch):
    """CONTROL: a Deprecation header on every response would train clients to
    ignore it."""
    app = Flask(__name__)

    @app.route('/current')
    def current_thing():
        return {'ok': True}

    monkeypatch.setitem(DEPRECATIONS, 'something_else', EXAMPLE)
    apply_deprecation_headers(app)

    response = app.test_client().get('/current')
    assert 'Deprecation' not in response.headers
    assert 'Sunset' not in response.headers


# --- the app under test --------------------------------------------------

@pytest.fixture(scope='module')
def app_client():
    import tempfile
    root = pathlib.Path(tempfile.mkdtemp()) / 'certmate'
    module_dir = root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    anchor = module_dir / 'factory.py'
    anchor.write_text('# test path anchor\n')
    for shared in ('templates', 'static'):
        source = REPO / shared
        if source.is_dir():
            (root / shared).symlink_to(source)

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('TESTING', 'true')
        patch.setenv('FLASK_ENV', 'testing')
        patch.setattr('modules.core.factory.__file__', str(anchor))
        from modules.core.factory import create_app
        app, _ = create_app()
    return app.test_client()
