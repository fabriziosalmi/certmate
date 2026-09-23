"""`POST /api/probe`: what is this host serving, right now.

CertMate could probe what its discovery configuration named, and could compare
a managed domain against what is deployed. It could not answer "read the
certificate at this host" for a host nobody had configured — so every tool
around it that wanted that answer reimplemented the probe, and at least one
reported a revocation status it had assumed rather than checked.

This is the endpoint that answers it: the same deep probe and the same verified
revocation the inventory uses, pointed at a host in the request. It describes
the certificate without trusting it, and it refuses what it must not do —
probe outside a scoped key's domains, or reach a private address.
"""
import secrets

import pytest

pytestmark = [pytest.mark.unit]


@pytest.fixture
def probe_app(tmp_path, monkeypatch):
    from modules.core.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    application, container = create_app()
    application.admin = {'Authorization': f'Bearer {token}'}
    return application, container


def _probe(application, body, headers=None):
    return application.test_client().post(
        '/api/probe', headers=headers or application.admin, json=body)


# --------------------------------------------------------------------------- #
# What it refuses
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('body, field', [
    ({}, 'host'),
    ({'host': ''}, 'host'),
    ({'host': '   '}, 'host'),
    ({'host': 7}, 'host'),
    ({'host': 'example.com', 'port': 0}, 'port'),
    ({'host': 'example.com', 'port': 70000}, 'port'),
    ({'host': 'example.com', 'port': '443'}, 'port'),
    ({'host': 'example.com', 'port': True}, 'port'),
    ({'host': 'example.com', 'server_name': 5}, 'server_name'),
    ({'host': 'example.com', 'check_revocation': 'false'}, 'check_revocation'),
])
def test_bad_input_is_refused_with_a_code(probe_app, body, field):
    application, _container = probe_app
    response = _probe(application, body)
    assert response.status_code == 400, response.get_json()
    payload = response.get_json()
    assert payload['code'] == 'INVALID_REQUEST'
    assert field in payload['error']


def test_a_private_address_is_refused_by_the_probe_itself(probe_app):
    """The SSRF guard the inventory sweep already has. It answers rather than
    raising, so the caller learns the target was refused, not that CertMate
    broke."""
    application, _container = probe_app
    response = _probe(application, {'host': '127.0.0.1', 'check_revocation': False})
    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'blocked'
    assert 'SSRF guard' in body['error']
    assert body['certificate'] is None


def test_an_unresolvable_host_is_a_status_not_an_error(probe_app):
    application, _container = probe_app
    body = _probe(application, {'host': 'nothing-here.invalid',
                                'check_revocation': False}).get_json()
    assert body['status'] == 'unreachable'
    assert body['error_class'] == 'dns_error'


# --------------------------------------------------------------------------- #
# The scope boundary
# --------------------------------------------------------------------------- #

def _scoped_key(application, domains, role='viewer'):
    created = application.test_client().post('/api/keys', headers=application.admin, json={
        'name': f'scoped-{secrets.token_hex(3)}', 'role': role, 'allowed_domains': domains})
    assert created.status_code in (200, 201), created.get_json()
    return {'Authorization': f'Bearer {created.get_json()["token"]}'}


def test_a_scoped_key_cannot_probe_outside_its_scope(probe_app):
    application, _container = probe_app
    scoped = _scoped_key(application, ['*.tenant-a.example'])
    refused = _probe(application, {'host': 'other.example.com'}, headers=scoped)
    assert refused.status_code == 403
    assert refused.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'


def test_the_sni_name_is_inside_the_boundary_too(probe_app):
    """server_name is what the probe asks the host for, so a scoped key must
    not be able to name someone else's host there."""
    application, _container = probe_app
    scoped = _scoped_key(application, ['*.tenant-a.example'])
    refused = _probe(application, {'host': 'app.tenant-a.example',
                                   'server_name': 'other.example.com'}, headers=scoped)
    assert refused.status_code == 403
    assert refused.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'


def test_a_scoped_key_may_probe_its_own(probe_app):
    application, _container = probe_app
    scoped = _scoped_key(application, ['*.tenant-a.example'])
    allowed = _probe(application, {'host': 'app.tenant-a.example',
                                   'check_revocation': False}, headers=scoped)
    # It does not resolve — the point is that scope let it through to the probe.
    assert allowed.status_code == 200
    assert allowed.get_json()['status'] == 'unreachable'


def test_it_is_rate_limited_as_its_own_category():
    """Each probe opens a TLS connection to a third party and may fetch that
    CA's OCSP or CRL: it does not belong in the generic bucket."""
    from modules.core.rate_limit import RateLimitConfig
    assert RateLimitConfig.DEFAULT_LIMITS['probe'] < RateLimitConfig.DEFAULT_LIMITS['default']


# --------------------------------------------------------------------------- #
# Against a real host
# --------------------------------------------------------------------------- #

@pytest.mark.network
def test_a_live_host_is_described_with_its_revocation(probe_app):
    """The answer another tool consumes: the certificate, the chain, the
    hostname match, and a revocation status that was checked rather than
    assumed."""
    application, _container = probe_app
    body = _probe(application, {'host': 'letsencrypt.org'}).get_json()
    assert body['status'] == 'ok'
    certificate = body['certificate']
    assert certificate['subject_cn']
    assert certificate['fingerprint_sha256']
    assert certificate['days_until_expiry'] > 0
    assert body['validation']['hostname_match'] is True
    assert body['chain']
    assert body['revocation']['status'] in ('good', 'unknown', 'unavailable')
    assert body['revocation']['method'] in ('ocsp', 'crl', None)


@pytest.mark.network
def test_a_revoked_certificate_is_reported_as_revoked(probe_app):
    application, _container = probe_app
    body = _probe(application, {'host': 'revoked.badssl.com'}).get_json()
    assert body['status'] == 'ok'
    assert body['revocation']['status'] == 'revoked'


@pytest.mark.network
def test_revocation_can_be_left_out(probe_app):
    """A caller that only wants the certificate does not pay for the CA
    round-trip, and gets None rather than a guess."""
    application, _container = probe_app
    body = _probe(application, {'host': 'letsencrypt.org', 'check_revocation': False}).get_json()
    assert body['status'] == 'ok'
    assert body['revocation'] is None


# --------------------------------------------------------------------------- #
# The client another tool will use
# --------------------------------------------------------------------------- #

def test_the_sdk_asks_the_endpoint_the_way_it_expects():
    """Read from the source, not by importing: the SDK is only installed in
    the jobs that exercise the clients, and importorskip here would be a check
    that quietly does not run.

    What matters is that the SDK sends the body this endpoint documents, and
    validates the boolean before the request rather than coercing it — the
    trap #863 is about.
    """
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent
              / 'clients' / 'certmate-sdk' / 'certmate' / 'client.py').read_text(encoding='utf-8')
    assert 'def probe(' in source
    assert '"POST", "/api/probe"' in source
    assert 'self._require_bool("check_revocation", check_revocation)' in source
