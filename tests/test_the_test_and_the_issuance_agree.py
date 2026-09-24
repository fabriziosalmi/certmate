"""The CA connection test refuses what issuance refuses, before fetching it.

The https-only rule for ACME directories lives in `acme_directory_refusal` and
is applied by `validate_ca_configuration`, which issuance and the Sectigo
branch of `POST /api/settings/test-ca-provider` both call. The **private_ca**
branch of that endpoint did not: it had its own
`startswith('http://') or startswith('https://')` check, written before the
rule existed, and then fetched the URL.

Measured against a reachable `http://` directory:

    private_ca, http:// reachable -> success=True, "ACME endpoint appears valid"
    private_ca, http:// issuance  -> refused, "must use https"

So an operator pressed **Test CA Connection**, saw green, saved, and had every
issuance fail — and the test had gone and fetched the directory in cleartext to
tell them so.

The asymmetry is ours rather than a defect that arrived: the rule was added to
`validate_ca_configuration` and this branch kept the check it already had. It
goes through the one helper now, and the refusal happens **before** any
request, which is the half that stops the cleartext fetch rather than merely
disagreeing about it afterwards.
"""
import pathlib
import secrets

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
TOKEN = secrets.token_urlsafe(32)


@pytest.fixture(scope='module')
def client(tmp_path_factory):
    import os

    tmp_path = tmp_path_factory.mktemp('ca-test-endpoint')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp_path / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', TOKEN)
        os.environ['API_BEARER_TOKEN'] = TOKEN
        from modules.core.factory import create_app
        application, _ = create_app()
        yield application.test_client()


def _test_ca(client, url):
    return client.post(
        '/api/settings/test-ca-provider',
        json={'ca_provider': 'private_ca',
              'config': {'acme_url': url, 'email': 'ops@example.com'}},
        headers={'Authorization': f'Bearer {TOKEN}', 'Origin': 'http://localhost'},
    ).get_json() or {}


def test_the_endpoint_is_reachable(client):
    """Guard the guard: a 401 or a 404 would make every refusal below pass
    for the wrong reason."""
    body = _test_ca(client, 'https://acme.internal/directory')
    assert 'ca_provider' in body or 'success' in body, body


@pytest.mark.parametrize('url', [
    'http://acme.internal/directory',
    'HTTP://acme.internal/directory',      # RFC 3986: still plain HTTP
    'http://127.0.0.1/directory',          # loopback looks safe and is not https
])
def test_plain_http_is_refused_by_the_test_too(client, url):
    body = _test_ca(client, url)
    assert body.get('success') is False, body
    assert 'https' in (body.get('message') or '').lower(), body


def test_the_refusal_happens_before_any_request(client, monkeypatch):
    """The half that matters beyond consistency. Refusing after the fetch
    would still have sent the request, which is what made this more than a
    disagreement about wording."""
    import requests

    called = []
    monkeypatch.setattr(requests, 'get',
                        lambda *a, **k: called.append(a) or (_ for _ in ()).throw(
                            AssertionError('fetched')))

    body = _test_ca(client, 'http://acme.internal/directory')
    assert body.get('success') is False
    assert not called, 'the directory was fetched before being refused'


def test_something_that_is_not_a_url_is_refused_as_malformed(client):
    """Kept distinct from plain HTTP: an operator who typed nonsense needs to
    be told the format is wrong, not to use https."""
    body = _test_ca(client, 'not-a-url')
    assert body.get('success') is False
    message = (body.get('message') or '').lower()
    assert 'format' in message and 'https' not in message, body


def test_the_test_and_the_issuance_use_one_rule():
    """Read from the source. Two spellings of this rule is how they came
    apart in the first place — the endpoint kept a `startswith` check written
    before `acme_directory_refusal` existed."""
    endpoint = (REPO / 'modules' / 'api' / 'resources_ca.py').read_text(
        encoding='utf-8')
    assert 'acme_directory_refusal' in endpoint
    assert "startswith('http://')" not in endpoint, (
        'the endpoint checks the scheme itself again'
    )


def test_https_is_still_accepted_far_enough_to_try(client):
    """The rule must refuse http without refusing the thing the endpoint is
    for. An https URL gets past this check and fails later on reachability,
    which is a different answer."""
    body = _test_ca(client, 'https://acme.internal.invalid/directory')
    message = (body.get('message') or '').lower()
    assert 'must use https' not in message, body
