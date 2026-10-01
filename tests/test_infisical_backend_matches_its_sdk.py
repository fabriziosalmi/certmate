"""The Infisical backend runs against the SDK it pins, not against a fake that agrees with it (#1054).

The backend imported `infisical`, called `update_secret(secret_name=...)` and read
`secret.secret_name`. The pinned package installs the module `infisical_client`, its client has
`updateSecret(options)`, and its results carry `secret_key`. Every one of those was wrong, and
nothing noticed, because the tests put a fake in `backend._client` that had the backend's names:
the one step that would have failed (importing the SDK) was the one they skipped. So the backend
ran in no release that shipped the pin.

Two layers here, both against the REAL package, which is why this file skips without it and why
the `storage-live` job (the one that installs it) asserts how many tests ran:

* **contract**: every method the backend calls exists on the real client, every options field
  the stub in tests/infisical_sdk_stub.py (which the SDK-free tests use) has exists on the real
  option class, and a result's name is `secret_key`;
* **end to end**: the backend, with no fake, through the real SDK, to a stand-in server
  (tests/infisical_stand_in.py) that speaks what the SDK sends. The stand-in is a SEPARATE PROCESS
  because the SDK's Rust core is called with the GIL held: a server thread in this interpreter
  can never answer it and the call hangs.
"""
import inspect
import json
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

infisical_client = pytest.importorskip('infisical_client')

from modules.core.storage_backends import (  # noqa: E402
    CertificateExistenceUnknown, InfisicalBackend)
from tests.infisical_sdk_stub import OPTION_FIELDS  # noqa: E402

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
FILES = {'cert.pem': b'CERT-PEM', 'chain.pem': b'CHAIN-PEM', 'fullchain.pem': b'FULLCHAIN-PEM',
         'privkey.pem': b'-----BEGIN PRIVATE KEY-----\nTHE-KEY\n-----END PRIVATE KEY-----\n'}


# --------------------------------------------------------------------------
# The contract with the real package
# --------------------------------------------------------------------------

def test_the_module_the_backend_imports_is_the_one_the_package_installs():
    from infisical_client import ClientSettings, InfisicalClient  # noqa: F401
    source = inspect.getsource(InfisicalBackend)
    assert 'from infisical_client import' in source
    assert 'from infisical import' not in source


def test_every_method_the_backend_calls_exists_on_the_real_client():
    called = set(re.findall(r'\bclient\.(\w+)\(', inspect.getsource(InfisicalBackend)))
    assert called, 'the backend calls no client method: this check is not looking at the right thing'
    missing = sorted(name for name in called if not hasattr(infisical_client.InfisicalClient, name))
    assert not missing, f'the backend calls {missing}, which the installed SDK does not have'


def test_the_option_fields_the_tests_assume_exist_on_the_real_option_classes():
    for name, fields in OPTION_FIELDS.items():
        real = getattr(infisical_client, name, None)
        assert real is not None, f'the SDK has no {name}'
        unknown = sorted(set(fields) - set(real.__annotations__))
        assert not unknown, f'{name} has no {unknown} in the installed SDK: the stub in tests/infisical_sdk_stub.py is out of date'


def test_the_fields_the_backend_passes_are_ones_the_options_have():
    """project_id, environment and secret_name/secret_value, which is all `_options` and its callers pass."""
    passed = {'GetSecretOptions': {'project_id', 'environment', 'secret_name'},
              'CreateSecretOptions': {'project_id', 'environment', 'secret_name', 'secret_value'},
              'UpdateSecretOptions': {'project_id', 'environment', 'secret_name', 'secret_value'},
              'DeleteSecretOptions': {'project_id', 'environment', 'secret_name'},
              'ListSecretsOptions': {'project_id', 'environment'}}
    for name, fields in passed.items():
        assert fields <= set(getattr(infisical_client, name).__annotations__), name


def test_a_result_names_its_secret_secret_key_not_secret_name():
    fields = infisical_client.SecretElement.__annotations__
    assert 'secret_key' in fields and 'secret_value' in fields
    assert 'secret_name' not in fields, (
        'the SDK now calls it secret_name: `_list_certificates_attempt` reads secret_key')


# --------------------------------------------------------------------------
# End to end, through the real SDK
# --------------------------------------------------------------------------

def _free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


class StandIn:
    def __init__(self, *extra):
        self.port = _free_port()
        self.process = subprocess.Popen(
            [sys.executable, str(REPO / 'tests' / 'infisical_stand_in.py'), str(self.port), *map(str, extra)],
            cwd=str(REPO), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                self._get('/__state')
                return
            except OSError:
                time.sleep(0.1)
        self.close()
        raise RuntimeError('the Infisical stand-in did not start')

    def _get(self, path):
        with urllib.request.urlopen(f'http://127.0.0.1:{self.port}{path}', timeout=5) as reply:
            return json.loads(reply.read().decode())

    def state(self):
        return self._get('/__state')

    def requests(self):
        return self._get('/__requests')

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=10)


@pytest.fixture
def stand_in():
    server = StandIn()
    yield server
    server.close()


def _backend(port):
    return InfisicalBackend({'client_id': 'cid', 'client_secret': 'csecret', 'project_id': 'proj',
                             'environment': 'prod', 'site_url': f'http://127.0.0.1:{port}'})


def test_a_certificate_stored_through_the_real_sdk_is_what_the_server_holds(stand_in):
    backend = _backend(stand_in.port)
    assert backend.store_certificate('example.com', FILES, {'domain': 'example.com'}) is True

    held = stand_in.state()
    assert set(held) == {'certmate-example.com-cert-pem', 'certmate-example.com-chain-pem',
                         'certmate-example.com-fullchain-pem', 'certmate-example.com-privkey-pem',
                         'certmate-example.com-metadata'}
    assert held['certmate-example.com-privkey-pem'] == FILES['privkey.pem'].decode()
    assert json.loads(held['certmate-example.com-metadata']) == {'domain': 'example.com'}


def test_what_was_stored_comes_back_listed_and_found(stand_in):
    backend = _backend(stand_in.port)
    backend.store_certificate('a.example.com', FILES, {'domain': 'a.example.com'})
    backend.store_certificate('b.example.com', FILES, {'domain': 'b.example.com'})

    files, metadata = backend.retrieve_certificate('a.example.com')
    assert files == FILES and metadata == {'domain': 'a.example.com'}
    assert backend.list_certificates() == ['a.example.com', 'b.example.com']
    assert backend.certificate_exists('a.example.com') is True
    assert backend.certificate_exists('c.example.com') is False


def test_storing_again_replaces_the_secrets_rather_than_failing(stand_in):
    """Update-then-create: the second store finds every name taken, and the server refuses a create over one."""
    backend = _backend(stand_in.port)
    backend.store_certificate('example.com', FILES, {'domain': 'example.com', 'n': 1})
    renewed = dict(FILES, **{'cert.pem': b'RENEWED-CERT'})
    assert backend.store_certificate('example.com', renewed, {'domain': 'example.com', 'n': 2}) is True

    files, metadata = backend.retrieve_certificate('example.com')
    assert files['cert.pem'] == b'RENEWED-CERT' and metadata['n'] == 2
    methods = [r['method'] for r in stand_in.requests() if r['path'].startswith('/api/v3/secrets/raw/')]
    assert 'PATCH' in methods and methods.count('POST') == 5, (
        f'expected five creates (the first store) and updates after: {methods}')


def test_delete_removes_every_secret_it_stored(stand_in):
    backend = _backend(stand_in.port)
    backend.store_certificate('example.com', FILES, {'domain': 'example.com'})
    assert backend.delete_certificate('example.com') is True
    assert stand_in.state() == {}
    assert backend.retrieve_certificate('example.com') is None


def test_a_missing_certificate_is_none_and_not_an_error(stand_in):
    backend = _backend(stand_in.port)
    assert backend.retrieve_certificate('nope.example.com') is None
    assert backend.certificate_exists('nope.example.com') is False


def test_a_server_that_cannot_be_reached_is_unknown_not_absent():
    """Not 'it is not there': the SDK raises the same bare Exception for this as for a missing secret."""
    backend = _backend(_free_port())            # nothing listens
    with pytest.raises(CertificateExistenceUnknown):
        backend.certificate_exists('example.com')


def test_known_limit_the_sdk_follows_a_redirect_and_sends_the_body_on():
    """Pinned as a LIMIT, not as a behaviour to want.

    When the server answers a secret write with 307, the SDK's HTTP client follows it to the
    other host and sends the body, which is the secret value (here a private key). It strips the
    credentials header on the way, and nothing in `ClientSettings` turns the following off, so
    CertMate cannot. What it can do is refuse the network position where a redirect is likely
    (plain HTTP): see `InfisicalBackend._require_https`. If this test starts failing because the
    key no longer arrives, the SDK changed: update the note in docs and remove the limit.
    """
    other = StandIn('--accept-any')              # a host that takes whatever it is sent
    first = StandIn('--redirect-to', other.port)
    try:
        backend = _backend(first.port)
        backend.store_certificate('example.com', FILES, {'domain': 'example.com'})
        arrived = [r for r in other.requests() if r['path'].startswith('/api/v3/secrets/raw/')]
        assert arrived, 'the SDK did not follow the redirect: the limit this test records no longer exists'
        assert all(r['authorization'] == '' for r in arrived), (
            'the credentials header reached the other host: the SDK stopped stripping it on a redirect')
        assert any('THE-KEY' in (r['body'].get('secretValue') or '') for r in arrived), (
            'the private key no longer reaches the redirected host: update the limit in docs/storage')
    finally:
        first.close()
        other.close()
