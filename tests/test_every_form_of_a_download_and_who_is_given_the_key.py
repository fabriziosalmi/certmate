"""Every form a download can be asked in, and who is given the private key.

A certificate's files are served by two routes, and what they serve is chosen
by the request: `file`, `format`, `include_private` and `key_format` in the
query of one, a short name in the path of the other. The role a private key
needs and the scope a restricted key is held to are checked inside those
branches, so a form nobody tried is a branch nobody tried.

The route walk makes one request per route, with no query. Here every
combination is made, by seven callers, and what comes back is opened: a PEM, a
JSON document, a ZIP archive or a PKCS#12 file all count if a private key is in
them.

What must hold, whatever the form:

* with no credentials, nothing is served;
* a viewer is never given a private key, and is given the public files;
* an operator and the owner are given the key in each form that carries one,
  which is the control: a form that served no one would pass the lines above;
* a key restricted to other domains is given nothing at all.
"""
import io
import itertools
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from modules.core import metrics
from tests.test_a_restricted_key_meets_nothing_outside_its_domains import _ordinary_application

pytestmark = [pytest.mark.unit]

PFX_PASSWORD = b'every-form'
KEY = b'PRIVATE KEY'

FILES = (None, 'cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem', 'combined.pem', 'cert.pfx',
         'metadata.json', '../privkey.pem')
FORMATS = (None, 'json', 'pfx', 'zip')
INCLUDE_PRIVATE = (None, '0', '1')
KEY_FORMATS = (None, 'pkcs1')
SHORT_NAMES = ('cert', 'chain', 'fullchain', 'privkey', 'combined', 'pfx', 'cert.pfx', 'privkey.pem', 'metadata')

# The forms that carry a private key, each as (path suffix, query). An operator
# must be given the key in every one of them.
KEY_BEARING = (
    ('', {}),
    ('', {'format': 'json'}),
    ('', {'file': 'privkey.pem'}),
    ('', {'file': 'privkey.pem', 'key_format': 'pkcs1'}),
    ('', {'file': 'combined.pem'}),
    ('', {'file': 'cert.pfx'}),
    ('/privkey', {}),
    ('/combined', {}),
)


def _carries_a_key(response):
    """Whether a private key is anywhere in an answer, in whatever container."""
    if response.status_code != 200:
        return False
    data = response.get_data()
    if KEY in data:
        return True
    if data[:2] == b'PK':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return any(KEY in archive.read(name) for name in archive.namelist())
    try:
        key, _cert, _more = pkcs12.load_key_and_certificates(data, PFX_PASSWORD)
    except ValueError:
        return False
    return key is not None


def _forms():
    for chosen in itertools.product(FILES, FORMATS, INCLUDE_PRIVATE, KEY_FORMATS):
        query = {name: value for name, value in zip(('file', 'format', 'include_private', 'key_format'), chosen, strict=True)
                 if value is not None}
        yield '', query
    for short, key_format in itertools.product(SHORT_NAMES, KEY_FORMATS):
        yield f'/{short}', ({'key_format': key_format} if key_format else {})


@pytest.fixture(scope='module')
def asked(tmp_path_factory):
    """Every form, asked by every caller: {caller: [(suffix, query, status, carries a key)]}."""
    tmp = tmp_path_factory.mktemp('every-form')
    try:
        with _ordinary_application(tmp) as (sweep, _app, _certbot):
            domain = sweep.world.domain
            held = tmp / 'certs' / domain
            # The two files an issuance may leave beside the four PEMs, so that
            # the forms that serve them have something to serve.
            key_pem = (held / 'privkey.pem').read_bytes()
            (held / 'combined.pem').write_bytes((held / 'fullchain.pem').read_bytes() + key_pem)
            (held / 'cert.pfx').write_bytes(pkcs12.serialize_key_and_certificates(
                b'every-form', serialization.load_pem_private_key(key_pem, None),
                x509.load_pem_x509_certificate((held / 'cert.pem').read_bytes()), None,
                serialization.BestAvailableEncryption(PFX_PASSWORD)))

            auth = sweep.container.managers['auth']
            callers = {'anonymous': {}, 'owner': {'Authorization': f'Bearer {sweep.token}'}}
            for role in ('viewer', 'operator'):
                ok, made = auth.create_api_key(f'unrestricted-{role}', role=role)
                assert ok, made
                callers[role] = {'Authorization': f"Bearer {made['token']}"}
            for who, credentials in sweep._keys().items():
                callers[f'restricted {who}'] = credentials

            answers = {who: [] for who in callers}
            for suffix, query in _forms():
                for who, credentials in callers.items():
                    sweep.forget_the_rate()
                    response = sweep.admin.get(f'/api/certificates/{domain}/download{suffix}',
                                               headers=credentials, query_string=query)
                    answers[who].append((suffix, query, response.status_code, _carries_a_key(response)))
                    response.close()
            yield answers
    finally:
        metrics.metrics_collector.last_collection = 0


def _given_a_key(answers):
    return [(suffix, query) for suffix, query, _status, key in answers if key]


def test_every_form_was_asked(asked):
    """CONTROL: the matrix is the size it claims, for each caller."""
    expected = len(FILES) * len(FORMATS) * len(INCLUDE_PRIVATE) * len(KEY_FORMATS) + len(SHORT_NAMES) * len(KEY_FORMATS)
    assert expected > 200
    assert {who: len(answers) for who, answers in asked.items()} == dict.fromkeys(asked, expected)
    assert len(asked) == 7


def test_nothing_is_served_without_credentials(asked):
    assert {status for _suffix, _query, status, _key in asked['anonymous']} == {401}


def test_a_viewer_is_never_given_a_private_key(asked):
    assert _given_a_key(asked['viewer']) == []
    # CONTROL: it is a caller the routes do serve.
    served = [(suffix, query) for suffix, query, status, _key in asked['viewer'] if status == 200]
    assert ('/fullchain', {}) in served and ('', {'include_private': '0'}) in served, served


@pytest.mark.parametrize('who', ['operator', 'owner'])
def test_the_key_is_in_each_form_that_carries_one(asked, who):
    """CONTROL: these are the forms the lines about a viewer and a restricted
    key are about. One that served nobody would let them pass."""
    given = _given_a_key(asked[who])
    missing = [form for form in KEY_BEARING if form not in given]
    assert missing == [], f'{who} is not given the key by {missing}'


@pytest.mark.parametrize('who', ['restricted viewer', 'restricted operator', 'restricted stored-admin'])
def test_a_key_restricted_to_other_domains_is_given_nothing(asked, who):
    served = [(suffix, query, status) for suffix, query, status, _key in asked[who] if status < 400]
    assert served == [], f'{who} was served {served[:5]}'
    # 400 is for a request that names no file the routes know; everything else is the refusal.
    assert {status for _suffix, _query, status, _key in asked[who]} <= {400, 403}
    refused = sum(status == 403 for _suffix, _query, status, _key in asked[who])
    assert refused > 190, refused
