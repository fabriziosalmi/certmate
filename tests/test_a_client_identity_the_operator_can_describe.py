"""Seven client-certificate defects, found by the certmate-website session.

Every one of them reproduced against v2.35.0.

* **`generate_key: false` could never succeed.** The core has taken `csr_pem`
  since #599; the request model had no field for it, so the only answer was
  "CSR required when generate_key=False" — and the UI's "Generate private key"
  checkbox posts exactly that when unticked.
* **Every issued identity claimed to be Swiss.** `country="CH"`,
  `state="Switzerland"` were literals at the CSR call, with no override.
* **The batch dropped `organizational_unit`.** It was parsed out of the CSV
  and then not passed, so every row fell back to "Users" while every other
  column came through — silently, for the whole batch.
* **Nothing served `ca.crt`.** Two comments in private_ca.py justify the 0600
  file mode by saying the CA cert "is served over HTTP by certmate"; the only
  `/ca` route in the url_map was `POST /ca/reset`.
* **`client_ca_subject` was rejected by `POST /api/settings`**, which
  docs/api.md has told operators to use since contract 2.3.
* **`notBefore` was stamped at exactly "now"**, so a relying party whose clock
  is a second fast rejects a certificate the instant it is issued.
* **docs/architecture.md claimed the EKU is serverAuth+clientAuth.** The code
  issues clientAuth only, and it is right to: a client certificate should not
  carry serverAuth. That one is a documentation fix.
"""
import datetime
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    return ClientCertificateManager(tmp_path / 'clients', ca)


def _subject(manager, **kwargs):
    from cryptography import x509

    params = {'common_name': 'alice.example.com', 'organization': 'Acme SpA',
              'organizational_unit': 'Engineering'}
    params.update(kwargs)
    ok, err, data = manager.create_client_certificate(**params)
    assert ok, err
    identifier = data['identifier']
    pem = (manager._get_cert_subdir(params.get('cert_usage', 'api-mtls'))
           / identifier / f'{identifier}.crt').read_bytes()
    return x509.load_pem_x509_certificate(pem)


# --- the subject an operator can set --------------------------------------

def test_the_country_is_the_one_the_caller_asked_for(manager):
    """THE regression: it was the literal "CH" for everyone, everywhere."""
    from cryptography.x509.oid import NameOID

    cert = _subject(manager, country='IT', state='Lazio')

    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == 'IT'
    assert cert.subject.get_attributes_for_oid(
        NameOID.STATE_OR_PROVINCE_NAME)[0].value == 'Lazio'


def test_an_instance_that_asks_for_nothing_gets_what_it_always_got(manager):
    """CONTROL, and the reason the default was NOT changed to "omit": a DN
    that changes on upgrade stops matching the mTLS allowlists and per-DN
    rules the previous cohort matches."""
    from cryptography.x509.oid import NameOID

    cert = _subject(manager)

    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == 'CH'
    assert cert.subject.get_attributes_for_oid(
        NameOID.STATE_OR_PROVINCE_NAME)[0].value == 'Switzerland'


def test_the_defaults_are_named_once():
    """They were two literals inside a function call. A default worth
    preserving is worth being able to find."""
    from modules.core import client_certificates

    assert client_certificates.DEFAULT_COUNTRY == 'CH'
    assert client_certificates.DEFAULT_STATE == 'Switzerland'


# --- notBefore ------------------------------------------------------------

def test_a_certificate_is_valid_the_moment_it_is_issued(manager):
    """It was `datetime.now(utc)` exactly, so any relying party running a
    second fast rejected a just-issued identity as not-yet-valid."""
    cert = _subject(manager)
    now = datetime.datetime.now(datetime.timezone.utc)

    assert cert.not_valid_before_utc < now - datetime.timedelta(minutes=1)


def test_the_ca_is_backdated_too(tmp_path):
    """The one that matters most on a fresh install: a CA that is not yet
    valid invalidates every certificate under it."""
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    now = datetime.datetime.now(datetime.timezone.utc)

    assert ca._ca_cert.not_valid_before_utc < now - datetime.timedelta(minutes=1)


def test_the_validity_window_did_not_shrink(manager):
    """CONTROL. Backdating must widen the window, not slide it: a 365-day
    certificate must still be good for 365 days from now."""
    cert = _subject(manager, days_valid=365)
    now = datetime.datetime.now(datetime.timezone.utc)

    assert cert.not_valid_after_utc > now + datetime.timedelta(days=364)


# --- the batch path -------------------------------------------------------

def test_the_batch_and_the_single_path_build_the_same_subject():
    """`organizational_unit` was the only column the batch dropped."""
    import ast
    import inspect

    from modules.api import client_certificates as api_module

    source = inspect.getsource(api_module)
    calls = [node for node in ast.walk(ast.parse(source))
             if isinstance(node, ast.Call)
             and 'create_client_certificate' in ast.unparse(node.func)]

    batch = [ast.unparse(c) for c in calls
             if any(kw.arg == 'cert_usage' for kw in c.keywords)]
    assert batch, 'the batch call was not found — this test reads nothing'
    for call in batch:
        assert 'organizational_unit' in call, (
            f'the batch still drops the OU it parsed: {call}')


# --- the CA certificate is reachable --------------------------------------

def test_there_is_a_route_that_serves_the_ca():
    """The comments in private_ca.py said there was. There was not."""
    # Read from the repo, not from `factory.__file__`: the suite has bitten
    # this project before with a module path that is not the source file.
    source = (REPO / 'modules' / 'core' / 'factory.py').read_text(encoding='utf-8')

    assert "'ClientCertificateAuthorityCert'], '/ca')" in source


def test_the_resource_reads_the_ca_through_the_manager():
    import inspect

    from modules.api.client_certificates import _build_ca_cert_resource

    source = inspect.getsource(_build_ca_cert_resource)

    assert 'private_ca.get_ca_cert_pem()' in source
    assert 'ca.crt' in source


def test_it_serves_the_certificate_and_not_the_key(manager):
    """CONTROL on the one thing this endpoint must never do."""
    pem = manager.private_ca.get_ca_cert_pem()
    text = pem.decode() if isinstance(pem, bytes) else pem

    assert 'BEGIN CERTIFICATE' in text
    assert 'PRIVATE KEY' not in text


# --- the documented settings key is writable ------------------------------

def test_the_ca_subject_can_be_set_the_way_the_docs_say():
    """docs/api.md has said since contract 2.3 that the subject "comes from
    client_ca_subject in settings". POST /api/settings answered 400 "Unknown
    fields in payload"."""
    from modules.core.settings import PUBLIC_SETTINGS_WRITABLE_KEYS

    assert 'client_ca_subject' in PUBLIC_SETTINGS_WRITABLE_KEYS


def test_the_docs_say_when_it_takes_effect():
    """It is read when the CA is generated. A key that can be written and
    appears to do nothing is the next question this answers in advance."""
    page = (REPO / 'docs' / 'api.md').read_text(encoding='utf-8')

    assert 'POST /api/settings' in page
    assert 'when the CA is created and never again' in page


# --- the documented EKU is the issued one ---------------------------------

def test_the_architecture_page_lists_the_eku_the_code_issues(manager):
    from cryptography.x509.oid import ExtensionOID

    cert = _subject(manager)
    eku = cert.extensions.get_extension_for_oid(
        ExtensionOID.EXTENDED_KEY_USAGE).value
    names = [usage._name for usage in eku]

    assert names == ['clientAuth']
    page = (REPO / 'docs' / 'architecture.md').read_text(encoding='utf-8')
    assert '"extended_key_usage": ["serverAuth", "clientAuth"]' not in page


# --- a CSR can be sent ----------------------------------------------------

def test_the_request_model_has_somewhere_to_put_a_csr():
    """Without it `generate_key: false` was a guaranteed 400 and the UI
    checkbox was a button that only produced an error."""
    import inspect

    from modules.api import client_certificates as api_module

    source = inspect.getsource(api_module)

    assert "'csr': fields.String(" in source


def test_the_parameters_helper_passes_the_csr_through():
    from modules.api.client_certificates import _client_cert_create_params

    params = _client_cert_create_params({
        'common_name': 'bob', 'generate_key': False,
        'csr': '-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----'})

    assert params['generate_key'] is False
    assert params['csr_pem'].startswith(b'-----BEGIN CERTIFICATE REQUEST-----')


def test_a_request_without_a_key_and_without_a_csr_is_refused():
    """CONTROL, and a better error than the old one: it names the field that
    is missing rather than a flag the caller did set."""
    from werkzeug.exceptions import HTTPException

    from modules.api.client_certificates import _client_cert_create_params

    with pytest.raises(HTTPException) as excinfo:
        _client_cert_create_params({'common_name': 'bob', 'generate_key': False})

    assert excinfo.value.code == 400
    assert 'csr is required' in str(excinfo.value.data.get('message', ''))


def test_the_form_offers_the_field_the_checkbox_needs():
    panel = (REPO / 'templates' / 'partials' /
             '_client_create.html').read_text(encoding='utf-8')
    script = (REPO / 'static' / 'js' / 'client-certs.js').read_text(encoding='utf-8')

    assert 'csrPem' in panel
    assert 'data.csr' in script


# --- the probe says whether it could read the chain ----------------------

def test_a_leaf_only_chain_says_so():
    """`get_unverified_chain()` is not available on the runtime in the image,
    so `chain` is ALWAYS one entry there — which is exactly what a server
    omitting its intermediate looks like. A discovery report reading it as
    "no intermediate served" would be wrong on every host.
    """
    from modules.core.cert_probe import probe_certificate

    result = probe_certificate('localhost', 1, timeout=1)

    assert 'chain_available' in result, (
        'the probe result cannot say whether the chain was readable')
    assert result['chain_available'] is False


def test_every_shape_of_probe_result_carries_the_field():
    """It is answered on the error paths too, so a caller never has to guess
    whether the key is missing or the chain was unreadable."""
    import ast
    import inspect

    from modules.core import cert_probe

    tree = ast.parse(inspect.getsource(cert_probe))
    results = [node for node in ast.walk(tree)
               if isinstance(node, ast.Dict)
               and any(isinstance(k, ast.Constant) and k.value == 'chain'
                       for k in node.keys if k is not None)]

    assert results, 'no probe result dict found — this test reads nothing'
    for node in results:
        keys = {k.value for k in node.keys
                if isinstance(k, ast.Constant)}
        assert 'chain_available' in keys, (
            f'a probe result carries `chain` without `chain_available`: '
            f'{sorted(keys)}')
