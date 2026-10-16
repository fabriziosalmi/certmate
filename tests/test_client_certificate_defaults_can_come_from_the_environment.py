"""The country and state of a client certificate default to the deployment's.

`DEFAULT_COUNTRY = "CH"` and `DEFAULT_STATE = "Switzerland"` are kept as the
answer when nothing is said, so an existing install keeps matching the mTLS
allowlists its earlier certificates match (see
tests/test_a_client_identity_the_operator_can_describe.py). But they were also
the only answer for every certificate issued without a country: the create
endpoint when the request leaves it out, every CSV batch row, and every
renewal — which re-issues from metadata that records neither field. An
organisation outside Switzerland had to send `country` and `state` on every
request, and still got `C=CH` back on the first renewal.

`CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY` and `CERTMATE_CLIENT_CERT_DEFAULT_STATE`
replace the default without replacing the rule:

* nothing set issues exactly what it always issued (the control);
* a value in the request still wins over the environment;
* the default is read when a certificate is issued, not when the module was
  imported — a default argument would have frozen it at import;
* a country no certificate can carry stops the instance at boot, naming the
  variable, instead of failing the next issuance or a renewal at night.
"""
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from modules.core.client_certificates import (
    DEFAULT_COUNTRY,
    DEFAULT_STATE,
    check_client_certificate_defaults,
    default_client_country,
    default_client_state,
)

pytestmark = [pytest.mark.unit]

COUNTRY = 'CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY'
STATE = 'CERTMATE_CLIENT_CERT_DEFAULT_STATE'


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv(COUNTRY, raising=False)
    monkeypatch.delenv(STATE, raising=False)


@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    return ClientCertificateManager(tmp_path / 'clients', ca)


def _issued(manager, identifier, usage='api-mtls'):
    pem = (manager._get_cert_subdir(usage) / identifier / f'{identifier}.crt').read_bytes()
    return x509.load_pem_x509_certificate(pem)


def _create(manager, **kwargs):
    params = {'common_name': 'alice.example.com', 'organization': 'Acme SL'}
    params.update(kwargs)
    ok, err, data = manager.create_client_certificate(**params)
    assert ok, err
    return data['identifier']


def _c_and_st(cert):
    return (cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value,
            cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value)


# --- the defaults themselves ---------------------------------------------

def test_with_nothing_set_the_defaults_are_what_they_always_were():
    """CONTROL."""
    assert default_client_country() == DEFAULT_COUNTRY == 'CH'
    assert default_client_state() == DEFAULT_STATE == 'Switzerland'


def test_the_environment_replaces_them(monkeypatch):
    monkeypatch.setenv(COUNTRY, 'ES')
    monkeypatch.setenv(STATE, 'Madrid')

    assert default_client_country() == 'ES'
    assert default_client_state() == 'Madrid'


def test_a_lower_case_country_is_the_same_country(monkeypatch):
    """`es` is what people type; X.509 C is written upper-case."""
    monkeypatch.setenv(COUNTRY, ' es ')

    assert default_client_country() == 'ES'


def test_an_empty_value_is_not_a_country(monkeypatch):
    """`CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY=` in a compose file is an unset
    variable, not a request for an empty attribute."""
    monkeypatch.setenv(COUNTRY, '  ')
    monkeypatch.setenv(STATE, '')

    assert default_client_country() == 'CH'
    assert default_client_state() == 'Switzerland'


# --- what gets issued ----------------------------------------------------

def test_a_certificate_issued_without_a_country_carries_the_declared_one(manager, monkeypatch):
    monkeypatch.setenv(COUNTRY, 'ES')
    monkeypatch.setenv(STATE, 'Madrid')

    assert _c_and_st(_issued(manager, _create(manager))) == ('ES', 'Madrid')


def test_the_default_is_read_when_issuing_not_when_imported(manager, monkeypatch):
    """The manager, and the module, existed before the variable was set. With
    the default in the function signature this was 'CH' regardless."""
    first = _create(manager)
    monkeypatch.setenv(COUNTRY, 'PT')
    second = _create(manager, common_name='bob.example.com')

    assert _c_and_st(_issued(manager, first))[0] == 'CH'
    assert _c_and_st(_issued(manager, second))[0] == 'PT'


def test_a_country_in_the_request_still_wins(manager, monkeypatch):
    monkeypatch.setenv(COUNTRY, 'ES')
    monkeypatch.setenv(STATE, 'Madrid')

    identifier = _create(manager, country='IT', state='Lazio')

    assert _c_and_st(_issued(manager, identifier)) == ('IT', 'Lazio')


def test_a_renewal_gets_the_declared_default_and_not_switzerland(manager, monkeypatch):
    """Renewal re-issues from metadata that does not record C or ST, so it
    always took the default. The default is now the deployment's."""
    monkeypatch.setenv(COUNTRY, 'ES')
    monkeypatch.setenv(STATE, 'Madrid')
    identifier = _create(manager)

    ok, err, renewed = manager.renew_certificate(identifier)

    assert ok, err
    assert _c_and_st(_issued(manager, renewed['identifier'])) == ('ES', 'Madrid')


# --- the create endpoint -------------------------------------------------

def test_the_create_endpoint_fills_the_declared_default(monkeypatch):
    """The API resolved its own default before calling the manager, from the
    constants, so fixing only the manager would have changed nothing for a
    request that leaves the fields out."""
    from modules.api.client_certificates import _client_cert_create_params

    monkeypatch.setenv(COUNTRY, 'ES')
    monkeypatch.setenv(STATE, 'Madrid')

    params = _client_cert_create_params({'common_name': 'alice.example.com'})

    assert params['country'] == 'ES'
    assert params['state'] == 'Madrid'


def test_the_create_endpoint_keeps_what_the_request_says(monkeypatch):
    from modules.api.client_certificates import _client_cert_create_params

    monkeypatch.setenv(COUNTRY, 'ES')

    params = _client_cert_create_params(
        {'common_name': 'alice.example.com', 'country': 'IT', 'state': 'Lazio'})

    assert (params['country'], params['state']) == ('IT', 'Lazio')


# --- refused at boot -----------------------------------------------------

def test_nothing_declared_passes_the_boot_check():
    """CONTROL: the check must not stop an instance that configures nothing."""
    check_client_certificate_defaults()


def test_a_valid_declaration_passes_the_boot_check(monkeypatch):
    monkeypatch.setenv(COUNTRY, 'es')
    monkeypatch.setenv(STATE, 'Madrid')

    check_client_certificate_defaults()


@pytest.mark.parametrize('value', ['Spain', 'E', 'E1', 'ESP'])
def test_a_country_that_is_not_a_code_is_refused_at_boot(monkeypatch, value):
    monkeypatch.setenv(COUNTRY, value)

    with pytest.raises(ValueError) as caught:
        check_client_certificate_defaults()

    assert COUNTRY in str(caught.value)
    assert 'two-letter' in str(caught.value)


def test_a_state_too_long_to_issue_is_refused_at_boot(monkeypatch):
    monkeypatch.setenv(STATE, 'x' * 129)

    with pytest.raises(ValueError) as caught:
        check_client_certificate_defaults()

    assert STATE in str(caught.value)
