"""The organisation and unit of a client certificate default to the deployment's.

`CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY` and `_STATE` let a deployment say where
its client identities are from. Who they belong to was still a set of
literals: "CertMate" and "Users" in the create endpoint, in the CSV batch and
in the manager's signature — and "CertMate" a second time, as the `value` of the
create form's Organization field, which the form always sends. So an
organisation outside the project's own name had to retype `O` on every
certificate, and could not set `OU` from the UI at all.

`CERTMATE_CLIENT_CERT_DEFAULT_ORGANIZATION` and
`CERTMATE_CLIENT_CERT_DEFAULT_ORGANIZATIONAL_UNIT` replace those defaults
without replacing the rules around them:

* nothing set issues exactly what it always issued (the control);
* a value in the request wins, and a blank one is the default, as for country;
* the create form starts from the deployment's organisation;
* a renewal keeps the organisation and unit the certificate was issued with,
  because an mTLS rule matching on `O`/`OU` must not stop matching after a
  renewal nobody chose;
* a value no certificate can carry stops the instance at boot.

They are not `CERTMATE_CLIENT_CA_ORGANIZATION` / `_ORGANIZATIONAL_UNIT`, which
name the CA. The two are kept apart on purpose, and a test below holds that.
"""
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from modules.core.client_certificates import (
    DEFAULT_ORGANIZATION,
    DEFAULT_ORGANIZATIONAL_UNIT,
    check_client_certificate_defaults,
    default_client_organization,
    default_client_organizational_unit,
)

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
ORG = 'CERTMATE_CLIENT_CERT_DEFAULT_ORGANIZATION'
OU = 'CERTMATE_CLIENT_CERT_DEFAULT_ORGANIZATIONAL_UNIT'


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (ORG, OU, 'CERTMATE_CLIENT_CA_ORGANIZATION',
                 'CERTMATE_CLIENT_CA_ORGANIZATIONAL_UNIT'):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    return ClientCertificateManager(tmp_path / 'clients', ca)


def _o_and_ou(manager, identifier):
    pem = (manager._get_cert_subdir('api-mtls') / identifier / f'{identifier}.crt').read_bytes()
    subject = x509.load_pem_x509_certificate(pem).subject
    return (subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
            subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value)


def _create(manager, **kwargs):
    ok, err, data = manager.create_client_certificate(common_name='alice.example.com', **kwargs)
    assert ok, err
    return data['identifier']


# --- the defaults themselves ---------------------------------------------

def test_with_nothing_set_the_defaults_are_what_they_always_were():
    """CONTROL."""
    assert default_client_organization() == DEFAULT_ORGANIZATION == 'CertMate'
    assert default_client_organizational_unit() == DEFAULT_ORGANIZATIONAL_UNIT == 'Users'


def test_the_environment_replaces_them(monkeypatch):
    monkeypatch.setenv(ORG, 'Acme SL')
    monkeypatch.setenv(OU, 'Engineering')

    assert default_client_organization() == 'Acme SL'
    assert default_client_organizational_unit() == 'Engineering'


def test_an_empty_value_keeps_the_default(monkeypatch):
    """The compose files pass every variable as `VAR=${VAR:-}`, so an operator
    who sets neither still hands the container two empty strings."""
    monkeypatch.setenv(ORG, '')
    monkeypatch.setenv(OU, '   ')

    assert default_client_organization() == 'CertMate'
    assert default_client_organizational_unit() == 'Users'


def test_they_are_not_the_ca_variables(monkeypatch):
    """Naming the CA must not rename every certificate it signs, nor the
    reverse: a CA is usually `OU=Certificate Authority`, its staff are not."""
    monkeypatch.setenv('CERTMATE_CLIENT_CA_ORGANIZATION', 'Acme CA Org')
    monkeypatch.setenv('CERTMATE_CLIENT_CA_ORGANIZATIONAL_UNIT', 'Certificate Authority')

    assert default_client_organization() == 'CertMate'
    assert default_client_organizational_unit() == 'Users'


# --- what the manager issues ---------------------------------------------

def test_a_certificate_issued_without_them_carries_the_declared_ones(manager, monkeypatch):
    monkeypatch.setenv(ORG, 'Acme SL')
    monkeypatch.setenv(OU, 'Engineering')

    assert _o_and_ou(manager, _create(manager)) == ('Acme SL', 'Engineering')


def test_with_nothing_declared_a_certificate_is_what_it_always_was(manager):
    """CONTROL, on the certificate itself."""
    assert _o_and_ou(manager, _create(manager)) == ('CertMate', 'Users')


def test_the_default_is_read_when_issuing_not_when_imported(manager, monkeypatch):
    """The manager existed before the variable was set. With the default in
    the function signature, as it was, this was 'CertMate' regardless."""
    monkeypatch.setenv(ORG, 'Acme SL')

    assert _o_and_ou(manager, _create(manager))[0] == 'Acme SL'


def test_values_in_the_call_still_win(manager, monkeypatch):
    monkeypatch.setenv(ORG, 'Acme SL')
    monkeypatch.setenv(OU, 'Engineering')

    identifier = _create(manager, organization='Other SpA', organizational_unit='Finance')

    assert _o_and_ou(manager, identifier) == ('Other SpA', 'Finance')


def test_a_renewal_keeps_the_organisation_it_was_issued_with(manager, monkeypatch):
    """The default changed between issuance and renewal. The renewed identity
    must still say what the old one said, or an mTLS rule on O/OU that matched
    it stops matching after a renewal nobody chose."""
    monkeypatch.setenv(ORG, 'Acme SL')
    monkeypatch.setenv(OU, 'Engineering')
    identifier = _create(manager)

    monkeypatch.setenv(ORG, 'Renamed SL')
    monkeypatch.setenv(OU, 'Platform')
    ok, err, renewed = manager.renew_certificate(identifier)

    assert ok, err
    assert _o_and_ou(manager, renewed['identifier']) == ('Acme SL', 'Engineering')


# --- the create endpoint and the CSV batch -------------------------------

def test_the_create_endpoint_fills_the_declared_defaults(monkeypatch):
    from modules.api.client_certificates import _client_cert_create_params

    monkeypatch.setenv(ORG, 'Acme SL')
    monkeypatch.setenv(OU, 'Engineering')

    params = _client_cert_create_params({'common_name': 'alice.example.com'})

    assert (params['organization'], params['organizational_unit']) == ('Acme SL', 'Engineering')


def test_a_blank_field_is_the_default_like_country_and_state(monkeypatch):
    """What the form sends for a field the operator emptied. It used to issue
    a certificate with an empty `O=` attribute."""
    from modules.api.client_certificates import _client_cert_create_params

    monkeypatch.setenv(ORG, 'Acme SL')

    params = _client_cert_create_params(
        {'common_name': 'alice.example.com', 'organization': '', 'organizational_unit': ''})

    assert (params['organization'], params['organizational_unit']) == ('Acme SL', 'Users')


def test_the_create_endpoint_keeps_what_the_request_says(monkeypatch):
    from modules.api.client_certificates import _client_cert_create_params

    monkeypatch.setenv(ORG, 'Acme SL')

    params = _client_cert_create_params(
        {'common_name': 'alice.example.com', 'organization': 'Other SpA',
         'organizational_unit': 'Finance'})

    assert (params['organization'], params['organizational_unit']) == ('Other SpA', 'Finance')


@pytest.mark.parametrize('cell, expected', [
    (None, None), ('', None), ('   ', None), ('Acme SL', 'Acme SL'),
])
def test_a_blank_csv_cell_leaves_the_choice_to_the_default(cell, expected):
    """A batch row without the column, or with it empty, gets the deployment's
    default; a filled cell is kept as written."""
    from modules.api.client_certificates import _blank_is_unset

    assert _blank_is_unset(cell) == expected


# --- the create form -----------------------------------------------------

def _render_form(**context):
    from flask import Flask

    app = Flask(__name__, template_folder=str(REPO / 'templates'))
    with app.app_context():
        return app.jinja_env.get_template('partials/_client_create.html').render(**context)


def test_the_form_starts_from_the_deployment_organisation():
    """It was `value="CertMate"` in the markup, and the form always sends the
    field, so the variable could never reach a certificate made from the UI."""
    html = _render_form(client_cert_default_organization='Acme SL')

    assert 'id="organization" name="organization" value="Acme SL"' in html


def test_the_form_without_the_value_still_says_certmate():
    """CONTROL: a page that renders the partial without it is unchanged."""
    html = _render_form()

    assert 'id="organization" name="organization" value="CertMate"' in html


def test_the_organisation_is_escaped_into_the_form():
    """It comes from the environment, but it is written into an attribute."""
    html = _render_form(client_cert_default_organization='Acme "SL" <x>')

    assert 'value="Acme &#34;SL&#34; &lt;x&gt;"' in html


def test_the_dashboard_hands_the_form_its_default():
    """The index view is the one that renders the partial. Asserted on the
    source because rendering it needs a signed-in session and the whole app."""
    source = (REPO / 'modules' / 'web' / 'ui_routes.py').read_text(encoding='utf-8')

    assert "client_cert_default_organization=default_client_organization()" in source


# --- refused at boot -----------------------------------------------------

def test_nothing_declared_passes_the_boot_check():
    """CONTROL."""
    check_client_certificate_defaults()


@pytest.mark.parametrize('variable', [ORG, OU])
def test_a_value_too_long_to_issue_is_refused_at_boot(monkeypatch, variable):
    """64 is what the create endpoint accepts and the X.509 bound for O and OU.
    Left to the first issuance, it would be a 400 to whoever came next."""
    monkeypatch.setenv(variable, 'x' * 65)

    with pytest.raises(ValueError) as caught:
        check_client_certificate_defaults()

    assert variable in str(caught.value)


def test_sixty_four_characters_is_still_accepted(monkeypatch):
    monkeypatch.setenv(ORG, 'x' * 64)
    monkeypatch.setenv(OU, 'y' * 64)

    check_client_certificate_defaults()
