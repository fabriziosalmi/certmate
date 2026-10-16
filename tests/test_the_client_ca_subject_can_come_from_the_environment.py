"""The client CA can be born with its own name, from the environment.

`client_ca_subject` in settings is read when the CA is created (#578), and on a
fresh install that is the first start: before the setup wizard, before anyone
could have sent `POST /api/settings`. So a container deployed for an
organisation came up as `C=CH, ST=Switzerland, O=CertMate, CN=CertMate CA`
every time, and the only way to put the organisation's name on it was a second
step — `POST /api/client-certs/ca/reset` — which also throws away anything
issued in between.

`CERTMATE_CLIENT_CA_COUNTRY`, `_STATE`, `_ORGANIZATION`,
`_ORGANIZATIONAL_UNIT` and `_COMMON_NAME` let the deployment say it up front.
The properties that matter:

* **nothing set, nothing changes** — the control, and the compatibility
  guarantee for every existing install;
* **an unset or empty variable keeps its field's default**, so naming only
  the organisation does not strip the state as a side effect — and the
  compose files, which pass every variable through as `${VAR:-}`, do not
  turn a default install into a CA with no organisation;
* **the setting still wins**, because it is the deliberate act for this
  instance and the environment is the bootstrap;
* **an existing CA is never replaced** because a variable changed — the same
  rule the setting obeys, for the same reason;
* **a mistyped country refuses to start**, before anything is written.
"""
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from modules.core.private_ca import (
    PrivateCAGenerator,
    client_ca_subject_from_environment,
    resolve_client_ca_subject,
)

pytestmark = [pytest.mark.unit]

VARIABLES = {
    'country': 'CERTMATE_CLIENT_CA_COUNTRY',
    'state': 'CERTMATE_CLIENT_CA_STATE',
    'organization': 'CERTMATE_CLIENT_CA_ORGANIZATION',
    'organizational_unit': 'CERTMATE_CLIENT_CA_ORGANIZATIONAL_UNIT',
    'common_name': 'CERTMATE_CLIENT_CA_COMMON_NAME',
}

ACME = {
    'country': 'ES',
    'state': 'Madrid',
    'organization': 'Acme SL',
    'organizational_unit': 'IT',
    'common_name': 'Acme Client CA',
}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """A developer with one of these exported must not change the answers."""
    for name in VARIABLES.values():
        monkeypatch.delenv(name, raising=False)


def _declare(monkeypatch, subject):
    for field, value in subject.items():
        monkeypatch.setenv(VARIABLES[field], value)


def _value(ca_dir, oid):
    subject = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes()).subject
    found = subject.get_attributes_for_oid(oid)
    return found[0].value if found else None


# --- reading the environment ---------------------------------------------

def test_with_nothing_set_there_is_nothing_to_say():
    """CONTROL. None, not the default spelled out: None is what lets the
    PrivateCAGenerator keep using its own default, exactly as before."""
    assert client_ca_subject_from_environment() is None
    assert resolve_client_ca_subject({}) is None
    assert resolve_client_ca_subject(None) is None


def test_every_field_can_be_declared(monkeypatch):
    _declare(monkeypatch, ACME)

    assert client_ca_subject_from_environment() == ACME


def test_a_field_not_declared_keeps_its_default(monkeypatch):
    """Naming only the organisation must not strip the state and the country:
    an unset variable is "I did not say", not "leave it out"."""
    monkeypatch.setenv('CERTMATE_CLIENT_CA_ORGANIZATION', 'Acme SL')

    subject = client_ca_subject_from_environment()

    assert subject['organization'] == 'Acme SL'
    for field in ('country', 'state', 'organizational_unit', 'common_name'):
        assert subject[field] == PrivateCAGenerator.DEFAULT_SUBJECT[field]


def test_the_compose_file_passing_every_variable_empty_changes_nothing(monkeypatch, tmp_path):
    """docker-compose.yml passes each variable as `VAR=${VAR:-}`, so an
    operator who sets none of them still hands the container five empty
    strings. That must be the default CA, not one stripped to its CN."""
    _declare(monkeypatch, dict.fromkeys(VARIABLES, ''))

    assert client_ca_subject_from_environment() is None

    ca = PrivateCAGenerator(tmp_path / 'ca', subject=resolve_client_ca_subject({}))
    assert ca.initialize()
    assert _value(tmp_path / 'ca', NameOID.COUNTRY_NAME) == 'CH'
    assert _value(tmp_path / 'ca', NameOID.ORGANIZATION_NAME) == 'CertMate'


def test_a_field_passed_empty_keeps_its_default(monkeypatch):
    """The same rule one field at a time: the compose file sets the state to
    '' when only the organisation was named in .env."""
    _declare(monkeypatch, {'organization': 'Acme SL', 'state': '  '})

    subject = client_ca_subject_from_environment()

    assert subject['organization'] == 'Acme SL'
    assert subject['state'] == PrivateCAGenerator.DEFAULT_SUBJECT['state']


def test_surrounding_whitespace_is_not_part_of_the_name(monkeypatch):
    """A compose file quoted with a trailing space would otherwise put the
    space in the issuer name of every client certificate."""
    monkeypatch.setenv('CERTMATE_CLIENT_CA_COMMON_NAME', '  Acme Client CA ')

    assert client_ca_subject_from_environment()['common_name'] == 'Acme Client CA'


# --- who wins ------------------------------------------------------------

def test_the_setting_wins_over_the_environment(monkeypatch):
    _declare(monkeypatch, ACME)
    configured = {'country': 'IT', 'common_name': 'From settings'}

    assert resolve_client_ca_subject({'client_ca_subject': configured}) == configured


def test_an_empty_or_malformed_setting_does_not_hide_the_environment(monkeypatch):
    """An empty object was already treated as "not configured" (the CA used
    its default); it must fall through to the environment the same way."""
    _declare(monkeypatch, ACME)

    assert resolve_client_ca_subject({'client_ca_subject': {}}) == ACME
    assert resolve_client_ca_subject({'client_ca_subject': 'nope'}) == ACME


# --- the CA it produces --------------------------------------------------

def test_a_new_ca_carries_the_declared_subject(monkeypatch, tmp_path):
    _declare(monkeypatch, ACME)

    ca = PrivateCAGenerator(tmp_path / 'ca', subject=resolve_client_ca_subject({}))
    assert ca.initialize()

    assert _value(tmp_path / 'ca', NameOID.COUNTRY_NAME) == 'ES'
    assert _value(tmp_path / 'ca', NameOID.STATE_OR_PROVINCE_NAME) == 'Madrid'
    assert _value(tmp_path / 'ca', NameOID.ORGANIZATION_NAME) == 'Acme SL'
    assert _value(tmp_path / 'ca', NameOID.ORGANIZATIONAL_UNIT_NAME) == 'IT'
    assert _value(tmp_path / 'ca', NameOID.COMMON_NAME) == 'Acme Client CA'


def test_changing_the_environment_later_does_not_touch_an_existing_ca(monkeypatch, tmp_path):
    """The rule the setting obeys, for the same reason: a restart with a new
    value must not regenerate the CA under every certificate it has signed."""
    ca_dir = tmp_path / 'ca'
    _declare(monkeypatch, ACME)
    assert PrivateCAGenerator(ca_dir, subject=resolve_client_ca_subject({})).initialize()
    key_before = (ca_dir / 'ca.key').read_bytes()

    monkeypatch.setenv('CERTMATE_CLIENT_CA_COMMON_NAME', 'Renamed CA')
    assert PrivateCAGenerator(ca_dir, subject=resolve_client_ca_subject({})).initialize()

    assert (ca_dir / 'ca.key').read_bytes() == key_before
    assert _value(ca_dir, NameOID.COMMON_NAME) == 'Acme Client CA'


def test_a_reset_without_a_subject_uses_the_declared_one(monkeypatch, tmp_path):
    """`POST /api/client-certs/ca/reset` with no `subject` rebuilds with the
    generator's own subject, which is the one resolved at start — so after
    changing the variables, a restart and a bare reset is enough."""
    ca_dir = tmp_path / 'ca'
    assert PrivateCAGenerator(ca_dir).initialize()
    assert _value(ca_dir, NameOID.COMMON_NAME) == 'CertMate CA'

    _declare(monkeypatch, ACME)
    restarted = PrivateCAGenerator(ca_dir, subject=resolve_client_ca_subject({}))
    assert restarted.initialize()
    assert _value(ca_dir, NameOID.COMMON_NAME) == 'CertMate CA', (
        'a restart alone must not replace the CA')

    assert restarted.regenerate()
    assert _value(ca_dir, NameOID.COMMON_NAME) == 'Acme Client CA'
    assert _value(ca_dir, NameOID.COUNTRY_NAME) == 'ES'


def test_a_country_that_is_not_a_code_refuses_before_writing(monkeypatch, tmp_path):
    """`CERTMATE_CLIENT_CA_COUNTRY=Spain` is the obvious mistake. It is refused
    the way the setting is, with a message that says what to type, and the
    instance does not start with half a CA on disk."""
    _declare(monkeypatch, dict(ACME, country='Spain'))

    with pytest.raises(ValueError) as caught:
        PrivateCAGenerator(tmp_path / 'ca', subject=resolve_client_ca_subject({})).initialize()

    assert 'two-letter' in str(caught.value).lower()
    assert not (tmp_path / 'ca' / 'ca.key').exists()


# --- wired into the application ------------------------------------------

def test_a_fresh_instance_is_born_with_the_declared_subject(tmp_path, monkeypatch):
    """End to end through create_app: the factory is the one place the
    subject is resolved, and a unit test of the resolver cannot show that the
    factory calls it."""
    import secrets

    from modules.factory import create_app

    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
    _declare(monkeypatch, ACME)

    create_app()

    ca_dir = tmp_path / 'data' / 'certs' / 'ca'
    assert _value(ca_dir, NameOID.ORGANIZATION_NAME) == 'Acme SL'
    assert _value(ca_dir, NameOID.COMMON_NAME) == 'Acme Client CA'
