"""#578 (from #562): the client CA was born Swiss, and nobody chose that.

`_generate_ca` built the subject from five hardcoded attributes, so every
CertMate install on earth signed its client certificates with
`C=CH, ST=Switzerland, O=CertMate, OU=Certificate Authority, CN=CertMate CA`.
An organisation issuing client certificates to its own staff wants its own
name on them.

The property that matters more than the feature: **the subject is read when
the CA is created and never again.** Re-reading it on every start would mean a
settings edit silently regenerating the CA, and every client certificate ever
issued would stop verifying against it. That case has its own deliberate,
confirmed action (see tests/test_resetting_the_client_ca_leaves_the_rest_alone).
"""
import pathlib

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]

DEFAULT = {
    NameOID.COUNTRY_NAME: 'CH',
    NameOID.STATE_OR_PROVINCE_NAME: 'Switzerland',
    NameOID.ORGANIZATION_NAME: 'CertMate',
    NameOID.ORGANIZATIONAL_UNIT_NAME: 'Certificate Authority',
    NameOID.COMMON_NAME: 'CertMate CA',
}


def _subject(ca_dir: pathlib.Path) -> x509.Name:
    return x509.load_pem_x509_certificate(
        (ca_dir / 'ca.crt').read_bytes()).subject


def _value(subject: x509.Name, oid):
    found = subject.get_attributes_for_oid(oid)
    return found[0].value if found else None


def test_an_install_that_configures_nothing_is_unchanged(tmp_path):
    """CONTROL, and the compatibility guarantee: the default subject is exactly
    what it has always been, attribute for attribute."""
    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()

    subject = _subject(tmp_path / 'ca')
    for oid, expected in DEFAULT.items():
        assert _value(subject, oid) == expected


def test_the_configured_subject_is_used(tmp_path):
    ca = PrivateCAGenerator(tmp_path / 'ca', subject={
        'country': 'IT',
        'state': 'Liguria',
        'organization': 'Acme SpA',
        'organizational_unit': 'IT Security',
        'common_name': 'Acme Client CA',
    })
    assert ca.initialize()

    subject = _subject(tmp_path / 'ca')
    assert _value(subject, NameOID.COUNTRY_NAME) == 'IT'
    assert _value(subject, NameOID.STATE_OR_PROVINCE_NAME) == 'Liguria'
    assert _value(subject, NameOID.ORGANIZATION_NAME) == 'Acme SpA'
    assert _value(subject, NameOID.ORGANIZATIONAL_UNIT_NAME) == 'IT Security'
    assert _value(subject, NameOID.COMMON_NAME) == 'Acme Client CA'


def test_a_field_left_empty_is_left_out(tmp_path):
    """Not everyone has a state, and a CA subject carrying an empty attribute
    is worse than one that omits it."""
    ca = PrivateCAGenerator(tmp_path / 'ca', subject={
        'country': 'IT',
        'state': '',
        'organization': 'Acme SpA',
        'organizational_unit': '',
        'common_name': 'Acme Client CA',
    })
    assert ca.initialize()

    subject = _subject(tmp_path / 'ca')
    assert _value(subject, NameOID.STATE_OR_PROVINCE_NAME) is None
    assert _value(subject, NameOID.ORGANIZATIONAL_UNIT_NAME) is None
    assert _value(subject, NameOID.ORGANIZATION_NAME) == 'Acme SpA'


def test_a_country_that_is_not_a_country_code_is_refused(tmp_path):
    """X.509 C is a two-letter code. cryptography enforces it at signing time
    with a message about the attribute, which is not a message anyone can act
    on; this refuses earlier and says what to type."""
    ca = PrivateCAGenerator(tmp_path / 'ca', subject={
        'country': 'Italy', 'common_name': 'Acme Client CA'})

    with pytest.raises(ValueError) as caught:
        ca.initialize()

    assert 'two-letter' in str(caught.value).lower()
    assert not (tmp_path / 'ca' / 'ca.key').exists(), (
        'a refused subject must not leave half a CA on disk'
    )


def test_a_subject_with_no_common_name_still_has_one(tmp_path):
    ca = PrivateCAGenerator(tmp_path / 'ca', subject={'organization': 'Acme SpA'})
    assert ca.initialize()

    assert _value(_subject(tmp_path / 'ca'), NameOID.COMMON_NAME) == 'CertMate CA'


def test_changing_the_setting_later_does_not_touch_an_existing_ca(tmp_path):
    """The property this feature lives or dies on.

    If the subject were re-read on every start, editing it would regenerate the
    CA, and every client certificate already issued would stop verifying. The
    CA must stay exactly as it was, key included.
    """
    ca_dir = tmp_path / 'ca'
    assert PrivateCAGenerator(ca_dir, subject={
        'country': 'IT', 'common_name': 'First CA'}).initialize()
    key_before = (ca_dir / 'ca.key').read_bytes()
    cert_before = (ca_dir / 'ca.crt').read_bytes()

    assert PrivateCAGenerator(ca_dir, subject={
        'country': 'DE', 'common_name': 'Second CA'}).initialize()

    assert (ca_dir / 'ca.key').read_bytes() == key_before
    assert (ca_dir / 'ca.crt').read_bytes() == cert_before
    assert _value(_subject(ca_dir), NameOID.COMMON_NAME) == 'First CA'
