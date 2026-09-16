"""#829: a certificate with hours left reported that it had expired.

`days_left` is `(expiry - now).days`, and `timedelta.days` truncates toward
minus infinity, so anything with less than 24 hours left comes out as 0. The
dashboard reads `days_until_expiry <= 0` as expired in six places, so a
certificate that is perfectly valid was rendered with a red Expired badge,
counted in the Expired tile, matched by the `expired` filter, and labelled
"0 days ago".

24 hours is step-ca's default certificate lifetime, so every operator pointing
CertMate at a default private CA saw every certificate as expired the moment it
was issued.

The test that could have caught this had to use a certificate whose remaining
life is not a whole number of days. Every existing test used multi-day
certificates, and none of them could fail on it.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]


class _Settings:
    def load_settings(self):
        return {}

    def get_domain_dns_provider(self, domain, settings):
        return 'cloudflare'


def _cert(hours_left):
    """A certificate that expires `hours_left` from now. May be negative."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'abc.local')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=30))
            .not_valid_after(now + datetime.timedelta(hours=hours_left))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _info(hours_left):
    manager = CertificateManager.__new__(CertificateManager)
    manager.settings_manager = _Settings()
    return manager._parse_certificate_info('abc.local', _cert(hours_left))


@pytest.mark.parametrize('hours_left', [23, 12, 1])
def test_a_certificate_with_hours_left_has_not_expired(hours_left):
    info = _info(hours_left)
    assert info['expired'] is False, (
        f"a certificate with {hours_left}h of validity left was reported as "
        f"expired, because days_left truncated to {info['days_left']}"
    )
    assert info['seconds_left'] > 0


@pytest.mark.parametrize('hours_ago', [1, 12, 72])
def test_a_certificate_that_has_expired_says_so(hours_ago):
    info = _info(-hours_ago)
    assert info['expired'] is True
    assert info['seconds_left'] < 0


def test_seconds_left_is_the_real_remaining_life():
    """The field the renewal decision and the display can both use.

    `days_left` cannot answer both questions while it is a whole number of
    days: one wants time remaining, the other wants "is this still valid".
    It is kept as it was, because clients read it, and the two honest answers
    are given their own fields.
    """
    info = _info(23)
    assert info['days_left'] == 0, "days_left keeps its meaning: whole days"
    assert 22 * 3600 < info['seconds_left'] <= 23 * 3600


def test_a_certificate_that_cannot_be_parsed_does_not_claim_to_be_valid():
    """The unparseable branch must not answer `expired: False`.

    Unknown is not the same as fine, and this is the branch that produced the
    `null <= 0` misrendering v2.2.4 patched in the browser.
    """
    manager = CertificateManager.__new__(CertificateManager)
    manager.settings_manager = _Settings()
    info = manager._parse_certificate_info('abc.local', b'not a certificate')
    assert info['days_left'] is None
    assert info['seconds_left'] is None
    assert info['expired'] is None
    assert info['needs_renewal'] is True


# Every front-end place that renders "has this expired". Fixing the API alone
# would leave the badge wrong, because each of these derived the answer itself.
# The list is the point: the first fix touched dashboard.js only, and the
# command palette went on saying Expired for a valid certificate, under a
# comment explaining why that must not happen.
RENDERERS = [
    ('static/js/dashboard.js', ['days_until_expiry <= 0']),
    ('static/js/cmd-palette.js', ['days > 0 ?']),
    ('templates/base.html', ['days <= 0']),
]


@pytest.mark.parametrize('relative_path,forbidden', RENDERERS)
def test_no_renderer_decides_expiry_from_a_day_count(relative_path, forbidden):
    import pathlib
    path = pathlib.Path(__file__).resolve().parent.parent / relative_path
    source = path.read_text(encoding='utf-8')
    # Comments are not code. The first version of this test failed on the
    # comment that explains why the pattern is wrong, which is the instrument
    # being wrong rather than the file.
    offenders = [line.strip() for line in source.splitlines()
                 if any(pattern in line for pattern in forbidden)
                 and not line.strip().startswith(('//', '*', '#'))]
    assert not offenders, (
        f"{relative_path} still decides expiry from a day count:\n  "
        + "\n  ".join(offenders)
        + "\nA certificate with 23 hours left has days_until_expiry 0 and has "
          "not expired. Use the `expired` field the API now sends."
    )


@pytest.mark.parametrize('relative_path,_forbidden', RENDERERS)
def test_every_renderer_reads_the_field_instead(relative_path, _forbidden):
    """The other direction: not using the bad pattern is not the same as
    using the right one. A file could pass the test above by deleting the
    check entirely."""
    import pathlib
    path = pathlib.Path(__file__).resolve().parent.parent / relative_path
    source = path.read_text(encoding='utf-8')
    assert '.expired' in source, (
        f"{relative_path} no longer reads the `expired` field, so whatever it "
        f"shows for a certificate's validity is derived from something else"
    )
