"""How urgent a certificate looks comes from the renewal rule, not from 30 and 7 days (#1429).

The dashboard counted a certificate as "Expiring" at 30 days left, and the notification
bell and the inventory called it critical at 7. A 160-hour certificate (Let's Encrypt's
`shortlived` profile) has less than 7 days from the moment it is issued, so every new
one raised a "Critical, 7 days or less" notification, and a 47-day certificate was
"expiring" for 30 of its 47 days. The backend already knew better: renewal_policy decides
when a certificate renews from its lifetime, and the API returns that instant.

`expiry_status` is that rule turned into a status: warning once renewal is due, critical
once it is overdue (a sixth of the lifetime left, never earlier than 7 days before
expiry). For a 90-day certificate and the default threshold that is 30 and 7 days, as
before, so nothing changes for the certificates most instances hold.
"""
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core import inventory_view, renewal_policy
from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

DAY, HOUR, SECOND = timedelta(days=1), timedelta(hours=1), timedelta(seconds=1)
ISSUED = datetime(2026, 11, 1)


def _status(lifetime, left, renew_at=None):
    not_after = ISSUED + lifetime
    return renewal_policy.expiry_status(ISSUED, not_after, 30, not_after - left, renew_at)


@pytest.mark.parametrize('lifetime,warn_from,critical_from', [
    # Unchanged: what every 90-day certificate showed before.
    (90 * DAY, 30 * DAY, 7 * DAY),
    # A third of the lifetime, and 7 days.
    (47 * DAY, 47 * DAY / 3, 7 * DAY),
    # Half of the lifetime (under 10 days), and a sixth.
    (160 * HOUR, 80 * HOUR, 160 * HOUR / 6),
    (24 * HOUR, 12 * HOUR, 4 * HOUR),
])
def test_the_edges_are_where_the_rule_puts_them(lifetime, warn_from, critical_from):
    assert _status(lifetime, lifetime) == 'ok'
    assert _status(lifetime, warn_from + SECOND) == 'ok'
    assert _status(lifetime, warn_from) == 'warning'
    assert _status(lifetime, critical_from + SECOND) == 'warning'
    assert _status(lifetime, critical_from) == 'critical'
    assert _status(lifetime, timedelta(0)) == 'expired'


def test_a_new_short_lived_certificate_is_not_an_alarm():
    """THE case of #1429: just issued, 160 hours left."""
    assert _status(160 * HOUR, 159 * HOUR) == 'ok'


def test_the_instant_the_sweep_renews_at_decides_the_warning():
    """An ARI window can move the renewal; the warning follows the renewal, not the margin."""
    not_after = ISSUED + 90 * DAY
    later = not_after - 20 * DAY

    assert renewal_policy.expiry_status(ISSUED, not_after, 30, not_after - 25 * DAY, later) == 'ok'
    assert renewal_policy.expiry_status(ISSUED, not_after, 30, later, later) == 'warning'


# --- the certificate's answer --------------------------------------------

def _certificate(not_before, not_after):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'short.example.com')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


@pytest.fixture
def manager(tmp_path):
    dirs = {name: tmp_path / name for name in ('certificates', 'data', 'backups', 'logs')}
    for path in dirs.values():
        path.mkdir()
    file_ops = FileOperations(cert_dir=dirs['certificates'], data_dir=dirs['data'],
                              backup_dir=dirs['backups'], logs_dir=dirs['logs'])
    settings = SettingsManager(file_ops=file_ops, settings_file=dirs['data'] / 'settings.json')
    return CertificateManager(cert_dir=dirs['certificates'], settings_manager=settings,
                              dns_manager=MagicMock(), shell_executor=MagicMock())


def _info(manager, lifetime, age):
    now = datetime.now(UTC)
    cert_pem, key_pem = _certificate(now - age, now - age + lifetime)
    path = Path(manager.cert_dir) / 'short.example.com'
    path.mkdir()
    (path / 'cert.pem').write_bytes(cert_pem)
    (path / 'privkey.pem').write_bytes(key_pem)
    return manager.get_certificate_info('short.example.com')


def test_a_new_160_hour_certificate_answers_ok(manager):
    info = _info(manager, 160 * HOUR, HOUR)

    assert info['days_until_expiry'] < 7, 'the case the fixed thresholds called critical'
    assert info['expiry_status'] == 'ok'
    assert info['not_before'].endswith('Z')


def test_a_160_hour_certificate_past_its_renewal_answers_warning(manager):
    assert _info(manager, 160 * HOUR, 100 * HOUR)['expiry_status'] == 'warning'


def test_a_90_day_certificate_answers_as_before(manager):
    assert _info(manager, 90 * DAY, 85 * DAY)['expiry_status'] == 'critical'


# --- the inventory -------------------------------------------------------

def _record(not_before, not_after):
    return {'not_before': not_before.isoformat(), 'not_after': not_after.isoformat()}


def test_the_inventory_classifies_by_lifetime():
    now = datetime(2026, 11, 11)
    fresh = _record(now - HOUR, now + 159 * HOUR)

    assert inventory_view.certificate_expiry_status(fresh, now) == 'ok'
    view = inventory_view.build_inventory_view([{**fresh, 'fingerprint': 'a'}], now=now)
    assert view['certificates'][0]['expiry_status'] == 'ok'


def test_the_inventory_falls_back_to_days_without_a_start_date():
    now = datetime(2026, 11, 11)

    assert inventory_view.certificate_expiry_status(
        {'not_after': (now + 5 * DAY).isoformat()}, now) == 'critical'


# --- the browser reads the field, and keeps the old rule for an old server --

def _read(path):
    return (Path(__file__).resolve().parent.parent / path).read_text(encoding='utf-8')


def test_the_bell_and_the_dashboard_read_expiry_status():
    base = _read('templates/base.html')
    dashboard = _read('static/js/dashboard.js')

    assert "c.expiry_status === 'critical'" in base
    assert "cert.expiry_status === 'warning'" in dashboard
    # The fixed 30 days survive only as the fallback for an answer without the field.
    assert dashboard.count('days_until_expiry <= 30') == 1


def test_the_dashboard_tile_counts_a_new_short_lived_certificate_as_valid():
    """updateStats itself, run in node: 6 days left, and the server says it is fine."""
    from tests.test_a_certificate_with_no_key_is_never_valid import _stats

    fresh = {'domain': 'short.example.com', 'exists': True, 'expired': False,
             'days_until_expiry': 6, 'reissue_required': False, 'expiry_status': 'ok'}
    due = {**fresh, 'domain': 'due.example.com', 'days_until_expiry': 2, 'expiry_status': 'warning'}
    old_server = {**fresh, 'domain': 'old.example.com'}
    del old_server['expiry_status']

    assert str(_stats([fresh])['chips']['expiring']) == '0'
    assert str(_stats([fresh, due])['chips']['expiring']) == '1'
    # An answer from a server before 2.62 keeps the 30 days it had.
    assert str(_stats([old_server])['chips']['expiring']) == '1'
