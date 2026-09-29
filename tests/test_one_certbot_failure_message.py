"""One message builder for a failed certbot run, on create and on renew (#666 S6).

Create and renew each built the error for a non-zero certbot exit on their
own, and they had drifted:

* a certbot killed mid-run (the OOM killer in a small container) leaves only
  its "Saving debug log to ..." banner on stderr. Measured against LE
  staging, certbot 2.10.0, SIGKILL after the order started: rc -9, stderr
  that banner and nothing else, stdout "Account registered. / Requesting a
  certificate for <domain>". Create raised "Certificate creation failed:
  Saving debug log to /.../letsencrypt.log", which names neither the kill nor
  how far it got;
* with an empty stderr, create raised "Certificate creation failed: " (no
  cause at all) and renew "Renewal failed: Certificate not found" (a cause
  never observed);
* stdout, where certbot narrates its progress, was dropped on both paths.

Both paths now go through ``_certbot_failure``: the redacted stderr when it
says anything besides the banner, otherwise the exit code or the signal and
the redacted tail of stdout; the same text is logged and raised.
"""
import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

SECRET = 'dns_cloudflare_api_token = sEcReT-do-not-print'


def _manager(tmp_path, shell):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1},
        'default_key_type': 'ecdsa', 'default_elliptic_curve': 'secp384r1',
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = ({'api_token': 't'}, 'default')
    ca_mgr = MagicMock()
    ca_mgr.ca_providers = {'letsencrypt': {'name': "Let's Encrypt"}}
    ca_mgr.get_ca_config.return_value = (None, None)
    mgr = CertificateManager(cert_dir=tmp_path, settings_manager=settings_mgr,
                             dns_manager=dns_mgr, storage_manager=None,
                             ca_manager=ca_mgr, shell_executor=shell)
    # No CAA lookups from a unit test: the explanation is not what is tested.
    mgr._caa_explanation = lambda *a, **k: ''
    return mgr


def _shell(returncode, stdout='', stderr=''):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=returncode, stdout=stdout, stderr=stderr)
    return shell


def _create(mgr):
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(RuntimeError) as err:
            mgr.create_certificate(domain='www.example.com', email='t@example.com',
                                   dns_provider='duckdns', ca_provider='letsencrypt')
    return str(err.value)


def _renew(tmp_path, mgr):
    d = tmp_path / 'app.example.com'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'cert.pem').write_bytes(b'existing\n')
    (d / 'metadata.json').write_text(json.dumps({'ca_provider': 'letsencrypt'}))
    with pytest.raises(RuntimeError) as err:
        mgr.renew_certificate('app.example.com')
    return str(err.value)


# --- certbot said nothing on stderr ---------------------------------------

# The shape measured on a real certbot 2.10.0 killed mid-order (see above).
KILLED_STDERR = 'Saving debug log to /data/certificates/x/logs/letsencrypt.log\n'
KILLED_STDOUT = 'Account registered.\nRequesting a certificate for www.example.com\n'


@pytest.mark.parametrize('operation', ['create', 'renew'])
def test_a_certbot_killed_mid_order_says_so_and_how_far_it_got(tmp_path, operation):
    mgr = _manager(tmp_path, _shell(-9, stdout=KILLED_STDOUT, stderr=KILLED_STDERR))
    text = _create(mgr) if operation == 'create' else _renew(tmp_path, mgr)
    assert 'certbot was killed by SIGKILL' in text, text
    assert 'Requesting a certificate for www.example.com' in text, text
    assert 'Saving debug log' not in text, text


def test_the_banner_is_dropped_but_a_real_error_after_it_is_kept(tmp_path):
    stderr = KILLED_STDERR + 'Error: DNS problem: NXDOMAIN looking up TXT\n'
    text = _create(_manager(tmp_path, _shell(1, stdout=KILLED_STDOUT, stderr=stderr)))
    assert text.endswith('Error: DNS problem: NXDOMAIN looking up TXT'), text
    assert 'Requesting' not in text


def test_an_unknown_signal_is_still_named():
    assert CertificateManager._certbot_silence(-200) == (
        'certbot was killed by signal 200 before it reported an error')

def test_a_silent_killed_create_names_the_signal(tmp_path):
    text = _create(_manager(tmp_path, _shell(-9)))
    assert 'certbot was killed by SIGKILL' in text, text
    assert not text.rstrip().endswith(':'), text


def test_a_silent_killed_renewal_names_the_signal_not_a_missing_certificate(tmp_path):
    text = _renew(tmp_path, _manager(tmp_path, _shell(-9)))
    assert 'Certificate not found' not in text, text
    assert 'certbot was killed by SIGKILL' in text, text


@pytest.mark.parametrize('operation', ['create', 'renew'])
def test_stdout_is_the_account_when_stderr_is_empty(tmp_path, operation):
    shell = _shell(1, stdout=f'Saving debug log\n{SECRET}\nAn unexpected error occurred: boom')
    mgr = _manager(tmp_path, shell)
    text = _create(mgr) if operation == 'create' else _renew(tmp_path, mgr)
    assert 'An unexpected error occurred: boom' in text, text
    assert 'sEcReT' not in text, text


@pytest.mark.parametrize('operation', ['create', 'renew'])
def test_only_the_tail_of_a_long_stdout_is_kept(tmp_path, operation):
    stdout = '\n'.join(f'line {n}' for n in range(500))
    mgr = _manager(tmp_path, _shell(1, stdout=stdout))
    text = _create(mgr) if operation == 'create' else _renew(tmp_path, mgr)
    assert 'line 499' in text
    assert 'line 0\n' not in text and len(text) < 3000


# --- certbot said something on stderr: unchanged, and the same on both ---

@pytest.mark.parametrize('operation', ['create', 'renew'])
def test_stderr_wins_and_is_redacted(tmp_path, operation):
    shell = _shell(1, stdout='noise on stdout', stderr=f'{SECRET}\nDetail: DNS problem')
    mgr = _manager(tmp_path, shell)
    text = _create(mgr) if operation == 'create' else _renew(tmp_path, mgr)
    assert 'Detail: DNS problem' in text
    assert 'sEcReT' not in text
    assert 'noise on stdout' not in text


def test_both_paths_say_the_same_thing_after_their_prefix(tmp_path):
    stderr = f'{SECRET}\nDetail: DNS problem'
    created = _create(_manager(tmp_path / 'c', _shell(1, stderr=stderr)))
    renewed = _renew(tmp_path / 'r', _manager(tmp_path / 'r', _shell(1, stderr=stderr)))
    assert created.split('failed: ', 1)[1] == renewed.split('failed: ', 1)[1]


@pytest.mark.parametrize('operation', ['create', 'renew'])
def test_the_log_carries_what_is_raised(tmp_path, operation, caplog):
    caplog.set_level(logging.ERROR, logger='modules.core.certificates')
    mgr = _manager(tmp_path, _shell(-9, stdout=SECRET))
    _create(mgr) if operation == 'create' else _renew(tmp_path, mgr)
    logged = '\n'.join(r.getMessage() for r in caplog.records)
    assert 'killed by SIGKILL' in logged
    assert 'sEcReT' not in logged


def test_an_eab_secret_echoed_by_certbot_is_masked(tmp_path):
    mgr = _manager(tmp_path, None)
    result = MagicMock(returncode=1, stdout='', stderr='bad hmac s3cr3t-hmac for kid-123')
    text = mgr._certbot_failure(
        'Certificate creation failed', 'www.example.com', result,
        secrets=('kid-123', 's3cr3t-hmac', ''))
    assert 's3cr3t-hmac' not in text and 'kid-123' not in text
    assert text == 'Certificate creation failed: bad hmac *** for ***'


@pytest.mark.parametrize('operation', ['create', 'renew'])
def test_an_ordinary_exit_names_its_code(tmp_path, operation):
    mgr = _manager(tmp_path, _shell(1, stderr=KILLED_STDERR))
    text = _create(mgr) if operation == 'create' else _renew(tmp_path, mgr)
    assert 'certbot exited with code 1 without reporting an error' in text, text


def test_neither_the_domain_nor_the_output_can_forge_a_log_line(tmp_path, caplog):
    caplog.set_level(logging.ERROR, logger='modules.core.certificates')
    mgr = _manager(tmp_path, None)
    result = MagicMock(returncode=1, stdout='',
                       stderr='Detail: one\r\nERROR certmate: all certificates revoked')
    mgr._certbot_failure('Renewal failed', 'evil.example\nERROR certmate: forged', result)
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert '\n' not in message and '\r' not in message
    assert 'Detail: one | ERROR certmate: all certificates revoked' in message
