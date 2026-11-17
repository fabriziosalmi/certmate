"""A CA account's EAB key never reaches certbot's own log (#1461).

certbot writes its whole command line to ``<cert>/logs/letsencrypt.log`` at the
start of every run, before it contacts the CA, failed runs included. CertMate
passed the EAB pair as ``--eab-kid``/``--eab-hmac-key``, so after every create
or reissue with an EAB account (ZeroSSL, Google, SSL.com, Actalis, Sectigo, a
private CA that binds accounts) the key sat in plain text in that log and in
every rotated copy. The pair now goes in a 0600 config file (``-c``), which
certbot reads and does not log, and the logs earlier runs wrote are masked once
at startup.

Measured with the real certbot, not a double: the command is the one
``build_certbot_command`` produces, and the CA is a closed port on loopback, so
certbot parses everything, logs its arguments, and fails at the first request.
"""
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from modules.core.ca_manager import CAManager
from modules.core.certbot_logs import MARKER, mask, mask_eab_in_certbot_logs

pytestmark = [pytest.mark.unit]

KID = 'kid-' + os.urandom(6).hex()
HMAC = 'hmac-' + os.urandom(12).hex()
DOMAIN = 'eab.example.test'
CLOSED_CA = 'https://127.0.0.1:9/directory'
RUN_CERTBOT = 'import sys; from certbot.main import main; sys.exit(main())'


def _certbot(argv, cwd):
    """Run the real certbot with *argv* (without the leading 'certbot')."""
    return subprocess.run([sys.executable, '-c', RUN_CERTBOT, *argv, '--standalone'],
                          cwd=cwd, capture_output=True, text=True, timeout=120)


def _log(cert_dir):
    return (cert_dir / DOMAIN / 'logs' / 'letsencrypt.log').read_text(encoding='utf-8')


def _built_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    temp_files = []
    cmd, _env = CAManager(settings_manager=None).build_certbot_command(
        DOMAIN, 'ops@example.test', 'private_ca', 'cloudflare', {},
        {'acme_url': CLOSED_CA, 'eab_kid': KID, 'eab_hmac': HMAC},
        cert_dir=tmp_path / 'certificates', temp_files=temp_files)
    return cmd, temp_files


def test_certbot_logs_neither_value_of_the_pair(tmp_path, monkeypatch):
    cmd, temp_files = _built_command(tmp_path, monkeypatch)
    result = _certbot(cmd[1:], tmp_path)

    log = _log(tmp_path / 'certificates')
    assert 'Arguments:' in log, 'certbot did not log its arguments: nothing was measured'
    # It read the file and got as far as the CA, which is closed.
    assert result.returncode != 0 and '127.0.0.1' in result.stderr
    assert KID not in log and HMAC not in log
    assert stat.S_IMODE(os.stat(temp_files[0]).st_mode) == 0o600


def test_on_the_command_line_the_pair_was_in_the_log(tmp_path):
    """CONTROL: what the code did before #1461, measured the same way. Without
    it the test above could pass because certbot logged nothing at all."""
    cert_dir = tmp_path / 'certificates' / DOMAIN
    _certbot(['certonly', '--non-interactive', '--agree-tos', '--email', 'ops@example.test',
              '--cert-name', DOMAIN, '--server', CLOSED_CA, '-d', DOMAIN,
              '--config-dir', str(cert_dir), '--work-dir', str(cert_dir / 'work'),
              '--logs-dir', str(cert_dir / 'logs'),
              '--eab-kid', KID, '--eab-hmac-key', HMAC], tmp_path)
    log = _log(tmp_path / 'certificates')
    assert KID in log and HMAC in log


# --- the logs earlier versions left ----------------------------------------

def _leaked_log(tmp_path):
    """A log written the old way, by the real certbot."""
    test_on_the_command_line_the_pair_was_in_the_log(tmp_path)
    return tmp_path / 'certificates'


def test_the_logs_earlier_runs_left_are_masked_once(tmp_path):
    cert_dir = _leaked_log(tmp_path)
    live = cert_dir / DOMAIN / 'logs' / 'letsencrypt.log'
    rotated = live.with_name('letsencrypt.log.1')
    rotated.write_bytes(live.read_bytes())
    os.chmod(live, 0o400)   # not the 0o600 the staged copy is created with
    before = live.read_text(encoding='utf-8')

    result = mask_eab_in_certbot_logs(cert_dir, tmp_path / 'data')

    assert result['masked_files'] == 2 and result['values'] == 4, result
    for path in (live, rotated):
        text = path.read_text(encoding='utf-8')
        assert KID not in text and HMAC not in text
        assert "'--eab-hmac-key', '***'" in text and "'--eab-kid', '***'" in text
    # Nothing else in the log changed.
    assert live.read_text(encoding='utf-8') == before.replace(KID, '***').replace(HMAC, '***')
    assert stat.S_IMODE(live.stat().st_mode) == 0o400
    assert (tmp_path / 'data' / MARKER).exists()
    assert not (cert_dir / MARKER).exists(), 'every entry of cert_dir is read as a certificate'
    assert not list(cert_dir.glob('*/logs/*.masking'))

    # Once: a later start does not walk the logs again.
    assert mask_eab_in_certbot_logs(cert_dir, tmp_path / 'data')['skipped'] is True


def test_a_log_that_cannot_be_rewritten_is_tried_again_at_the_next_start(tmp_path):
    cert_dir = _leaked_log(tmp_path)
    logs = cert_dir / DOMAIN / 'logs'
    os.chmod(logs, 0o500)   # the masked copy cannot be written beside it
    try:
        result = mask_eab_in_certbot_logs(cert_dir, tmp_path / 'data')
    finally:
        os.chmod(logs, 0o700)
    assert result['failed'], result
    assert not (tmp_path / 'data' / MARKER).exists()
    assert mask_eab_in_certbot_logs(cert_dir, tmp_path / 'data')['values'] == 2


@pytest.mark.parametrize('line, expected', [
    ("Arguments: ['--eab-hmac-key=abc', '-d', 'x']", "Arguments: ['--eab-hmac-key=***', '-d', 'x']"),
    ('Arguments: ["--eab-kid", "k\'1", "-d"]', 'Arguments: ["--eab-kid", "***", "-d"]'),
    ("Arguments: ['--eab-kid', '', '-d']", "Arguments: ['--eab-kid', '***', '-d']"),
    ("Arguments: ['--email', 'a@b.c']", "Arguments: ['--email', 'a@b.c']"),
])
def test_the_other_shapes_certbot_can_log(line, expected):
    assert mask(line)[0] == expected


def test_the_pass_runs_when_the_application_starts(tmp_path, monkeypatch):
    cert_dir = _leaked_log(tmp_path)
    from modules.factory import create_app
    root = tmp_path / 'app' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('CERTMATE_CERT_DIR', str(cert_dir))
    _app, container = create_app()
    container.certbot_log_mask.join(timeout=30)
    assert Path(container.cert_dir).resolve() == cert_dir.resolve()
    assert HMAC not in _log(cert_dir)
    assert (Path(container.data_dir) / MARKER).exists()
    assert not (cert_dir / MARKER).exists()


# --- a real issuance, with the pair read from the file ----------------------

@pytest.fixture
def acme_server_requiring_eab():
    """CertMate's own ACME server, in process, with EAB required (as an
    operator runs it), over plain HTTP on loopback."""
    import socket
    import threading

    from werkzeug.serving import make_server

    from tests import contract_support
    from tests.acme_support import enable, resolve_for_tests

    app, _token = contract_support.build_app()
    entry = enable(app, allow_http=True)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        http01_port = probe.getsockname()[1]
    acme = app.extensions['certmate_container'].managers['acme_server']
    acme.http01_port = http01_port
    acme.resolve = resolve_for_tests
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield entry, f'http://127.0.0.1:{server.server_port}/acme/directory', http01_port
    finally:
        server.shutdown()
        thread.join(timeout=10)


def _issue(tmp_path, monkeypatch, directory, http01_port, account):
    monkeypatch.chdir(tmp_path)
    temp_files = []
    cmd, _env = CAManager(settings_manager=None).build_certbot_command(
        'eab.lab.internal', 'ops@lab.internal', 'private_ca', 'cloudflare', {},
        {'acme_url': 'https://acme.lab.internal/acme/directory', **account},
        cert_dir=tmp_path / 'certificates', temp_files=temp_files)
    # The builder refuses a directory over plain HTTP, as it should; the server
    # here has no TLS in front. Only --server is pointed at it: the EAB file and
    # everything else are the builder's.
    cmd[cmd.index('--server') + 1] = directory
    result = subprocess.run(
        [sys.executable, '-c', RUN_CERTBOT, *cmd[1:], '--standalone',
         '--http-01-port', str(http01_port), '--http-01-address', '127.0.0.1'],
        cwd=tmp_path, capture_output=True, text=True, timeout=180)
    lineage = tmp_path / 'certificates' / 'eab.lab.internal' / 'live' / 'eab.lab.internal'
    return result, lineage, (tmp_path / 'certificates' / 'eab.lab.internal' / 'logs')


def test_certbot_registers_with_the_pair_from_the_file(
        acme_server_requiring_eab, tmp_path, monkeypatch):
    """The server refuses an account without EAB, so an account here means
    certbot read both values from the file and bound the account with them.

    The run goes on to prove http-01, finalize and write the certificate;
    tests/test_certbot_gets_a_certificate_from_the_acme_server.py asserts that
    part (#1484).
    """
    entry, directory, http01_port = acme_server_requiring_eab
    result, _lineage, logs = _issue(tmp_path, monkeypatch, directory, http01_port,
                                    {'eab_kid': entry['kid'], 'eab_hmac': entry['hmac_key']})
    accounts = list((tmp_path / 'certificates' / 'eab.lab.internal' / 'accounts').rglob('regr.json'))
    assert len(accounts) == 1, result.stderr[-2000:]
    assert 'externalAccountRequired' not in result.stderr
    every_log = ''.join(p.read_text(encoding='utf-8') for p in logs.glob('letsencrypt.log*'))
    assert 'Arguments:' in every_log
    assert entry['hmac_key'] not in every_log


def test_without_the_pair_the_same_server_refuses_the_account(
        acme_server_requiring_eab, tmp_path, monkeypatch):
    """CONTROL: the server does require EAB, so the issuance above proves the
    file was read rather than that EAB was never checked."""
    _entry, directory, http01_port = acme_server_requiring_eab
    result, lineage, _logs = _issue(tmp_path, monkeypatch, directory, http01_port, {})
    assert result.returncode != 0
    assert 'externalAccountRequired' in result.stderr or 'external account' in result.stderr.lower(), \
        result.stderr[-2000:]
    assert not list((tmp_path / 'certificates' / 'eab.lab.internal' / 'accounts').rglob('regr.json'))
    assert not (lineage / 'fullchain.pem').exists()
