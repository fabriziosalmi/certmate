"""Editing a deployment probe must not delete the host it was set up with.

A wildcard certificate is verified through `deployment_host`, a name the
wildcard covers (#381). The certificate answer returned `deployment_port` and
`deployment_protocol` but not `deployment_host`, so Settings -> Probe opened its
edit form with an empty host, and saving it sent `deployment_host: null`,
which the server reads as "delete it". Changing only the port of a probe
silently removed the one setting that made a wildcard verifiable, and the
certificate then reported a deployment mismatch nobody had caused.

Two halves, because either alone can be green while the defect stands: the
server has to SAY what host is stored, and the browser code has to SEND it back
when the operator did not touch it.
"""

import json
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def _manager_with_probe_metadata(tmp_path, monkeypatch, metadata):
    import datetime
    import secrets

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    for var, sub in (('CERTMATE_CERT_DIR', 'certificates'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(48))

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '*.example.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=60))
            .sign(key, hashes.SHA256()))
    cert_dir = tmp_path / 'certificates' / 'example.com'
    cert_dir.mkdir()
    (cert_dir / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / 'privkey.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (cert_dir / 'metadata.json').write_text(json.dumps(
        {'domain': 'example.com', 'dns_provider': 'cloudflare', **metadata}))

    from modules.factory import create_app
    _, container = create_app()
    return container.managers['certificates']


def test_the_certificate_answer_says_which_host_is_probed(tmp_path, monkeypatch):
    manager = _manager_with_probe_metadata(
        tmp_path, monkeypatch,
        {'deployment_host': 'www.example.com', 'deployment_port': 8443,
         'deployment_protocol': 'tls'})

    info = manager.get_certificate_info('example.com', use_cache=False)

    assert info['deployment_host'] == 'www.example.com'
    # The two it always carried, so this cannot pass by returning the wrong dict.
    assert info['deployment_port'] == 8443
    assert info['deployment_protocol'] == 'tls'


def test_a_certificate_without_a_probe_host_says_null_not_nothing(tmp_path, monkeypatch):
    manager = _manager_with_probe_metadata(tmp_path, monkeypatch, {})
    info = manager.get_certificate_info('example.com', use_cache=False)
    assert 'deployment_host' in info and info['deployment_host'] is None


_EDIT_SCRIPT = r"""
const fs = require('fs');
global.window = global;
global.CertMate = {toast() {}, confirm() { return Promise.resolve(true); }};
let sent = null;
global.fetch = (url, opts) => {
    if (opts && opts.method === 'PATCH') sent = JSON.parse(opts.body);
    return Promise.resolve({ok: true, json: () => Promise.resolve([])});
};
// eval of this repository's own browser script, the same way the other frontend
// unit tests load it: it defines window.probeManager and has no module system.
eval(fs.readFileSync(process.argv[1], 'utf8'));
const cert = JSON.parse(process.argv[2]);
const probe = window.probeManager();
const check = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };

probe.startEdit(cert);
check(probe.editHost === cert.deployment_host, 'the edit form did not start from the stored host');

// The operator changes only the port.
probe.editPort = '9443';
probe.saveEdit();
check(sent !== null, 'no PATCH was sent');
check(sent.deployment_host === cert.deployment_host,
      'saving a port-only edit sent deployment_host=' + JSON.stringify(sent.deployment_host));
check(sent.deployment_port === 9443, 'the port change was not sent');
console.log('ok');
"""


def test_a_port_only_edit_sends_the_stored_host_back(node):
    cert = {'domain': 'example.com', 'deployment_host': 'www.example.com',
            'deployment_port': 8443, 'deployment_protocol': 'tls'}
    done = subprocess.run(
        [node, '-e', _EDIT_SCRIPT, '--', str(ROOT / 'static' / 'js' / 'settings-probe.js'),
         json.dumps(cert)],
        capture_output=True, text=True, timeout=30)
    assert done.returncode == 0 and done.stdout.strip() == 'ok', done.stderr or done.stdout
