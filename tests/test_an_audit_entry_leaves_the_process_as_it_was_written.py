"""What an audit entry says survives the sanitisers on its way out.

Found by the review of #1511 B12. A download entry said whether it carried the
private key in `details.private_key`, and `private_key` is one of the field
names the structured-log sanitiser redacts: the local .log, the hash chain and
/api/activity kept `true`, but the JSON line on stdout and the SIEM sink
(audit_sink, through the same sanitiser) received "[REDACTED]". The one fact
the entry exists for was the one taken out of it.

Each entry these batches write is passed through both, and its details must
come out the same.
"""
import json
import logging

import pytest

from modules.core.audit import AuditLogger
from modules.core.audit_sink import _SANITIZER
from modules.core.structured_logging import JSONFormatter

pytestmark = [pytest.mark.unit]


class _Sink:
    def __init__(self):
        self.entries = []

    def send(self, entry):
        self.entries.append(entry)


@pytest.fixture
def written(tmp_path):
    sink = _Sink()
    audit = AuditLogger(tmp_path, enable_chain=False, audit_sink=sink)
    audit.log_certificate_downloaded('payments.example.com', 'zip', True)
    audit.log_certificate_downloaded('laptop-anna-1a2b', 'crt', False,
                                     resource_type='client_certificate', common_name='laptop-anna')
    audit.log_certificate_created('laptop-anna-1a2b', 'laptop-anna', 'vpn',
                                  resource_type='client_certificate')
    audit.log_certificate_renewed('laptop-anna-1a2b', resource_type='client_certificate',
                                  common_name='laptop-anna', new_identifier='laptop-anna-9f8e')
    audit.log_certificate_revoked('laptop-anna-9f8e', 'keyCompromise', resource_type='client_certificate',
                                  common_name='laptop-anna')
    return sink.entries


def test_every_entry_reaches_the_siem_sink_as_it_was_written(written):
    assert len(written) == 5
    for entry in written:
        assert _SANITIZER.sanitize_data(entry)['details'] == entry['details'], entry


def test_every_entry_reaches_stdout_as_it_was_written(written):
    formatter = JSONFormatter()
    for entry in written:
        record = logging.LogRecord('certmate.audit', logging.INFO, __file__, 1,
                                   json.dumps(entry), None, None)
        line = json.loads(formatter.format(record))
        assert json.loads(line['message'])['details'] == entry['details'], line['message']


def test_a_download_says_whether_it_carried_the_key(written):
    downloads = [e for e in written if e['operation'] == 'download']
    assert [d['details']['key_included'] for d in downloads] == [True, False]


def test_the_compliance_page_gives_the_size_a_download_line_measures(tmp_path, monkeypatch):
    """docs/compliance.md said the chain grows by "hundreds of kilobytes per
    year on a busy instance", then that every line is 450 to 650 bytes; a
    revoke measured 745. A download is a line now and an automation pulls on a
    schedule, so the page gives the size of a download line, which is what
    this measures through the real application, and says what makes a line
    larger rather than claiming one range for every operation."""
    import re
    import secrets
    from pathlib import Path

    from modules.factory import create_app
    checkout = Path(__file__).resolve().parent.parent
    text = (checkout / 'docs' / 'compliance.md').read_text(encoding='utf-8')
    stated = re.search(r'download line\s+measures about (\d+) to (\d+) bytes', text)
    assert stated, 'docs/compliance.md does not give the size of a download line'
    low, high = int(stated.group(1)), int(stated.group(2))
    assert not re.search(r'per audited operation, of \d+ to \d+ bytes', text), (
        'the page claims one size for every operation')
    for larger in ('reason', 'batch download', 'API key', 'client-certificate download'):
        assert larger in text, f'the page does not say a {larger} makes a line larger'

    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    for name in ('templates', 'static'):
        (root.parent / name).symlink_to(checkout / name, target_is_directory=True)
    monkeypatch.setattr('modules.factory.__file__', str(root / 'factory.py'))
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    app, container = create_app()
    certificate = Path(container.cert_dir) / 'payments.example.com'
    certificate.mkdir(parents=True)
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
        (certificate / name).write_text('x\n')
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    for suffix in ('', '/fullchain', ''):
        assert client.get(f'/api/certificates/payments.example.com/download{suffix}').status_code == 200
    chain = next(Path(container.data_dir).rglob('certificate_audit.chain.jsonl'))
    # The first line of a chain links to no previous hash and is shorter: it is
    # left out, as on any instance that has run for a while.
    sizes = [len(line) + 1 for line in chain.read_bytes().splitlines()
             if b'"operation": "download"' in line and not line.startswith(b'{"seq": 0,')]
    assert len(sizes) == 2, sizes
    assert all(low <= size <= high for size in sizes), (sizes, low, high)


def test_the_sanitiser_still_redacts_a_key_field():
    """CONTROL: the comparison above would also pass if the sanitiser did nothing."""
    assert _SANITIZER.sanitize_data({'private_key': 'x'}) == {'private_key': '[REDACTED]'}
