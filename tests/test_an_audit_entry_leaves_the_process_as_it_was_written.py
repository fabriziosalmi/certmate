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


def test_the_size_the_compliance_page_gives_a_chain_line_is_the_size_of_one(tmp_path):
    """docs/compliance.md said the chain grows by "hundreds of kilobytes per
    year on a busy instance". A download is a line now, and an automation
    pulls on a schedule: the page has to give the size of a line, and that
    size has to be what a line measures. Outside a request the actor is the
    short `system` one, so this is the low end of the range."""
    import re
    from pathlib import Path
    text = (Path(__file__).resolve().parent.parent / 'docs' / 'compliance.md').read_text(encoding='utf-8')
    stated = re.search(r'of (\d+) to (\d+) bytes', text)
    assert stated, 'docs/compliance.md does not give the size of a chain line'
    low, high = int(stated.group(1)), int(stated.group(2))
    audit = AuditLogger(tmp_path)
    audit.log_certificate_downloaded('payments.example.com', 'fullchain.pem', False,
                                     user='api_user', ip_address='127.0.0.1')
    line = audit.audit_chain_file.read_bytes().splitlines()[-1]
    assert low <= len(line) + 1 <= high, (len(line) + 1, low, high)


def test_the_sanitiser_still_redacts_a_key_field():
    """CONTROL: the comparison above would also pass if the sanitiser did nothing."""
    assert _SANITIZER.sanitize_data({'private_key': 'x'}) == {'private_key': '[REDACTED]'}
