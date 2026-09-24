"""Sending the weekly digest leaves an audit entry — and therefore a SIEM event.

Item 11 of #876. `digest.py` *read* the audit log (`get_recent_entries`, to
count the week's activity) and never wrote to it, so "was the weekly report
produced and sent" had no answer in the record.

One absence caused two symptoms. The SIEM sink streams **each audit entry**
(#474), so an operation that is not an audit entry is not a SIEM event either;
there was nothing separate to fix.

**What it records is deliberately narrow.** Not the recipients — they are
personal data, and this chain is append-only and tamper-evident by
construction, so there is no supported way to take them back out afterwards.
The count is enough to notice a distribution list that emptied itself, which is
the failure an operator would otherwise find out about by nobody complaining.

**Failures are recorded as deliberately as successes.** A digest that did not
go out is the case an auditor cares about most.

**Configuration skips are not recorded.** "Notifications are disabled" is
answered by the settings, and writing a weekly entry saying so on every
instance that never turned the digest on would grow the chain forever to say
nothing. The absence of entries is the signal, and it is readable.
"""
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent


class _Audit:
    def __init__(self):
        self.entries = []

    def log_operation(self, **kwargs):
        self.entries.append(kwargs)

    def get_recent_entries(self, limit=500):
        return []


class _Notifier:
    def __init__(self, config):
        self._config = config

    def _get_config(self):
        return self._config


def _digest_manager(audit, config, monkeypatch, sendmail=None):
    """A WeeklyDigest wired to fakes, with SMTP replaced."""
    import smtplib

    from modules.core.digest import WeeklyDigest

    class _SMTP:
        def __init__(self, host, port, timeout=10):
            pass

        def starttls(self):
            pass

        def login(self, u, p):
            pass

        def sendmail(self, *args):
            if sendmail:
                sendmail()

        def quit(self):
            pass

    monkeypatch.setattr(smtplib, 'SMTP', _SMTP)
    manager = WeeklyDigest.__new__(WeeklyDigest)
    manager.audit_logger = audit
    manager.notifier = _Notifier(config)
    manager.settings_manager = None
    # The REAL build_digest, with its three inputs stubbed. The first version
    # of this replaced build_digest itself and returned `{'certificates': ...,
    # 'activity': ...}` — a shape it has never produced; the server figures are
    # under `server_certs`. So the record read a key that does not exist,
    # stored null in a chain that cannot be rewritten, and this file agreed
    # with it, because both sides were my assumption rather than the code.
    monkeypatch.setattr(manager, '_get_server_cert_stats',
                        lambda: {'total': 3, 'valid': 2, 'expiring_soon': 1,
                                 'expired': 0, 'expiring_domains': []})
    monkeypatch.setattr(manager, '_get_client_cert_stats',
                        lambda: {'total': 5, 'active': 4, 'revoked': 1})
    monkeypatch.setattr(manager, '_get_weekly_activity',
                        lambda: {'created': 1, 'renewed': 4, 'failed': 0})
    monkeypatch.setattr(manager, '_format_text', lambda d: 'text')
    monkeypatch.setattr(manager, '_format_html', lambda d: '<p>html</p>')
    return manager


WORKING = {
    'enabled': True, 'digest_enabled': True,
    'channels': {'smtp': {
        'enabled': True, 'host': 'smtp.example.com', 'port': 587,
        'username': 'u', 'password': 'p', 'from_address': 'ops@example.com',
        'to_addresses': ['a@example.com', 'b@example.com'],
    }},
}


def test_a_sent_digest_is_recorded(monkeypatch):
    audit = _Audit()
    assert _digest_manager(audit, WORKING, monkeypatch).send() == {'success': True}

    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry['operation'] == 'send'
    assert entry['resource_type'] == 'digest'
    assert entry['status'] == 'success'


def test_the_record_carries_the_numbers_the_digest_reported(monkeypatch):
    """A record saying only "it was sent" cannot be reconciled with the mail
    anyone received."""
    audit = _Audit()
    _digest_manager(audit, WORKING, monkeypatch).send()

    details = audit.entries[0]['details']
    assert details['recipients'] == 2
    assert details['server_certs']['total'] == 3
    assert details['client_certs']['total'] == 5
    assert details['activity'] == {'created': 1, 'renewed': 4, 'failed': 0}


def test_no_recipient_address_reaches_the_chain(monkeypatch):
    """The decision this file exists to hold. Addresses are personal data and
    this chain cannot be edited afterwards — a mistake here is permanent."""
    import json

    audit = _Audit()
    _digest_manager(audit, WORKING, monkeypatch).send()

    written = json.dumps(audit.entries[0])
    for address in WORKING['channels']['smtp']['to_addresses']:
        assert address not in written, f'{address} was recorded'
    assert 'ops@example.com' not in written


def test_a_failed_send_is_recorded_too(monkeypatch):
    """The case an auditor cares about most: the report that did not go out."""
    audit = _Audit()

    def explode():
        raise OSError('connection refused')

    result = _digest_manager(audit, WORKING, monkeypatch, sendmail=explode).send()

    assert 'error' in result
    assert len(audit.entries) == 1
    assert audit.entries[0]['status'] == 'failed'
    assert 'connection refused' in audit.entries[0]['error']


def test_a_failed_send_still_says_how_many_it_was_for(monkeypatch):
    audit = _Audit()

    def explode():
        raise OSError('nope')

    _digest_manager(audit, WORKING, monkeypatch, sendmail=explode).send()
    assert audit.entries[0]['details']['recipients'] == 2


@pytest.mark.parametrize('config,expected', [
    ({'enabled': False}, 'notifications disabled'),
    ({'enabled': True, 'channels': {'smtp': {'enabled': False}}}, 'SMTP not enabled'),
    ({'enabled': True, 'digest_enabled': False,
      'channels': {'smtp': {'enabled': True}}}, 'digest disabled'),
])
def test_a_configuration_skip_writes_nothing(config, expected, monkeypatch):
    """Deliberate. "Notifications are disabled" is answered by the settings,
    and a weekly entry saying so on every instance that never turned the
    digest on would grow the chain forever to say nothing."""
    audit = _Audit()
    result = _digest_manager(audit, config, monkeypatch).send()

    assert result == {'skipped': expected}
    assert audit.entries == []


def test_an_instance_without_an_audit_logger_still_sends(monkeypatch):
    """The record must never be why the digest stops going out."""
    manager = _digest_manager(_Audit(), WORKING, monkeypatch)
    manager.audit_logger = None
    assert manager.send() == {'success': True}


def test_the_record_is_written_without_a_second_safety_net():
    """`log_operation` catches everything itself — audit writes are
    best-effort by design and never block the operation they describe — so
    wrapping it would add a broad handler that cannot fire, and an exception
    budget entry defending against nothing."""
    import ast
    import inspect
    import textwrap

    from modules.core.digest import WeeklyDigest

    # Parsed, not grepped. The first version searched the source text for
    # 'except' and matched the docstring above, which says why there is none —
    # a check defeated by the sentence explaining it.
    tree = ast.parse(textwrap.dedent(inspect.getsource(WeeklyDigest._record)))
    handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)]
    assert not handlers, (
        'a handler was added around log_operation; it cannot fire, and it '
        'costs a line of the exception budget to say so'
    )


# Fragments that survive the line wrapping. Asserting the whole phrase failed
# on text that was already correct: `**not\n  the recipients themselves**` is
# one sentence to a reader and two lines to a substring search. Third time
# today, so it is written down here.
@pytest.mark.parametrize('page,claim', [
    ('compliance.md', 'the recipients themselves'),
    ('it/compliance.md', 'i destinatari stessi'),
])
def test_the_page_no_longer_says_the_digest_is_outside_the_record(page, claim):
    """`docs/compliance.md` said "The scheduled summary digest is not an audit
    entry and is not sent through the sink". True when written; the opposite
    now, including the part about what is deliberately left out."""
    text = (REPO / 'docs' / page).read_text(encoding='utf-8')
    assert 'is not an\n  audit entry' not in text
    assert 'non è una voce di audit' not in text
    assert claim in text


def test_the_record_reads_only_keys_the_digest_produces():
    """The guard that was missing, and the reason this file was wrong.

    `_record` read `certificates`; `build_digest` returns `server_certs`. Both
    the code and its test used the same invented name, so the test agreed with
    the defect. Comparing the two functions — rather than a fixture against a
    fixture — is what makes that impossible to repeat.
    """
    import inspect
    import re

    from modules.core.digest import WeeklyDigest

    produced = set(re.findall(r"'(\w+)':",
                              inspect.getsource(WeeklyDigest.build_digest)))
    read = set(re.findall(r"'(\w+)': \(digest or \{\}\)",
                          inspect.getsource(WeeklyDigest._record)))

    assert read, 'the record no longer reads the digest at all'
    assert read <= produced, (
        f'_record reads {sorted(read - produced)}, which build_digest does '
        f'not return — the entry would store null for it'
    )


def test_the_siem_gets_it_because_the_chain_does():
    """Stated as a property of the design rather than tested through a sink:
    the sink streams each audit entry, so there was never a second thing to
    fix here, and a future change that gave the digest its own SIEM path
    would be adding a second source for one fact."""
    audit_source = (REPO / 'modules' / 'core' / 'audit.py').read_text(encoding='utf-8')
    assert 'self.audit_sink.send(audit_entry)' in audit_source
