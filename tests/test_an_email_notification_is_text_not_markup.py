"""What an event carries reaches an email as text, not as markup or headers.

The HTML part interpolated the message and each detail as they came, and a
detail can be a domain, an error message or a command's output. The subject
went into its header with any line break in it.
"""
import email
from unittest.mock import MagicMock

import pytest

from tests.test_notifier_coverage import _mk_notifier

pytestmark = [pytest.mark.unit]

CFG = {'host': 'smtp.example.com', 'port': 587, 'from_address': 'noreply@example.com',
       'to_addresses': ['ops@example.com'], 'use_tls': False}


def _sent(tmp_path, monkeypatch, subject, body, details):
    smtp = MagicMock()
    monkeypatch.setattr('modules.core.notifier.smtplib.SMTP', MagicMock(return_value=smtp))
    assert _mk_notifier(tmp_path, {})._send_email(CFG, subject, body, details=details).get('success')
    return email.message_from_string(smtp.sendmail.call_args[0][2])


def _html(message):
    return next(part.get_payload(decode=True).decode() for part in message.walk()
                if part.get_content_type() == 'text/html')


def test_the_message_and_details_are_escaped(tmp_path, monkeypatch):
    message = _sent(tmp_path, monkeypatch, 'Renewal failed', 'stderr: <b>boom</b>',
                    {'<i>key</i>': '<img src=x>'})
    html = _html(message)
    assert '<b>boom</b>' not in html and '&lt;b&gt;boom&lt;/b&gt;' in html
    assert '<img' not in html and '&lt;img src=x&gt;' in html
    assert '<i>key</i>' not in html


def test_a_line_break_in_the_subject_starts_no_header(tmp_path, monkeypatch):
    message = _sent(tmp_path, monkeypatch, 'Renewal failed\r\nBcc: someone@example.com', 'body', None)
    assert message['Bcc'] is None
    assert 'Bcc: someone@example.com' in message['Subject']
