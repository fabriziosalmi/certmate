"""Unit tests for modules/core/notifier.py.

Webhook delivery + SMTP + delivery-log lifecycle. Network is fully
mocked — no live HTTP calls, no SMTP connections. The Notifier was at
~14% coverage before this file landed.
"""

import hashlib
import hmac
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk_notifier(tmp_path, settings):
    """Build a Notifier wrapping a stub settings_manager + isolated
    delivery log under tmp_path."""
    from modules.core.notifier import Notifier
    sm = MagicMock()
    sm.load_settings.return_value = settings
    return Notifier(sm, data_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# notify() — top-level dispatch and gating
# ---------------------------------------------------------------------------


class TestNotifyDispatch:
    def test_returns_skipped_when_globally_disabled(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {'notifications': {'enabled': False}})
        result = notifier.notify('certificate_created', 'Test', 'Hello')
        assert result == {'skipped': 'notifications disabled'}

    def test_returns_skipped_when_event_not_in_filter(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {
            'notifications': {
                'enabled': True,
                'events': ['certificate_expiring'],
            }
        })
        result = notifier.notify('certificate_created', 'Test', 'Hello')
        assert result == {'skipped': 'event not in filter'}

    def test_no_channel_configured_returns_empty(self, tmp_path):
        """Enabled + matching event but no channel → empty result dict.
        Avoids crashing when notifications are enabled but the operator
        hasn't wired any channel yet."""
        notifier = _mk_notifier(tmp_path, {
            'notifications': {'enabled': True, 'channels': {}}
        })
        result = notifier.notify('certificate_created', 'Test', 'Hello')
        assert result == {}

    def test_dispatches_to_smtp_when_enabled(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {
            'notifications': {
                'enabled': True,
                'channels': {
                    'smtp': {'enabled': True, 'host': 'smtp.example.com'},
                }
            }
        })
        with patch.object(notifier, '_send_email', return_value={'success': True}) as send:
            notifier.notify('certificate_created', 'Subj', 'Body', details={'k': 'v'})
            send.assert_called_once()

    def test_per_webhook_event_filter_drops_non_matching(self, tmp_path):
        """A webhook can declare its own event subset; events outside that
        subset must not fire that webhook even if the global event filter
        accepts them."""
        notifier = _mk_notifier(tmp_path, {
            'notifications': {
                'enabled': True,
                'channels': {
                    'webhooks': [
                        {
                            'name': 'only-expiring',
                            'enabled': True,
                            'events': ['certificate_expiring'],
                            'url': 'https://example.test/wh',
                            'type': 'generic',
                        },
                    ]
                }
            }
        })
        with patch.object(notifier, '_send_webhook_with_retry') as send:
            result = notifier.notify('certificate_created', 'Subj', 'Body')
        send.assert_not_called()
        assert 'only-expiring' not in result

    def test_disabled_webhook_skipped(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {
            'notifications': {
                'enabled': True,
                'channels': {
                    'webhooks': [
                        {'name': 'off', 'enabled': False, 'url': 'https://x', 'type': 'generic'},
                    ]
                }
            }
        })
        with patch.object(notifier, '_send_webhook_with_retry') as send:
            result = notifier.notify('certificate_created', 'Subj', 'Body')
        send.assert_not_called()
        assert 'off' not in result


# ---------------------------------------------------------------------------
# Webhook payload shape (Slack / Discord / generic) and URL guards
# ---------------------------------------------------------------------------


class TestSendWebhookPayload:
    def _capture_urlopen(self, monkeypatch):
        """Replace urlopen with a recorder that captures the Request +
        returns a context-managed fake response."""
        captured = {}

        class _FakeResponse:
            status = 200
            def __enter__(self_inner): return self_inner
            def __exit__(self_inner, *a): return False

        def fake_urlopen(req, timeout=None):
            captured['url'] = req.full_url
            captured['method'] = req.get_method()
            captured['headers'] = dict(req.header_items())
            captured['body'] = req.data
            return _FakeResponse()

        monkeypatch.setattr('modules.core.notifier.urlopen', fake_urlopen)
        return captured

    def test_generic_webhook_posts_json_with_user_agent(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        captured = self._capture_urlopen(monkeypatch)

        result = notifier._send_webhook(
            {'url': 'https://example.test/wh', 'type': 'generic', 'name': 'test'},
            'test', 'Title', 'Message', {'cert': 'example.com'},
        )

        assert result == {'success': True, 'status': 200}
        assert captured['url'] == 'https://example.test/wh'
        assert captured['method'] == 'POST'
        # User-Agent + Content-Type set; header keys are title-cased by urllib.
        assert captured['headers'].get('User-agent') == 'CertMate-Webhook/2.0'
        assert captured['headers'].get('Content-type') == 'application/json'
        # The body is the generic envelope.
        body = json.loads(captured['body'].decode())
        assert body['event'] == 'test'
        assert body['title'] == 'Title'
        assert body['message'] == 'Message'
        assert body['details'] == {'cert': 'example.com'}
        assert body['timestamp'].endswith('Z')

    def test_slack_payload_shape(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        captured = self._capture_urlopen(monkeypatch)

        notifier._send_webhook(
            {'url': 'https://hooks.slack.test/srv', 'type': 'slack', 'name': 'sl'},
            'event', 'Cert renewed', 'foo.example.com renewed', {'days_left': 90},
        )

        body = json.loads(captured['body'].decode())
        # Slack envelope: top-level text + blocks (header + section + section with fields)
        assert body['text'] == '*Cert renewed*\nfoo.example.com renewed'
        assert isinstance(body['blocks'], list)
        block_types = [b['type'] for b in body['blocks']]
        assert 'header' in block_types and 'section' in block_types

    def test_discord_payload_shape(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        captured = self._capture_urlopen(monkeypatch)

        notifier._send_webhook(
            {'url': 'https://discord.test/api/webhooks/x/y', 'type': 'discord', 'name': 'd'},
            'event', 'Cert created', 'bar.example.com', {'provider': 'cloudflare'},
        )

        body = json.loads(captured['body'].decode())
        # Discord envelope: embeds[0].title/description/fields.
        assert 'embeds' in body
        embed = body['embeds'][0]
        assert embed['title'] == 'Cert created'
        assert embed['description'] == 'bar.example.com'
        assert {f['name'] for f in embed['fields']} == {'provider'}

    def test_hmac_signature_only_added_for_generic_when_secret_present(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        captured = self._capture_urlopen(monkeypatch)

        notifier._send_webhook(
            {'url': 'https://x.test/wh', 'type': 'generic', 'secret': 's3cret', 'name': 'g'},
            'event', 'T', 'M',
        )
        sig_header = captured['headers'].get('X-certmate-signature')
        assert sig_header is not None
        # Header shape: "t=<unixsec>,v1=<sha256-hex>"
        assert sig_header.startswith('t=')
        assert ',v1=' in sig_header

    def test_no_signature_when_secret_missing(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        captured = self._capture_urlopen(monkeypatch)

        notifier._send_webhook(
            {'url': 'https://x.test/wh', 'type': 'generic', 'name': 'g'},
            'event', 'T', 'M',
        )
        assert 'X-certmate-signature' not in captured['headers']

    def test_signature_skipped_for_slack_discord(self, tmp_path, monkeypatch):
        """Slack/Discord use their own auth (the secret URL) — adding our
        signature header is pointless and would pollute their payload
        validation."""
        notifier = _mk_notifier(tmp_path, {})
        captured = self._capture_urlopen(monkeypatch)
        notifier._send_webhook(
            {'url': 'https://hooks.slack.test/srv', 'type': 'slack', 'secret': 'x', 'name': 'sl'},
            'event', 'T', 'M',
        )
        assert 'X-certmate-signature' not in captured['headers']

    def test_missing_url_returns_error(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        result = notifier._send_webhook(
            {'type': 'generic', 'name': 'no-url'}, 'event', 'T', 'M',
        )
        assert 'error' in result and 'URL' in result['error']

    def test_non_http_scheme_rejected(self, tmp_path):
        """Defense in depth: a file://, ftp://, or javascript: URL must be
        refused to prevent the webhook channel from being used as an
        exfiltration vector."""
        notifier = _mk_notifier(tmp_path, {})
        for scheme in ('file:///etc/passwd', 'ftp://x', 'gopher://x', 'javascript:alert(1)'):
            result = notifier._send_webhook(
                {'url': scheme, 'type': 'generic', 'name': 'attack'},
                'event', 'T', 'M',
            )
            assert 'error' in result, f"scheme {scheme!r} should have been refused"
            assert 'http' in result['error'].lower()

    def test_urlerror_returns_error_dict(self, tmp_path, monkeypatch):
        from urllib.error import URLError

        def fake_urlopen(req, timeout=None):
            raise URLError('connection refused')

        monkeypatch.setattr('modules.core.notifier.urlopen', fake_urlopen)
        notifier = _mk_notifier(tmp_path, {})
        result = notifier._send_webhook(
            {'url': 'https://x.test/wh', 'type': 'generic', 'name': 'g'},
            'event', 'T', 'M',
        )
        assert 'error' in result
        # No success flag set on the failure path.
        assert not result.get('success')

    def test_custom_headers_applied_for_generic_only(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        captured = self._capture_urlopen(monkeypatch)

        notifier._send_webhook(
            {
                'url': 'https://x.test/wh',
                'type': 'generic',
                'name': 'g',
                'headers': {'X-Tenant': 'acme', 'X-Trace-Id': 'abc123'},
            },
            'event', 'T', 'M',
        )
        # urllib title-cases header names.
        assert captured['headers'].get('X-tenant') == 'acme'
        assert captured['headers'].get('X-trace-id') == 'abc123'


# ---------------------------------------------------------------------------
# Retry wrapper around _send_webhook
# ---------------------------------------------------------------------------


class TestWebhookRetry:
    def test_first_attempt_success_does_not_retry(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)

        send_mock = MagicMock(return_value={'success': True, 'status': 200})
        with patch.object(notifier, '_send_webhook', send_mock):
            result = notifier._send_webhook_with_retry(
                {'url': 'https://x', 'type': 'generic', 'name': 'g'},
                'event', 'T', 'M',
            )
        assert result == {'success': True, 'status': 200}
        assert send_mock.call_count == 1

    def test_retries_on_failure_until_success(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)

        # Two failures then one success.
        send_mock = MagicMock(side_effect=[
            {'error': 'temp 1'},
            {'error': 'temp 2'},
            {'success': True, 'status': 200},
        ])
        with patch.object(notifier, '_send_webhook', send_mock):
            result = notifier._send_webhook_with_retry(
                {'url': 'https://x', 'type': 'generic', 'name': 'g'},
                'event', 'T', 'M',
            )
        assert result == {'success': True, 'status': 200}
        assert send_mock.call_count == 3

    def test_returns_last_error_after_max_retries(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)
        send_mock = MagicMock(return_value={'error': 'always-fails'})
        with patch.object(notifier, '_send_webhook', send_mock):
            result = notifier._send_webhook_with_retry(
                {'url': 'https://x', 'type': 'generic', 'name': 'g'},
                'event', 'T', 'M',
            )
        assert result == {'error': 'always-fails'}
        assert send_mock.call_count == 3  # max_retries default


class TestSmtpRetry:
    """SMTP must follow the same retry/backoff + delivery-log contract as
    webhooks (P-03: it previously had neither)."""

    def _smtp_settings(self):
        return {
            'notifications': {
                'enabled': True,
                'channels': {
                    'smtp': {'enabled': True, 'host': 'smtp.example.com',
                             'to_addresses': ['ops@example.com']},
                }
            }
        }

    def test_retries_on_failure_until_success(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, self._smtp_settings())
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)
        send_mock = MagicMock(side_effect=[
            {'error': 'connect refused'},
            {'success': True},
        ])
        with patch.object(notifier, '_send_email', send_mock):
            result = notifier.notify('certificate_created', 'T', 'M')
        assert result['smtp'] == {'success': True}
        assert send_mock.call_count == 2

    def test_returns_last_error_after_max_retries(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, self._smtp_settings())
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)
        send_mock = MagicMock(return_value={'error': 'always-fails'})
        with patch.object(notifier, '_send_email', send_mock):
            result = notifier.notify('certificate_created', 'T', 'M')
        assert result['smtp'] == {'error': 'always-fails'}
        assert send_mock.call_count == 3

    def test_config_error_is_not_retried(self, tmp_path, monkeypatch):
        """'SMTP not fully configured' is static — retrying just burns 3s."""
        notifier = _mk_notifier(tmp_path, self._smtp_settings())
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)
        send_mock = MagicMock(return_value={'error': 'SMTP not fully configured'})
        with patch.object(notifier, '_send_email', send_mock):
            notifier.notify('certificate_created', 'T', 'M')
        assert send_mock.call_count == 1

    def test_smtp_failures_land_in_delivery_log(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, self._smtp_settings())
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)
        send_mock = MagicMock(return_value={'error': 'boom'})
        with patch.object(notifier, '_send_email', send_mock):
            notifier.notify('certificate_created', 'T', 'M')
        deliveries = notifier.get_deliveries()
        assert len(deliveries) == 1
        entry = deliveries[0]
        assert entry['webhook_name'] == 'smtp'
        assert entry['webhook_type'] == 'smtp'
        assert entry['event'] == 'certificate_created'
        assert entry['success'] is False
        assert entry['attempts'] == 3
        assert entry['error'] == 'boom'

    def test_smtp_success_logged_with_single_attempt(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, self._smtp_settings())
        monkeypatch.setattr('time.sleep', lambda *_a, **_k: None)
        with patch.object(notifier, '_send_email', return_value={'success': True}):
            notifier.notify('certificate_created', 'T', 'M')
        entry = notifier.get_deliveries()[0]
        assert entry['success'] is True
        assert entry['attempts'] == 1


# ---------------------------------------------------------------------------
# Delivery log: write + read + truncation cap
# ---------------------------------------------------------------------------


class TestDeliveryLog:
    def test_log_delivery_writes_jsonl_entry(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        notifier._log_delivery(
            {'name': 'g', 'type': 'generic', 'url': 'https://x'},
            'event_x', {'success': True, 'status': 200}, attempts=1, duration_ms=42,
        )
        log_path = Path(tmp_path) / 'webhook_deliveries.jsonl'
        assert log_path.exists()
        line = log_path.read_text().strip()
        entry = json.loads(line)
        assert entry['webhook_name'] == 'g'
        assert entry['success'] is True
        assert entry['status'] == 200
        assert entry['attempts'] == 1
        assert entry['duration_ms'] == 42

    def test_get_deliveries_returns_newest_first(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        for i in range(5):
            notifier._log_delivery(
                {'name': f'w{i}', 'type': 'generic'}, 'evt',
                {'success': True, 'status': 200}, attempts=1, duration_ms=1,
            )
        deliveries = notifier.get_deliveries(limit=10)
        # Newest first → w4 at index 0.
        names = [d['webhook_name'] for d in deliveries]
        assert names == ['w4', 'w3', 'w2', 'w1', 'w0']

    def test_get_deliveries_respects_limit(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        for i in range(5):
            notifier._log_delivery(
                {'name': f'w{i}', 'type': 'generic'}, 'evt',
                {'success': True}, attempts=1, duration_ms=1,
            )
        deliveries = notifier.get_deliveries(limit=2)
        assert len(deliveries) == 2

    def test_get_deliveries_returns_empty_when_no_log(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        assert notifier.get_deliveries() == []

    def test_get_deliveries_swallows_malformed_lines(self, tmp_path):
        """A corrupted log file (truncated mid-line, manual edit) must not
        crash the deliveries view — it falls back to []."""
        notifier = _mk_notifier(tmp_path, {})
        log_path = Path(tmp_path) / 'webhook_deliveries.jsonl'
        log_path.write_text('{"valid": true}\nthis is not JSON\n')
        # Either drops the bad line or returns [] — current impl returns [].
        # Pin "doesn't raise" as the actual contract.
        assert notifier.get_deliveries() == []

    def test_truncate_keeps_last_max_entries(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        notifier.MAX_DELIVERY_LOG_ENTRIES = 3  # smaller cap for the test

        # Write 5 entries — should be truncated to last 3.
        for i in range(5):
            notifier._log_delivery(
                {'name': f'w{i}', 'type': 'generic'}, 'evt',
                {'success': True}, attempts=1, duration_ms=1,
            )

        log_path = Path(tmp_path) / 'webhook_deliveries.jsonl'
        lines = [ln for ln in log_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 3
        # The retained entries are the most recent three (w2, w3, w4).
        kept_names = [json.loads(ln)['webhook_name'] for ln in lines]
        assert kept_names == ['w2', 'w3', 'w4']


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------


class TestSendEmail:
    def test_smtp_send_success_path(self, tmp_path, monkeypatch):
        notifier = _mk_notifier(tmp_path, {})

        # The implementation uses smtplib.SMTP directly (not via context
        # manager) and calls server.starttls() + login() + sendmail() +
        # quit(). Mock the class so each method is a MagicMock that we
        # can assert against.
        smtp_instance = MagicMock()
        smtp_class = MagicMock(return_value=smtp_instance)
        monkeypatch.setattr('modules.core.notifier.smtplib.SMTP', smtp_class)

        result = notifier._send_email(
            {
                'host': 'smtp.example.com',
                'port': 587,
                'username': 'u',
                'password': 'p',
                'from_address': 'noreply@example.com',
                'to_addresses': ['ops@example.com'],
                'use_tls': True,
            },
            'Subject', 'Body', details={'extra': 'x'},
        )
        assert result.get('success') is True
        smtp_class.assert_called_once_with('smtp.example.com', 587, timeout=10)
        smtp_instance.starttls.assert_called_once()
        smtp_instance.login.assert_called_once_with('u', 'p')
        smtp_instance.sendmail.assert_called_once()
        smtp_instance.quit.assert_called_once()
        # Sendmail args: (from_addr, to_addrs, msg_as_string).
        args = smtp_instance.sendmail.call_args.args
        assert args[0] == 'noreply@example.com'
        assert args[1] == ['ops@example.com']
        assert '[CertMate] Subject' in args[2]

    def test_smtp_no_recipients_returns_error(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        result = notifier._send_email(
            {'host': 'smtp.example.com', 'to_addresses': []},
            'Subj', 'Body',
        )
        # Empty recipients → error dict (no success). Don't pin the exact
        # message; just confirm it didn't claim success.
        assert not result.get('success')

    def test_smtp_connect_failure_returns_error(self, tmp_path, monkeypatch):
        def raise_oserror(*a, **kw):
            raise OSError('connection refused')

        monkeypatch.setattr('modules.core.notifier.smtplib.SMTP', raise_oserror)
        notifier = _mk_notifier(tmp_path, {})
        result = notifier._send_email(
            {
                'host': 'smtp.example.com', 'port': 587,
                'from_address': 'a@x', 'to_addresses': ['b@x'],
            },
            'Subj', 'Body',
        )
        assert not result.get('success')
        assert 'error' in result


# ---------------------------------------------------------------------------
# test_channel() — dispatches to the right private method
# ---------------------------------------------------------------------------


class TestTestChannel:
    def test_smtp_dispatch(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        with patch.object(notifier, '_send_email', return_value={'success': True}) as send:
            notifier.test_channel('smtp', {'host': 'x'})
            send.assert_called_once()

    def test_webhook_dispatch(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        with patch.object(notifier, '_send_webhook', return_value={'success': True}) as send:
            notifier.test_channel('webhook', {'url': 'https://x', 'type': 'generic'})
            send.assert_called_once()

    def test_unknown_channel_returns_error(self, tmp_path):
        notifier = _mk_notifier(tmp_path, {})
        result = notifier.test_channel('telegram', {})
        assert 'error' in result
