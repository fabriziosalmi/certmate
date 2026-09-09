"""A receiver that answers 404 answers 404 to the identical retry.

`_send_webhook_with_retry` left the loop on success and on nothing else. So a
webhook pointing at a URL the receiver does not serve — a Slack app removed, a
path typo, a token revoked into a 401 — was sent three times with 1s + 2s of
sleep between the attempts, on every notification, for as long as it stayed
configured. Under a renewal sweep that is once per certificate, on the sweep's
own thread.

`_send_email_with_retry`, ten lines above it in the same file, already had the
shape: it leaves the loop when the failure is a static configuration problem,
because retrying cannot change one. The webhook path had the same idea started
and never finished — `config_error: True` was set by two of the return paths in
`_send_webhook` and read by nobody.

Two kinds of failure are now permanent:

* the receiver answered and said no, with a 4xx that describes the request
  rather than the moment. 408, 425 and 429 are excluded: those describe this
  attempt. 5xx is the server's problem and is exactly what backoff is for;
* CertMate refused to send at all — no URL, a scheme that is not http(s), an
  SSRF-guarded target, a channel missing its token, a broken payload template.
  Nothing about any of those changes in four seconds.

Everything else still gets the full backoff: DNS, connection refused, TLS,
timeouts, 5xx.
"""
import json
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from modules.core.notifier import Notifier

pytestmark = [pytest.mark.unit]


def _notifier(tmp_path, webhook=None):
    settings = {'notifications': {
        'enabled': True,
        'events': ['certificate_created'],
        'channels': {'webhooks': [webhook or {
            'name': 'wh', 'type': 'generic', 'enabled': True,
            'url': 'https://example.com/hook'}]},
    }}
    manager = MagicMock()
    manager.load_settings.return_value = settings
    return Notifier(manager, data_dir=str(tmp_path))


def _attempts(notifier, result, monkeypatch):
    """Run one notification with `_send_webhook` stubbed, counting attempts."""
    monkeypatch.setattr('time.sleep', lambda *a, **k: None)
    send = MagicMock(return_value=result)
    with patch.object(notifier, '_send_webhook', send):
        notifier.notify('certificate_created', 'T', 'M')
    return send.call_count


# --- THE regression -------------------------------------------------------

@pytest.mark.parametrize('status', [400, 401, 403, 404, 410, 422])
def test_a_rejected_request_is_sent_once(tmp_path, monkeypatch, status):
    notifier = _notifier(tmp_path)

    assert _attempts(notifier, {'error': f'HTTP {status}', 'status': status,
                                'permanent': True}, monkeypatch) == 1


@pytest.mark.parametrize('status', [408, 425, 429, 500, 502, 503])
def test_a_failure_that_may_pass_still_gets_the_backoff(tmp_path, monkeypatch,
                                                        status):
    """CONTROL, and the half that must not change: 429 says come back, 5xx is
    the receiver's problem, and both are what retrying is for."""
    notifier = _notifier(tmp_path)
    permanent = _permanent(status)

    assert not permanent
    assert _attempts(notifier, {'error': f'HTTP {status}', 'status': status,
                                'permanent': permanent}, monkeypatch) == 3


def test_a_transport_failure_still_gets_the_backoff(tmp_path, monkeypatch):
    """CONTROL. DNS, connection refused, TLS, timeout: no status at all, and
    every one of them can succeed on the next attempt."""
    notifier = _notifier(tmp_path)

    assert _attempts(notifier, {'error': 'connection refused'}, monkeypatch) == 3


def test_a_refusal_to_send_is_not_retried(tmp_path, monkeypatch):
    """The other permanent kind: CertMate never reached the network."""
    notifier = _notifier(tmp_path)

    assert _attempts(notifier, {'error': 'Webhook URL not configured',
                                'config_error': True}, monkeypatch) == 1


# --- the classification itself -------------------------------------------

def _permanent(status):
    from modules.core.notifier import _is_permanent_http_status
    return _is_permanent_http_status(status)


@pytest.mark.parametrize('status,expected', [
    (400, True), (401, True), (403, True), (404, True), (410, True),
    (408, False),   # Request Timeout: about this attempt
    (425, False),   # Too Early
    (429, False),   # Too Many Requests: explicitly "come back"
    (500, False), (502, False), (503, False),
    (200, False), (302, False),
    (None, False), ('nonsense', False),
])
def test_what_counts_as_permanent(status, expected):
    assert _permanent(status) is expected


# --- the static refusals all say so --------------------------------------

@pytest.mark.parametrize('cfg,fragment', [
    ({'name': 'w', 'type': 'generic', 'url': ''}, 'not configured'),
    ({'name': 'w', 'type': 'generic', 'url': 'ftp://x/y'}, 'http or https'),
    ({'name': 'w', 'type': 'telegram'}, 'token and chat_id'),
    ({'name': 'w', 'type': 'gotify', 'url': 'https://x/'}, 'url and token'),
    ({'name': 'w', 'type': 'generic', 'url': 'https://example.com/h',
      'method': 'TRACE'}, 'method must be one of'),
    ({'name': 'w', 'type': 'generic', 'url': 'https://example.com/h',
      'auth_type': 'bearer'}, 'auth_token'),
])
def test_every_refusal_to_send_is_marked(tmp_path, cfg, fragment):
    """Each of these was a `return {'error': ...}` the retry loop could not
    tell from a connection reset."""
    notifier = _notifier(tmp_path)

    result = notifier._send_webhook(cfg, 'certificate_created', 'T', 'M')

    assert fragment in result['error']
    assert result.get('config_error') is True, (
        f'"{result["error"]}" is a static configuration problem but is not '
        f'marked as one, so it is retried with the full backoff')


def test_the_ssrf_refusal_is_marked(tmp_path, monkeypatch):
    """CertMate declined to send this one on purpose. Trying again three times
    declines three times."""
    monkeypatch.delenv('CERTMATE_ALLOW_INTERNAL_WEBHOOKS', raising=False)
    notifier = _notifier(tmp_path)

    result = notifier._send_webhook(
        {'name': 'w', 'type': 'generic', 'url': 'http://127.0.0.1:8080/hook'},
        'certificate_created', 'T', 'M')

    assert 'SSRF' in result['error']
    assert result.get('config_error') is True


# --- the status reaches the caller and the log ---------------------------

def test_an_http_rejection_carries_its_status(tmp_path):
    """It used to arrive as `HTTP Error 404: Not Found` in a free-text error
    field, so the delivery log recorded status None for every failure and an
    operator could not tell a 404 from a DNS failure without reading prose."""
    notifier = _notifier(tmp_path)

    def _raise(*args, **kwargs):
        raise HTTPError('https://example.com/hook', 404, 'Not Found', {}, None)

    with patch('modules.core.notifier.urlopen', _raise):
        result = notifier._send_webhook(
            {'name': 'w', 'type': 'generic', 'url': 'https://example.com/hook'},
            'certificate_created', 'T', 'M')

    assert result['status'] == 404
    assert result['permanent'] is True
    assert not result.get('success')


def test_a_transport_failure_carries_no_status(tmp_path):
    """CONTROL for the branch above: URLError is not an answer from anyone."""
    notifier = _notifier(tmp_path)

    def _raise(*args, **kwargs):
        raise URLError('name or service not known')

    with patch('modules.core.notifier.urlopen', _raise):
        result = notifier._send_webhook(
            {'name': 'w', 'type': 'generic', 'url': 'https://example.com/hook'},
            'certificate_created', 'T', 'M')

    assert 'status' not in result
    assert not result.get('permanent')


def test_the_delivery_log_records_one_attempt(tmp_path, monkeypatch):
    """What an operator sees afterwards. Three attempts against a 404 read as
    a flaky receiver; one attempt reads as a webhook to fix."""
    notifier = _notifier(tmp_path)
    _attempts(notifier, {'error': 'HTTP 404: Not Found', 'status': 404,
                         'permanent': True}, monkeypatch)

    entry = notifier.get_deliveries()[0]

    assert entry['attempts'] == 1
    assert entry['status'] == 404
    assert entry['success'] is False


def test_the_email_path_is_unchanged(tmp_path, monkeypatch):
    """CONTROL. SMTP already had this shape and is what the webhook path was
    modelled on; it must not have been disturbed."""
    settings = {'notifications': {
        'enabled': True, 'events': ['certificate_created'],
        'channels': {'smtp': {
            'enabled': True, 'host': 'smtp.example.com', 'port': 587,
            'from_address': 'a@example.com',
            'to_addresses': ['b@example.com']}},
    }}
    manager = MagicMock()
    manager.load_settings.return_value = settings
    notifier = Notifier(manager, data_dir=str(tmp_path))
    monkeypatch.setattr('time.sleep', lambda *a, **k: None)

    send = MagicMock(return_value={'error': 'SMTP not fully configured'})
    with patch.object(notifier, '_send_email', send):
        notifier.notify('certificate_created', 'T', 'M')

    assert send.call_count == 1


def test_the_retry_loop_reads_both_markers():
    """A guard on the shape: the loop must consult the marker `_send_webhook`
    sets, not re-derive the decision from the error string."""
    import inspect

    source = inspect.getsource(Notifier._send_webhook_with_retry)

    assert "result.get('config_error')" in source
    assert "result.get('permanent')" in source
    assert json is not None
