"""deploy_hook_failed must reach the operator even with an event filter set.

deploy_hook_failed is the silent-deploy alarm: a renewal succeeds but its deploy
hook (nginx reload, LB push) exits non-zero, so the service keeps serving the OLD
certificate while the dashboard says success. The events UI offers only the five
certificate_* events, so an operator who ticks any of them sets a filter that
does not include deploy_hook_failed and permanently silences exactly the alert it
exists to raise. Critical failure events now bypass both the global and the
per-webhook event filter.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.notifier import Notifier, _ALWAYS_NOTIFY_EVENTS

pytestmark = [pytest.mark.unit]


def _notifier(config):
    n = Notifier(settings_manager=MagicMock(), data_dir='/nonexistent')
    n._get_config = lambda: config
    sent = []
    n._send_webhook_with_retry = (
        lambda *a, **k: sent.append(a[1]) or {'success': True})
    n._send_email_with_retry = (
        lambda *a, **k: sent.append(a[1]) or {'success': True})
    return n, sent


_WH = {'name': 'w', 'enabled': True, 'type': 'generic', 'url': 'https://x'}


def test_deploy_hook_failed_bypasses_a_global_filter():
    n, sent = _notifier({'enabled': True, 'events': ['certificate_renewed'],
                         'channels': {'webhooks': [dict(_WH)]}})
    n.notify('deploy_hook_failed', 't', 'm', {})
    assert 'deploy_hook_failed' in sent


def test_deploy_hook_failed_bypasses_a_per_webhook_filter():
    wh = dict(_WH, events=['certificate_renewed'])
    n, sent = _notifier({'enabled': True, 'events': [],
                         'channels': {'webhooks': [wh]}})
    n.notify('deploy_hook_failed', 't', 'm', {})
    assert 'deploy_hook_failed' in sent


def test_a_non_critical_event_still_honours_the_filter():
    """CONTROL: the exemption is narrow — an ordinary event the operator
    filtered out stays filtered."""
    n, sent = _notifier({'enabled': True, 'events': ['certificate_renewed'],
                         'channels': {'webhooks': [dict(_WH)]}})
    r = n.notify('certificate_created', 't', 'm', {})
    assert r.get('skipped') == 'event not in filter'
    assert 'certificate_created' not in sent


def test_the_master_switch_still_wins():
    """CONTROL: 'notifications disabled' is not bypassed — a critical event is
    silenced when the whole system is off, unlike a mere filter."""
    n, sent = _notifier({'enabled': False})
    r = n.notify('deploy_hook_failed', 't', 'm', {})
    assert 'skipped' in r
    assert sent == []


def test_deploy_hook_failed_is_in_the_always_notify_set():
    assert 'deploy_hook_failed' in _ALWAYS_NOTIFY_EVENTS
