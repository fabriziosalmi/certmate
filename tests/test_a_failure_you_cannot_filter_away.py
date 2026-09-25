"""certificate_failed reaches the operator whatever the event filter says.

The report (#943) was "notification webhook does not fire on errors". The
webhook fired correctly for everything it was asked to send; what the operator
had not been told is that asking for anything at all is how you stop being told
about failures. Tick `renewed` to hear about successful renewals and the
`events` list becomes `['certificate_renewed']` — which excludes
`certificate_failed`, the event a renewal that did NOT happen publishes. The
filter was working. It was the only setting in the product where choosing what
you want to hear silently chooses what you will never hear.

`deploy_hook_failed` and `certificate_deploy_incomplete` were exempted from the
filter for exactly that reason in an earlier release. `certificate_failed` was
not, although it is the plainer case: a certificate that did not renew expires,
and then the site stops working. It is exempt now, and has no checkbox, because
a checkbox implies a choice that does not exist.

These tests go through the real Notifier and a real HTTP receiver rather than a
stubbed sender, because the claim is that the message *arrives* — a filter that
lets the event through to a send that then refuses it would satisfy a stub and
fail an operator.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock

import pytest

from modules.core.notifier import Notifier, _ALWAYS_NOTIFY_EVENTS

pytestmark = [pytest.mark.unit]


class _Receiver:
    """An operator's webhook endpoint: records the JSON bodies it is POSTed."""

    def __init__(self):
        self.bodies = []
        receiver = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                clen = int(self.headers.get('Content-Length', 0) or 0)
                raw = self.rfile.read(clen) if clen else b'{}'
                receiver.bodies.append(json.loads(raw.decode('utf-8')))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f'http://127.0.0.1:{self.srv.server_port}/hook'

    @property
    def events(self):
        return [b.get('event') for b in self.bodies]

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def receiver(monkeypatch):
    # The receiver is on loopback, which the SSRF guard refuses by default.
    # This is the same switch an operator uses for an internal endpoint.
    monkeypatch.setenv('CERTMATE_ALLOW_INTERNAL_WEBHOOKS', 'true')
    r = _Receiver()
    yield r
    r.stop()


def _notifier(config):
    n = Notifier(settings_manager=MagicMock(), data_dir='/nonexistent')
    n._get_config = lambda: config
    return n


def _config(receiver, *, global_events, webhook_events):
    """What the operator in #943 had: a filter picked to hear about renewals."""
    return {
        'enabled': True,
        'events': global_events,
        'channels': {'webhooks': [{
            'name': 'ops', 'enabled': True, 'type': 'generic',
            'url': receiver.url, 'events': webhook_events,
        }]},
    }


def test_a_renewal_failure_arrives_although_the_global_filter_excludes_it(receiver):
    n = _notifier(_config(receiver, global_events=['certificate_renewed'],
                          webhook_events=[]))
    n.notify('certificate_failed', 'Renewal failed',
             'certbot exited 1', {'domain': 'example.com'})
    assert receiver.events == ['certificate_failed']
    assert receiver.bodies[0]['details']['domain'] == 'example.com'


def test_a_renewal_failure_arrives_although_the_webhook_filter_excludes_it(receiver):
    n = _notifier(_config(receiver, global_events=[],
                          webhook_events=['certificate_renewed']))
    n.notify('certificate_failed', 'Renewal failed', 'certbot exited 1', {})
    assert receiver.events == ['certificate_failed']


def test_a_renewal_failure_arrives_although_both_filters_exclude_it(receiver):
    """Both lists are narrowing, neither names the event: it still arrives.

    Two filters that each individually let critical events through could still
    be composed wrongly — the per-webhook loop is reached only after the global
    check returns, so this is the path the operator actually configures."""
    n = _notifier(_config(receiver, global_events=['certificate_renewed'],
                          webhook_events=['certificate_created']))
    n.notify('certificate_failed', 'Renewal failed', 'certbot exited 1', {})
    assert receiver.events == ['certificate_failed']


def test_an_expiry_warning_with_the_same_filter_does_not_arrive(receiver):
    """CONTROL: the exemption is narrow.

    certificate_expiring is a warning about the future and stays filterable —
    if it arrived here too, the tests above would prove nothing except that the
    filter had stopped working."""
    n = _notifier(_config(receiver, global_events=['certificate_renewed'],
                          webhook_events=[]))
    result = n.notify('certificate_expiring', 'Expiring', 'soon', {})
    assert result.get('skipped') == 'event not in filter'
    assert receiver.events == []


def test_the_master_switch_still_silences_it(receiver):
    """CONTROL: exempt from the filter is not exempt from being switched off.

    An operator who turns notifications off has said something unambiguous.
    Only the filter — a setting about *which* messages — is overridden."""
    n = _notifier({'enabled': False})
    result = n.notify('certificate_failed', 'Renewal failed', 'boom', {})
    assert result == {'skipped': 'notifications disabled'}
    assert receiver.events == []


def test_the_settings_page_says_failures_are_always_sent():
    """The chip did not just disappear — the page explains why it is gone.

    Removing the checkbox without a word would read, to the operator who filed
    #943, as the option being taken away. What the page must say is the
    opposite: this one is not yours to switch off."""
    from pathlib import Path
    page = Path('templates/partials/settings_notifications.html').read_text()
    both_lists = page.lower().count('always sent')
    assert both_lists == 2, (
        'the global "Notify on Events" list and the per-webhook list each need '
        f'to say that failures are always sent; found {both_lists} of 2')


def test_certificate_failed_has_no_checkbox():
    """Anchors the UI half of the fix to the report.

    tests/test_every_filterable_event_is_selectable.py already derives the
    whole selectable set from the backend's two sets; this one names the event
    #943 was about, so deleting it from _ALWAYS_NOTIFY_EVENTS later fails a
    test that says which report it would be reopening."""
    from pathlib import Path
    assert 'certificate_failed' in _ALWAYS_NOTIFY_EVENTS
    js = Path('static/js/settings-notifications.js').read_text()
    listed = js.split('notifiableEvents:', 1)[1].split(']', 1)[0]
    assert "'certificate_failed'" not in listed
