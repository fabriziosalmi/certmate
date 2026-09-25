"""A saved webhook URL shows its origin and nothing else (#944).

The URL is masked on read because it IS the credential: for Slack, Discord, ntfy
and Gotify the incoming-webhook URL embeds the bearer secret. What that cost is
#944 — the settings page showed a name and `********`, so an operator could not
tell which receiver a webhook pointed at, could not spot a wrong host, and had to
re-type the whole thing from memory to change anything next to it.

The rule these tests hold to: **enough to recognise the destination, never enough
to use it.** Origin only, plus markers that a path and/or a query exist, with
none of their content — because "show the first path segment" would be safe for
Slack and would hand over the topic for ntfy.

The placement matters as much as the rendering. `GET /api/notifications/config`
is admin-only, and admins can already read this exact origin for every delivery
through `GET /api/webhooks/deliveries`. `mask_secrets_in_settings` is a different
audience: it also serves `GET /api/web/settings`, which the **viewer** role may
read, and the share-safe backup ZIP. Folding the hint in there is the obvious
move and the wrong one, so a test below forbids it.
"""
import json
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.notifier import webhook_url_hint
from modules.core.settings import SECRET_MASK_SENTINEL, mask_secrets_in_settings

pytestmark = [pytest.mark.unit]


#: One row per receiver type CertMate supports, each with the part that must
#: never appear spelled out. The secret is in a different place in every one,
#: which is the reason the hint keeps no path or query content at all.
RECEIVERS = [
    ('slack', 'https://hooks.slack.com/services/T0A/B0B/zZtOpSeCrEt',
     'zZtOpSeCrEt', 'https://hooks.slack.com/…'),
    ('discord', 'https://discord.com/api/webhooks/1234567890/dIsCoRdToKeN',
     'dIsCoRdToKeN', 'https://discord.com/…'),
    # ntfy has no token: publishing to a topic is authorised by knowing the
    # topic, so the FIRST path segment is the credential here.
    ('ntfy', 'https://ntfy.sh/my-private-alerts',
     'my-private-alerts', 'https://ntfy.sh/…'),
    # Gotify puts it in the query instead.
    ('gotify', 'https://gotify.example.com:8443/message?token=gOtIfYtOkEn',
     'gOtIfYtOkEn', 'https://gotify.example.com:8443/…?…'),
    ('google_chat',
     'https://chat.googleapis.com/v1/spaces/AAA/messages?key=kEy&token=tOk',
     'tOk', 'https://chat.googleapis.com/…?…'),
    # userinfo is a credential of its own and goes with the rest.
    ('generic with userinfo', 'https://admin:pAsSwOrD@receiver.example.com/hook',
     'pAsSwOrD', 'https://receiver.example.com/…'),
]


@pytest.mark.parametrize('label,url,secret,expected', RECEIVERS,
                         ids=[r[0] for r in RECEIVERS])
def test_the_hint_is_the_origin_and_the_secret_is_not_in_it(label, url, secret, expected):
    hint = webhook_url_hint(url)
    assert hint == expected
    assert secret not in hint, f'{label}: the hint spells out the credential'


def test_the_hint_keeps_the_port_because_a_wrong_one_is_a_real_mistake():
    """:8443 rather than :443 is exactly the kind of typo this exists to show."""
    assert webhook_url_hint('https://gotify.example.com:8443/message') == \
        'https://gotify.example.com:8443/…'
    assert webhook_url_hint('https://gotify.example.com/message') == \
        'https://gotify.example.com/…'


def test_an_absent_or_unreadable_url_says_which_it_was():
    """Two different facts, and flattening them tells an operator less."""
    assert webhook_url_hint('') == ''
    assert webhook_url_hint(None) == ''
    assert webhook_url_hint('not a url at all') == '(unparseable)'


def test_a_bare_origin_gets_no_markers():
    """CONTROL: the markers mean "there is more, hidden". With nothing more to
    hide they must be absent, or they would imply a path that is not there."""
    assert webhook_url_hint('https://receiver.example.com') == \
        'https://receiver.example.com'
    assert webhook_url_hint('https://receiver.example.com/') == \
        'https://receiver.example.com'


def test_the_viewer_facing_masker_gains_nothing():
    """The hint must NOT leak into `mask_secrets_in_settings`.

    That helper serves `GET /api/web/settings` (role: **viewer**) and the
    share-safe backup ZIP. Both mask the whole URL today. Putting the hint in
    the shared masker rather than in the admin route would widen the audience
    from admins to viewers and write the origin into backups people share —
    which is why this test exists rather than a comment saying not to."""
    masked = mask_secrets_in_settings({'notifications': {'channels': {'webhooks': [
        {'name': 'ops', 'type': 'slack',
         'url': 'https://hooks.slack.com/services/T0/B0/sEcReT'},
    ]}}})
    webhook = masked['notifications']['channels']['webhooks'][0]
    assert webhook['url'] == SECRET_MASK_SENTINEL
    assert 'url_hint' not in webhook, (
        'the origin hint reached the viewer-facing masker and the share-safe '
        'backup; it belongs to the admin notifications route only')
    assert 'hooks.slack.com' not in json.dumps(masked)


# ── the route, end to end ─────────────────────────────────────────────

STORED = {
    'enabled': True,
    'channels': {
        'smtp': {'host': 'smtp.example.com', 'smtp_password': 'REAL-PASSWORD'},
        'webhooks': [
            {'name': 'ops', 'type': 'slack', 'enabled': True,
             'url': 'https://hooks.slack.com/services/T0A/B0B/zZtOpSeCrEt'},
            {'name': 'pager', 'type': 'gotify', 'enabled': True,
             'url': 'https://gotify.example.com/message?token=gOtIfYtOkEn'},
        ],
    },
}


@pytest.fixture
def client():
    settings_manager = MagicMock()
    saved = {}

    def _update(mutator):
        state = {'notifications': json.loads(json.dumps(STORED))}
        saved.update(mutator(state))
        return saved
    settings_manager.update = MagicMock(side_effect=_update)
    settings_manager.load_settings.return_value = {
        'notifications': json.loads(json.dumps(STORED))}

    from modules.core.notifier import Notifier
    notifier = Notifier.__new__(Notifier)
    notifier.settings_manager = settings_manager
    notifier._get_config = lambda: json.loads(json.dumps(STORED))

    auth_manager = MagicMock()

    def passthrough_role(_min_role):
        def deco(fn):
            return fn
        return deco
    auth_manager.require_role = MagicMock(side_effect=passthrough_role)
    auth_manager.require_session_role = MagicMock(side_effect=passthrough_role)

    app = Flask(__name__)
    app.config['TESTING'] = True
    from modules.web.misc_routes import register_misc_routes
    register_misc_routes(app, {
        'auth': auth_manager, 'settings': settings_manager,
        'notifier': notifier, 'digest': MagicMock(), 'audit': MagicMock(),
        'cache': MagicMock(), 'metrics': MagicMock(), 'dns': MagicMock(),
        'deployer': MagicMock(),
    }, lambda fn: fn, auth_manager)
    c = app.test_client()
    c._saved = saved
    return c


def test_the_route_returns_a_hint_per_webhook_and_still_masks_the_url(client):
    r = client.get('/api/notifications/config')
    assert r.status_code == 200, r.data
    whs = r.get_json()['channels']['webhooks']
    assert [w['url'] for w in whs] == [SECRET_MASK_SENTINEL] * 2
    assert [w['url_hint'] for w in whs] == [
        'https://hooks.slack.com/…',
        'https://gotify.example.com/…?…',
    ]
    # Defence in depth: no part of either credential anywhere in the body.
    for secret in ('zZtOpSeCrEt', 'gOtIfYtOkEn', 'REAL-PASSWORD'):
        assert secret.encode() not in r.data


def test_the_hints_line_up_with_the_right_webhooks(client):
    """Two webhooks, two different origins: a zip that slipped by one would
    tell an operator their Slack hook points at Gotify."""
    whs = client.get('/api/notifications/config').get_json()['channels']['webhooks']
    by_name = {w['name']: w['url_hint'] for w in whs}
    assert by_name['ops'] == 'https://hooks.slack.com/…'
    assert by_name['pager'] == 'https://gotify.example.com/…?…'


def test_echoing_the_response_back_does_not_store_the_hint(client):
    """The UI round-trips the GET response. A derived field that came back as
    configuration would be written to settings.json and go stale the moment the
    URL changed — and a share-safe backup would then carry the origin."""
    echoed = client.get('/api/notifications/config').get_json()
    r = client.post('/api/notifications/config', json=echoed)
    assert r.status_code == 200, r.data
    stored = client._saved['notifications']['channels']['webhooks']
    for webhook in stored:
        assert 'url_hint' not in webhook
    # And the round-trip did not clobber the real URLs with the sentinel.
    assert stored[0]['url'] == 'https://hooks.slack.com/services/T0A/B0B/zZtOpSeCrEt'


def test_the_field_stops_claiming_to_hold_a_url_while_it_holds_the_mask():
    """`type="url"` with `********` in it makes the browser mark a correctly
    saved webhook invalid, which is the complaint's other half. The type is
    bound to the value, so url validation returns as soon as one is typed."""
    from pathlib import Path
    page = Path('templates/partials/settings_notifications.html').read_text()
    assert 'x-model="wh.url"' in page
    assert ':type="wh.url === MASK' in page, (
        'the webhook URL input must not be a fixed type="url" while it can '
        'hold the masking sentinel'
    )
    # And the hint is shown only for a saved-and-hidden value, not over
    # something the operator is in the middle of typing.
    assert 'x-show="wh.url === MASK &amp;&amp; wh.url_hint"' in page

    js = Path('static/js/settings-notifications.js').read_text()
    assert "MASK: '********'" in js, 'the template reads MASK from the component'


def test_the_endpoint_that_shows_the_origin_is_still_admin_only():
    """The whole safety argument is one decorator.

    Showing the origin is defensible *because* `GET /api/notifications/config`
    requires admin, and admins can already read the same origin through
    `GET /api/webhooks/deliveries`. Lower that role and the feature starts
    handing receiver hostnames to viewers, with nothing else in the code
    objecting — so the role is asserted here rather than trusted.

    docs/webhooks.md states both roles; this is the line under that sentence."""
    from pathlib import Path
    import re

    routes = Path('modules/web/misc_routes.py').read_text()
    for path in ('/api/notifications/config', '/api/webhooks/deliveries'):
        pattern = re.compile(
            re.escape(f"@app.route('{path}'") + r"[^\n]*\n\s*@auth_manager\.require_role\('(\w+)'\)")
        found = pattern.search(routes)
        assert found, f'{path}: no require_role immediately under the route'
        assert found.group(1) == 'admin', (
            f'{path} is now {found.group(1)!r}; the origin hint assumes admin')

    settings_routes = Path('modules/web/settings_routes.py').read_text()
    assert "@auth_manager.require_role('viewer')" in settings_routes, (
        'the viewer-readable settings route is what the hint must stay out of; '
        'if it is gone, re-derive where the hint may appear'
    )


# ── what the page says this endpoint does ─────────────────────────────

def test_a_partial_save_deep_merges_instead_of_replacing(client):
    """docs/api.md said "POST replaces rather than merges". It does not.

    Measured against a live instance while writing that page: a body of only
    `{"enabled": false}` turned notifications off and left three configured
    webhooks and the SMTP block untouched. The merge was deliberate (audit H4 —
    a partial submit must not destroy siblings) and the sentence describing the
    endpoint had outlived it. This pins the behaviour the corrected page now
    describes, so the next person to change one has to change the other."""
    r = client.post('/api/notifications/config', json={'enabled': False})
    assert r.status_code == 200, r.data
    saved = client._saved['notifications']
    assert saved['enabled'] is False
    assert len(saved['channels']['webhooks']) == 2, (
        'a partial save destroyed the webhooks'
    )
    assert saved['channels']['smtp']['host'] == 'smtp.example.com'


def test_the_webhooks_list_is_replaced_wholesale(client):
    """The exception the page now names: a list has no key to merge on.

    Sending one webhook replaces the two that were stored — and the masked URL
    of the survivor is still restored from disk, because that is done by
    identity and not by position."""
    r = client.post('/api/notifications/config', json={'channels': {'webhooks': [
        {'name': 'ops', 'type': 'slack', 'enabled': True,
         'url': SECRET_MASK_SENTINEL},
    ]}})
    assert r.status_code == 200, r.data
    webhooks = client._saved['notifications']['channels']['webhooks']
    assert [w['name'] for w in webhooks] == ['ops']
    assert webhooks[0]['url'].endswith('zZtOpSeCrEt')


def test_the_new_field_is_recorded_where_the_rule_lives():
    """`url_hint` shipped without moving API_CONTRACT_VERSION.

    The rule beside the constant has six clauses — new endpoint, endpoint
    removed, new response field, field removed or retyped, request field become
    required, status code changed — and the only gate over it
    (test_the_contract_moves_with_the_surface.py) compares a snapshot of the
    ROUTES. It sees two of the six. A new field on a response is invisible to
    it, which is how this one went out in 2.19.

    So the check is that the field is written down in the changelog beside the
    constant, and in the page a caller reads. Neither is derivable; both are the
    thing that was missing."""
    from pathlib import Path
    constants = Path('modules/core/constants.py').read_text()
    assert 'url_hint' in constants, (
        'a new response field is not recorded in the contract changelog'
    )
    api_doc = Path('docs/api.md').read_text()
    assert 'url_hint' in api_doc, 'the field is not documented for callers'
    # Stated positively on purpose. Banning the old, false sentence would be a
    # gate that encodes yesterday's mistake rather than today's truth, and the
    # behaviour it describes is already pinned by the two tests above — which
    # are what fails first if the endpoint ever does start replacing.
    assert 'deep-merge' in api_doc.lower(), (
        'the page no longer says what the endpoint does with a partial body'
    )
