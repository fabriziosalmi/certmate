"""A webhook URL is a credential, and the delivery log kept it in full.

`modules/core/settings.py` declares `webhooks.url` a secret, and says why where
it declares it: for Slack, Discord, ntfy and Gotify the incoming-webhook URL
embeds the bearer token in its path, so anyone who reads it can post to the
channel. It is masked in `GET /api/web/settings` and kept out of the share-safe
backup ZIP for that reason (#16).

`Notifier._log_delivery` then wrote the same value, in full, into
`data/webhook_deliveries.jsonl`, and `get_deliveries` handed it straight back
through `GET /api/webhooks/deliveries`. Measured before the fix:

    settings say  : ********
    on disk       : https://hooks.slack.com/services/T000/B111/XXXsupersecretXXX
    from the API  : the same

So one module declared the field sensitive and another copied it, which is what
`test_what_counts_as_a_secret_is_declared.py` exists to prevent for settings —
and this file is not settings.

The module already knew the answer. Its SSRF refusal and its redirect guard
both log `urlparse(url).hostname` and nothing else; `_log_delivery` was the one
call site that did not. The record keeps the origin now, and carries
`webhook_name`, `webhook_type` and `event` for identity.

**Both directions, and that is not symmetry for its own sake.** Fixing the
writer alone leaves every line already on disk — up to 1000 of them, written by
every earlier version — still leaving through the endpoint until they age out.
A file keeps what it was given.
"""
import ast
import inspect
import json
import pathlib

import pytest

from modules.core.notifier import (
    DELIVERY_URL_UNPARSEABLE, Notifier, delivery_log_url)
from modules.core.settings import SECRET_MASK_SENTINEL, mask_secrets_in_settings

pytestmark = [pytest.mark.unit]

SECRET = 'XXXsupersecretXXX'
SLACK = f'https://hooks.slack.com/services/T000/B111/{SECRET}'


@pytest.fixture
def notifier(tmp_path):
    """A Notifier with nothing but a log path — the rest of the object needs
    settings, an event bus and network, and none of it is under test here."""
    instance = Notifier.__new__(Notifier)
    instance._delivery_log_path = tmp_path / 'webhook_deliveries.jsonl'
    return instance


def _deliver(notifier, url, name='slack-ops', wh_type='slack'):
    notifier._log_delivery(
        {'name': name, 'type': wh_type, 'url': url},
        'certificate_renewed', {'status': 200, 'success': True}, 1, 42)


# ── the premise ──────────────────────────────────────────────────────

def test_the_settings_layer_really_treats_this_as_a_secret():
    """Guard the guard. Every assertion below rests on the claim that a
    webhook url is a credential; if settings ever stopped masking it, this
    file would be enforcing a rule the project no longer holds, and should
    fail here rather than quietly elsewhere."""
    masked = mask_secrets_in_settings(
        {'notifications': {'channels': {'webhooks': [{'name': 'x', 'url': SLACK}]}}})
    assert masked['notifications']['channels']['webhooks'][0]['url'] == \
        SECRET_MASK_SENTINEL


def test_the_probe_url_actually_contains_something_secret():
    """An empty needle is found in every haystack."""
    assert SECRET and SECRET in SLACK


# ── what gets written ────────────────────────────────────────────────

def test_the_secret_does_not_reach_the_file(notifier):
    _deliver(notifier, SLACK)
    assert SECRET not in notifier._delivery_log_path.read_text()


def test_the_origin_does(notifier):
    """Reduced, not dropped. Which host a delivery went to is the question an
    operator opens this log to answer."""
    _deliver(notifier, SLACK)
    entry = json.loads(notifier._delivery_log_path.read_text().strip())
    assert entry['url'] == 'https://hooks.slack.com'


def test_the_record_still_says_which_webhook_and_how_it_went(notifier):
    """Reducing the url costs nothing an operator needs, because identity was
    never carried by the url in the first place."""
    _deliver(notifier, SLACK)
    entry = json.loads(notifier._delivery_log_path.read_text().strip())
    assert entry['webhook_name'] == 'slack-ops'
    assert entry['webhook_type'] == 'slack'
    assert entry['event'] == 'certificate_renewed'
    assert entry['status'] == 200 and entry['success'] is True
    assert entry['attempts'] == 1


# ── what comes back out ──────────────────────────────────────────────

def test_the_secret_does_not_reach_the_api(notifier):
    _deliver(notifier, SLACK)
    assert SECRET not in json.dumps(notifier.get_deliveries())


def test_a_line_written_by_an_earlier_version_is_reduced_on_read(notifier):
    """The half a writer-only fix would miss. This is what is on disk right
    now on every instance that has ever delivered a webhook."""
    notifier._delivery_log_path.write_text(json.dumps({
        'timestamp': '2026-01-01T00:00:00Z', 'webhook_name': 'old',
        'webhook_type': 'slack', 'event': 'certificate_created',
        'url': SLACK, 'status': 200, 'success': True, 'attempts': 1,
    }) + '\n')
    deliveries = notifier.get_deliveries()
    assert SECRET not in json.dumps(deliveries)
    assert deliveries[0]['url'] == 'https://hooks.slack.com'
    assert deliveries[0]['webhook_name'] == 'old'


def test_reading_does_not_choke_on_a_record_without_a_url(notifier):
    notifier._delivery_log_path.write_text(
        json.dumps({'timestamp': 't', 'webhook_name': 'x'}) + '\n')
    assert notifier.get_deliveries() == [{'timestamp': 't', 'webhook_name': 'x'}]


# ── the reducer itself ───────────────────────────────────────────────

@pytest.mark.parametrize('url,expected', [
    (SLACK, 'https://hooks.slack.com'),
    # Userinfo is a credential too, and it lives in netloc — which is why the
    # reducer reads `hostname` and not `netloc`.
    ('https://user:p4ssw0rd@example.com/hook', 'https://example.com'),
    # Slack puts the secret in the path; a generic receiver may put it in the
    # query. Neither is kept.
    (f'https://example.com/hook?token={SECRET}', 'https://example.com'),
    (f'https://example.com/hook#{SECRET}', 'https://example.com'),
    # A non-default port is a real difference when a receiver sits behind a
    # proxy, and it is not secret.
    ('https://example.com:8443/hook', 'https://example.com:8443'),
    ('http://example.com/hook', 'http://example.com'),
    # Already reduced: reading must not degrade a value further, or every
    # read of an unchanged file would rewrite history.
    ('https://example.com', 'https://example.com'),
    ('', ''),
    (None, ''),
    ('not a url', DELIVERY_URL_UNPARSEABLE),
    ('://missing-scheme/x', DELIVERY_URL_UNPARSEABLE),
])
def test_the_reducer_keeps_the_origin_and_nothing_else(url, expected):
    assert delivery_log_url(url) == expected


def test_reducing_twice_changes_nothing():
    """`get_deliveries` reduces on read, so a record written after the fix is
    reduced twice. If that were lossy the log would erode as it is read."""
    for url in (SLACK, 'https://example.com:8443/x', 'not a url', ''):
        once = delivery_log_url(url)
        assert delivery_log_url(once) == once, url


def test_nothing_that_looks_like_a_secret_survives():
    """A property rather than a list: whatever the receiver puts where, the
    reducer keeps scheme and host, so anything else is gone by construction."""
    for placement in ('https://h.example/{s}', 'https://h.example/a?t={s}',
                      'https://h.example/a#{s}', 'https://{s}:x@h.example/a'):
        assert SECRET not in delivery_log_url(placement.format(s=SECRET))


# ── the wiring the endpoint depends on ───────────────────────────────

def test_the_endpoint_hands_through_what_the_notifier_reduced():
    """`GET /api/webhooks/deliveries` is the second route the URL left by.

    Read from the source rather than driven, because the route needs a whole
    application. What is pinned is narrow and is the thing that would undo
    this: the handler returns `get_deliveries(...)` and does not reach into
    the live webhook config to put the real url back alongside it.
    """
    from modules.web import misc_routes

    tree = ast.parse(inspect.getsource(misc_routes))
    handler = next(
        (node for node in ast.walk(tree)
         if isinstance(node, ast.FunctionDef)
         and node.name == 'api_webhook_deliveries'), None)
    assert handler is not None, 'api_webhook_deliveries is gone'
    # The body only. The decorators carry the route path, which contains the
    # word "webhooks" — the first version of this test read them too and
    # failed on `@app.route('/api/webhooks/deliveries')`, reporting the
    # endpoint as reading the webhook config when it does nothing of the kind.
    body = '\n'.join(ast.unparse(statement) for statement in handler.body)
    assert 'get_deliveries' in body
    for forbidden in ("channels", "load_settings", "config"):
        assert forbidden not in body, (
            f'api_webhook_deliveries now reads {forbidden!r}; the reduced url '
            f'in the log is no longer the only url this endpoint can return'
        )


@pytest.mark.parametrize('page,claim', [
    ('webhooks.md', 'the **origin** of its'),
    ('api.md', '`url` is the **origin** only'),
])
def test_the_pages_describe_what_is_actually_recorded(page, claim):
    """`docs/webhooks.md` said the log records "the webhook's name, type and
    URL". That was true, and it was the defect. Both pages say origin now, and
    if the reduction is removed the sentence goes back to being a description
    of a credential sitting in a file — so it is checked from both ends."""
    repo = pathlib.Path(__file__).resolve().parent.parent
    text = (repo / 'docs' / page).read_text(encoding='utf-8')
    assert claim in text, f'docs/{page} no longer describes what is recorded'
    assert delivery_log_url(SLACK) == 'https://hooks.slack.com'


def test_the_delivery_log_is_not_carried_into_a_backup():
    """Stated here because it is load-bearing for the severity of this, and
    because it is one edit away from stopping being true.

    A share-safe backup walks `data/certs`, `data/audit` and `data/inventory`.
    `webhook_deliveries.jsonl` sits at the top of `data/`, so it was never in
    the archive — the exposure was the file and the endpoint, not the ZIP.
    """
    from modules.core.file_operations import _BACKUP_DATA_SUBTREES

    assert 'webhook_deliveries.jsonl' not in _BACKUP_DATA_SUBTREES
    repo = pathlib.Path(__file__).resolve().parent.parent
    source = (repo / 'modules' / 'core' / 'file_operations.py').read_text(
        encoding='utf-8')
    assert 'webhook_deliveries' not in source


# --- and it must still say WHERE the message went ------------------------

def test_an_smtp_delivery_records_a_server_it_can_name():
    """`delivery_log_url` answers "(unparseable)" for anything with no
    scheme, and the SMTP call site passed `cfg['host']` — a bare hostname.
    So every SMTP row in the delivery log said "(unparseable)" and the log
    could not answer the one question it exists for: which server did this
    go to. Found by the certmate-website session.

    The call site spells a URL; the helper's strictness is what keeps a
    credential out of the log, so it is not the part to loosen.
    """
    from modules.core.notifier import delivery_log_url

    assert delivery_log_url('smtp.example.com') == DELIVERY_URL_UNPARSEABLE
    assert delivery_log_url('smtp://smtp.example.com:587') == \
        'smtp://smtp.example.com:587'


def test_the_smtp_call_site_does_not_pass_a_bare_host():
    """Asserted on the call, not the text: the first version of a check like
    this in another file matched a comment quoting the old expression."""
    import ast
    import inspect

    from modules.core.notifier import Notifier

    source = inspect.getsource(Notifier._send_email_with_retry)
    calls = [ast.unparse(node) for node in ast.walk(ast.parse(source.strip()))
             if isinstance(node, ast.Call)]
    log_calls = [c for c in calls if '_log_delivery' in c]

    assert log_calls, 'the SMTP path no longer logs a delivery'
    for call in log_calls:
        assert "'url': cfg.get('host'" not in call, (
            f'the bare host is back: {call}'
        )


def test_a_credential_in_the_smtp_url_is_still_dropped():
    """CONTROL. Spelling a URL at the call site must not become a way to
    write `user:password@` into the log."""
    from modules.core.notifier import delivery_log_url

    assert delivery_log_url('smtp://mailer:hunter2@smtp.example.com:587') == \
        'smtp://smtp.example.com:587'
