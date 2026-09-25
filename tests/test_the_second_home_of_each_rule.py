"""Six fixes from v2.35.0 that were applied in one place and lived in several.

Found by the certmate-website session reading every page against `7fbbe4b`.
Each item below is the same defect: a rule was corrected where the issue
pointed, and the rule had another home that kept the old behaviour — which is
precisely the class of defect that release spent its time closing.

They are kept in one file because the lesson is one lesson, and separating
them would lose it.

1. **The update check had no switch.** `UpdateCheck.save_config` existed,
   nothing called it, and the only route was a GET. Off by default is the
   contract; no way to turn it on is not an opt-in.
2. **`CERTMATE_CERT_DIR` still lost three places.** The storage info endpoint
   and the test/migrate backends each re-derived
   `Path(config.get('cert_dir', 'certificates'))`, so a migrate from local read
   a relative `./certificates` while issuance used the volume.
3. **Reissue kept the substring and the double prefix.** `'rate limit'` matches
   none of the markers a CA sends, and the create path already prefixes its
   message.
4. **`write_checkpoint`'s docstring still said nothing calls it on shutdown**,
   in the release that added the caller.
5. **`docs/webhooks.md` still said six selectable events**, and named
   `certificate_deployed` as excluded, in the release that made it seven.
6. **`docs/api.md` said `complete: false` means older matches exist**; the code
   says there may be.
"""
import pathlib
import re
import secrets

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
TOKEN = secrets.token_urlsafe(32)


# ── 1. the update check can be turned on ─────────────────────────────

@pytest.fixture(scope='module')
def client(tmp_path_factory):
    import os

    tmp_path = tmp_path_factory.mktemp('second-home')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp_path / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', TOKEN)
        os.environ['API_BEARER_TOKEN'] = TOKEN
        from modules.factory import create_app
        application, _ = create_app()
        yield application.test_client()


def _headers():
    return {'Authorization': f'Bearer {TOKEN}', 'Origin': 'http://localhost'}


def test_it_is_off_to_begin_with(client):
    """Guard the guard, and the contract: an instance that was never asked to
    reach the internet does not."""
    body = client.get('/api/web/update-check', headers=_headers()).get_json()
    assert body['status'] == 'disabled'
    assert body['enabled'] is False


def test_it_can_be_turned_on_and_off(client):
    """The route that was missing. Without it the only way to enable the
    feature was to edit settings.json by hand."""
    on = client.post('/api/web/update-check', json={'enabled': True},
                     headers=_headers())
    assert on.status_code == 200, on.get_data(as_text=True)
    assert on.get_json()['enabled'] is True
    assert client.get('/api/web/update-check',
                      headers=_headers()).get_json()['enabled'] is True

    client.post('/api/web/update-check', json={'enabled': False}, headers=_headers())
    assert client.get('/api/web/update-check',
                      headers=_headers()).get_json()['enabled'] is False


@pytest.mark.parametrize('body', [{}, {'enabled': 'yes'}, {'enabled': 1}])
def test_it_refuses_a_body_that_is_not_a_decision(client, body):
    """`{"enabled": 1}` read as true would turn on an outbound check because
    somebody sent the wrong type."""
    assert client.post('/api/web/update-check', json=body,
                       headers=_headers()).status_code == 400


def test_the_settings_page_offers_it():
    """A route alone leaves the feature reachable only by curl, which is the
    same problem one layer up."""
    panel = (REPO / 'templates' / 'partials' /
             'settings_general.html').read_text(encoding='utf-8')
    assert 'update_check_enabled' in panel
    settings_js = (REPO / 'static' / 'js' / 'settings.js').read_text(encoding='utf-8')
    assert "'/api/web/update-check'" in settings_js
    assert 'update_check_enabled' in settings_js


# ── 2. the certificate directory has one answer ──────────────────────

def test_no_module_re_derives_the_certificate_directory():
    """Three sites kept `Path(config.get('cert_dir', 'certificates'))` after
    the manager stopped using it. The constructor's own default is the one
    that stays."""
    # CALLS, not text. Two earlier versions of this assertion failed on a
    # file that was already correct: the first searched the source, the second
    # unparsed the module — and `ast.unparse` keeps docstrings, so it still
    # matched the helper's own docstring quoting the expression it replaced.
    # Fourth time today that prose has been mistaken for code.
    import ast

    storage_api = (REPO / 'modules' / 'api' /
                   'resources_storage.py').read_text(encoding='utf-8')
    calls = [ast.unparse(node) for node in ast.walk(ast.parse(storage_api))
             if isinstance(node, ast.Call)]
    offenders = [c for c in calls if "'cert_dir', 'certificates'" in c]
    assert not offenders, (
        f'a module here derives the certificate directory again: {offenders}'
    )
    assert any('local_cert_dir' in c for c in calls)

    backends = (REPO / 'modules' / 'core' /
                'storage_backends.py').read_text(encoding='utf-8')
    assert backends.count("Path('certificates')") == 1


def test_the_rule_is_reachable_by_its_callers():
    """It was private, and the callers are in another module. A rule the
    people who need it cannot call is a rule that gets copied."""
    from modules.core.storage_backends import StorageManager

    assert hasattr(StorageManager, 'local_cert_dir')
    assert not hasattr(StorageManager, '_local_cert_dir')


# ── 3. reissue answers like create ───────────────────────────────────

def test_a_reissue_says_its_prefix_once():
    from modules.api.resources_lifecycle import (
        _CREATION_PREFIX, _REISSUE_PREFIX, _prefixed)

    doubled = _prefixed(_REISSUE_PREFIX, _CREATION_PREFIX + 'certbot died')
    assert doubled == _REISSUE_PREFIX + 'certbot died'
    assert doubled.count('failed:') == 1

    assert _prefixed(_REISSUE_PREFIX, 'certbot died') == \
        _REISSUE_PREFIX + 'certbot died'
    assert _prefixed(_REISSUE_PREFIX, _REISSUE_PREFIX + 'x') == _REISSUE_PREFIX + 'x'


def test_reissue_recognises_a_rate_limit_the_way_create_does():
    """It kept the substring `rate limit`, which matches none of the markers a
    CA actually sends — so a rate limit arrived as a DNS credentials problem
    on the path an operator reaches after a failed renewal."""
    route = (REPO / 'modules' / 'api' /
             'resources_lifecycle.py').read_text(encoding='utf-8')
    assert "if 'rate limit' in error_msg.lower()" not in route
    assert route.count('_certbot_hint(error_msg)') >= 2


# ── 4-6. sentences that outlived what they described ─────────────────

def test_the_checkpoint_docstring_knows_about_its_second_caller():
    import inspect

    from modules.core.audit import AuditLogger

    doc = inspect.getdoc(AuditLogger.write_checkpoint) or ''
    assert 'nothing calls' not in doc
    assert 'shutdown' in doc.lower()
    factory = (REPO / 'modules' / 'factory.py').read_text(encoding='utf-8')
    assert 'write_checkpoint()' in factory, (
        'the docstring now claims a shutdown caller that is not there'
    )


_NUMBER_WORDS = {1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five',
                 6: 'six', 7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten'}


# The claim shape that drifted: "the settings page offers six events".
# Not every "N events" is a count of the offered list — a comment saying "the
# two events above" is prose about neighbouring lines, and an earlier draft of
# this gate flagged it.
_COUNT_CLAIM = re.compile(
    r'\b(?:offers|offering|lists|names|only the)\s+'
    r'(one|two|three|four|five|six|seven|eight|nine|ten)\s+events\b')


def _miscounts(text, correct):
    """Number words that claim a count of the offered events and are wrong."""
    claimed = set(_COUNT_CLAIM.findall(text))
    return sorted(claimed - {_NUMBER_WORDS[correct]})


def test_the_webhooks_page_counts_the_events_the_ui_offers():
    """The page must say the number the code produces.

    This test used to forbid the literal string 'six events', because six was
    the wrong number on the day it was written. Then #943 moved
    certificate_failed out of the filterable set and six became the right
    answer — and a gate that bans a string cannot tell those two apart, so it
    failed the corrected page. It derives the number now."""
    from modules.factory import _EVENT_TITLES
    from modules.core.notifier import _ALWAYS_NOTIFY_EVENTS

    page = (REPO / 'docs' / 'webhooks.md').read_text(encoding='utf-8')
    filterable = set(_EVENT_TITLES) - set(_ALWAYS_NOTIFY_EVENTS)
    correct = _NUMBER_WORDS[len(filterable)]

    assert f'{correct} events' in page, (
        f'the settings page offers {len(filterable)} filterable events; '
        f'docs/webhooks.md does not say "{correct} events"')
    assert not _miscounts(page, len(filterable)), (
        f'docs/webhooks.md also claims {_miscounts(page, len(filterable))}')
    for event in filterable:
        assert f'`{event}`' in page, f'{event} is offered and the page omits it'
    for event in _ALWAYS_NOTIFY_EVENTS:
        assert f'`{event}`' in page, (
            f'{event} bypasses the filter and the page does not say so')


def test_no_comment_claims_a_different_count():
    """The comments in notifier.py are what the next person reads before the
    page, and they drift the same way."""
    from modules.factory import _EVENT_TITLES
    from modules.core.notifier import _ALWAYS_NOTIFY_EVENTS

    notifier = (REPO / 'modules' / 'core' / 'notifier.py').read_text(encoding='utf-8')
    correct = len(set(_EVENT_TITLES) - set(_ALWAYS_NOTIFY_EVENTS))
    assert not _miscounts(notifier, correct), (
        f'a comment in notifier.py claims {_miscounts(notifier, correct)} '
        f'while {correct} events are filterable')
    assert 'five certificate_*' not in notifier


def test_the_api_page_does_not_promise_more_than_the_code_knows():
    """`complete: false` means the search stopped at `limit`. Whether older
    matches exist is exactly what it did not find out."""
    page = (REPO / 'docs' / 'api.md').read_text(encoding='utf-8')
    assert 'older matches exist' not in page
    assert 'there may be older matches' in page
