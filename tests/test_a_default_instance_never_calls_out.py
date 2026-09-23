"""The update check is off until asked for, and says so when it cannot look.

`docs/ca-providers.md` offers the private CA for "internal networks, corporate
environments, air-gapped systems". An instance that was never asked to reach
the internet must not reach it — that is a product promise, and the
deployments relying on it are the ones least able to notice it being broken:
a phone-home shows up as a timeout in a log nobody reads, or a proxy denial
that looks like the product failing.

So the first test here does not assert on a return value. It gives the checker
a fetcher that fails the test if it is called at all, and then exercises every
path that could plausibly reach for one.

The rest is the rule this codebase keeps relearning: a check that could not
reach GitHub reports `unknown`, never `current`. An air-gapped instance told
daily that it is up to date, while running a release with a known defect, is
worse served than one told nothing.
"""
from unittest.mock import MagicMock

import pytest

from modules.core import update_check as uc

pytestmark = [pytest.mark.unit]


def _settings(config=None):
    manager = MagicMock()
    manager.load_settings.return_value = (
        {'update_check': config} if config is not None else {})
    return manager


def _forbidden_fetcher():
    def fetcher(*args, **kwargs):
        raise AssertionError(
            'the update check reached for the network on an instance that '
            'never enabled it'
        )
    return fetcher


# --------------------------------------------------------------------------- #
# The promise
# --------------------------------------------------------------------------- #

def test_a_default_instance_never_calls_out():
    """The test this file exists for."""
    checker = uc.UpdateCheck(_settings(), '2.34.0', fetcher=_forbidden_fetcher())
    result = checker.status()
    assert result['status'] == uc.DISABLED
    assert result['latest'] is None


def test_not_even_when_forced():
    """`force` skips the cache, not the operator's decision. A refresh button
    must not be a way to opt in by accident."""
    checker = uc.UpdateCheck(_settings(), '2.34.0', fetcher=_forbidden_fetcher())
    assert checker.status(force=True)['status'] == uc.DISABLED


@pytest.mark.parametrize('config', [None, {}, {'enabled': False},
                                    {'enabled': 0}, {'enabled': ''}])
def test_every_shape_of_not_enabled_stays_silent(config):
    checker = uc.UpdateCheck(_settings(config), '2.34.0',
                             fetcher=_forbidden_fetcher())
    assert checker.status()['status'] == uc.DISABLED


def test_disabled_is_not_the_same_answer_as_could_not_look():
    """"You did not ask" and "I asked and could not find out" are different,
    and an operator seeing the second should go looking at egress rules."""
    assert uc.DISABLED != uc.UNKNOWN

    off = uc.UpdateCheck(_settings(), '2.34.0', fetcher=_forbidden_fetcher())
    blind = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                           fetcher=lambda: None)
    assert off.status()['status'] == uc.DISABLED
    assert blind.status()['status'] == uc.UNKNOWN


def test_the_default_config_is_off():
    assert uc.DEFAULT_CONFIG['enabled'] is False


# --------------------------------------------------------------------------- #
# When it is asked for
# --------------------------------------------------------------------------- #

def test_a_newer_release_is_reported():
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                             fetcher=lambda: 'v2.35.0')
    result = checker.status()
    assert result['status'] == uc.OUTDATED
    assert result['latest'] == 'v2.35.0'
    assert result['running'] == '2.34.0'


def test_the_same_release_is_current():
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                             fetcher=lambda: 'v2.34.0')
    assert checker.status()['status'] == uc.CURRENT


def test_running_ahead_of_the_latest_release_is_current_not_outdated():
    """A build from main during a release. Telling that operator to upgrade
    to something older than what they run is noise."""
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.35.0',
                             fetcher=lambda: 'v2.34.0')
    assert checker.status()['status'] == uc.CURRENT


def test_a_check_that_could_not_reach_github_says_unknown_not_current():
    """The rule, in the place it matters most: an air-gapped instance told
    daily that it is up to date, while running a release with a known defect,
    is worse served than one told nothing."""
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                             fetcher=lambda: None)
    result = checker.status()
    assert result['status'] == uc.UNKNOWN
    assert result['status'] != uc.CURRENT
    assert result['latest'] is None


@pytest.mark.parametrize('tag', ['', 'latest', 'release-2026-09', None, '2.x'])
def test_a_tag_this_does_not_understand_is_unknown(tag):
    """A release tagged in an unexpected form is not evidence the instance is
    current."""
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                             fetcher=lambda: tag)
    assert checker.status()['status'] == uc.UNKNOWN


def test_a_running_version_that_cannot_be_parsed_is_unknown():
    checker = uc.UpdateCheck(_settings({'enabled': True}), 'dev',
                             fetcher=lambda: 'v2.34.0')
    assert checker.status()['status'] == uc.UNKNOWN


# --------------------------------------------------------------------------- #
# Version comparison
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('text,expected', [
    ('v2.34.0', (2, 34, 0)), ('2.34.0', (2, 34, 0)),
    ('  v10.0.1  ', (10, 0, 1)), ('v2.34.0-rc1', (2, 34, 0)),
    ('v2.34', None), ('', None), (None, None), ('vX.Y.Z', None),
])
def test_a_tag_is_read_as_a_version_or_not_at_all(text, expected):
    assert uc.parse_version(text) == expected


@pytest.mark.parametrize('running,latest,expected', [
    ('2.34.0', 'v2.34.1', uc.OUTDATED),
    ('2.34.0', 'v2.35.0', uc.OUTDATED),
    ('2.34.0', 'v3.0.0', uc.OUTDATED),
    ('2.9.0', 'v2.10.0', uc.OUTDATED),      # not a string comparison
    ('2.34.0', 'v2.34.0', uc.CURRENT),
    ('2.34.1', 'v2.34.0', uc.CURRENT),
])
def test_versions_are_compared_as_numbers(running, latest, expected):
    assert uc.compare(running, latest) == expected


# --------------------------------------------------------------------------- #
# It does not become a source of traffic
# --------------------------------------------------------------------------- #

def test_the_answer_is_cached():
    calls = []

    def fetcher():
        calls.append(1)
        return 'v2.34.0'

    clock = [1000.0]
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                             fetcher=fetcher, now=lambda: clock[0])
    for _ in range(5):
        checker.status()
    assert len(calls) == 1


def test_the_cache_expires():
    calls = []

    def fetcher():
        calls.append(1)
        return 'v2.34.0'

    clock = [1000.0]
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                             fetcher=fetcher, now=lambda: clock[0])
    checker.status()
    clock[0] += uc.CACHE_SECONDS + 1
    checker.status()
    assert len(calls) == 2


def test_force_bypasses_the_cache():
    calls = []
    checker = uc.UpdateCheck(_settings({'enabled': True}), '2.34.0',
                             fetcher=lambda: calls.append(1) or 'v2.34.0',
                             now=lambda: 1000.0)
    checker.status()
    checker.status(force=True)
    assert len(calls) == 2


# --------------------------------------------------------------------------- #
# The fetcher itself, without a network
# --------------------------------------------------------------------------- #

def test_the_fetcher_turns_every_failure_into_none(monkeypatch):
    import urllib.error

    for error in (urllib.error.URLError('offline'),
                  OSError('connection refused'),
                  ValueError('not json'),
                  TimeoutError('slow')):
        monkeypatch.setattr(uc.urllib.request, 'urlopen',
                            MagicMock(side_effect=error))
        assert uc.fetch_latest() is None


def test_the_fetcher_reads_the_tag(monkeypatch):
    class Response:
        status = 200

        def read(self, *a):
            return b'{"tag_name": "v2.35.0"}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(uc.urllib.request, 'urlopen', lambda *a, **k: Response())
    assert uc.fetch_latest() == 'v2.35.0'


@pytest.mark.parametrize('body,status', [
    (b'{"tag_name": 42}', 200),
    (b'{}', 200),
    (b'[]', 200),
    (b'{"tag_name": "v2.35.0"}', 403),      # rate-limited
])
def test_a_body_that_is_not_what_was_expected_is_none(monkeypatch, body, status):
    class Response:
        def __init__(self):
            self.status = status

        def read(self, *a):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(uc.urllib.request, 'urlopen', lambda *a, **k: Response())
    assert uc.fetch_latest() is None


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def test_saving_the_config_coerces_and_persists():
    manager = _settings()
    checker = uc.UpdateCheck(manager, '2.34.0', fetcher=_forbidden_fetcher())
    assert checker.save_config({'enabled': 'yes'}) == {'enabled': True}
    assert manager.update.called


def test_saving_it_off_is_the_default_shape():
    checker = uc.UpdateCheck(_settings(), '2.34.0', fetcher=_forbidden_fetcher())
    assert checker.save_config({}) == {'enabled': False}


# --------------------------------------------------------------------------- #
# Through the app
# --------------------------------------------------------------------------- #

@pytest.fixture(scope='module')
def client(tmp_path_factory):
    """The real app, signed in. Module-scoped: the login rate limiter is
    process-global, so signing in per test returns 429 partway through."""
    import secrets

    from modules.core.factory import create_app

    tmp_path = tmp_path_factory.mktemp('updatecheck')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp_path / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
        application, container = create_app()
        container.managers['auth'].create_user(
            'ops', 'Str0ng-Passw0rd-For-A-Test!', 'admin')
        container.managers['auth'].enable_local_auth(True)
        test_client = application.test_client()
        signed_in = test_client.post(
            '/api/auth/login',
            json={'username': 'ops', 'password': 'Str0ng-Passw0rd-For-A-Test!'})
        assert signed_in.status_code == 200, signed_in.get_data(as_text=True)
        test_client.container = container
        yield test_client


def test_a_real_instance_answers_disabled_out_of_the_box(client):
    """End to end: a freshly created app, nothing configured, and the
    endpoint the footer polls says the check is off."""
    body = client.get('/api/web/update-check').get_json()
    assert body['status'] == 'disabled'
    assert body['latest'] is None


def test_the_endpoint_of_a_real_instance_does_not_reach_out(client, monkeypatch):
    """The promise, asserted against the app rather than the unit: with the
    default configuration, no request leaves."""
    monkeypatch.setattr(
        client.container.managers['update_check'], '_fetch',
        lambda: (_ for _ in ()).throw(AssertionError('reached out while disabled')))
    assert client.get('/api/web/update-check').get_json()['status'] == 'disabled'


def test_the_endpoint_needs_a_session(client):
    """It is behind the same guard as every other /api/web route here."""
    from modules.core.factory import create_app  # noqa: F401  (documents the path)

    anonymous = client.application.test_client()
    assert anonymous.get('/api/web/update-check').status_code in (401, 302)


@pytest.mark.parametrize('url', [
    'file:///etc/passwd',
    'http://example.invalid/releases',
    'ftp://example.invalid/releases',
    'gopher://example.invalid/',
    '/etc/passwd',
])
def test_the_fetcher_opens_nothing_that_is_not_https(url, monkeypatch):
    """`urlopen` will open file:// and custom schemes, and this function takes
    its URL as an argument — so the constant being right is not the same as
    the function being safe. The guard is what makes bandit's B310 a settled
    question here rather than a suppression over nothing."""
    def forbidden(*args, **kwargs):
        raise AssertionError(f'opened {url!r}')

    monkeypatch.setattr(uc.urllib.request, 'urlopen', forbidden)
    assert uc.fetch_latest(url) is None


def test_the_url_it_actually_uses_is_https():
    assert uc.RELEASES_URL.startswith('https://')
