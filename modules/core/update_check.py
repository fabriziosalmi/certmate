"""Whether a newer CertMate exists — asked only when an operator asks for it.

#855 wants a notice when a release is available. The version itself is in the
footer now; this is the other half, and it is the half that needs care,
because it makes the instance call out.

**Off by default, and that is the contract, not a preference.**
`docs/ca-providers.md` offers the private CA for "internal networks, corporate
environments, air-gapped systems", and an instance that was never asked to
reach the internet must not reach it. An update check that phoned home on
first start would break that promise for exactly the deployments that chose
CertMate because of it — and would do so invisibly, as a timeout in a log
nobody reads, or a proxy denial that looks like the product being broken.

So: nothing happens until `update_check.enabled` is true.
``test_a_default_instance_never_calls_out`` is what holds that, by replacing
the fetcher with one that fails the test if it is called at all.

The second rule is the one this codebase keeps relearning: **a check that
could not reach GitHub says so.** It does not report "up to date", which is
what an air-gapped instance would otherwise be told every day while running a
release with a known defect in it. `unknown` is a first-class answer here as
it is everywhere else.
"""

import json
import logging
import re
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

RELEASES_URL = 'https://api.github.com/repos/fabriziosalmi/certmate/releases/latest'

DEFAULT_CONFIG = {'enabled': False}

# Once a day is generous for something that changes every few weeks, and it
# keeps an instance from becoming a source of traffic if a page ever polls it.
CACHE_SECONDS = 24 * 60 * 60
TIMEOUT_SECONDS = 5.0

CURRENT = 'current'          # running the newest release
OUTDATED = 'outdated'        # a newer release exists
UNKNOWN = 'unknown'          # could not find out — never rendered as `current`
DISABLED = 'disabled'        # not asked for

_SEMVER = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)')


def parse_version(text):
    """``v2.34.0`` or ``2.34.0`` -> ``(2, 34, 0)``, else None."""
    match = _SEMVER.match((text or '').strip())
    return tuple(int(p) for p in match.groups()) if match else None


def compare(running, latest):
    """What to say about *running* given *latest*. Never guesses.

    A version either side cannot parse gives `unknown`: a release tagged in a
    form this does not understand is not evidence that the instance is
    current, and saying so would be the reassuring-without-grounds answer this
    project keeps having to take back out.
    """
    here, there = parse_version(running), parse_version(latest)
    if here is None or there is None:
        return UNKNOWN
    return OUTDATED if there > here else CURRENT


def fetch_latest(url=RELEASES_URL, timeout=TIMEOUT_SECONDS):
    """The newest release tag from GitHub, or None.

    None for every failure — offline, proxied, rate-limited, a body that is
    not what was expected. The caller turns that into `unknown`, never into
    `current`.
    """
    # https only, checked here rather than trusted from the caller. `urlopen`
    # will happily open `file:///etc/passwd` or a custom scheme, and this
    # function takes its URL as an argument — so the constant above being
    # correct is not the same as the function being safe. Refusing anything
    # else is also what makes bandit's B310 a settled question rather than a
    # suppression.
    if not str(url).lower().startswith('https://'):
        logger.warning("Update check refused a non-https URL")
        return None

    request = urllib.request.Request(
        url, headers={'Accept': 'application/vnd.github+json',
                      'User-Agent': 'CertMate-update-check'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - https enforced above
            if response.status != 200:
                return None
            body = json.loads(response.read(64 * 1024).decode('utf-8'))
    except (urllib.error.URLError, OSError, ValueError, TypeError) as e:
        logger.info("Update check could not reach %s: %s", url, e.__class__.__name__)
        return None
    tag = body.get('tag_name') if isinstance(body, dict) else None
    return tag if isinstance(tag, str) else None


class UpdateCheck:
    """Settings-backed, opt-in, and cached.

    *fetcher* is the seam: the tests pass one that fails if called, which is
    how "a default instance never calls out" is proven rather than asserted.
    """

    def __init__(self, settings_manager, running_version, *, fetcher=None,
                 now=time.monotonic):
        self.settings_manager = settings_manager
        self.running_version = running_version
        self._fetch = fetcher or fetch_latest
        self._now = now
        self._cached = None
        self._cached_at = None

    def get_config(self):
        settings = self.settings_manager.load_settings() or {}
        config = dict(DEFAULT_CONFIG)
        config.update(settings.get('update_check') or {})
        return config

    def save_config(self, config):
        clean = {'enabled': bool(config.get('enabled', False))}
        self.settings_manager.update(
            lambda s: s.__setitem__('update_check', clean), 'update_check_save')
        return clean

    def status(self, *, force=False):
        """``{'status', 'running', 'latest'}``. Never raises.

        Disabled is its own status rather than `unknown`: "you did not ask"
        and "I asked and could not find out" are different answers, and an
        operator seeing the second should go looking at their egress rules.
        """
        running = {'running': self.running_version}
        if not self.get_config().get('enabled'):
            return dict(running, status=DISABLED, latest=None)

        if not force and self._cached is not None and self._cached_at is not None:
            if self._now() - self._cached_at < CACHE_SECONDS:
                return dict(running, **self._cached)

        latest = self._fetch()
        answer = ({'status': UNKNOWN, 'latest': None} if latest is None
                  else {'status': compare(self.running_version, latest),
                        'latest': latest})
        self._cached, self._cached_at = answer, self._now()
        return dict(running, **answer)
