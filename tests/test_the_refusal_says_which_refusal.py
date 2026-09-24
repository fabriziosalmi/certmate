"""Two small ones from #876: the create error, and the health grace period.

**Item 8 — the hint sent people to the wrong place, and the prefix was said
twice.**

`certificates.py` raises `RuntimeError('Certificate creation failed: ...')` and
the API prefixed it again, so every certbot failure read

    Certificate creation failed: Certificate creation failed: ...

The worse half is the hint. It matched the substring `rate limit`, which
appears in none of the markers a CA actually sends: the ACME error is
`urn:ietf:params:acme:error:rateLimited` — no space — and the human text is
`too many certificates already issued`, which does not contain the words at
all. Measured before the fix:

    rateLimited: too many certificates -> "Check DNS provider credentials"
    too many certificates (5) issued   -> "Check DNS provider credentials"
    too many failed authorizations     -> "DNS provider authentication failed.
                                           Verify your API credentials."

The third decided the order of the checks. It contains "auth", so it reached
the authentication branch, and an operator was told to rotate credentials that
were working — about a refusal that retrying makes worse. `is_acme_rate_limit`
is now asked first, and it tests the markers rather than guessing at words.

**Item 9 — `--start-period=5s` against docker-compose's 40s.**

Measured: a container reaches its first healthy `/health` in about 7 seconds on
a warm host, so the Dockerfile's grace period was already shorter than a normal
boot. A shorter one buys nothing — it only makes a failing check start counting
against `--retries` sooner — so the two agree on 40s now.
"""
import pathlib
import re

import pytest

from modules.api.resources_lifecycle import (
    _CREATION_PREFIX, _certbot_hint, _creation_failure)
from modules.core.utils import _ACME_RATE_LIMIT_MARKERS, is_acme_rate_limit

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
RATE_LIMIT_HINT = "rate limit"

# Real refusals, in the shapes the CA sends them.
REAL_RATE_LIMITS = [
    'urn:ietf:params:acme:error:rateLimited: too many certificates already issued',
    'Error creating new order :: too many certificates (5) already issued for '
    '"example.com" in the last 168 hours',
    'too many failed authorizations recently',
    'too many currently pending authorizations',
]


def test_the_examples_are_really_rate_limits():
    """Guard the guard: these are the input to every assertion below, and if
    the project's own predicate stopped recognising them the tests would be
    measuring agreement between two broken things."""
    for message in REAL_RATE_LIMITS:
        assert is_acme_rate_limit(message), message


def test_the_old_substring_would_still_miss_them():
    """States why the check changed rather than leaving it to the commit
    message. If a marker containing the words "rate limit" is ever added this
    fails, and the reasoning here needs revisiting."""
    assert not any(RATE_LIMIT_HINT in m for m in _ACME_RATE_LIMIT_MARKERS)
    assert not any(RATE_LIMIT_HINT in m.lower() for m in REAL_RATE_LIMITS)


@pytest.mark.parametrize('message', REAL_RATE_LIMITS)
def test_a_rate_limit_is_named_as_one(message):
    assert 'rate limit' in _certbot_hint(message).lower(), (
        f'{message[:60]!r} got {_certbot_hint(message)!r}'
    )


def test_the_worst_case_no_longer_blames_the_credentials():
    """"too many failed authorizations" contains "auth". An operator sent to
    verify working credentials will change them, which fixes nothing and costs
    a rotation."""
    hint = _certbot_hint('too many failed authorizations recently').lower()
    assert 'authentication failed' not in hint
    assert 'rate limit' in hint


@pytest.mark.parametrize('message,expected', [
    ('DNS provider returned unauthorized', 'authentication failed'),
    ('DNS propagation timeout waiting for TXT', 'propagation timed out'),
    ('something else entirely', 'ensure dns records can be created'),
])
def test_the_other_hints_still_work(message, expected):
    """Putting the rate-limit test first must not swallow the rest."""
    assert expected in _certbot_hint(message).lower()


# ── the prefix ───────────────────────────────────────────────────────

def test_an_already_prefixed_message_is_not_prefixed_again():
    body = _creation_failure(_CREATION_PREFIX + 'certbot exploded')
    assert body['error'] == _CREATION_PREFIX + 'certbot exploded'
    assert body['error'].count('Certificate creation failed') == 1


def test_an_unprefixed_message_still_gets_one():
    """Not every RuntimeError from the create path carries it, and an error
    body that starts mid-sentence is worse than one that repeats itself."""
    body = _creation_failure('certbot exploded')
    assert body['error'] == _CREATION_PREFIX + 'certbot exploded'


def test_the_prefix_is_the_one_the_core_actually_raises():
    """The two are in different modules and only agree by literal. If the
    core's wording changes, this fails instead of the duplication coming
    back silently."""
    core = (REPO / 'modules' / 'core' / 'certificates.py').read_text(encoding='utf-8')
    assert f'f"{_CREATION_PREFIX}{{safe_stderr}}"' in core or \
           f"f'{_CREATION_PREFIX}{{safe_stderr}}'" in core, (
        'the create path no longer raises with this prefix; _CREATION_PREFIX '
        'is now guarding against a duplication that cannot happen, and a real '
        'one may have taken its place'
    )


def test_the_body_still_carries_a_hint_and_a_code():
    body = _creation_failure('too many certificates already issued')
    assert body['code'] == 'CERTIFICATE_CREATION_FAILED'
    assert 'rate limit' in body['hint'].lower()


# ── the grace period ─────────────────────────────────────────────────

def _start_period(text, pattern):
    match = re.search(pattern, text)
    assert match, f'no start period found for {pattern!r}'
    return int(match.group(1))


def test_the_image_and_compose_agree_on_the_grace_period():
    """They disagreed 5 against 40. The Dockerfile's was shorter than a normal
    boot — measured at about 7 seconds — and a shorter grace period only makes
    a failing check count against retries sooner."""
    dockerfile = (REPO / 'Dockerfile').read_text(encoding='utf-8')
    compose = (REPO / 'docker-compose.yml').read_text(encoding='utf-8')

    image = _start_period(dockerfile, r'--start-period=(\d+)s')
    # The certmate service, not the nginx one below it, which has its own.
    service = _start_period(
        compose[:compose.index('  nginx:')] if '  nginx:' in compose else compose,
        r'start_period:\s*(\d+)s')

    assert image == service, (
        f'the image grants {image}s before a failed health check counts and '
        f'compose grants {service}s; an operator reading one learns the wrong '
        f'thing about the other'
    )


def test_the_grace_period_is_longer_than_a_boot():
    """7 seconds measured on a warm host; the margin is for the runs that are
    not warm. A value below that is a grace period that expires during normal
    startup."""
    dockerfile = (REPO / 'Dockerfile').read_text(encoding='utf-8')
    assert _start_period(dockerfile, r'--start-period=(\d+)s') >= 20
