"""A token made the way the documentation says to make it is never refused for being random (#1057).

`validate_api_token` refused 0.19% of the tokens `openssl rand -hex 32` makes ("too many repeating
patterns": some 3-character window turned up three times by chance, in about 1 token in 580), and
1.7% of the 32-character ones `openssl rand -hex 16` makes (fewer than 12 distinct characters, by
chance). A refused `API_BEARER_TOKEN` makes CertMate refuse to start, so the user who did exactly what
the README says got a service that does not come up. The refusal names the cause, which is no comfort
to someone whose token was fine.

What this holds, and what it does not:

* the two STRUCTURAL rules (repetition, variety) never fire on a random token from any generator the
  documentation names. Sampled with a fixed seed, so the result is the same on every run;
* the weak-PATTERN rule (`12345`, `qwerty`...) is outside that claim, deliberately: it exists to catch a
  value copied out of the documentation, and a random token contains `12345` by chance about once in
  12,000. That residue is measured below and bounded, not hidden;
* the tokens the rules exist to refuse are still refused, and the threshold sits BETWEEN the two groups
  with room on both sides (a margin test, so moving it cannot quietly cross over).
"""
import pathlib
import random

import pytest

from modules.core.utils import _MIN_TRIGRAM_VARIETY, validate_api_token

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent

HEX = '0123456789abcdef'
ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
URLSAFE = ALNUM + '-_'

# generator as the documentation words it -> (alphabet, length). Each command is checked below to
# exist where it is claimed to, so this list cannot drift from what users are told to run.
GENERATORS = {
    'openssl rand -hex 32': (HEX, 64),
    'openssl rand -hex 24': (HEX, 48),
    'openssl rand -hex 16': (HEX, 32),
    'openssl rand -base64 32 | tr -d "=+/" | cut -c1-32': (ALNUM, 32),
    'secrets.token_urlsafe(32)': (URLSAFE, 43),
    'secrets.token_urlsafe(48)': (URLSAFE, 64),
}
SAMPLES = 20000


def _tokens(generator, seed=1057):
    alphabet, length = GENERATORS[generator]
    rng = random.Random(f'{seed}:{generator}')
    return [''.join(rng.choices(alphabet, k=length)) for _ in range(SAMPLES)]


def _ratio(token):
    windows = len(token) - 2
    return len({token[i:i + 3] for i in range(windows)}) / windows


@pytest.mark.parametrize('generator', sorted(GENERATORS))
def test_no_structural_rule_refuses_a_random_token(generator):
    structural = []
    weak_pattern = 0
    for token in _tokens(generator):
        ok, reason = validate_api_token(token)
        if ok:
            continue
        if 'weak patterns' in reason:
            weak_pattern += 1
        else:
            structural.append((token, reason))
    assert not structural, (
        f'{len(structural)} of {SAMPLES} random tokens from `{generator}` were refused for a structural '
        f'reason, which is the user following the instructions and the service not starting: '
        f'{structural[:2]}')
    assert weak_pattern / SAMPLES < 0.001, (
        f'{weak_pattern} of {SAMPLES} random tokens contained a weak pattern; chance alone gives ~1 in 12,000')


def test_a_32_character_hex_token_with_few_distinct_characters_is_accepted():
    """The case the old floor of 12 got wrong most often: random 32-hex with 9 to 11 distinct characters."""
    candidates = [t for t in _tokens('openssl rand -hex 16') if 9 <= len(set(t)) <= 11]
    assert candidates, 'the seeded sample has none: this test is not looking at the case it names'
    for token in candidates[:50]:
        assert validate_api_token(token)[0] is True, token


@pytest.mark.parametrize('label,token', [
    ('a three-letter unit, repeated', 'abc' * 21 + 'a'),
    ('a digit run, repeated', '0123456789' * 6 + '0123'),
    ('a four-character unit, repeated', 'a1b2' * 16),
    ('a phrase said twice', 'correct-horse-battery-staple-correct-horse-battery-staple'),
    ('random, then padded with one letter', 'f3a91c07d2b64e58a1c93f07d26b4e' + 'a' * 30),
    ('a placeholder with digits after it', 'password123456789012345678901234567890'),
    ('four symbols only', ''.join(random.Random('dna').choices('ACGT', k=64))),
])
def test_a_token_the_rules_exist_to_refuse_is_still_refused(label, token):
    ok, reason = validate_api_token(token)
    assert ok is False, f'{label}: {token!r} was accepted'


def test_the_threshold_sits_between_random_tokens_and_the_weak_ones_with_room():
    random_floor = min(_ratio(t) for g in GENERATORS for t in _tokens(g)[:4000])
    weak_ceiling = max(_ratio(t) for t in (
        'abc' * 21 + 'a', '0123456789' * 6 + '0123', 'a1b2' * 16,
        'correct-horse-battery-staple-correct-horse-battery-staple',
        'f3a91c07d2b64e58a1c93f07d26b4e' + 'a' * 30))
    # Only the tokens the REPETITION rule is for. "Four symbols only" is refused by the variety floor
    # (4 distinct characters), and a random 4-symbol token is not repetitive: its ratio is ~0.6 to 0.66.
    assert random_floor - _MIN_TRIGRAM_VARIETY > 0.05, (
        f'the least varied random token ({random_floor:.3f}) is within 0.05 of the threshold '
        f'({_MIN_TRIGRAM_VARIETY}): a random token could be refused')
    assert _MIN_TRIGRAM_VARIETY - weak_ceiling > 0.05, (
        f'the most varied weak token ({weak_ceiling:.3f}) is within 0.05 of the threshold '
        f'({_MIN_TRIGRAM_VARIETY}): a weak token could be accepted')


@pytest.mark.parametrize('command,where', [
    ('openssl rand -hex 32', 'README.md'),
    ('openssl rand -hex 32', 'deploy/install.sh'),
    ('openssl rand -base64 32', 'start-certmate.sh'),
    ('secrets.token_urlsafe(32)', '.env.example'),
])
def test_the_generators_named_here_are_the_ones_users_are_told_to_run(command, where):
    assert command in (REPO / where).read_text(encoding='utf-8'), (
        f'`{command}` is not in {where}: the list of generators above has drifted from the instructions')
