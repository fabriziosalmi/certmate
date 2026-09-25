"""#938: "1 day ago" for a certificate that expired a minute ago.

Two defects in one sentence, and they are the two halves of #829.

**The expired side.** `static/js/dashboard.js` already carried the right
answer — `absDays === 0 ? 'less than a day ago'` — under a comment saying
exactly why it was needed. That branch could never run. `days_until_expiry` is
`timedelta.days`, which truncates toward minus infinity, so anything expired
within 24 hours is **-1 and never 0**. Measured on the private-CA bench: a
certificate expired 1h18m earlier was rendered "1 day ago".

**The live side.** `templates/notifications.html` had no zero case at all and
tested `days <= 0`, so a certificate with 23 hours of life read "0 days ago" —
described in the past tense while it was still working. That is the sentence
#829 was closed for, on a page #829's fix never reached, because the warning
object `CertMateNotif.deriveWarnings` builds **dropped `expired` and
`seconds_left`** — the two fields #829 added for exactly this question.

## Why the existing guard missed it

`tests/test_a_valid_certificate_does_not_read_as_expired.py` has a list of
every renderer, under a comment that says *"The list is the point: the first
fix touched dashboard.js only."* `templates/notifications.html` was not in it.
The mechanism was right and the list was incomplete, which is the failure mode
of every hand-written list.

So the guard here is **derived from the tree** instead. Any file that prints
one of these phrases has to go through the shared helper, and a fourth
renderer added next year fails this without anyone remembering to add it
anywhere.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMPLEMENTATION = 'static/js/certmate.js'
HELPER = 'CertMate.lifetimePhrase'

# The phrases the user reads. A file that builds one of these is a renderer.
PHRASES = (' day ago', ' days ago', ' day left', ' days left')

SEARCHED = ['static/js', 'templates']

# Files that print one of the phrases and must NOT be routed through the
# helper. The default is "checked": an exemption is written here with its
# reason, and `test_every_exemption_is_still_earned` fails when one stops
# matching, so the list cannot rot the way a list of things TO check does.
EXEMPT = {
    'templates/partials/settings_general.html':
        'prose in a field label -- "Renew certificates when they have this '
        'many days left before expiration" -- not a rendered duration.',
    'static/js/cmd-palette.js':
        'renders a STATUS, not a duration. It returns "Expired" or "Expiry '
        'unknown" before reaching any phrase, so it can only get there with '
        '`expired === false` and days >= 0, and it already has the zero case. '
        'Routing it through the helper would replace a one-word palette label '
        'with "less than a day ago", which is worse in a single-line row.',
}


def _code_lines(source):
    """Lines that are code, not commentary.

    The first version of the #829 guard failed on the comment explaining why
    the pattern was wrong, which is the instrument being wrong rather than the
    file. Every phrase in this file's own fixtures lives in a comment.
    """
    lines = []
    in_block = False
    for line in source.splitlines():
        stripped = line.strip()
        if in_block:
            if '*/' in stripped:
                in_block = False
            continue
        if stripped.startswith('/*') or stripped.startswith('{#'):
            in_block = '*/' not in stripped and '#}' not in stripped
            continue
        if stripped.startswith(('//', '*', '#', '<!--')):
            continue
        lines.append(line)
    return lines


def _renderers():
    """Every file that prints one of the phrases, from the tree."""
    found = []
    for directory in SEARCHED:
        for path in sorted((ROOT / directory).rglob('*')):
            if path.suffix not in ('.js', '.html') or not path.is_file():
                continue
            source = path.read_text(encoding='utf-8')
            if any(phrase in line for line in _code_lines(source)
                   for phrase in PHRASES):
                found.append(path.relative_to(ROOT).as_posix())
    return found


# --- the shared implementation --------------------------------------------

def test_there_is_one_implementation():
    """CONTROL for the guard below: with no helper, every renderer would have
    to build the sentence itself and the rule would be unenforceable."""
    source = (ROOT / IMPLEMENTATION).read_text(encoding='utf-8')

    assert 'CM.lifetimePhrase = function' in source


def test_the_magnitude_comes_from_seconds_not_from_a_day_count():
    """THE fix. A day count cannot tell an hour of lateness from a day of it,
    and cannot tell 23 hours of life from none."""
    source = (ROOT / IMPLEMENTATION).read_text(encoding='utf-8')
    body = source[source.index('CM.lifetimePhrase = function'):]
    body = body[:body.index('\n    };')]

    assert 'seconds_left' in body
    assert 'SECONDS_IN_DAY' in body, 'the day boundary is a magic number again'


def test_a_day_count_is_still_the_fallback():
    """An older server sends no `seconds_left`, and "1 day ago" is the best
    answer -1 can support. Dropping the fallback would blank the phrase."""
    source = (ROOT / IMPLEMENTATION).read_text(encoding='utf-8')
    body = source[source.index('CM.lifetimePhrase = function'):]

    assert 'days_until_expiry' in body[:body.index('\n    };')]


# --- the rule, derived from the tree --------------------------------------

def test_the_scan_reads_code_and_not_commentary():
    """CONTROL for the instrument. Every phrase in this repository's comments
    explains why a phrase is wrong; a scan that counted those would flag the
    explanation as the offence — which is how the first #829 guard failed."""
    sample = """
        // a comment saying ' 1 day ago ' must not count
        /* nor a block one saying ' 2 days left ' */
        var real = n + ' days left';
    """
    lines = _code_lines(sample)

    assert any("' days left'" in line for line in lines), 'the scan dropped code'
    assert not any('day ago' in line for line in lines), 'the scan counted a comment'


def test_the_scan_finds_something_to_check():
    """A scan that matched nothing would make every rule below vacuously true
    — which is how the previous guard's hand-written list came to be
    incomplete without anything noticing."""
    found = _renderers()

    # Not the implementation: it COMPOSES the phrase from parts, so a literal
    # search cannot see it — which is the point. What this catches is a file
    # assembling the sentence by hand.
    assert len(found) >= 2, f'only {found} print an expiry phrase; the scan is broken'


def test_the_three_that_were_wrong_now_use_the_helper():
    """Named rather than derived, because a file that is fixed stops printing
    the phrase and drops out of the scan entirely. The scan catches the NEXT
    offender; this catches a regression in the three this issue is about."""
    for relative_path in ('static/js/dashboard.js',
                          'templates/notifications.html'):
        source = (ROOT / relative_path).read_text(encoding='utf-8')
        assert HELPER in source, f'{relative_path} no longer uses the helper'

    dashboard = (ROOT / 'static/js/dashboard.js').read_text(encoding='utf-8')
    assert dashboard.count(HELPER) == 2, (
        'the dashboard renders this in two places -- the table and the detail '
        'panel -- and both must go through the helper')


def test_every_exemption_is_still_earned():
    """An exemption for a file that no longer prints a phrase is a comment
    pretending to be a rule, and the next reader believes it."""
    found = set(_renderers())
    stale = sorted(path for path in EXEMPT if path not in found)

    assert not stale, (
        f'these are exempted from a rule they no longer trip: {stale}. '
        f'Remove the entry rather than leaving a reason for nothing.')


@pytest.mark.parametrize('relative_path', _renderers())
def test_every_renderer_goes_through_the_shared_helper(relative_path):
    if relative_path == IMPLEMENTATION or relative_path in EXEMPT:
        pytest.skip(EXEMPT.get(relative_path, 'this is the implementation'))
    source = (ROOT / relative_path).read_text(encoding='utf-8')

    assert HELPER in source, (
        f'{relative_path} builds an expiry phrase of its own. There were three '
        f'of these and they had already drifted: two carried a "less than a '
        f'day" case and one did not, so the same certificate was described '
        f'differently on two pages.')


@pytest.mark.parametrize('relative_path', _renderers())
def test_no_renderer_measures_the_gap_in_days(relative_path):
    """`Math.abs(days)` is how both halves of this got it wrong."""
    if relative_path == IMPLEMENTATION or relative_path in EXEMPT:
        pytest.skip(EXEMPT.get(relative_path,
                               'this is the implementation, and its fallback '
                               'is deliberate'))
    source = (ROOT / relative_path).read_text(encoding='utf-8')
    offenders = [line.strip() for line in _code_lines(source)
                 if re.search(r'Math\.abs\(\s*\w*\.?days', line)]

    assert not offenders, (
        f'{relative_path} still measures the gap in whole days:\n  '
        + '\n  '.join(offenders))


# --- what the notifications page needs to answer at all -------------------

def test_a_warning_carries_what_the_sentence_needs():
    """`deriveWarnings` used to build `{domain, days, type, expiry_date}`, so
    the notifications page had a day count and nothing else — it could not
    have got this right with any amount of care at the other end."""
    source = (ROOT / 'templates/base.html').read_text(encoding='utf-8')
    body = source[source.index('deriveWarnings'):]
    body = body[:body.index('return out;')]
    # Code only. The first version of this searched the raw text and passed
    # against a mutation that removed the field, because the COMMENT above it
    # names both fields — the same way the #829 guard once failed on the
    # comment explaining the defect.
    body = '\n'.join(_code_lines(body))

    for field in ('expired', 'seconds_left'):
        assert field in body, (
            f'the warning object drops `{field}`, so every page rendering a '
            f'warning is back to guessing from a day count')


# --- executing it, which is the only guard the arithmetic cannot walk past --

HARNESS = r"""
const fs = require('fs');
const win = { addEventListener() {}, document: { addEventListener() {} } };
global.window = win; global.document = win.document; global.navigator = {};
// argv[0] is node and argv[1] is this harness; the arguments start at [2].
try { eval(fs.readFileSync(process.argv[2], 'utf8')); } catch (e) { /* DOM bits */ }
const cases = JSON.parse(process.argv[3]);
console.log(JSON.stringify(cases.map(c => win.CertMate.lifetimePhrase(c))));
"""

DAY = 86400

# Each row is a certificate as the API sends it, and the sentence a reader
# must get. The first two are the measured defect; the third is #829's.
CASES = [
    ({'expired': True, 'seconds_left': -60, 'days_until_expiry': -1},
     'less than a day ago', 'expired one minute ago'),
    ({'expired': True, 'seconds_left': -4680, 'days_until_expiry': -1},
     'less than a day ago', 'expired 1h18m ago — the case measured on the bench'),
    ({'expired': False, 'seconds_left': 82800, 'days_until_expiry': 0},
     'less than a day left', 'ALIVE with 23 hours of life'),
    ({'expired': True, 'seconds_left': -86340, 'days_until_expiry': -1},
     'less than a day ago', 'expired 23h59m ago, still under a day'),
    ({'expired': True, 'seconds_left': -2 * DAY, 'days_until_expiry': -2},
     '2 days ago', 'expired two days ago'),
    ({'expired': False, 'seconds_left': DAY, 'days_until_expiry': 1},
     '1 day left', 'singular, not "1 days left"'),
    ({'expired': False, 'seconds_left': 45 * DAY, 'days_until_expiry': 45},
     '45 days left', 'the ordinary case'),
    ({'days_until_expiry': -1},
     '1 day ago', 'a server too old to send seconds: the day count is all there is'),
    ({'expired': None},
     '', 'unparseable: no sentence rather than a wrong one'),
]


def test_the_sentence_is_right_for_every_case(node, tmp_path):
    """The guards above read the source. This runs it — and it is the only one
    of them that fails when the arithmetic is rewritten to measure in whole
    days again, which is exactly how both halves of this defect were born."""
    import json
    import subprocess

    harness = tmp_path / 'harness.js'
    harness.write_text(HARNESS, encoding='utf-8')
    certs = [row[0] for row in CASES]

    result = subprocess.run(
        [node, str(harness), str(ROOT / IMPLEMENTATION), json.dumps(certs)],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr

    produced = json.loads(result.stdout.strip().splitlines()[-1])
    wrong = [f'{why}: expected {expected!r}, got {got!r}'
             for (_cert, expected, why), got in zip(CASES, produced)
             if got != expected]

    assert not wrong, '\n  '.join([''] + wrong)
