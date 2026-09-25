"""#940: dates in two conventions, sometimes on the same line.

The activity feed printed this, one line above the other, for the same event:

    08/09/2026
    8 set, 16:23

`set` is `settembre`. The second line followed the **browser's** locale in an
interface that is entirely in English — it is the documentation that is
translated in this project, not the application — and the first was numeric,
which is 8 September or 9 August depending on a convention the page never
states.

Twenty-one call sites formatted a date. Five pinned `en-US` and sixteen took
whatever the browser had; `static/js/client-certs.js` did both, four lines
apart. There was no decision, only two habits, and neither was visible from an
`en-US` machine — which is why this survived: every rendering looks correct
there.

## What was decided, and it is two things

**Named months, never numeric.** `08/09/2026` is ambiguous in every locale;
"Sep 8, 2026" cannot be read two ways. This is the half that is not about
locale at all.

**Pinned to `en-US`,** because the interface is English and a date in the
reader's language is an inconsistency rather than a courtesy — and because a
screenshot in a bug report should show what everyone else sees. The **time
zone** stays local, which is what an operator wants; only the language is
fixed. The clock is 24-hour, stated rather than inherited: `en-US` would
otherwise render "04:27 PM" in a tool whose times sit beside log lines.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMPLEMENTATION = 'static/js/certmate.js'

# Nothing is exempt today. The vendored ReDoc bundle was listed here at first
# and the "still earned" test below rejected it on its first run: it contains
# `toLocaleString` only as a STRING, in a polyfill's list of property names,
# and never as a call. An exemption for a rule a file does not trip is a
# reason written for nothing, and the next reader believes it.
EXEMPT = {}

FORMATTERS = ('formatDate', 'formatDateTime', 'formatTimestamp', 'formatTime')
CALL = re.compile(r'\.toLocale(?:Date|Time)?String\s*\(')


def _files():
    for directory in ('static/js', 'templates'):
        for path in sorted((ROOT / directory).rglob('*')):
            if path.suffix in ('.js', '.html') and path.is_file():
                yield path.relative_to(ROOT).as_posix()


def _formatting_their_own():
    return [rel for rel in _files()
            if CALL.search((ROOT / rel).read_text(encoding='utf-8'))]


# --- the implementation ---------------------------------------------------

@pytest.mark.parametrize('name', FORMATTERS)
def test_each_shape_exists(name):
    """Four shapes because four things are being said: a day, a moment, an
    audited moment, and a clock reading. Collapsing them would mean call sites
    passing options again, which is where the drift started."""
    source = (ROOT / IMPLEMENTATION).read_text(encoding='utf-8')

    assert f'CM.{name} = function' in source


def test_the_locale_is_stated_once():
    source = (ROOT / IMPLEMENTATION).read_text(encoding='utf-8')

    assert "var DATE_LOCALE = 'en-US';" in source
    assert source.count("'en-US'") == 1, (
        'the locale is written more than once, so half of it can be changed')


def test_the_clock_is_not_inherited():
    """`en-US` means 12-hour unless told otherwise, and "04:27 PM" beside a log
    line is worse than what the browser locale was already giving."""
    source = (ROOT / IMPLEMENTATION).read_text(encoding='utf-8')

    assert 'hour12: false' in source


def test_an_unparseable_value_is_not_printed_as_a_date():
    """`new Date('nonsense').toLocaleString()` renders "Invalid Date", which in
    a table reads as data rather than as an absence."""
    source = (ROOT / IMPLEMENTATION).read_text(encoding='utf-8')
    body = source[source.index('function _formatted('):]
    body = body[:body.index('\n    }')]

    assert 'isNaN' in body and "return ''" in body


# --- the rule, derived from the tree --------------------------------------

def test_the_scan_finds_the_implementation():
    """CONTROL: a scan matching nothing would make the rule vacuous."""
    found = _formatting_their_own()

    assert IMPLEMENTATION in found, 'the scan cannot see the one legitimate call'


@pytest.mark.parametrize('relative_path', _formatting_their_own())
def test_nothing_else_formats_a_date_itself(relative_path):
    if relative_path == IMPLEMENTATION:
        pytest.skip('this is the implementation')
    if relative_path in EXEMPT:
        pytest.skip(EXEMPT[relative_path])

    pytest.fail(
        f'{relative_path} calls toLocale...String itself. That is how this '
        f'project came to print `08/09/2026` above `8 set, 16:23` on one row: '
        f'twenty-one call sites and two habits. Use CertMate.formatDate, '
        f'formatDateTime, formatTimestamp or formatTime.')


def test_every_exemption_is_still_earned():
    found = set(_formatting_their_own())
    stale = sorted(path for path in EXEMPT if path not in found)

    assert not stale, (
        f'these are exempted from a rule they no longer trip: {stale}')


# --- executing it ---------------------------------------------------------

HARNESS = r"""
const fs = require('fs');
const win = { addEventListener() {}, document: { addEventListener() {} } };
global.window = win; global.document = win.document; global.navigator = {};
try { eval(fs.readFileSync(process.argv[2], 'utf8')); } catch (e) { /* DOM bits */ }
const [when, tz] = JSON.parse(process.argv[3]);
process.env.TZ = tz;
const C = win.CertMate;
console.log(JSON.stringify({
  date: C.formatDate(when), dateTime: C.formatDateTime(when),
  timestamp: C.formatTimestamp(when), time: C.formatTime(when),
  rubbish: C.formatDate('not a date'), absent: C.formatDate(null),
}));
"""


def test_the_four_shapes_read_the_way_they_are_meant_to(node, tmp_path):
    """Executed, not read. The locale is the one thing a source-level check
    cannot confirm: `toLocaleString('en-US', ...)` is what the source says
    either way, and what comes out is the question."""
    import json
    import subprocess

    harness = tmp_path / 'harness.js'
    harness.write_text(HARNESS, encoding='utf-8')

    result = subprocess.run(
        [node, str(harness), str(ROOT / IMPLEMENTATION),
         json.dumps(['2026-09-25T14:27:05Z', 'UTC'])],
        capture_output=True, text=True, timeout=60,
        env={'TZ': 'UTC', 'PATH': '/usr/bin:/bin:/usr/local/bin'})
    assert result.returncode == 0, result.stderr

    out = json.loads(result.stdout.strip().splitlines()[-1])

    assert out['date'] == 'Sep 25, 2026'
    assert out['dateTime'] == 'Sep 25, 2026, 14:27'
    assert out['timestamp'] == 'Sep 25, 2026, 14:27:05'
    assert out['time'] == '14:27:05'
    # Not "Invalid Date", and not the string it was handed.
    assert out['rubbish'] == ''
    assert out['absent'] == ''
