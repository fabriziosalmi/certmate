"""A certificate whose expiry could not be read is not an expired certificate.

Reported three times by the same person. #88 (March): a newly created
certificate showed as Expired, DNS-01 over RFC2136. The cause was in the
browser — `null <= 0` is `true` in JavaScript, so any certificate whose
validity could not be parsed rendered with a red Expired badge — and v2.2.4
guarded the four comparison sites the dashboard had then. #92, days later:
"still persists after 2.2.4", closed six months on with no reply. #786
yesterday, on v2.29, same setup.

What the backend sends has not changed and is not the problem: when the
certificate file cannot be parsed, `_parse_certificate_info` returns
`days_left: None` and `days_until_expiry: None` with `exists: True`, and when
the file or directory is missing `_create_empty_cert_info` returns
`exists: False` with both fields None. Both are honest answers. Every consumer
has to treat "I do not know" as its own state.

The dashboard's guards from v2.2.4 are intact. The command palette, written
later, was not guarded: `c.days_until_expiry > 0 ? ... : 'Expired'` is `false`
for null, so an unknown expiry read as Expired there — the same defect, in a
file that arrived after the fix.

This test is a shape check on the shipped JavaScript rather than a behavioural
one. There is no JS unit runner in this repository (`npm test` belongs to the
MCP server, and the browser suite is Playwright behind the `ui` marker), and
the property worth pinning is exactly the one a reviewer misses: a comparison
against days_until_expiry with no null guard in sight. It names the file and
the line when it fails, which is what the next person needs.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
JS_DIR = REPO_ROOT / 'static' / 'js'

# Vendored bundles are not ours to hold to this rule.
VENDORED = {'redoc.standalone.js', 'alpine.min.js'}

# What counts as knowing the value is present. `daysKnown` is the dashboard's
# own name for it; the explicit comparisons are what v2.2.4 introduced.
GUARDS = ('!== null', '!== undefined', '=== null', '=== undefined',
          'daysKnown', 'typeof', '!= null', '== null')

# Two shapes are dangerous, and only two.
#
# `days <= 0` asked directly: null wins that comparison, so an unknown expiry
# is reported expired. That is what v2.2.4 fixed on the dashboard.
#
# A branch labelled 'Expired' taken because `days > 0` was false: null loses
# that one, so it arrives at the same wrong answer by the other door. That is
# what the command palette did.
#
# What is NOT dangerous, and must not be flagged, is `days > 0 && days <= 30`:
# an unknown expiry falls out of a positive filter on its own, which is the
# right outcome for "expiring soon".
ASKS_IF_PAST_ZERO = re.compile(r'days_until_expiry\s*(<=|<)\s*0')
LABELS_EXPIRED = re.compile(r'days_until_expiry.*[\'"]Expired[\'"]')


def _sources():
    return [path for path in sorted(JS_DIR.glob('*.js'))
            if path.name not in VENDORED]


def _context(lines, index, before=6):
    """The line and a little of what precedes it — a guard is often a variable
    assigned a few lines up rather than part of the same expression."""
    return '\n'.join(lines[max(0, index - before):index + 1])


def test_there_is_javascript_to_check():
    """A parametrised sweep over an empty list is a green build over nothing."""
    assert len(_sources()) >= 5


def test_no_expiry_decision_is_made_without_knowing_the_value():
    """THE regression. `null <= 0` is true and `null > 0` is false, so an
    unguarded comparison calls an unknown expiry expired either way."""
    unguarded = []
    for path in _sources():
        lines = path.read_text(encoding='utf-8').splitlines()
        for index, line in enumerate(lines):
            if not (ASKS_IF_PAST_ZERO.search(line)
                    or LABELS_EXPIRED.search(line)):
                continue
            if not any(guard in _context(lines, index) for guard in GUARDS):
                unguarded.append(f'{path.name}:{index + 1}: {line.strip()}')

    assert not unguarded, (
        'these decide whether a certificate is expired from a value that may '
        'be null, and null loses both comparisons — so a certificate whose '
        'expiry could not be read is shown as expired (#88, #92, #786):\n  '
        + '\n  '.join(unguarded))


def test_the_command_palette_names_the_unknown_state():
    """The specific site this change fixes, pinned by behaviour rather than by
    line number: three outcomes, not two."""
    source = (JS_DIR / 'cmd-palette.js').read_text(encoding='utf-8')

    assert 'Expiry unknown' in source, (
        'the palette has no wording for an expiry it could not read, so it has '
        'only two states to put a three-state answer into')
    assert 'describeExpiry' in source


@pytest.mark.parametrize('name', ['dashboard.js', 'cmd-palette.js'])
def test_the_guard_stayed_where_it_was_put(name):
    """CONTROL for the sweep above: it passes vacuously if these files stop
    mentioning the field at all — a rename would silently end the checking."""
    source = (JS_DIR / name).read_text(encoding='utf-8')

    assert 'days_until_expiry' in source


def test_the_backend_still_says_it_does_not_know():
    """The other half of the contract. The browser can only distinguish
    unknown from expired if the API keeps sending None rather than 0 — a
    backend that answered 0 would put every one of these guards back to
    square one."""
    import inspect

    from modules.core.certificates import CertificateManager

    empty = inspect.getsource(CertificateManager._create_empty_cert_info)
    assert "'days_left': None" in empty
    assert "'days_until_expiry': None" in empty

    parse = inspect.getsource(CertificateManager._parse_certificate_info)
    unparseable = parse[parse.index('except Exception'):]
    assert "'days_left': None" in unparseable, (
        'a certificate that cannot be parsed no longer reports an unknown '
        'expiry, so the browser cannot tell unknown from expired')
