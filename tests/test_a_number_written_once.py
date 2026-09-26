"""The provider count is written in one place, and that place agrees with the code.

Searching `certmate` on Google put an AI Overview above every result saying
CertMate "supporta oltre **22** provider DNS". It is 29. Google did not invent
the number: `README.md` stated it three different ways — "29", "two dozen+" and
"25+" — and the summariser picked one of the vague ones. Counting across the
translated trees, the same product described itself with a quantity in fifteen
places and five languages.

An incoherent document used to produce a confused reader who then went and
checked. With an AI Overview it produces a confident wrong answer for everyone
who never opens the page at all, and the README is also the landing page for the
repository and the body of the Docker Hub listing.

So the rule this file holds: **a number that describes the product is written
once.** Everywhere else points at the list. The one remaining statement is
checked against the code rather than against a previous copy of itself, because
a gate that pins prose to prose only proves the two have not diverged, not that
either is true.
"""
import pathlib
import re

import pytest

from modules.core.dns_providers import DNSManager

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent

#: Where a reader meets a claim about how many providers there are. Only the
#: English pages carry a count now; translations point at the list instead,
#: which is also why this does not have to be re-run in five languages.
#:
#: `docs/releases/` is excluded, and that is not a convenience. A release note
#: is a record of what was true on a date: v2.5.4 says the setup wizard "only
#: knew 14 providers", which is the defect that release fixed, and v2.11.4
#: counts 8. Both were correct when written, and a gate that made them agree
#: with today would be falsifying the history it is reading. The first run of
#: this test flagged both — the rule needed the exclusion, not the notes.
PROSE = ['README.md'] + [
    str(path.relative_to(REPO)) for path in sorted((REPO / 'docs').rglob('*.md'))
    if 'releases' not in path.parts
]

#: A quantity attached to "provider(s)". Matched by shape, not by banning a
#: particular wrong number: "two dozen+" and "25+" were both wrong, and the
#: next wrong one will be spelled differently again. `one provider` is prose
#: about a single provider ("configure one DNS provider") and is not a count of
#: what exists, so the word forms start at two.
COUNT = re.compile(
    r'\b('
    r'\d{1,3}\+?'
    r'|(?:two|three|four|five|six|seven|eight|nine|ten)\s+dozen\+?'
    r'|dozens?\+?'
    r')\s+(?:DNS\s+)?providers\b',
    re.IGNORECASE,
)


def _claims():
    """Every counted provider claim in the English prose, with its location."""
    found = []
    for name in PROSE:
        path = REPO / name
        if not path.exists():
            continue
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            for match in COUNT.finditer(line):
                found.append((name, number, match.group(1), line.strip()))
    return found


def test_the_count_is_stated_exactly_once():
    claims = _claims()
    where = [f'{name}:{line} says "{text}"' for name, line, text, _ in claims]
    assert len(claims) == 1, (
        'A number that describes the product is written once, and every other '
        'place points at the list. Found ' + str(len(claims)) + ': '
        + '; '.join(where)
    )


def test_the_one_statement_is_the_number_the_code_supports():
    """Derived from the registry, not pinned to a copy of the prose.

    Three registries in the app agree on the count; this reads the one the
    DNS manager validates against, so adding a provider and forgetting the
    sentence fails here rather than in an AI summary six weeks later."""
    truth = len(DNSManager.SUPPORTED_PROVIDERS)
    (name, line, stated, text) = _claims()[0]
    assert stated == str(truth), (
        f'{name}:{line} says "{stated} DNS providers"; the app supports '
        f'{truth}. The line reads: {text}'
    )


def test_the_registries_still_agree_with_each_other():
    """CONTROL: the test above is only worth something if the registry it reads
    is the same one the rest of the app uses. Three independent lists exist;
    if they ever disagree, the sentence cannot be right for all of them and
    this fails before the count test can give a false answer."""
    from modules.core.settings import SettingsManager  # noqa: F401

    settings_source = (REPO / 'modules' / 'core' / 'settings.py').read_text(encoding='utf-8')
    block = re.search(r'supported_providers\s*=\s*\{([^}]+)\}', settings_source, re.S)
    assert block, 'supported_providers is no longer a set literal; re-derive this'
    validated = {m.group(1) for m in re.finditer(r"'([a-z0-9-]+)'", block.group(1))}

    credentials_source = (REPO / 'modules' / 'core' / 'utils.py').read_text(encoding='utf-8')
    creds = re.search(
        r'_DNS_PROVIDER_CREDENTIALS\s*=\s*\{(.*?)^\}', credentials_source, re.S | re.M)
    assert creds, '_DNS_PROVIDER_CREDENTIALS is no longer a dict literal'
    known = {m.group(1) for m in re.finditer(r"^\s*'([a-z0-9-]+)'\s*:", creds.group(1), re.M)}

    registry = set(DNSManager.SUPPORTED_PROVIDERS)
    assert registry == validated, sorted(registry ^ validated)
    assert registry == known, sorted(registry ^ known)


def test_no_release_section_outlives_its_release():
    """The README carried a section headed "What's New in v2.0.0" while the
    product was at 2.37.0 — thirty-seven minor releases later, and the only
    version the file named. Release notes have their own directory and their
    own index; a snapshot of one release frozen into the front page is a
    fossil, and the reader cannot tell how old it is without checking."""
    import modules

    readme = (REPO / 'README.md').read_text(encoding='utf-8')
    announced = set(re.findall(r"What's New in (v\d+\.\d+(?:\.\d+)?)", readme))
    assert not announced, (
        f'README.md announces {sorted(announced)} as new; the product is at '
        f'v{modules.__version__}. Release notes live in docs/releases/.'
    )
