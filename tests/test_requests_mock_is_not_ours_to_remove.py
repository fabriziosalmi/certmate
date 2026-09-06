"""`requests-mock` in the production image is upstream's choice, not ours —
and this watches for the day that stops being true.

A test-shaped library in a production image is a real smell, and the obvious
reaction is to delete the line from requirements.txt. That would not remove the
package: three certbot DNS plugins declare `requests-mock` as an unconditional
runtime requirement, so pip installs it regardless. Deleting the line would only
un-pin it, leaving the shipped version to whichever floating lower bound a
plugin happens to carry — strictly worse than choosing it ourselves.

So the pin stays, and the justification beside it has to remain true. This
checks both directions (#660):

* the claim is still accurate — something really does require it at runtime;
* and when nothing does any more, this fails and says the line can go, instead
  of the pin outliving its reason the way stale rationale usually does.
"""
import importlib.metadata as metadata
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REQUIREMENTS = Path(__file__).resolve().parent.parent / 'requirements.txt'
PACKAGE = 'requests-mock'


def _runtime_requirers():
    """Installed distributions that declare *PACKAGE* as a runtime dependency.

    Extras are excluded: a dependency behind `; extra == "test"` is not
    installed by default and would not reach the image.
    """
    found = []
    for dist in metadata.distributions():
        for requirement in (dist.requires or []):
            name = re.split(r'[\s\[<>=!;()]', requirement.strip(), 1)[0]
            if name.lower().replace('_', '-') != PACKAGE:
                continue
            if 'extra ==' in requirement:
                continue
            found.append(dist.metadata['Name'])
    return sorted(set(found))


def _justification_block():
    """The comment lines immediately above the requests-mock pin.

    Scoped deliberately: the rest of requirements.txt lists every plugin by
    name, so searching the whole file would make the check vacuous.
    """
    lines = REQUIREMENTS.read_text(encoding='utf-8').splitlines()
    for index, line in enumerate(lines):
        if re.match(r'^requests[-_]mock==', line, re.IGNORECASE):
            block = []
            for previous in reversed(lines[:index]):
                if not previous.startswith('#'):
                    break
                block.append(previous)
            return "\n".join(reversed(block))
    return ''


def _is_pinned_in_requirements():
    text = REQUIREMENTS.read_text(encoding='utf-8')
    return re.search(r'^requests[-_]mock==', text, re.MULTILINE | re.IGNORECASE)


def test_something_really_does_require_it_at_runtime():
    """If this fails, the pin has outlived its reason — delete it."""
    if not _is_pinned_in_requirements():
        pytest.skip('requests-mock is no longer pinned; nothing to justify')

    requirers = _runtime_requirers()
    if not metadata.distributions():
        pytest.skip('no distribution metadata available in this environment')

    try:
        metadata.version('requests-mock')
    except metadata.PackageNotFoundError:
        pytest.skip('requests-mock is not installed in this environment')

    assert requirers, (
        "requirements.txt pins requests-mock on the grounds that certbot DNS "
        "plugins require it at runtime, but no installed distribution declares "
        "it any more. The reason is gone: remove the pin and the comment "
        "rather than shipping a test library in the production image."
    )


def test_the_comment_names_the_plugins_that_actually_require_it():
    """CONTROL: the justification must not drift from reality.

    It previously named Hetzner and Porkbun; Porkbun does not require it, while
    arvancloud and infomaniak do. A rationale naming the wrong packages reads as
    authoritative while pointing at nothing.
    """
    if not _is_pinned_in_requirements():
        pytest.skip('requests-mock is no longer pinned')
    requirers = _runtime_requirers()
    if not requirers:
        pytest.skip('nothing requires it here; the other test covers that case')

    # Search ONLY the comment block that justifies the pin, not the whole file:
    # every plugin appears in requirements.txt anyway as its own requirement
    # line, so scanning the file made this assertion impossible to fail. A
    # guard that cannot fail is the thing this milestone is about.
    justification = _justification_block().lower()
    # The comment refers to plugins by their short name (certbot-dns-hetzner
    # is spoken of as "hetzner"), so match on that.
    missing = [
        name for name in requirers
        if name.lower().replace('certbot-dns-', '').replace('certbot-', '')
        not in justification
    ]
    assert not missing, (
        f"these distributions require requests-mock at runtime but the "
        f"justification in requirements.txt does not mention them: {missing}"
    )
