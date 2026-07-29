"""Single-source-of-truth guard: every user-facing copy of the version number
must agree with modules.__version__. A drift here means a release bumped one
and forgot the others.

The rule these tests encode: a version string that has to be *remembered* is a
version string that goes stale. Everything listed here is bumped by
scripts/release.sh, and these tests are what turn a forgotten bump into a red
CI run instead of a release that quietly misinforms people about what they are
running."""
import json
import pathlib
import re

import pytest

from modules import __version__

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Globbed, not enumerated: a translation added later is covered the day it
# lands, without anyone remembering to extend this list. Both v2.24.0 and
# v2.24.1 shipped with these pages stale (#483, and again in #487) precisely
# because they were only ever fixed by hand.
DOCS_LANDING_PAGES = sorted(REPO_ROOT.glob("docs/index.md")) + sorted(
    REPO_ROOT.glob("docs/*/index.md")
)

# Matches the localised "current version" line in any language:
#   **Current Version**: 2.24.1
#   **Version actuelle** : 2.24.1
#   **Versione corrente**: 2.24.1
DOCS_VERSION_LINE = re.compile(
    r"^\*\*[^*]+\*\*\s*:?[ \t]*([0-9]+\.[0-9]+\.[0-9]+)[ \t]*$", re.M
)


def test_package_json_matches_module_version():
    pkg = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    assert pkg["version"] == __version__, (
        f"package.json version {pkg['version']!r} != modules.__version__ "
        f"{__version__!r} - bump both (or neither) in the same release commit."
    )


def test_dockerhub_readme_health_example_matches_module_version():
    """The example an operator compares their own /health output against.

    It is bumped by scripts/release.sh, not by hand — this test is what makes
    a forgotten bump fail rather than quietly misinform someone about which
    version they are running.
    """
    text = (REPO_ROOT / "README.dockerhub.md").read_text(encoding="utf-8")
    versions = re.findall(r'"version": "([0-9]+\.[0-9]+\.[0-9]+)"', text)
    assert versions, "no version example found in README.dockerhub.md"
    for found in versions:
        assert found == __version__, (
            f"README.dockerhub.md shows version {found!r} but "
            f"modules.__version__ is {__version__!r}."
        )


def test_there_are_docs_landing_pages_to_check():
    """Guard the guard: an empty glob would make the test below vacuously pass."""
    assert DOCS_LANDING_PAGES, (
        "neither docs/index.md nor docs/*/index.md matched - has the layout moved?"
    )


@pytest.mark.parametrize(
    "path", DOCS_LANDING_PAGES, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_docs_landing_page_version_matches_module_version(path):
    """The "Current Version" line on every docs landing page, in every language."""
    found = DOCS_VERSION_LINE.findall(path.read_text(encoding="utf-8"))
    rel = path.relative_to(REPO_ROOT)
    assert found, (
        f"{rel} has no '**Current Version**: X.Y.Z' line. If the line was "
        f"renamed or removed, update DOCS_VERSION_LINE - do not delete this "
        f"test, or the page can drift unnoticed."
    )
    for version in found:
        assert version == __version__, (
            f"{rel} advertises version {version!r} but modules.__version__ is "
            f"{__version__!r}. scripts/release.sh bumps this file; if you are "
            f"seeing this outside a release, it was edited by hand."
        )


def test_release_notes_document_the_current_version():
    """No version may ship without a section describing it.

    scripts/release.sh refuses to prepare a release whose notes are missing,
    but that check only runs on the machine cutting the release. This makes the
    same rule hold in CI, for any path that reaches main.
    """
    text = (REPO_ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    # The trailing space is part of the contract, not sloppiness: notes_section()
    # in scripts/release.sh matches with `awk -v v="## v$1 "` and index($0,v)==1,
    # so a bare "## v2.24.1" heading with no title extracts an EMPTY section and
    # the release dies there. Asserting the looser form would let CI go green on
    # notes the release script cannot read.
    assert re.search(rf"^## v{re.escape(__version__)} \S", text, re.M), (
        f"RELEASE_NOTES.md has no '## v{__version__} <title>' section. Every "
        f"released version needs one, and the heading must carry a title after "
        f"the version - scripts/release.sh extracts the GitHub release body by "
        f"matching the literal prefix '## v{__version__} '."
    )
