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
# README.md, not index.md. `docs/index.md` had the version stamp only because
# of its filename: it was the client-certificate launch write-up, never an
# index. The index is README.md — which is what GitHub renders when you browse
# to `docs/`, and is now what scripts/release.sh stamps.
DOCS_LANDING_PAGES = sorted(REPO_ROOT.glob("docs/README.md")) + sorted(
    REPO_ROOT.glob("docs/*/README.md")
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


def test_package_lock_matches_module_version():
    """npm rewrites these two fields from package.json on any install.

    Left stale they are a permanent source of noisy lockfile diffs, and they
    misreport which release the frontend bundle belongs to. This drifted to
    two releases behind (2.23.0 while package.json said 2.24.2) before anyone
    noticed — the same failure as the docs landing pages: a copy of the
    version that the release script did not own.
    """
    lock = json.loads((REPO_ROOT / "package-lock.json").read_text(encoding="utf-8"))
    found = {
        "version": lock.get("version"),
        'packages[""].version': lock.get("packages", {}).get("", {}).get("version"),
    }
    for where, value in found.items():
        assert value == __version__, (
            f"package-lock.json {where} is {value!r} but modules.__version__ is "
            f"{__version__!r}. scripts/release.sh bumps this file."
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
    assert len(DOCS_LANDING_PAGES) >= 5, (
        f"expected a docs/README.md per language, found {len(DOCS_LANDING_PAGES)} "
        f"- has the layout moved again?"
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


def test_release_script_ignores_client_tags_when_finding_the_last_release():
    """The real-cert gate must be measured from the last RELEASE, not any tag.

    The clients publish from their own `clients-v*` tags, so one of those is
    routinely the newest tag on main. A bare `git describe --tags` resolves to
    it, the sensitive-path diff is then computed from the wrong point, and a
    release that DID touch the issuance pipeline is reported as "no
    issuance-pipeline change" — which lets --skip-real-cert bypass a gate the
    script itself calls MANDATORY.

    Caught while cutting v2.25.0: the diff from `clients-v0.1.3` was
    RELEASE_NOTES.md alone, while the diff from `v2.24.2` contained
    modules/api/resources.py.
    """
    script = (REPO_ROOT / "scripts" / "release.sh").read_text(encoding="utf-8")
    describe_lines = [
        line for line in script.splitlines()
        if "describe --tags" in line and not line.strip().startswith("#")
    ]
    assert describe_lines, "release.sh no longer resolves a last tag - has it moved?"
    for line in describe_lines:
        assert "--match 'v*'" in line, (
            "release.sh resolves the last tag without --match 'v*', so a "
            "clients-v* tag can be mistaken for the last release and disarm "
            f"the mandatory real-cert gate: {line.strip()}"
        )


def test_security_policy_names_the_current_minor_line():
    """SECURITY.md is what a researcher reads before reporting.

    It said `2.25.x`... no: it said `2.21.x` while 2.25.0 was the release,
    four minor lines stale. Someone reading that concludes the version they
    are running is out of scope, or that nobody is home. It names the MINOR
    line, so it only moves on a x.y.0 — but it moves without being remembered.
    """
    major, minor, _ = __version__.split(".")
    text = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")

    supported = set(re.findall(r"`(\d+\.\d+)\.x`", text))
    assert supported == {f"{major}.{minor}"}, (
        f"SECURITY.md declares support for {sorted(supported)} but the current "
        f"release is {__version__}. scripts/release.sh bumps this file."
    )
    retired = set(re.findall(r"`< (\d+\.\d+)`", text))
    assert retired == {f"{major}.{minor}"}, (
        f"SECURITY.md retires everything below {sorted(retired)}, which does "
        f"not match the supported line {major}.{minor}.x"
    )


# The clients version independently of the app (their own `clients-v*` tags and
# their own PyPI packages), so they are NOT compared to modules.__version__ —
# only to themselves.
CLIENT_PACKAGES = [
    ("certmate-cli", "certmate_cli"),
    ("certmate-sdk", "certmate"),
]

PYPROJECT_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)
DUNDER_VERSION = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)


@pytest.mark.parametrize("dist,module", CLIENT_PACKAGES)
def test_client_dunder_version_matches_its_pyproject(dist, module):
    """A published wheel must report the version it was published as.

    This is the same drift class the rest of this file guards, in the one
    place it was not being guarded: both clients went to PyPI as 0.1.3 while
    their `__version__` still said 0.1.2, so every bug report quoting
    `certmate.__version__` named the wrong release. The build reads the
    version from pyproject.toml, so nothing failed — it just lied.
    """
    root = REPO_ROOT / "clients" / dist
    declared = PYPROJECT_VERSION.search(
        (root / "pyproject.toml").read_text(encoding="utf-8"))
    dunder = DUNDER_VERSION.search(
        (root / module / "__init__.py").read_text(encoding="utf-8"))
    assert declared, f"{dist}: no version in pyproject.toml"
    assert dunder, f"{dist}: no __version__ in {module}/__init__.py"
    assert declared.group(1) == dunder.group(1), (
        f"{dist}: pyproject.toml says {declared.group(1)!r} but "
        f"{module}/__init__.py says {dunder.group(1)!r} — bump both in the "
        f"same commit, they are what the wheel and the runtime each report."
    )


def test_both_clients_ship_the_same_version():
    """The CLI depends on the SDK and they are released from one `clients-v*`
    tag, so a split version means the tag names only half of what it built."""
    versions = {}
    for dist, _ in CLIENT_PACKAGES:
        pyproject = REPO_ROOT / "clients" / dist / "pyproject.toml"
        found = PYPROJECT_VERSION.search(pyproject.read_text(encoding="utf-8"))
        # Asserted rather than dereferenced: a client moving to
        # `dynamic = ["version"]` should fail with a sentence explaining what
        # happened, not an AttributeError on `.group`.
        assert found, (
            f"{dist}/pyproject.toml has no inline `version = \"...\"` line. If "
            f"it moved to a dynamic version, this guard needs to read the "
            f"version the same way the build does."
        )
        versions[dist] = found.group(1)
    assert len(set(versions.values())) == 1, (
        f"clients disagree on their version: {versions} — they publish from a "
        f"single clients-v* tag, so one tag cannot name two versions."
    )
