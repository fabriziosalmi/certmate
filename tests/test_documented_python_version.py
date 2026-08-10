"""The Python version the documentation names must be one that can install this.

Every surface said **Python 3.9+** — the README badge, the README requirements
list, the architecture guide in five languages, the installation guide in five
languages — while `requirements.txt` cannot be installed on 3.9 at all. Not
"is untested on": cannot be installed. Six pinned packages declare
`Requires-Python >=3.10`, so pip refuses before it downloads anything:

    $ python3.9 -m pip install -r requirements.txt
    ERROR: Ignored the following versions that require a different python
    version: ... 1.0.5 Requires-Python >=3.10 ...
    ERROR: No matching distribution found for certbot-dns-hetzner-cloud==1.0.5

    $ python3.9 -m pip install -r requirements-minimal.txt
    ERROR: No matching distribution found for dns-lexicon==3.25.1

Measured on 3.9.6, not inferred from metadata. So the very first command a
source installer runs failed, on the version the badge at the top of the README
told them to use, and `docs/testing.md` claimed CI covered 3.9 and 3.11 while
the matrix has only ever held one entry.

The floor and the tested version are two different questions, and the honest
answer to both is the same number today: the image is built `FROM python:3.12`
and the matrix is `['3.12']`. So the rule is that documentation names the
version we actually build and test — not a floor nobody exercises.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

_SKIP_DIRS = (".venv", "node_modules", ".git", "scratch", ".claude", "backups")
# History records what was true then, including a version we have moved off.
_SKIP_FILES = ("RELEASE_NOTES.md", "CHANGELOG.md")


def _dockerfile_version():
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    found = set(re.findall(r"^FROM python:(\d+\.\d+)", text, re.M))
    assert found, "Dockerfile no longer builds FROM a python: image"
    assert len(found) == 1, f"Dockerfile builds from several Pythons: {found}"
    return found.pop()


def _ci_versions():
    text = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    match = re.search(r"python-version:\s*\[([^\]]+)\]", text)
    assert match, "ci.yml no longer declares a python-version matrix"
    return {v.strip().strip("'\"") for v in match.group(1).split(",")}


def _documented():
    """(file, line number, version) for every Python version the docs name."""
    found = []
    targets = [REPO_ROOT / "README.md", REPO_ROOT / "README.dockerhub.md"]
    targets += sorted(REPO_ROOT.glob("docs/**/*.md"))
    targets += [REPO_ROOT / "CONTRIBUTING.md", REPO_ROOT / "SECURITY.md"]
    for path in targets:
        if not path.exists() or path.name in _SKIP_FILES:
            continue
        if any(part in path.parts for part in _SKIP_DIRS):
            continue
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            # A version stated *about a third-party package* is not a claim
            # about what CertMate runs on, and treating it as one made this
            # gate reject true sentences. The provider table explains that
            # `certbot-dns-namecheap` 1.0.0 targets Python 2.7-3.8 — accurate,
            # and the reason that plugin is marked Unavailable. Lines naming a
            # backticked distribution are describing that distribution.
            if re.search(r"`[\w.-]*(?:certbot|dns)[\w.-]*`|`Scaleway`|`PowerDNS`",
                         line):
                continue
            for match in re.finditer(r"[Pp]ython[- ](\d+\.\d+)", line):
                found.append((str(path.relative_to(REPO_ROOT)), number,
                              match.group(1)))
    return found


def test_the_sources_of_truth_agree():
    """The image and the matrix must not drift apart from each other either."""
    image, matrix = _dockerfile_version(), _ci_versions()
    assert image in matrix, (
        f"the image is built on Python {image} but CI tests {sorted(matrix)} — "
        f"nothing is testing what ships."
    )


def test_the_documentation_names_a_version():
    """Anchored on a specific line, not on an arbitrary count.

    `len(found) >= 10` cuts both ways: it fails a documentation refactor that
    legitimately reduces the mentions, and it passes a scan that has quietly
    stopped reading four of the five languages (Copilot, #536). So it checks
    that the README badge — the most visible version claim in the project, and
    the one that was wrong — is among what the scan found.
    """
    found = _documented()
    assert found, "the scan found no Python version mentions at all"
    assert any(entry[0] == "README.md" for entry in found), (
        "the scan found no Python version in README.md. The badge at the top "
        "of it is the claim this file exists to check; a scan that misses it "
        "is not checking anything that matters."
    )


# Scanned once. Calling _documented() for the values and again for the ids is
# two walks of the documentation and two chances for them to disagree in length
# or order, which pytest reports as a parametrisation error rather than a docs
# problem (Copilot, #536).
DOCUMENTED = _documented()


@pytest.mark.parametrize("path,number,version", DOCUMENTED,
                         ids=[f"{p}:{n}" for p, n, _v in DOCUMENTED])
def test_no_document_names_a_python_we_neither_build_nor_test(path, number, version):
    image, matrix = _dockerfile_version(), _ci_versions()
    allowed = {image} | matrix
    assert version in allowed, (
        f"{path}:{number} names Python {version}. The image is built on "
        f"{image} and CI tests {sorted(matrix)}. "
        f"Documenting a version nothing builds or tests is how `Python 3.9+` "
        f"sat in the README badge while `pip install -r requirements.txt` "
        f"refused to run on 3.9."
    )


def test_no_pin_requires_a_python_newer_than_the_one_we_build_on():
    """The other direction: a bump that quietly raises the floor past the image.

    Offline — reads the declared floor from any `python_requires` comment the
    requirements files carry, plus the interpreter the image uses. The full
    check against PyPI metadata belongs in CI, where the install happens for
    real; this catches the case where someone writes the constraint down.
    """
    built_on = tuple(int(part) for part in _dockerfile_version().split("."))
    offenders = []
    for path in sorted(REPO_ROOT.glob("requirements*.txt")):
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            for match in re.finditer(r"[Rr]equires[-_ ][Pp]ython\s*>=\s*(\d+\.\d+)",
                                     line):
                needed = tuple(int(p) for p in match.group(1).split("."))
                if needed > built_on:
                    offenders.append(f"{path.name}:{number}: needs "
                                     f"{match.group(1)}, image builds on "
                                     f"{_dockerfile_version()}")
    assert not offenders, "\n  ".join(offenders)
