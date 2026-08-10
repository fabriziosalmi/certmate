"""Any version a document tells you to install must be a version we ship.

`docs/installation.md` and its four translations published a hand-maintained
pin list under "DNS Plugin Version Conflicts" — the section you land on when an
install has already gone wrong. It said `certbot==4.1.1` while the project is
pinned to `2.10.0`, in all five languages, for long enough that nobody
remembered writing it. Following it gave you a stack CertMate has never been
tested against: the 5.x migration is still issue #103, a plan.

Correcting the numbers would not have been enough, and this is the part worth
remembering. The pins that make certbot start are `cryptography`, `pyopenssl`,
`josepy` and `acme`, none of which the list mentioned. Adding them back one at
a time, in a clean virtualenv, `certbot --version` failed four times in a row:

    AttributeError: module 'OpenSSL.crypto' has no attribute 'X509Req'
    AttributeError: module 'josepy' has no attribute 'ComparableX509'
    ...

So the lists were replaced by `pip install -r <the file we ship>`, and this
test keeps any new list honest.

Scope: fenced code blocks only. Prose may name a wrong version — the sections
above now explain the drift by quoting `certbot==4.1.1`, and a check that could
not tell the difference would have to be silenced to let that stand.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

_SKIP_DIRS = (".venv", "node_modules", ".git", "scratch", ".claude", "backups")
# History is allowed to quote what it corrected.
_SKIP_FILES = ("RELEASE_NOTES.md", "CHANGELOG.md")


def _requirement_pins():
    pins = {}
    for path in sorted(REPO_ROOT.glob("requirements*.txt")):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^([A-Za-z0-9_.-]+)==([\w.]+)", line.strip())
            if match:
                name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
                pins.setdefault(name, match.group(2))
    return pins


def _documented_pins():
    """(file, line, package, version) for every pin inside a code fence."""
    found = []
    for path in sorted(REPO_ROOT.rglob("*.md")):
        if any(part in path.parts for part in _SKIP_DIRS):
            continue
        if path.name in _SKIP_FILES:
            continue
        fenced = False
        for number, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if not fenced:
                continue
            for match in re.finditer(r"\b([A-Za-z][A-Za-z0-9_.-]*)==([\w.]+)", line):
                name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
                found.append((str(path.relative_to(REPO_ROOT)), number,
                              name, match.group(2)))
    return found


def test_the_scan_sees_the_documentation():
    """Guard the guard: an empty scan would make every check below vacuous."""
    pins = _requirement_pins()
    assert len(pins) >= 20, f"parsed only {len(pins)} requirement pins"
    assert "certbot" in pins, "certbot is not pinned in any requirements file"
    markdown = [p for p in REPO_ROOT.rglob("*.md")
                if not any(part in p.parts for part in _SKIP_DIRS)]
    assert len(markdown) >= 20, f"only found {len(markdown)} markdown files"


def test_no_document_tells_you_to_install_a_version_we_do_not_ship():
    known = _requirement_pins()
    wrong = [
        f"{path}:{number}: {package}=={version} — we pin {known[package]}"
        for path, number, package, version in _documented_pins()
        if package in known and known[package] != version
    ]
    assert not wrong, (
        "documentation tells operators to install versions the project does "
        "not pin:\n  " + "\n  ".join(wrong)
        + "\nThese lists drift because nothing installs them. Point at the "
          "requirements file instead — it is the set CI resolves and boots."
    )


@pytest.mark.parametrize("package", ["certbot", "cryptography", "pyopenssl", "josepy"])
def test_the_interlocking_pins_are_never_split_across_a_document(package):
    """certbot cannot be documented without what makes it start.

    A code block naming `certbot==` and nothing else is the shape of the
    section this test came from: correct in isolation, unusable in practice.
    """
    offenders = []
    for path, number, name, _version in _documented_pins():
        if name != "certbot":
            continue
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        if not re.search(r"\b(cryptography|pyopenssl|josepy)\s*==", text):
            offenders.append(f"{path}:{number}")
    assert not offenders, (
        f"these pin certbot without pinning cryptography / pyopenssl / josepy "
        f"anywhere in the file: {sorted(set(offenders))}. certbot installed "
        f"that way does not start — it raises AttributeError on "
        f"OpenSSL.crypto.X509Req before it can issue anything. Tell people to "
        f"install from requirements.txt."
    )
