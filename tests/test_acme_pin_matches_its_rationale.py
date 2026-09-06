"""The ACME protocol client must be pinned, and the pins that reason about it
must reason about the version actually pinned.

``acme`` is the most protocol- and security-sensitive package in the tree, and
certbot 2.10.0 declares a bare unbounded ``Requires: acme`` — so its version was
whatever PyPI happened to serve, and a clean install was not guaranteed to
reproduce the one that had been tested.

That is load-bearing rather than tidy. The rationale written on the
``cryptography`` and ``pyopenssl`` pins is stated in terms of a specific acme
version (it import-evaluates ``OpenSSL.crypto.X509Extension``, which is why
pyopenssl may not move). So the two most carefully reasoned pins in the file
depended on a version nothing enforced, and a silent acme bump would have
invalidated their reasoning while leaving the prose looking authoritative
(#657).
"""
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / 'requirements.txt'
# Both published sets carry the pin and the rationale, so both are checked.
REQUIREMENT_FILES = [REQUIREMENTS, ROOT / 'requirements-minimal.txt']


def _pinned_version(package, path=None):
    """The exact version pinned for *package*, or None if it is not pinned."""
    pattern = re.compile(
        rf'^{re.escape(package)}==([0-9][^\s#]*)', re.IGNORECASE | re.MULTILINE)
    match = pattern.search((path or REQUIREMENTS).read_text(encoding='utf-8'))
    return match.group(1) if match else None


@pytest.mark.parametrize('path', REQUIREMENT_FILES, ids=lambda p: p.name)
def test_acme_is_pinned(path):
    assert _pinned_version('acme', path) is not None, (
        "acme is the ACME protocol client; certbot declares it without a "
        "version bound, so leaving it unpinned means a clean install can "
        "resolve a version that was never tested"
    )


@pytest.mark.parametrize('path', REQUIREMENT_FILES, ids=lambda p: p.name)
def test_the_dependency_rationale_names_the_version_that_is_pinned(path):
    """The prose explaining why cryptography and pyopenssl are held must refer
    to the acme version actually enforced.

    If acme is bumped and the rationale is not, the comments keep asserting a
    constraint about a version that is no longer installed — authoritative
    prose describing a stack that no longer exists.
    """
    acme_version = _pinned_version('acme', path)
    assert acme_version, "acme must be pinned before this can be checked"

    # Case-insensitive throughout: 'PyOpenSSL' and 'pyopenssl' are the same
    # requirement, and a rationale that said 'ACME' would be just as binding.
    # A guard that silently stops matching on a capitalisation change is the
    # kind of instrument this milestone exists to remove.
    text = path.read_text(encoding='utf-8')
    rationale_lines = [
        line for line in text.splitlines()
        if re.match(r'^(cryptography|pyopenssl)==', line, re.IGNORECASE)
        and 'acme' in line.lower()
    ]
    assert rationale_lines, (
        "the cryptography/pyopenssl pins no longer explain themselves in terms "
        "of acme; if that coupling really is gone, remove this guard "
        "deliberately rather than letting it pass vacuously"
    )

    # Report the WHOLE line, comment included. Stripping the comment would hide
    # the stale rationale — the one thing a reader needs to fix this.
    stale = [line.strip() for line in rationale_lines
             if acme_version not in line]
    assert not stale, (
        f"acme is pinned to {acme_version} but these pins justify themselves "
        f"against a different acme version:\n  " + "\n  ".join(stale)
    )
