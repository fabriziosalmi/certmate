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

    text = path.read_text(encoding='utf-8')
    rationale_lines = [
        line for line in text.splitlines()
        if line.startswith(('cryptography==', 'pyopenssl==')) and 'acme' in line
    ]
    assert rationale_lines, (
        "the cryptography/pyopenssl pins no longer explain themselves in terms "
        "of acme; if that coupling really is gone, remove this guard "
        "deliberately rather than letting it pass vacuously"
    )

    stale = [line.split('#', 1)[0].strip() for line in rationale_lines
             if acme_version not in line]
    assert not stale, (
        f"acme is pinned to {acme_version} but these pins justify themselves "
        f"against a different acme version: {stale}"
    )
