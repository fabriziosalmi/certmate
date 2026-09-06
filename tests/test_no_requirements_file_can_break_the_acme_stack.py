"""No requirements file may admit a cryptography the ACME stack rejects.

`cryptography` is held at an exact version because moving it kills
`certbot --version`: the versions that clear the open advisories need
pyopenssl>=26.2.0, which removes `OpenSSL.crypto.X509Extension` that acme
evaluates at import.

The optional storage sets carried a bare floor (`cryptography>=41.0.0`) with no
ceiling. They are documented as installable on their own, and standalone
nothing else constrains the package — it resolves to the newest release, which
breaks issuance. That it had not yet bitten was an accident of Docker's install
order (the main file goes first, and the held version already satisfies the
floor), not a property anything enforced (#658).

This checks the property directly: every constraint in every requirements file
must accept the held version and reject the versions known to break the stack.
"""
import re
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'cryptography'

# Versions that are known to kill `certbot --version` through the pyopenssl
# route. If the stack is ever moved (#103) these stop being forbidden — which
# is a deliberate change, and this list is where it gets made.
BREAKS_THE_STACK = ['47.0.0', '48.0.1', '49.0.0', '50.0.0', '50.0.1']


def _requirements_files():
    return sorted(ROOT.glob('requirements*.txt'))


def _constraint(path):
    """The cryptography specifier declared in *path*, or None."""
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.split('#', 1)[0].strip()
        match = re.match(rf'^{PACKAGE}\s*(.+)$', line, re.IGNORECASE)
        if match:
            return SpecifierSet(match.group(1))
    return None


def _held_version():
    spec = _constraint(ROOT / 'requirements.txt')
    assert spec is not None, "requirements.txt no longer constrains cryptography"
    pinned = [s.version for s in spec if s.operator == '==']
    assert pinned, "cryptography is no longer held at an exact version"
    return pinned[0]


@pytest.mark.parametrize('path', _requirements_files(), ids=lambda p: p.name)
def test_every_file_accepts_the_held_version(path):
    """A file that rejects the held version cannot be installed alongside the
    others, whatever the order."""
    spec = _constraint(path)
    if spec is None:
        pytest.skip(f'{path.name} does not constrain {PACKAGE}')
    held = _held_version()
    assert spec.contains(Version(held)), (
        f"{path.name} declares {PACKAGE}{spec}, which excludes the held "
        f"version {held}"
    )


@pytest.mark.parametrize('path', _requirements_files(), ids=lambda p: p.name)
def test_every_constraint_is_bounded_above(path):
    """The defect class, independent of which versions exist today.

    Listing known-bad versions can only describe the past: a release published
    tomorrow would slip through an unbounded floor while this file still looked
    green. What made the storage sets dangerous was not version 50 in
    particular, it was `>=41` with nothing on the right-hand side.
    """
    spec = _constraint(path)
    if spec is None:
        pytest.skip(f'{path.name} does not constrain {PACKAGE}')
    bounded = any(s.operator in ('==', '<', '<=', '~=') for s in spec)
    assert bounded, (
        f"{path.name} declares {PACKAGE}{spec} with no upper bound, so it "
        f"resolves to whatever is newest — including releases that do not "
        f"exist yet and cannot be listed here"
    )


@pytest.mark.parametrize('path', _requirements_files(), ids=lambda p: p.name)
def test_no_file_admits_a_version_that_breaks_issuance(path):
    """The real defect: a floor with no ceiling.

    Installed on its own — a documented path for the storage sets — such a
    file resolves to the newest release and `certbot --version` dies.
    """
    spec = _constraint(path)
    if spec is None:
        pytest.skip(f'{path.name} does not constrain {PACKAGE}')
    admitted = [v for v in BREAKS_THE_STACK if spec.contains(Version(v))]
    assert not admitted, (
        f"{path.name} declares {PACKAGE}{spec}, which would resolve to "
        f"{admitted} when this file is installed on its own — versions that "
        f"install cleanly and then kill `certbot --version`"
    )
