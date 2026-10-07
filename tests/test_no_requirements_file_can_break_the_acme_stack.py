"""No requirements file may admit a cryptography the ACME stack rejects.

`cryptography` is pinned exactly in requirements.txt, and the stack states the
window it works in: certbot and acme 5.8.0 require `cryptography>=47`, and
pyopenssl 26.4.0 requires `>=49,<51`. pip enforces that window when the main file
is installed, so the pin cannot silently leave it.

The optional storage sets carry their own `cryptography` constraint, and they are
documented as installable on their own. Standalone nothing else bounds the
package, so a floor with no ceiling resolves to the newest release, which
pyopenssl then refuses. On the stack that preceded this one it was worse: such a
release installed cleanly and then killed `certbot --version`, and only Docker's
install order (the main file goes first, and the held version already satisfies
the floor) had kept it from biting (#658). So the check stays, and it is
stated for the window above.

This checks the property directly: every constraint in every requirements file
must accept the pinned version and reject the versions the stack does not accept.
"""
import re
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'cryptography'

# Versions the stack does not accept: below the `>=49` pyopenssl 26.4.0 needs, or
# below the `>=47` certbot and acme need. They are what a constraint with a low
# floor would still let a standalone install pick over time, and what a future
# change to the window has to make a deliberate edit to.
BREAKS_THE_STACK = ['41.0.0', '46.0.7', '47.0.0', '48.0.1']


def _requirements_files():
    return sorted(ROOT.glob('requirements*.txt'))


# Files with no constraint of their own for `cryptography`. Each is either installed on top
# of requirements.txt under the constraints file that pins it, or is a tool set with a lock
# of its own (build, lint, galaxy, test). They are listed, and not skipped, so a file that
# starts or stops constraining it is a decision someone makes here, with the three checks
# below starting or stopping to cover it, and not a test that quietly stops running.
WITHOUT_A_CONSTRAINT = [
    'requirements-aws-storage.txt', 'requirements-azure.txt', 'requirements-build.txt',
    'requirements-extended.txt', 'requirements-galaxy.txt', 'requirements-infisical-storage.txt',
    'requirements-lint.txt', 'requirements-test.txt', 'requirements-vault-storage.txt',
]


def _constraint(path):
    """The cryptography specifier declared in *path*, or None."""
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.split('#', 1)[0].strip()
        match = re.match(rf'^{PACKAGE}\s*(.+)$', line, re.IGNORECASE)
        if match:
            return SpecifierSet(match.group(1))
    return None


def _constraining_files():
    return [path for path in _requirements_files() if _constraint(path) is not None]


def _held_version():
    spec = _constraint(ROOT / 'requirements.txt')
    assert spec is not None, "requirements.txt no longer constrains cryptography"
    pinned = [s.version for s in spec if s.operator == '==']
    assert pinned, "cryptography is no longer held at an exact version"
    return pinned[0]


@pytest.mark.parametrize('path', _constraining_files(), ids=lambda p: p.name)
def test_every_file_accepts_the_held_version(path):
    """A file that rejects the pinned version cannot be installed alongside the
    others, whatever the order."""
    spec = _constraint(path)
    held = _held_version()
    assert spec.contains(Version(held)), (
        f"{path.name} declares {PACKAGE}{spec}, which excludes the held "
        f"version {held}"
    )


@pytest.mark.parametrize('path', _constraining_files(), ids=lambda p: p.name)
def test_every_constraint_is_bounded_above(path):
    """The defect class, independent of which versions exist today.

    Listing known-bad versions can only describe the past: a release published
    tomorrow would slip through an unbounded floor while this file still looked
    green. What made the storage sets dangerous was not version 50 in
    particular, it was `>=41` with nothing on the right-hand side.
    """
    spec = _constraint(path)
    bounded = any(s.operator in ('==', '<', '<=', '~=') for s in spec)
    assert bounded, (
        f"{path.name} declares {PACKAGE}{spec} with no upper bound, so it "
        f"resolves to whatever is newest — including releases that do not "
        f"exist yet and cannot be listed here"
    )


@pytest.mark.parametrize('path', _constraining_files(), ids=lambda p: p.name)
def test_no_file_admits_a_version_that_breaks_issuance(path):
    """The real defect: a floor with no ceiling.

    Installed on its own — a documented path for the storage sets — such a
    file resolves to the newest release and `certbot --version` dies.
    """
    spec = _constraint(path)
    admitted = [v for v in BREAKS_THE_STACK if spec.contains(Version(v))]
    assert not admitted, (
        f"{path.name} declares {PACKAGE}{spec}, which would resolve to "
        f"{admitted} when this file is installed on its own — versions that "
        f"install cleanly and then kill `certbot --version`"
    )


def test_the_files_without_a_constraint_are_the_ones_listed():
    """What the three checks above do not look at, written down. A file that gains a constraint
    is covered from then on; a file that loses one stops being, and this says so."""
    without = [path.name for path in _requirements_files() if _constraint(path) is None]

    assert without == WITHOUT_A_CONSTRAINT, (
        f'the files without a `{PACKAGE}` constraint changed: now {without}. Add the file to '
        f'WITHOUT_A_CONSTRAINT with the reason it needs none, or give it a constraint the '
        f'checks above will cover')


def test_the_checks_have_files_to_look_at():
    """CONTROL: a parametrization over an empty list is skipped, not failed."""
    assert len(_constraining_files()) >= 5, [path.name for path in _constraining_files()]
