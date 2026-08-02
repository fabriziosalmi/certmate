"""Guard: no two requirements may install the same import path.

pip has no opinion about two distributions that ship the same top-level
package. It installs both, one over the other, and reports success. The
version pin on the loser is then decorative — and nothing in CI notices,
because every test still passes against whichever copy happened to win.

That is exactly what `certbot-dns-hetzner==3.0.0` did: it depends on
`dns-lexicon-coop`, a third-party fork of `dns-lexicon` that ships an
identical `lexicon/` package. Both were resolved into the default image, so
`dns-lexicon==3.25.1` in requirements.txt could be silently replaced by the
fork's 3.24.3, and `modules/core/dns_alias_hook.py` — which imports
`lexicon.client` for alias mode across fourteen providers — ran whichever one
landed last.

These tests are cheap and offline: they read requirements files and the
installed metadata, and never touch the network.
"""
import pathlib
import re
from collections import defaultdict

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Distributions known to collide with something else we depend on. Keyed by
# the fork, valued by the upstream it shadows, so the failure message can say
# what the conflict actually is instead of just naming a banned string.
KNOWN_SHADOWING_FORKS = {
    "dns-lexicon-coop": "dns-lexicon",
}

REQUIREMENT_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[].*)?$")

# Collisions we have looked at, accepted, and do not want the gate to keep
# re-reporting. Each entry must say why it is harmless — a bare exclusion list
# is how a gate quietly stops gating.
#
#   tests/  — `certbot-dns-porkbun` and `pkb_client` both ship their own test
#     package to the top level of site-packages instead of nesting it. They
#     overwrite each other's `tests/__init__.py`, but neither imports it and
#     no CertMate code path touches a site-packages `tests`; our own suite
#     wins on sys.path because pytest puts the repo root first. It is upstream
#     packaging sloppiness in two projects we do not control, so failing the
#     build on it would leave a gate nobody can turn green.
ACCEPTED_COLLIDING_PREFIXES = ("tests/",)


def _requirements_files():
    return sorted(REPO_ROOT.glob("requirements*.txt"))


def _declared_distributions(path):
    names = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = REQUIREMENT_LINE.match(line)
        if match:
            names.add(match.group(1).lower().replace("_", "-"))
    return names


@pytest.mark.parametrize(
    "path", _requirements_files(), ids=lambda p: p.name
)
def test_requirements_do_not_name_a_shadowing_fork(path):
    """No requirements file may pull in a fork that shadows an upstream pin."""
    declared = _declared_distributions(path)
    for fork, upstream in KNOWN_SHADOWING_FORKS.items():
        assert fork not in declared, (
            f"{path.name} declares {fork!r}, which ships the same import path "
            f"as {upstream!r}. pip installs both and lets one overwrite the "
            f"other, so the {upstream!r} pin stops meaning anything."
        )


def test_installed_distributions_do_not_claim_the_same_files():
    """Nothing in the CURRENT environment may own another package's files.

    This is the general form of the check — it catches a collision arriving
    transitively, through a dependency nobody edited, which is how this one
    arrived. Skipped when running against an environment that has no metadata
    to inspect.
    """
    from importlib import metadata

    owners = defaultdict(set)
    for dist in metadata.distributions():
        name = (dist.metadata["Name"] or "").lower()
        if not name:
            continue
        for file in dist.files or []:
            path = str(file)
            # Only top-level importable modules matter; shared data dirs
            # (dist-info, console scripts, .libs) legitimately overlap.
            if not path.endswith(".py") or path.startswith(".."):
                continue
            if path.startswith(ACCEPTED_COLLIDING_PREFIXES):
                continue
            owners[path].add(name)

    collisions = {
        path: sorted(names)
        for path, names in owners.items()
        if len(names) > 1
    }
    assert not collisions, (
        "two installed distributions claim the same import path — pip "
        "overwrote one with the other and the loser's version pin is now "
        "meaningless:\n" + "\n".join(
            f"  {path}: {names}" for path, names in sorted(collisions.items())[:20]
        )
    )
