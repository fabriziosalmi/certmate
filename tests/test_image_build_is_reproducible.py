"""The image build must not depend on what a mirror happens to serve today.

The Dockerfile pins its base image by digest and pins pip, and says in both
places that it does so because two builds of the same commit must produce the
same image. In the same RUN instruction it then ran `apt-get upgrade -y`, which
pulls whatever Debian is serving at that moment — so the OS layer was
reproducible in intent and arbitrary in fact.

That was removed deliberately (#659). OS security patches now arrive as
base-image digest bumps, which Dependabot proposes weekly as reviewable PRs:
auditable, tied to a commit, and reproducible from it.

These guard the property, because a reproducibility decision nothing enforces
comes back the first time someone wants a quick patch.
"""
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

DOCKERFILE = Path(__file__).resolve().parent.parent / 'Dockerfile'


def _instructions():
    """Dockerfile lines with comments stripped and continuations joined."""
    joined = re.sub(r'\\\s*\n', ' ', DOCKERFILE.read_text(encoding='utf-8'))
    return [line for line in joined.splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


def test_the_build_does_not_upgrade_os_packages_at_build_time():
    offenders = [line.strip() for line in _instructions()
                 if re.search(r'apt-get\s+(-\S+\s+)*upgrade|apt\s+upgrade'
                              r'|dist-upgrade', line)]
    assert not offenders, (
        "an OS upgrade at build time makes the image depend on what the "
        "mirror serves that day, so two builds of the same commit differ. "
        "Security patches come from a base-image digest bump instead: "
        f"{offenders}"
    )


def test_every_base_image_is_pinned_by_digest():
    """The other half of the trade.

    Dropping the build-time upgrade is only sound because the base is pinned
    and bumped deliberately. A floating tag would give up both properties at
    once: neither reproducible nor patched.
    """
    unpinned = [line.strip() for line in _instructions()
                if line.startswith('FROM ') and '@sha256:' not in line]
    assert not unpinned, (
        f"these base images are not pinned by digest, so the build is neither "
        f"reproducible nor deliberately patched: {unpinned}"
    )


def test_pip_is_pinned_rather_than_upgraded_to_latest():
    """CONTROL: the same reasoning, already applied to pip.

    If a bare `pip install -U pip` returns, the runtime stage's contents go
    back to depending on what PyPI serves at build time.
    """
    offenders = [line.strip() for line in _instructions()
                 if re.search(r'pip install\s+(-U|--upgrade)\s+pip(?!==)', line)
                 and 'PIP_VERSION' not in line]
    assert not offenders, (
        f"pip is upgraded to whatever is newest rather than a pinned version: "
        f"{offenders}"
    )


def test_dependabot_still_watches_the_base_image():
    """The patches have to arrive somehow.

    Removing the build-time upgrade is safe only while digest bumps are
    actually proposed. If the docker ecosystem is dropped from Dependabot, the
    image silently stops receiving OS security updates altogether.
    """
    yaml = pytest.importorskip('yaml')
    config_path = DOCKERFILE.parent / '.github' / 'dependabot.yml'
    config = yaml.safe_load(config_path.read_text(encoding='utf-8'))

    docker = [u for u in config['updates']
              if u.get('package-ecosystem') == 'docker']
    assert docker, (
        "Dependabot no longer watches the docker ecosystem, so base-image "
        "digest bumps stop being proposed — and with no build-time upgrade "
        "the image would receive no OS security patches at all"
    )

    for update in docker:
        ignored = {
            entry.get('dependency-name'): entry.get('update-types') or []
            for entry in update.get('ignore', [])
        }
        for name, types in ignored.items():
            assert 'version-update:semver-patch' not in types, (
                f"digest/patch updates are ignored for {name}, which is the "
                f"channel OS security fixes now arrive through"
            )
