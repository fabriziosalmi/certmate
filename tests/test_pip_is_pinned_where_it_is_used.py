"""Both pips in the image must be pinned, and pinned to the same version.

The Dockerfile pinned `pip` in the runtime stage with a comment giving
reproducibility as the reason — "an unpinned `--upgrade pip` would make the
runtime stage's contents depend on whatever PyPI happens to serve at build
time, so two builds of the same commit could differ".

That reasoning was right and applied to the other copy. The builder stage ran a
bare `pip install -U pip` into `/opt/venv`, and `ENV PATH` puts `/opt/venv/bin`
first — so the pinned pip was the one nothing uses, and the one on `PATH`
floated. Measured inside the published v2.25.4 image:

    /usr/local/bin/pip   26.1.2      pinned
    /opt/venv/bin/pip    26.2.1      whatever PyPI served that day
    which pip         -> /opt/venv/bin/pip

Two builds of the same commit did differ, exactly where the comment said they
must not. Both stages now take the same `PIP_VERSION`, so a deliberate bump
moves them together — and this test is what stops them drifting apart, since
Docker scopes ARG per stage and the value has to be written twice.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"

pytestmark = [pytest.mark.unit]


def _pip_version_args():
    """Every `ARG PIP_VERSION=` default in the Dockerfile, in order."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    return re.findall(r"^ARG\s+PIP_VERSION=(\S+)", text, re.M)


def _pip_installs():
    """Every line that installs pip itself, with its line number."""
    found = []
    for number, line in enumerate(
            DOCKERFILE.read_text(encoding="utf-8").splitlines(), 1):
        # Comments quote the old unpinned form to explain why it was wrong —
        # including the ones above these very lines. A check that reads them as
        # instructions fails on its own documentation.
        if line.lstrip().startswith("#"):
            continue
        if re.search(r"pip install[^&|]*\bpip\b", line) and "requirements" not in line:
            found.append((number, line.strip()))
    return found


def test_the_dockerfile_installs_pip_more_than_once():
    """Guard the guard: one stage means one of these checks is asleep."""
    installs = _pip_installs()
    assert len(installs) >= 2, (
        f"expected pip to be installed in both the builder and the runtime "
        f"stage, found {len(installs)}: {installs}. If the layout changed, "
        f"this file needs to change with it rather than pass quietly."
    )


def test_every_stage_declares_the_same_pip_version():
    versions = _pip_version_args()
    assert len(versions) >= 2, (
        f"found {len(versions)} `ARG PIP_VERSION=` declarations. Docker scopes "
        f"ARG per stage, so each stage that installs pip needs its own."
    )
    assert len(set(versions)) == 1, (
        f"the stages pin different pip versions: {versions}. They must move "
        f"together — a `--build-arg PIP_VERSION=` sets both, and a default "
        f"that has drifted means the image ships two pips again."
    )


@pytest.mark.parametrize("number,line", _pip_installs(),
                         ids=[f"line-{n}" for n, _l in _pip_installs()])
def test_no_pip_install_of_pip_is_unpinned(number, line):
    """`pip install -U pip` is the shape that started this."""
    assert re.search(r'pip==\$\{?PIP_VERSION\}?|pip==[0-9]', line), (
        f"Dockerfile:{number} installs pip without a version:\n    {line}\n"
        f"That is how /opt/venv/bin/pip — the one on PATH — floated at 26.2.1 "
        f"while the pinned copy nothing uses sat at 26.1.2."
    )
