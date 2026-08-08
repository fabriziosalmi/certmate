"""Guards on the requirements files the Dockerfile advertises.

`requirements-minimal.txt` is not a convenience copy — the Dockerfile documents
`REQUIREMENTS_FILE` as a supported build argument, so it is a shipped product
surface. It had been missing SQLAlchemy for months: `modules/core/factory.py`
imports APScheduler's `SQLAlchemyJobStore` at module scope, so an image built
from it died during gunicorn's worker import and restart-looped forever (#514).

Nothing caught it because nothing built it. CI now builds *and boots* every
advertised variant; these tests are the cheap part of that guard — they run in
milliseconds and catch the two failure modes a Docker job is slow at proving:
a boot-critical distribution going missing, and the two files drifting apart on
a version pin.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

FULL = REPO_ROOT / "requirements.txt"
MINIMAL = REPO_ROOT / "requirements-minimal.txt"

# Distributions whose absence stops the process from starting, because a module
# on the import path of `app.py` imports them unguarded. Anything optional is
# deliberately absent from this list: bcrypt, Authlib and prometheus_client are
# all wrapped in try/except with a working fallback, which is why the minimal
# image survives without them.
BOOT_CRITICAL = {
    "flask",
    "flask-cors",
    "flask-restx",
    "certbot",
    "cryptography",
    "requests",
    "urllib3",
    "apscheduler",
    "sqlalchemy",     # via apscheduler.jobstores.sqlalchemy — factory.py:11
    "gunicorn",
}


def _requirements(path):
    """Map distribution name (normalised) -> full specifier, comments stripped."""
    found = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[=<>!~\[]", line)[0].strip()
        if name:
            found[name.lower().replace("_", "-")] = line
    return found


def test_minimal_requirements_can_actually_boot_the_app():
    """Every distribution needed to reach a running process must be present."""
    minimal = _requirements(MINIMAL)
    missing = sorted(BOOT_CRITICAL - set(minimal))
    assert not missing, (
        f"requirements-minimal.txt is missing {missing}. The Dockerfile "
        f"advertises REQUIREMENTS_FILE=requirements-minimal.txt, so an image "
        f"built from it must start — leaving one of these out produces a "
        f"container that restart-loops on an ImportError (#514)."
    )


def test_the_full_set_is_a_superset_of_the_minimal_one():
    """Minimal is the Cloudflare-only subset. It cannot contain a package the
    full set lacks — that would mean the default image is missing something."""
    extra = sorted(set(_requirements(MINIMAL)) - set(_requirements(FULL)))
    assert not extra, (
        f"requirements-minimal.txt lists {extra}, absent from requirements.txt. "
        f"Minimal is meant to be a subset; anything here belongs in both."
    )


@pytest.mark.parametrize("name", sorted(BOOT_CRITICAL))
def test_shared_pins_do_not_drift_between_the_two_files(name):
    """The same distribution must carry the same specifier in both files.

    A pin that moves in one file and not the other means the two images run
    different code while claiming the same release — the drift class that
    test_version_consistency exists to stop for the version string.
    """
    full, minimal = _requirements(FULL), _requirements(MINIMAL)
    if name not in full or name not in minimal:
        pytest.skip(f"{name} is not in both files")
    assert full[name] == minimal[name], (
        f"{name} is pinned differently:\n"
        f"  requirements.txt         {full[name]}\n"
        f"  requirements-minimal.txt {minimal[name]}"
    )


def test_every_advertised_requirements_file_is_built_by_ci():
    """A requirements file the Dockerfile advertises but CI never builds is a
    product surface with no test. That is exactly how #514 shipped."""
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for path in (FULL, MINIMAL):
        assert path.name in workflow, (
            f"{path.name} is not built anywhere in ci.yml. Either build it or "
            f"stop advertising it in the Dockerfile."
        )
    assert "/health" in workflow, (
        "the image job no longer checks /health — `docker build` proves the "
        "layers assemble, not that the container starts."
    )
