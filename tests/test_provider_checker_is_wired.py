"""The in-image provider check must exist, ship, and be run by something.

`scripts/check_providers.py` asks the built image whether every provider it
offers can actually reach certbot. It exists because the suite validates that
path against mocks: nine test files stub `check_certbot_plugin_installed` to
return True, so the one guard between a configured provider and certbot's
"unrecognized arguments" is never exercised for real. Infomaniak shipped that
way — strategy, credentials writer, factory entry, README row, no plugin.

A checker nothing runs is the shape this repository keeps finding, so this
asserts the wiring rather than the logic. The logic is verified by running it
against an image with the plugin removed, and against one with its entry point
renamed; both exit non-zero.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_providers.py"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"

pytestmark = [pytest.mark.unit]


def test_the_checker_exists():
    assert SCRIPT.exists(), "scripts/check_providers.py is gone"


def test_ci_runs_it_against_the_built_image():
    text = CI.read_text(encoding="utf-8")
    assert "check_providers.py" in text, (
        "no workflow runs scripts/check_providers.py"
    )
    assert re.search(r"docker exec[^\n]*check_providers\.py", text), (
        "check_providers.py is referenced but not run inside the container. "
        "Running it on the CI host checks the runner's virtualenv, which is "
        "not what ships."
    )


def test_ci_passes_the_requirements_file_it_built_from():
    """Without it the check cannot tell a missing plugin from an optional one."""
    text = CI.read_text(encoding="utf-8")
    assert re.search(r"check_providers\.py\s+\"?\$\{?req", text), (
        "the workflow does not pass the requirements file to the checker. "
        "Defaulting to requirements.txt while building requirements-minimal "
        "would report every extended provider as missing."
    )


def test_the_script_ships_in_the_image():
    """`tests/` is dockerignored; `scripts/` must not be."""
    if not DOCKERIGNORE.exists():
        return
    ignored = [
        line.strip() for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert not any(re.fullmatch(r"scripts/?\*?", entry) for entry in ignored), (
        "scripts/ is excluded from the image, so the checker cannot run there. "
        "That is how tests/ ended up unavailable in the container."
    )
