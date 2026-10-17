"""The finished image ships no pip (#403).

It used to ship two. The runtime stage pinned the base image's pip for
reproducibility while the builder ran a bare `pip install -U pip` into
/opt/venv, the copy on PATH, so the pinned one was the one nothing used: on
the published v2.25.4 image /usr/local/bin/pip was 26.1.2 and /opt/venv/bin/pip
whatever PyPI served that day. Both were then pinned to one version, from
requirements-build.lock, and a test held the two together.

Pinning kept the CVEs in pip itself out, and not the ones in what pip
vendors. Measured on the v2.50.1 image (Trivy, 2026-10-17): urllib3 2.7.0,
msgpack 1.1.2 and setuptools 70.3.0 inside pip 26.2.1, the latest release,
made 6 of the 16 findings that had a fix, 4 of them HIGH. The app runs from
/opt/venv and never calls pip, so pip now does the installing in the builder
and leaves: the builder removes it from the venv, the runtime stage removes the
base image's copy, and CI reads the installed set with importlib.metadata.

These read the Dockerfile and the workflow; the built image was checked by
hand when this changed (no pip on PATH, `import pip` fails in both
interpreters, no pip/_vendor anywhere, certbot runs, /health is healthy).
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docker-multiplatform.yml"

pytestmark = [pytest.mark.unit]


def _stages():
    """The Dockerfile's stages, as lists of instruction text without comments."""
    stages, current = [], None
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        if line.startswith("FROM "):
            current = []
            stages.append(current)
        if current is not None:
            current.append(line)
    return ["\n".join(stage) for stage in stages]


def test_there_are_a_builder_and_a_runtime_stage():
    """CONTROL: the checks below read the stages by position."""
    assert len(_stages()) == 2, "the Dockerfile no longer has exactly two stages"


def test_the_builder_takes_its_tools_from_the_hashed_lock():
    builder = _stages()[0]
    assert "pip install --no-cache-dir --require-hashes -r requirements-build.lock" in builder, (
        "the builder no longer installs its tools from requirements-build.lock with hashes")


def test_the_builder_removes_pip_from_the_venv_after_the_last_install():
    """/opt/venv is copied into the runtime stage whole; pip must leave it first."""
    builder = _stages()[0]
    installs = [m.start() for m in re.finditer(r"\bpip install\b", builder)]
    removal = builder.find("pip uninstall -y pip")
    assert installs, "CONTROL: the builder installs nothing with pip"
    assert removal != -1, "the builder leaves pip in /opt/venv, and the runtime stage copies it"
    assert removal > max(installs), "pip is removed before the last install that needs it"


def test_the_runtime_stage_removes_the_base_image_pip():
    runtime = _stages()[1]
    assert "python -m pip uninstall -y pip" in runtime, (
        "the runtime stage keeps the base image's pip under /usr/local")


def test_nothing_installs_or_upgrades_pip_any_more():
    """An upgrade puts back the vendored copies the removal took out."""
    offenders = [line.strip() for stage in _stages() for line in stage.splitlines()
                 if re.search(r"pip install[^&|;]*\bpip\b", line) and "requirements" not in line]
    assert not offenders, f"pip is installed again: {offenders}"


def test_ci_reads_the_shipped_set_without_pip():
    """With no pip in the image, `pip freeze` fails and the advisory check reads nothing."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "/opt/venv/bin/pip" not in text, "the workflow still calls the image's pip"
    assert "importlib.metadata" in text, "the workflow no longer lists the shipped set"
