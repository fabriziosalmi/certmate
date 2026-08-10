"""Numbers and names the documentation states, checked against their source.

Three separate claims, one shape: a value written down once and never compared
with the thing it describes.

  * **The coverage floor.** `docs/testing.md` was corrected to say CI enforces
    65% (`--cov-fail-under=65`). All four translations still promised "80%
    overall, 95%+ on critical paths" — numbers no gate has ever enforced.
    codecov.yml marks both its statuses `informational: true` in as many words.
    The English page being right is exactly what stopped anyone noticing.

  * **Two environment variables in a compose example.** `GUNICORN_WORKERS=1`
    and `GUNICORN_THREADS=8`, in the production docker-compose block. The image
    hardcodes `--workers 1 --threads 8`; neither name is read anywhere in the
    repository. An operator tuning them saw no change and no error.

  * **A Docker Hub link to an image nobody publishes.** `certmate/certmate`,
    once, among twenty correct `fabriziosalmi/certmate` references.

Each check reads the source of truth rather than a second copy of the claim.
"""
import functools
import os
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

_SKIP_DIRS = (".venv", "node_modules", ".git", "scratch", ".claude", "backups")
_SKIP_FILES = ("RELEASE_NOTES.md", "CHANGELOG.md")


@functools.lru_cache(maxsize=1)
def _markdown():
    """Every markdown file, pruning the heavy trees instead of walking them.

    `rglob` descends into `.git`, `node_modules` and `.venv` in full and only
    then discards what it found — tens of thousands of stats for a set that is
    static within a run (Copilot, #537). `os.walk` with in-place pruning of
    `dirs` never enters them.
    """
    found = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if name.endswith(".md") and name not in _SKIP_FILES:
                found.append(pathlib.Path(root) / name)
    return tuple(sorted(found))


def _enforced_coverage_floor():
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    match = re.search(r"--cov-fail-under=(\d+)", ci)
    assert match, "ci.yml no longer passes --cov-fail-under; this check is stale"
    return int(match.group(1))


def test_the_scan_sees_the_documentation():
    assert len(_markdown()) >= 20, f"only {len(_markdown())} markdown files found"


@pytest.mark.parametrize("path", [p for p in _markdown() if p.name == "testing.md"],
                         ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_no_testing_guide_promises_a_coverage_floor_ci_does_not_enforce(path):
    floor = _enforced_coverage_floor()
    offenders = []
    for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1):
        if not re.search(r"cov|Cov|copertura|couverture|cobertura|Abdeckung",
                         line):
            continue
        for match in re.finditer(r"\*\*(\d{2})%", line):
            if int(match.group(1)) != floor:
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert not offenders, (
        f"these promise a coverage number CI does not enforce (the only "
        f"enforced floor is --cov-fail-under={floor}; codecov.yml marks both "
        f"its statuses informational):\n  " + "\n  ".join(offenders)
    )


def test_no_compose_example_sets_a_variable_nothing_reads():
    """Applies to the docs' examples, not to the repo's own compose file.

    The variables are read by the container's command line and the entrypoint,
    so those are the files that decide. `GUNICORN_TIMEOUT` is real;
    `GUNICORN_WORKERS` and `GUNICORN_THREADS` never were.
    """
    consumers = ""
    for name in ("Dockerfile", "docker-compose.yml", "docker-entrypoint.sh",
                 "entrypoint.sh"):
        path = REPO_ROOT / name
        if path.exists():
            consumers += path.read_text(encoding="utf-8")
    consumers += "".join(
        p.read_text(encoding="utf-8") for p in REPO_ROOT.glob("modules/**/*.py"))
    consumers += (REPO_ROOT / "app.py").read_text(encoding="utf-8")

    offenders = []
    for path in _markdown():
        fenced = False
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if not fenced:
                continue
            match = re.match(r"\s*-\s+(GUNICORN_[A-Z_]+)=", line)
            if match and not re.search(rf"\b{match.group(1)}\b", consumers):
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")
    assert not offenders, (
        "these compose examples set a variable nothing in the image reads, so "
        "an operator tuning them gets no change and no error:\n  "
        + "\n  ".join(offenders)
    )


def test_every_docker_hub_reference_names_the_image_we_publish():
    """The docs must name the image this repository publishes.

    An earlier docstring here claimed the expected name was derived from the
    publish workflow. It is not, and saying so was the kind of overclaim this
    file exists to catch (Copilot, #537). The workflow builds the namespace
    from `secrets.DOCKERHUB_USER`, which no test can read, falling back to the
    repository owner. So the owner is what this checks against — correct while
    the secret matches it, which is the documented fallback and the case today.

    If publishing ever moves to an organisation account whose name differs from
    the GitHub owner, this test fails on correct documentation. The failure
    message says so, and the fix is to name the account here rather than to
    delete the check.
    """
    # The publish workflow builds the tag as `${namespace}/${IMAGE_NAME}`, and
    # its own comment says the namespace falls back to the repository owner. So
    # the owner is the truth, and it is written down in every GitHub link in
    # the documentation — a surface independent of the Docker Hub links being
    # checked. (Checking the Docker Hub links against each other would only
    # prove they agree, not that they are right.)
    workflow = (REPO_ROOT / ".github/workflows/docker-multiplatform.yml").read_text(
        encoding="utf-8")
    image = re.search(r"^\s*IMAGE_NAME:\s*(\S+)", workflow, re.M)
    assert image, "the publish workflow no longer sets IMAGE_NAME"

    owners = set()
    for path in _markdown():
        owners.update(re.findall(r"github\.com/([\w.-]+)/certmate\b",
                                 path.read_text(encoding="utf-8")))
    assert len(owners) == 1, (
        f"the documentation names {len(owners)} different GitHub owners for "
        f"this repository: {sorted(owners)}"
    )
    published = {f"{owners.pop()}/{image.group(1)}"}

    offenders = []
    for path in _markdown():
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            for match in re.finditer(r"hub\.docker\.com/r/([\w.-]+/[\w.-]+)",
                                     line):
                if match.group(1) not in published:
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}:{number}: "
                        f"{match.group(1)} — expected {sorted(published)} "
                        f"(the GitHub owner, which is the namespace the "
                        f"publish workflow falls back to; if DOCKERHUB_USER "
                        f"now names a different account, record it here)")
    assert not offenders, (
        "documentation links to a Docker Hub image nobody publishes:\n  "
        + "\n  ".join(offenders)
    )
