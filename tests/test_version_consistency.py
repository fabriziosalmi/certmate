"""Single-source-of-truth guard: package.json, modules.__version__ and the
version printed in the Docker Hub README's /health example must agree. A drift
here means a release bumped one and forgot the others."""
import json
import pathlib
import re

from modules import __version__

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_package_json_matches_module_version():
    pkg = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    assert pkg["version"] == __version__, (
        f"package.json version {pkg['version']!r} != modules.__version__ "
        f"{__version__!r} - bump both (or neither) in the same release commit."
    )


def test_dockerhub_readme_health_example_matches_module_version():
    """The example an operator compares their own /health output against.

    It is bumped by scripts/release.sh, not by hand — this test is what makes
    a forgotten bump fail rather than quietly misinform someone about which
    version they are running.
    """
    text = (REPO_ROOT / "README.dockerhub.md").read_text(encoding="utf-8")
    versions = re.findall(r'"version": "([0-9]+\.[0-9]+\.[0-9]+)"', text)
    assert versions, "no version example found in README.dockerhub.md"
    for found in versions:
        assert found == __version__, (
            f"README.dockerhub.md shows version {found!r} but "
            f"modules.__version__ is {__version__!r}."
        )
