"""Single-source-of-truth guard: package.json and modules.__version__ must
agree. A drift here means a release bumped one and forgot the other."""
import json
import pathlib

from modules import __version__

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_package_json_matches_module_version():
    pkg = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    assert pkg["version"] == __version__, (
        f"package.json version {pkg['version']!r} != modules.__version__ "
        f"{__version__!r} - bump both (or neither) in the same release commit."
    )
