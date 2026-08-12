"""Every endpoint the API reference documents must resolve against the route map.

`templates/help.html` got this check when `GET /{domain}/tls` turned out to be
a 404 advertised four times. The API reference — the document people integrate
against — did not, and it had drifted a different way.

`docs/api.md` declared `Base URL: http://localhost:8000/api`, then wrote
thirteen paths relative to that base (`POST /client-certs/create`) and eight
with the prefix already on them (`GET /api/settings/rate-limits`). Read against
its own stated base, the second set resolved to `/api/api/...`. Whichever
convention a reader picked, one set was wrong.

The four translations were worse: they had **lost the base-URL line entirely**
while keeping the thirteen relative paths, so those had nothing to resolve
against at all. The same blind spot as every other defect found in this sweep —
the English page carried the piece that made it work, and the translations did
not.

Every path is absolute now, and this asks the application whether each one
exists, which is the only thing that knows.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
API_DOCS = sorted(REPO_ROOT.glob("docs/**/api.md"))

pytestmark = [pytest.mark.unit]


def _normalise(path):
    path = re.sub(r"<[^>]+>", "<X>", path)
    path = re.sub(r"\{[^}]+\}", "<X>", path)
    return path.rstrip("/") or "/"


@pytest.fixture(scope="session")
def url_map(tmp_path_factory):
    """The route table, built once under a temporary root.

    `setup_directories()` creates data/, certificates/ and logs/ relative to
    `factory.__file__`, so a test that only reads the route table would
    otherwise write into the checkout. Same anchoring as
    tests/test_advertised_endpoints_exist.py.
    """
    root = tmp_path_factory.mktemp("apidocs") / "certmate"
    module_dir = root / "modules" / "core"
    module_dir.mkdir(parents=True)
    anchor = module_dir / "factory.py"
    anchor.write_text("# test path anchor\n", encoding="utf-8")

    # No sys.path insert: pytest's rootdir handling already puts the repo
    # root first, and a session fixture that prepends to sys.path leaks
    # that for the rest of the run — global state escaping a fixture
    # (Copilot, #554). Verified the import still resolves without it, in
    # isolation and in the full suite.
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TESTING", "true")
        patch.setenv("FLASK_ENV", "testing")
        from modules.core.factory import create_app
        patch.setattr("modules.core.factory.__file__", str(anchor))
        result = create_app()
    app = result[0] if isinstance(result, tuple) else result
    return {
        _normalise(str(rule)): {m for m in rule.methods
                                if m not in ("HEAD", "OPTIONS")}
        for rule in app.url_map.iter_rules()
    }


def _documented():
    """(file, line, verb, path) for every endpoint the API docs state."""
    found = []
    for doc in API_DOCS:
        for number, line in enumerate(
                doc.read_text(encoding="utf-8").splitlines(), 1):
            for match in re.finditer(
                    r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[\w/{}.<>:-]+)", line):
                path = re.sub(r"\?.*$", "", match.group(2)).rstrip(".,`)")
                found.append((str(doc.relative_to(REPO_ROOT)), number,
                              match.group(1), path))
    return found


DOCUMENTED = _documented()


def test_the_api_docs_are_being_read():
    assert len(API_DOCS) >= 5, (
        f"found {len(API_DOCS)} api.md files — English plus four translations "
        f"is five; a smaller number means the scan is missing languages, which "
        f"is exactly where these defects live."
    )
    assert len(DOCUMENTED) >= 50, (
        f"parsed {len(DOCUMENTED)} endpoints out of them — the format changed "
        f"and every check below would pass over nothing."
    )


@pytest.mark.parametrize("doc,number,verb,path", DOCUMENTED,
                         ids=[f"{d}:{n}" for d, n, _v, _p in DOCUMENTED])
def test_every_documented_path_is_absolute(doc, number, verb, path):
    """One convention, so no reader has to guess which base to prepend."""
    assert path.startswith("/api"), (
        f"{doc}:{number} documents `{verb} {path}`, which is relative. The "
        f"file used to mix relative and absolute paths, and the translations "
        f"had lost the base-URL line that made the relative ones resolvable."
    )


@pytest.mark.parametrize("doc,number,verb,path", DOCUMENTED,
                         ids=[f"{d}:{n}" for d, n, _v, _p in DOCUMENTED])
def test_every_documented_path_is_a_real_route(doc, number, verb, path, url_map):
    wanted = _normalise(path).strip("/").split("/")

    # Literal segments win over parameters, the way a router resolves. Without
    # this, `/api/client-certs/batch` matched `/api/client-certs/<identifier>`
    # first — a GET-only route — and the check reported a POST mismatch on an
    # endpoint that is perfectly correct. Candidates are ranked by how many
    # segments they match literally.
    matches = []
    for candidate, methods in url_map.items():
        parts = candidate.strip("/").split("/")
        if len(parts) != len(wanted):
            continue
        if not all(p == "<X>" or p == w for p, w in zip(parts, wanted)):
            continue
        literal = sum(1 for p in parts if p != "<X>")
        matches.append((literal, candidate, methods))

    if matches:
        _score, candidate, methods = max(matches, key=lambda m: m[0])
        assert verb in methods, (
            f"{doc}:{number} documents `{verb} {path}`, but {candidate} "
            f"accepts {sorted(methods)}."
        )
        return
    pytest.fail(
        f"{doc}:{number} documents `{verb} {path}`, which is not a route this "
        f"application serves. Anyone integrating against the API reference "
        f"gets a 404."
    )
