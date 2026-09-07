"""Every endpoint the product advertises must be a route the app serves.

`GET /{domain}/tls` was in the README's feature list, in the README's
"Automation-Friendly Download URL" section with a worked example, and in the
in-product help page — as a listed endpoint *and* as the copy-pasteable curl
command underneath it. It returns 404. There are 130 routes in the app and not
one of them contains `/tls`; the real endpoints are
`/api/certificates/<domain>/download` and `.../download/<file_type>`.

Nothing caught it because the documentation was checked against itself. The
route table is the only thing that knows what exists, so the check below asks
the application, not a list someone maintains by hand.
"""
import pathlib
import re

import pytest


pytestmark = [pytest.mark.unit]

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def url_map(tmp_path_factory):
    """The application's route table, built once, under a temporary root.

    Built once because the first version called `create_app()` inside every
    parametrised case, and under a temporary root because `setup_directories()`
    creates `data/`, `certificates/` and `logs/` relative to
    `modules/core/factory.__file__` — so a test that only wants to read the
    route table was creating directories in the working tree and would fail on
    a read-only checkout (Copilot, #534). Anchoring the module's `__file__` to
    a temp tree is the pattern the rest of the suite already uses; see
    tests/test_csp_img_src_airgap.py.
    """
    root = tmp_path_factory.mktemp("routes") / "certmate"
    module_dir = root / "modules" / "core"
    module_dir.mkdir(parents=True)
    anchor = module_dir / "factory.py"
    anchor.write_text("# test path anchor\n", encoding="utf-8")

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TESTING", "true")
        patch.setenv("FLASK_ENV", "testing")
        from modules.core.factory import create_app
        patch.setattr("modules.core.factory.__file__", str(anchor))
        result = create_app()
    app = result[0] if isinstance(result, tuple) else result
    # Union the verbs, do not overwrite them. Several paths are served by more
    # than one rule — `/api/settings` by three, with GET and POST on separate
    # endpoints — and a dict comprehension keeps only whichever rule iterated
    # last. That silently reports a documented `GET /api/settings` as a route
    # that "accepts POST", which is how a correct piece of documentation gets
    # reported as a defect (or, the other way round, a real one gets missed).
    merged = {}
    for rule in app.url_map.iter_rules():
        verbs = {m for m in rule.methods if m not in ("HEAD", "OPTIONS")}
        merged.setdefault(_normalise(str(rule)), set()).update(verbs)
    return merged


def _normalise(path):
    """`/api/x/<string:domain>/y` and `/api/x/{domain}/y` are the same route."""
    path = re.sub(r"<[^>]+>", "<X>", path)
    path = re.sub(r"\{[^}]+\}", "<X>", path)
    return path.rstrip("/") or "/"


def _match(path, routes):
    """Find the route a documented path would reach, or None.

    Segment-wise, because documentation writes worked examples with real
    values: `/api/certificates/example.com/download` must resolve against
    `/api/certificates/<X>/download`. A `<X>` in the route matches exactly one
    literal segment — never several, or `/example.com/tls` would be absorbed by
    some unrelated two-segment rule and this file would prove nothing.
    """
    wanted = _normalise(path).strip("/").split("/")
    for candidate, methods in routes.items():
        parts = candidate.strip("/").split("/")
        if len(parts) != len(wanted):
            continue
        if all(p == "<X>" or p == w for p, w in zip(parts, wanted)):
            return candidate, methods
    return None


def _readme_advertised():
    """(source, verb, path) for every endpoint the README shows in a code block.

    The README is where the phantom `/{domain}/tls` appeared twice, and it was
    never checked — this file only ever read the help page, so a wrong path in
    the file most people read first passed unnoticed (#706).

    Fences are walked line by line rather than paired with a regex. Pairing the
    whole document with a non-greedy pattern looks correct and is not: one
    unbalanced or unexpectedly-formatted fence shifts every pair after it, and
    the extractor then returns nothing at all while still passing.
    """
    found = []
    for name in ("README.md", "README.dockerhub.md"):
        path = REPO_ROOT / name
        if not path.exists():
            continue
        inside = False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("```"):
                inside = not inside
                continue
            if not inside:
                continue
            match = re.match(r"^\s*(GET|POST|PUT|PATCH|DELETE)\s+(/[^\s\\]*)",
                             line)
            if match:
                # A worked example may carry a query string; the route table
                # knows nothing about those.
                found.append((name, match.group(1),
                              match.group(2).split("?")[0]))
    return found


def _advertised():
    """(source, verb, path) for every endpoint the product advertises."""
    html = (REPO_ROOT / "templates" / "help.html").read_text(encoding="utf-8")
    found = []
    for match in re.finditer(
            r'<span class="text-\w+-500">(GET|POST|PUT|PATCH|DELETE)</span>\s*'
            r'([^\s<]+)', html):
        found.append(("templates/help.html", match.group(1), match.group(2)))
    # The curl examples underneath. These are the ones people actually run, so
    # the verb comes from the command's own -X flag rather than being assumed.
    for block in re.finditer(r'curl\b(.*?)(?:</code>|\n\n)', html, re.S):
        text = block.group(1)
        verb = (re.search(r"-X\s+([A-Z]+)", text) or [None, "GET"])[1]
        for url in re.finditer(r'http://localhost:8000(/[^\s<\\"\']+)', text):
            found.append(("templates/help.html (curl)", verb, url.group(1)))
    found.extend(_readme_advertised())
    return found


def test_the_help_page_advertises_something():
    """Otherwise the parametrised checks below pass over an empty list."""
    listed = _advertised()
    assert len(listed) >= 5, (
        f"parsed {len(listed)} endpoints out of templates/help.html — the "
        f"markup changed and this file is no longer checking the help page."
    )


def test_the_readme_advertises_something():
    """The check this file most needed and did not have.

    An extractor that quietly parses nothing passes every case below while
    verifying no endpoint at all — and a green gate that reads nothing is worse
    than no gate, because its existence reads as coverage. A first attempt at
    this really did return zero from a plausible-looking regex.
    """
    listed = _readme_advertised()
    assert len(listed) >= 20, (
        f"parsed {len(listed)} endpoints out of the README — the fenced-block "
        f"walk stopped matching and this file is no longer checking it."
    )


def test_the_readme_and_the_help_page_are_both_covered():
    """CONTROL: neither source may quietly drop out of the combined list."""
    sources = {source for source, _v, _p in _advertised()}
    assert any("help.html" in s for s in sources), sources
    assert any("README" in s for s in sources), sources


def test_the_route_map_is_populated(url_map):
    assert len(url_map) > 50, f"only {len(url_map)} routes — did the app boot?"


def test_a_path_served_by_several_rules_keeps_every_verb(url_map):
    """CONTROL for the map itself, not for what is advertised.

    `/api/settings` is served by three rules, GET and POST on separate
    endpoints. Built with a dict comprehension the map kept only the last one,
    so a documented `GET /api/settings` was reported as a route that "accepts
    POST" — a correct piece of documentation flagged as a defect, and the
    reverse just as possible.
    """
    settings = url_map.get("/api/settings")
    assert settings and {"GET", "POST"} <= settings, (
        f"/api/settings resolved to {settings}; the route map is losing verbs "
        f"where more than one rule serves the same path"
    )


@pytest.mark.parametrize("source,verb,path", _advertised(),
                         ids=[f"{v} {p}" for _s, v, p in _advertised()])
def test_every_advertised_endpoint_is_a_real_route(source, verb, path, url_map):
    routes = url_map
    # `{cert|key|chain}` in a listing stands for one path segment.
    hit = _match(re.sub(r"\{[^}]*\|[^}]*\}", "<X>", path), routes)
    assert hit, (
        f"{source} advertises `{verb} {path}`, which is not a route this "
        f"application serves. It returns 404 to anyone who copies it."
    )
    route, methods = hit
    assert verb in methods, (
        f"{source} advertises `{verb} {path}`, but {route} accepts "
        f"{sorted(methods)}."
    )


def test_the_readme_does_not_advertise_the_phantom_download_url():
    """The specific claim, in the file most people read first.

    Kept as its own check because the README's prose is not machine-readable
    the way the help page's markup is, and this endpoint appeared there three
    times — a feature bullet, a request block, and a worked example.
    """
    for name in ("README.md", "README.dockerhub.md"):
        path = REPO_ROOT / name
        if not path.exists():
            continue
        offenders = [
            f"{name}:{number}: {line.strip()}"
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1)
            if re.search(r"(?<!kubernetes\.io)/\{domain\}/tls|localhost:8000/[\w.]+/tls",
                         line)
        ]
        assert not offenders, (
            "the README advertises `/{domain}/tls`, which no route serves:\n  "
            + "\n  ".join(offenders)
            + "\nUse /api/certificates/{domain}/download."
        )
