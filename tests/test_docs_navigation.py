"""Guard: every documentation page must be reachable, in every language.

A page nobody links to is a page nobody reads. `docs/mcp.md` had existed in
all five languages for months — a full reference for the MCP server, sixteen
tools, the agent-attribution model — and no `index.md` in any language linked
to it, so the only way to find it was to already know it was there. The same
was true of `compliance.md`, `deploy-hooks.md` and `probes*.md`.

The README's own "Complete Documentation Set" table was missing six of the
thirteen pages, which is a specific kind of wrong: a table that claims to be
complete and is not.

These tests are pure file reads — no network, no build.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"

LANGUAGES = ["en", "it", "de", "es", "fr"]

# README.md is the index — it is what GitHub renders when you browse to a
# directory, and the only entry point anyone actually reaches, since nothing
# builds this folder into a site. index.md is a stub kept so that deep links
# from before the rename do not 404; the theme note is a one-off record.
INDEX = "README.md"
NOT_LINKABLE = {"README.md", "index.md", "THEME_MIGRATION.md"}


def _lang_dir(lang):
    return DOCS if lang == "en" else DOCS / lang


def _pages(lang):
    return {p.name for p in _lang_dir(lang).glob("*.md")} - NOT_LINKABLE


def _links(path):
    """Markdown link targets pointing at a .md file, relative or parent."""
    return set(re.findall(r"\]\((?:\./|\.\./)?([a-z0-9._-]+\.md)", path.read_text(
        encoding="utf-8")))


@pytest.mark.parametrize("lang", LANGUAGES)
def test_every_page_is_linked_from_its_index(lang):
    index = _lang_dir(lang) / INDEX
    assert index.exists(), f"docs/{lang}: no {INDEX}"
    unreachable = sorted(_pages(lang) - _links(index))
    assert not unreachable, (
        f"docs/{lang}/{INDEX} links to none of {unreachable} — those pages "
        f"exist but nothing points at them."
    )


@pytest.mark.parametrize("lang", LANGUAGES)
def test_the_index_stub_still_points_somewhere_real(lang):
    """`index.md` is a redirect note for old deep links, nothing more.

    It must stay short — if it grows content again it becomes a second index,
    which is the whole problem it was created to end — and it must point at
    both the guide that absorbed it and the real index.
    """
    stub = _lang_dir(lang) / "index.md"
    assert stub.exists(), f"docs/{lang}/index.md is gone — old deep links 404"
    text = stub.read_text(encoding="utf-8")
    assert len(text) < 800, (
        f"docs/{lang}/index.md is {len(text)} chars — it is turning back into a "
        f"page. It is a redirect note."
    )
    assert "./guide.md" in text and f"./{INDEX}" in text


@pytest.mark.parametrize("lang", LANGUAGES)
def test_index_links_resolve(lang):
    """No entry may point at a file that is not there."""
    directory = _lang_dir(lang)
    index = directory / INDEX
    text = index.read_text(encoding="utf-8")
    broken = []
    for prefix, target in re.findall(r"\]\((\./|\.\./)([a-z0-9._-]+\.md)", text):
        base = directory if prefix == "./" else directory.parent
        if not (base / target).exists():
            broken.append(prefix + target)
    assert not broken, f"docs/{lang}/index.md points at missing files: {broken}"


def test_readme_documentation_table_is_actually_complete():
    """The README table says "Complete Documentation Set". Hold it to that."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    linked = set(re.findall(r"\]\(docs/([a-z0-9._-]+\.md)\)", readme))
    missing = sorted(_pages("en") - linked)
    assert not missing, (
        f"README's documentation table omits {missing}. Either list them or "
        f"stop calling the table complete."
    )


def test_readme_documents_the_mcp_server():
    """CertMate ships an MCP server in `mcp/`; the README has to say so.

    It used to mention it once, inside a feature bullet, with no setup, no
    tool list and no link to docs/mcp.md.
    """
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/mcp.md" in readme, "README never links the MCP guide"
    assert re.search(r"^##\s+.*MCP", readme, re.M | re.I), (
        "README has no MCP section heading"
    )


def test_mcp_readme_tool_count_matches_the_server():
    """The README states how many tools the server exposes. Keep it true."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    server = (REPO_ROOT / "mcp" / "index.js").read_text(encoding="utf-8")
    actual = len(set(re.findall(r"\bcertmate_[a-z_]+", server)))
    claimed = re.search(r"exposes \*\*(\d+) tools\*\*", readme)
    assert claimed, "README no longer states an MCP tool count"
    assert int(claimed.group(1)) == actual, (
        f"README claims {claimed.group(1)} MCP tools, mcp/index.js defines "
        f"{actual}."
    )


# --- claims that go stale --------------------------------------------------- #

ALL_MARKDOWN = [
    p for p in REPO_ROOT.rglob("*.md")
    if not any(part in p.parts for part in
               (".venv", "node_modules", ".git", "scratch", ".claude", "backups"))
]


def test_no_markdown_file_documents_the_broken_test_command():
    """`pytest tests/ -v` produces four failures on a clean checkout.

    It ran the Playwright `ui` suite in the same process as everything else.
    Eleven files told contributors to run it — CONTRIBUTING.md and every
    index/README in all five languages — so the documented way to check your
    work was the one way that reliably went red.
    """
    offenders = [
        str(p.relative_to(REPO_ROOT)) for p in ALL_MARKDOWN
        if re.search(r"pytest\s+tests/\s+-v", p.read_text(encoding="utf-8", errors="replace"))
    ]
    assert not offenders, (
        f"{offenders} document `pytest tests/ -v`, which fails on a clean "
        f'checkout. Use `-m "not ui and not e2e"`.'
    )


@pytest.mark.parametrize("lang", LANGUAGES)
def test_file_structure_listing_matches_disk(lang):
    """The docs README draws its own directory tree. Keep it true.

    It listed eleven files while seventeen existed, so six pages — including
    the whole MCP guide — were invisible to anyone reading the map.
    """
    directory = _lang_dir(lang)
    readme = (directory / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```\n(docs/[^\n]*\n(?:  [^\n]*\n)+)```", readme)
    assert block, f"docs/{lang}/README.md has no file-structure block"
    listed = set(re.findall(r"^  ([A-Za-z0-9._-]+\.md)", block.group(1), re.M))
    on_disk = {p.name for p in directory.glob("*.md")}
    assert listed == on_disk, (
        f"docs/{lang}/README.md file listing is out of date — "
        f"missing {sorted(on_disk - listed)}, phantom {sorted(listed - on_disk)}"
    )


def test_contributing_names_the_gates_that_actually_run():
    """CONTRIBUTING must describe the CI that exists, not one that used to.

    It advertised flake8/black/isort/bandit as coming from
    requirements-test.txt, which contains none of them, and never mentioned
    the theme, CSS-freshness, coverage-floor or real-cert gates at all.
    """
    contributing = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    for gate in ("bandit", "theme_codemod", "css:build", "cov-fail-under",
                 "not ui and not e2e"):
        assert gate in contributing, f"CONTRIBUTING.md never mentions {gate!r}"


def test_contributing_does_not_promise_tools_that_are_not_installed():
    """Anything CONTRIBUTING says requirements-test.txt provides must be in it."""
    contributing = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    declared = (REPO_ROOT / "requirements-test.txt").read_text(encoding="utf-8").lower()
    claim = re.search(r"requirements-test\.txt\s*#\s*([^\n]*)", contributing)
    if not claim:
        return
    for tool in re.findall(r"[a-z0-9_-]{3,}", claim.group(1).lower()):
        if tool in {"and", "the", "in", "repo", "editable", "sdk", "cli", "test",
                    "dev", "tooling", "clients"}:
            continue
        assert tool in declared, (
            f"CONTRIBUTING.md says requirements-test.txt installs {tool!r}, "
            f"but it does not."
        )


def test_a_pull_request_template_exists():
    """Branch protection requires resolved review threads and green CI; the
    template is where a contributor finds that out before pushing."""
    template = REPO_ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
    assert template.exists(), "no PR template"
    text = template.read_text(encoding="utf-8")
    assert "not ui and not e2e" in text
    assert "conversation" in text.lower()


def test_docs_use_the_port_the_app_actually_listens_on():
    """Every documented URL must hit the port CertMate binds by default.

    210 examples across api.md and guide.md, in all five languages, used
    `localhost:5000` — Flask's dev-server default, never CertMate's. `app.py`
    parses `--port` with `default=8000` and the Dockerfile sets `ENV PORT=8000`.
    So the single most copy-pasted thing in the documentation, the curl
    example, produced connection refused.
    """
    app_py = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    declared = re.search(r"--port['\"].*?default=(\d+)", app_py)
    assert declared, "app.py no longer declares a default port"
    port = declared.group(1)

    # The test harness binds its own container elsewhere on purpose, so it can
    # run beside a real instance; conftest.py owns that number.
    conftest = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    test_port = re.search(r'CERTMATE_TEST_PORT", "(\d+)"', conftest)
    allowed = {port} | ({test_port.group(1)} if test_port else set())

    wrong = []
    for path in sorted((REPO_ROOT / "docs").rglob("*.md")):
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            for match in re.finditer(r"localhost:(\d{2,5})", line):
                if match.group(1) not in allowed:
                    wrong.append(
                        f"{path.relative_to(REPO_ROOT)}:{number}: "
                        f"localhost:{match.group(1)}")
    assert not wrong, (
        f"docs point at a port the app does not listen on (default is {port}):"
        f"\n  " + "\n  ".join(wrong[:20])
        + (f"\n  ... and {len(wrong) - 20} more" if len(wrong) > 20 else "")
    )
