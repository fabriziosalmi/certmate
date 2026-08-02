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

# Not content pages: the index links to everything else, README.md is the
# alternative index, and the theme note is a one-off migration record.
NOT_LINKABLE = {"index.md", "README.md", "THEME_MIGRATION.md"}


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
    index = _lang_dir(lang) / "index.md"
    assert index.exists(), f"docs/{lang}: no index.md"
    unreachable = sorted(_pages(lang) - _links(index))
    assert not unreachable, (
        f"docs/{lang}/index.md links to none of {unreachable} — those pages "
        f"exist but nothing points at them."
    )


@pytest.mark.parametrize("lang", LANGUAGES)
def test_index_links_resolve(lang):
    """No entry may point at a file that is not there."""
    directory = _lang_dir(lang)
    index = directory / "index.md"
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
