"""Every relative link in a Markdown file of the repository opens a file that is there.

tests/test_docs_navigation.py checks the links of the documentation indexes. The
rest of the Markdown had no check, and twelve links in the release notes opened
nothing: they were written from the repository root (``docs/deploy-hooks.md``,
``modules/web/routes.py``) in files that live in docs/releases/, where GitHub
resolves them against that directory.

Release notes are excluded from the gates that check what a document says about
today (tests/historical_documents.py), and rightly. A link is not a claim about
today: one that opens a 404 is broken in a note from 2025 as much as in a page
written this morning, and the notes of each new release travel in its release
pull request, where this runs. A note that names code as it was links to the
file at its release tag, which stays true; a note that sends the reader to the
documentation links to the page as it is now.
"""
import pathlib
import re
import subprocess

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

FENCE = re.compile(r'```.*?```', re.S)
LINK = re.compile(r'\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
NOT_A_FILE = re.compile(r'([a-z][a-z0-9+.-]*:|#|<)', re.I)


def _markdown_files():
    listed = subprocess.run(
        ['git', 'ls-files', '*.md'], cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    return [REPO_ROOT / name for name in listed]


def broken_links(path: pathlib.Path, text: str):
    """The relative links in ``text`` (the content of ``path``) whose target is not on disk, as (line, link)."""
    # Code blocks show Markdown rather than link to anything; blanked, newlines kept.
    text = FENCE.sub(lambda match: '\n' * match.group(0).count('\n'), text)
    found = []
    for match in LINK.finditer(text):
        link = match.group(1)
        if NOT_A_FILE.match(link):
            continue
        target = link.split('#', 1)[0].split('?', 1)[0]
        if target and not (path.parent / target).exists():
            found.append((text.count('\n', 0, match.start()) + 1, link))
    return found


def test_every_relative_link_opens_a_file():
    files = _markdown_files()
    assert len(files) > 100, 'git ls-files found too little Markdown: this test has lost its subject'
    broken = [
        f'{path.relative_to(REPO_ROOT)}:{line} {link}'
        for path in files
        for line, link in broken_links(path, path.read_text(errors='replace'))
    ]
    assert not broken, (
        'these links open nothing; a link is resolved from the directory of the file it is in:\n'
        + '\n'.join(broken))


def test_the_check_resolves_from_the_files_own_directory():
    note = REPO_ROOT / 'docs' / 'releases' / 'v0.0.0.md'
    assert broken_links(note, 'See [hooks](docs/deploy-hooks.md).') == [(1, 'docs/deploy-hooks.md')]
    assert broken_links(note, 'See [hooks](../deploy-hooks.md#security).') == []
    assert broken_links(note, 'See [the tag](https://github.com/fabriziosalmi/certmate/blob/v2.5.0/x.py).') == []
    assert broken_links(note, '```\n[not a link](nowhere.md)\n```') == []
