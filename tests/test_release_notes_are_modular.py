"""The release notes are one file per release, and the index is generated.

RELEASE_NOTES.md was 4,780 lines across 94 releases. The size was a symptom;
the problem was that one file held both an append-only archive of statements
that were true once and a document the gates read as a description of the
product now. Five test files had to carve out an exception for that filename,
and one of them named a CHANGELOG.md that has never existed in this repository
— five copies of a rule, one of them fiction, is how a rule stops being read.

Each release now owns docs/releases/vX.Y.Z.md, the exception is one definition
in tests/historical_documents.py, and RELEASE_NOTES.md is generated from the
directory by scripts/build_release_index.py.

Generated rather than maintained because the failure mode of a hand-kept index
is silent: a release missing from the list looks exactly like a release that
was never cut. So the index is checked against the directory here, the way a
lockfile is checked against its manifest.
"""
import pathlib
import re
import subprocess
import sys

import pytest

from modules import __version__

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
RELEASES = REPO / 'docs' / 'releases'
INDEX = REPO / 'RELEASE_NOTES.md'
BUILDER = REPO / 'scripts' / 'build_release_index.py'

HEADING = re.compile(r'^## v(\d+\.\d+\.\d+) (\S.*)$')


def _release_files():
    return sorted(RELEASES.glob('v*.md'))


def test_the_index_is_what_the_directory_generates():
    """The check the builder itself offers, run where CI will see it."""
    result = subprocess.run(
        [sys.executable, str(BUILDER), '--check'],
        cwd=REPO, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f'{result.stdout}{result.stderr}\n'
        f'RELEASE_NOTES.md is generated from docs/releases/. Run '
        f'scripts/build_release_index.py and commit the result.'
    )


@pytest.mark.parametrize('path', _release_files(), ids=lambda p: p.name)
def test_each_release_file_names_the_release_it_is(path):
    """File name and heading have to be the same release.

    scripts/release.sh takes the GitHub release body from the file named after
    the version, and the index takes the title from the heading inside it. If
    those disagree, the release is published under one number with another
    one's notes, and nothing else would notice.
    """
    first = path.read_text(encoding='utf-8').lstrip().split('\n', 1)[0]
    match = HEADING.match(first)
    assert match, (
        f'{path.relative_to(REPO)} must start with "## vX.Y.Z <title>"; it '
        f'starts with {first!r}'
    )
    assert path.name == f'v{match.group(1)}.md', (
        f'{path.relative_to(REPO)} contains the notes for v{match.group(1)}'
    )


def test_the_current_version_has_its_notes():
    """The same rule scripts/release.sh enforces on the machine cutting the
    release, held here for any path that reaches main."""
    assert (RELEASES / f'v{__version__}.md').exists(), (
        f'modules/__init__.py says v{__version__} and '
        f'docs/releases/v{__version__}.md does not exist'
    )


def test_there_are_notes_to_check():
    """CONTROL for the instrument. An empty or missing directory would make
    every parametrised case above vanish, and this file would report success
    for a structure that is not there."""
    assert len(_release_files()) > 50, (
        f'only {len(_release_files())} release files found; the directory is '
        f'not being read'
    )


def test_the_release_script_reads_the_directory():
    """The structure is only real if the release path uses it. A tidy
    directory that scripts/release.sh ignores would leave the 4,780-line file
    as the thing that actually ships."""
    script = (REPO / 'scripts' / 'release.sh').read_text(encoding='utf-8')
    assert 'docs/releases' in script, (
        'scripts/release.sh does not mention docs/releases; it is still '
        'reading the notes from somewhere else'
    )
    assert 'build_release_index.py --check' in script, (
        'scripts/release.sh does not verify the index is current, so a '
        'release can ship with an index that omits it'
    )
