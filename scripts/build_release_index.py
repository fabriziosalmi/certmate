#!/usr/bin/env python3
"""Generate RELEASE_NOTES.md from docs/releases/, so the two cannot disagree.

RELEASE_NOTES.md had grown to 4,780 lines across 94 releases in one file, and
the cost was not its size. It was that a single file mixes an append-only
archive of statements that were true once with the documents that describe the
product now, and every gate that reads the tree then has to carve out an
exception for it: six test files list it in a `_SKIP_FILES` tuple, for pinned
version numbers, documented Python versions, dependency pins, frontend state,
docs navigation and real numbers. Six exceptions for one filename is the tree
telling you the file is a different kind of thing.

So each release owns a file, `docs/releases/vX.Y.Z.md`, and this script builds
the index. Generated rather than hand-maintained because an index someone keeps
up to date is an index that is occasionally wrong, and the failure is silent:
a release missing from the list looks exactly like a release that was never
cut.

Two properties the index keeps on purpose:

* Every `## vX.Y.Z (title)` heading survives, so any link anyone has to a
  section anchor still resolves. This is a public repository and the anchors
  are not ours to break.
* The title comes from the file, never retyped here, so the index cannot
  describe a release differently from the release.

Usage:
  scripts/build_release_index.py            write RELEASE_NOTES.md
  scripts/build_release_index.py --check    exit 1 if it would change
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RELEASES = REPO / 'docs' / 'releases'
INDEX = REPO / 'RELEASE_NOTES.md'

HEADING = re.compile(r'^## v(\d+\.\d+\.\d+) (\S.*)$')

PREAMBLE = """# Release notes

One file per release, in [docs/releases/](docs/releases/). This page is
generated from them by `scripts/build_release_index.py`; edit the release file,
not this list.

"""


def _version_key(version: str) -> tuple:
    return tuple(int(part) for part in version.split('.'))


def collect() -> list[tuple[str, str]]:
    """(version, title) for every release file, newest first."""
    found = []
    for path in sorted(RELEASES.glob('v*.md')):
        first = path.read_text(encoding='utf-8').lstrip().split('\n', 1)[0]
        match = HEADING.match(first)
        if not match:
            raise SystemExit(
                f'{path.relative_to(REPO)} does not start with '
                f'"## vX.Y.Z <title>". scripts/release.sh extracts the GitHub '
                f'release body by matching that literal prefix, so a file '
                f'without it produces an empty release body.'
            )
        version, title = match.group(1), match.group(2)
        if path.name != f'v{version}.md':
            raise SystemExit(
                f'{path.relative_to(REPO)} declares v{version}; the file name '
                f'and the heading have to be the same release.'
            )
        found.append((version, title))
    return sorted(found, key=lambda item: _version_key(item[0]), reverse=True)


def render(entries: list[tuple[str, str]]) -> str:
    lines = [PREAMBLE.rstrip('\n'), '']
    for version, title in entries:
        lines.append(f'## v{version} {title}')
        lines.append('')
        lines.append(f'[Read the notes](docs/releases/v{version}.md)')
        lines.append('')
    return '\n'.join(lines).rstrip('\n') + '\n'


def main() -> int:
    entries = collect()
    if not entries:
        raise SystemExit(
            f'no release files in {RELEASES.relative_to(REPO)}; refusing to '
            f'write an empty index over the one that is there.'
        )
    rendered = render(entries)
    if '--check' in sys.argv:
        current = INDEX.read_text(encoding='utf-8') if INDEX.exists() else ''
        if current != rendered:
            print(
                'RELEASE_NOTES.md is not what docs/releases/ generates. Run '
                'scripts/build_release_index.py and commit the result.',
                file=sys.stderr,
            )
            return 1
        print(f'Release index OK: {len(entries)} releases, newest v{entries[0][0]}.')
        return 0
    INDEX.write_text(rendered, encoding='utf-8')
    print(f'Wrote {INDEX.name}: {len(entries)} releases, newest v{entries[0][0]}.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
