"""What counts as a record of the past rather than a description of the present.

Several gates walk the documentation and assert that what it says is true now:
that every pinned version matches requirements, that no document names a Python
we neither build nor test, that no page still points at an endpoint that was
renamed. All of them are right, and all of them have to exclude the same thing,
because release notes are not that kind of document. A note saying v2.4.12
pinned cryptography 42 is correct forever and describes nothing about today.

Before this module the exclusion was a `("RELEASE_NOTES.md", "CHANGELOG.md")`
tuple copied into five test files, and `CHANGELOG.md` has never existed in this
repository. Five copies of a rule, one of them naming a file that is not there,
is how a rule stops being read.

Now there is one definition, and it covers the directory as well as the index:
each release owns a file under docs/releases/, so the archive is 94 files
rather than one, and a per-file exclusion list would have to grow with every
release.
"""
from __future__ import annotations

import pathlib

# The generated index. Its own content is version headings and links, but it is
# excluded on the same grounds: it is a list of the past.
HISTORICAL_FILES = ('RELEASE_NOTES.md',)

# One file per release. See scripts/build_release_index.py.
HISTORICAL_DIRS = ('docs/releases',)


def is_historical(path) -> bool:
    """True for a document that records what was true at a point in time.

    Accepts a path in any form a caller already has: absolute, relative, str
    or Path. The comparison is on the POSIX-joined parts so a Windows
    checkout answers the same as a POSIX one.
    """
    path = pathlib.Path(path)
    if path.name in HISTORICAL_FILES:
        return True
    posix = path.as_posix()
    return any(f'/{directory}/' in f'/{posix}' for directory in HISTORICAL_DIRS)
