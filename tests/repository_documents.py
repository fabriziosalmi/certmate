"""Which markdown files in the repository the documentation gates read.

Several gates walk the documentation and assert that what it says is true. Each
used to carry its own copy of the directories to leave out, and each tested
that tuple against the parts of the ABSOLUTE path. A checkout that itself sits
under one of those names, such as a worktree under `.claude/worktrees/`, then
had every document skipped: three gates failed their own "the scan sees the
documentation" guard, and the gates without such a guard passed over nothing.

Here the rule has one definition, and it is applied to the path relative to the
repository root, so the answer does not depend on where the checkout lives.
Records of the past are a separate question; see tests/historical_documents.py.
"""
from __future__ import annotations

import os
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent

# Trees that are not the project's documentation: dependencies, VCS internals,
# agent worktrees, local scratch space and backups an operator may keep here.
SKIPPED_DIRS = frozenset({'.venv', 'node_modules', '.git', 'scratch', '.claude', 'backups'})


def is_skipped(path, root: pathlib.Path = REPO) -> bool:
    """True when `path` lies inside one of SKIPPED_DIRS below `root`.

    Only the parts below `root` count. A directory above the checkout is where
    the checkout happens to live, not something the repository contains.
    """
    relative = pathlib.Path(path).relative_to(root)
    return any(part in SKIPPED_DIRS for part in relative.parts)


def markdown_files(root: pathlib.Path = REPO) -> tuple[pathlib.Path, ...]:
    """Every markdown file below `root`, sorted, outside SKIPPED_DIRS.

    `os.walk` with in-place pruning never enters `.git`, `node_modules` or
    `.venv`, where `rglob` would stat tens of thousands of files and only then
    discard them (Copilot, #537). The names pruned are those of directories
    below `root`, which is what makes the rule relative by construction.
    """
    root = pathlib.Path(root)
    found = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS]
        found.extend(pathlib.Path(directory) / name for name in files if name.endswith('.md'))
    return tuple(sorted(found))
