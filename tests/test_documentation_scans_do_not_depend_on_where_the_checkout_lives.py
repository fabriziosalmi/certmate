"""The documentation gates read the same files wherever the checkout lives.

Measured on 2026-11-25: from a worktree under `.claude/worktrees/`, three gates
failed their "the scan sees the documentation" guard and the gates without such
a guard passed while reading no file at all. Each tested its skip tuple against
the parts of the absolute path, and `.claude` was one of them. The rule now
lives in tests/repository_documents.py and looks only below the repository root.
"""
import pathlib
import re

import pytest

from tests.repository_documents import REPO, SKIPPED_DIRS, is_skipped, markdown_files

pytestmark = [pytest.mark.unit]

# A tree with a document in each place the rule has to decide about: kept at the
# top, kept nested, and left out at the top and nested.
_KEPT = ('README.md', 'docs/guide.md', 'docs/it/guida.md')
_LEFT_OUT = ('node_modules/pkg/README.md', '.claude/notes.md', '.venv/lib/x.md',
             'docs/scratch/draft.md', 'backups/old.md', '.git/info.md')


def _tree(root: pathlib.Path) -> pathlib.Path:
    for relative in _KEPT + _LEFT_OUT:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# doc\n', encoding='utf-8')
    return root


def _relative(root: pathlib.Path) -> list[str]:
    return [p.relative_to(root).as_posix() for p in markdown_files(root)]


@pytest.mark.parametrize('skipped', sorted(SKIPPED_DIRS))
def test_a_checkout_under_a_skipped_name_still_sees_its_documents(tmp_path, skipped):
    """Every skipped name, used as a directory above the checkout, changes nothing."""
    plain = _tree(tmp_path / 'plain' / 'certmate')
    nested = _tree(tmp_path / skipped / 'worktrees' / 'certmate')
    assert _relative(plain) == sorted(_KEPT)
    assert _relative(nested) == _relative(plain), (
        f'a checkout under {skipped}/ reads {_relative(nested)}, the same tree '
        f'elsewhere reads {_relative(plain)}'
    )


def test_is_skipped_judges_only_the_part_below_the_root(tmp_path):
    root = _tree(tmp_path / '.claude' / 'worktrees' / 'certmate')
    assert not is_skipped(root / 'docs' / 'guide.md', root)
    assert is_skipped(root / 'docs' / 'scratch' / 'draft.md', root)
    assert is_skipped(root / 'node_modules' / 'pkg' / 'README.md', root)


def test_this_checkout_sees_its_documentation():
    """Whatever directory this run happens to start from."""
    assert len(markdown_files(REPO)) >= 20


def test_no_gate_keeps_its_own_copy_of_the_rule():
    """Six copies of the tuple are how one of them stays wrong when the others are fixed."""
    copies = []
    for path in sorted((REPO / 'tests').glob('*.py')):
        if path.name == 'repository_documents.py':
            continue
        text = path.read_text(encoding='utf-8')
        if re.search(r"""["']scratch["']\s*,\s*["']\.claude["']""", text):
            copies.append(path.name)
    assert not copies, (
        f'{copies} define their own list of directories to skip; use '
        f'tests/repository_documents.py so the rule has one definition'
    )
