"""Regenerating a lock moves what the change needs moved, and nothing else (#1095).

The pip-based `regenerate_lockfiles.sh` re-resolved the whole set every time, so a one-line bump
came back with transitive pins nobody had touched (#1076 had four, and I kept one line by hand).
uv treats the pins already in its output file as preferences, and the script hands it the existing
lock as that file. This runs the real script, on a copy of the files it reads, and checks both
halves of the property: an unchanged requirements file moves nothing, and a changed pin moves that
package and what has to follow it.

It needs uv and the package index, so it is a `network` test: it runs in `make test` and in the
release gate, where uv is present, and skips where it is not.
"""
import pathlib
import re
import shutil
import subprocess

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.network]

REPO = pathlib.Path(__file__).resolve().parent.parent
PIN = re.compile(r'^([A-Za-z0-9._-]+)==(\S+)$')

pytestmark.append(pytest.mark.skipif(shutil.which('uv') is None, reason='uv is not installed'))


def _pins(path):
    """`name -> version`. The lock is in the hashed form (`name==version \\`
    followed by `--hash=` lines), so the trailing backslash is dropped first:
    without that, this read no pin at all, and every comparison below compared
    two empty dicts and passed."""
    pins = {m.group(1).lower(): m.group(2) for line in path.read_text().splitlines()
            for m in [PIN.match(line.strip().rstrip('\\').strip())] if m}
    assert len(pins) > 50 or path.name == 'requirements-build.lock', (
        f'read only {len(pins)} pins from {path.name}: the parser no longer matches the file')
    return pins


@pytest.fixture
def tree(tmp_path):
    """The files the script reads and writes, copied, so the real ones are never touched."""
    for name in ('Dockerfile', 'requirements.txt', 'requirements-minimal.txt',
                 'requirements.lock', 'requirements-minimal.lock',
                 'requirements.constraints', 'requirements-minimal.constraints',
                 'requirements-build.txt', 'requirements-build.lock',
                 'requirements-lint.txt', 'requirements-lint.lock',
                 'requirements-galaxy.txt', 'requirements-galaxy.lock'):
        shutil.copy(REPO / name, tmp_path / name)
    (tmp_path / 'scripts').mkdir()
    for name in ('lockfile.py', 'regenerate_lockfiles.sh'):
        shutil.copy(REPO / 'scripts' / name, tmp_path / 'scripts' / name)
    return tmp_path


def _regenerate(tree):
    done = subprocess.run(['bash', 'scripts/regenerate_lockfiles.sh'], cwd=tree, capture_output=True, text=True,
                          timeout=300)
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_regenerating_an_unchanged_set_moves_no_pin(tree):
    before = {name: _pins(tree / name) for name in ('requirements.lock', 'requirements-minimal.lock')}

    output = _regenerate(tree)

    assert 'both architectures resolve identically' in output
    for name, pins in before.items():
        assert _pins(tree / name) == pins, f'{name}: regenerating with nothing to change moved a pin'
    # The hashes too: a regeneration with nothing to change writes the same
    # bytes, hashes sorted, so it produces no diff to review.
    for name in ('requirements.lock', 'requirements-minimal.lock', 'requirements-build.lock',
                 'requirements-lint.lock', 'requirements-galaxy.lock',
                 'requirements.constraints', 'requirements-minimal.constraints'):
        assert (tree / name).read_text() == (REPO / name).read_text(), (
            f'{name}: regenerating with nothing to change rewrote the file')


def test_a_changed_pin_moves_that_package_and_what_must_follow_it_and_nothing_else(tree):
    """boto3 needs a matching botocore, so those two move. The packages the index has newer
    versions of today and that this change has nothing to do with must stay where they are."""
    before = _pins(tree / 'requirements.lock')
    assert before['boto3'] != '1.43.100', 'the pin this test moves is already the one it moves to'
    text = (tree / 'requirements.txt').read_text()
    assert 'boto3==' in text
    (tree / 'requirements.txt').write_text(re.sub(r'^boto3==\S+', 'boto3==1.43.100', text, flags=re.MULTILINE))

    _regenerate(tree)

    after = _pins(tree / 'requirements.lock')
    moved = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
    assert after['boto3'] == '1.43.100'
    assert moved <= {'boto3', 'botocore', 's3transfer'}, f'a regeneration for one pin moved {sorted(moved)}'
    assert 'boto3' in moved
