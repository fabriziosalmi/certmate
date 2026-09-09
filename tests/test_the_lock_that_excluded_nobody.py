"""The file lock in `safe_file_write` protected nothing, and said it did.

    fd = os.open(str(temp_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        # Use file locking for safety
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

The exclusive lock is on the file `mkstemp` created two lines earlier: a name
no other process has, held for the duration of a write to it, released before
the rename that actually publishes the content. No other holder of that path
ever waited, because there is no other holder. `safe_file_read`'s `LOCK_SH` was
the other half of a pair whose first half was never on the same file.

That is worse than no lock. A reader of this function finds locking and stops
asking how concurrent writes are handled, and the comment tells them it is "for
safety" — so the question of what happens when two callers write the same
settings file has an answer in the source that was never true.

The real guarantee was always the rename, and it is a good one: a reader gets
the whole old file or the whole new one, never a mixture. What it does NOT give
is mutual exclusion between a read and a later write by the same caller — a
lost update — and that is handled where it can be, in `SettingsManager.update`,
which holds a lock across both halves.

These tests pin the guarantee that is real, under actual concurrency, so that
removing the locks is a claim the suite checks rather than an assertion in a
docstring.
"""
import json
import threading

import pytest

from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    return FileOperations(cert_dir=tmp_path / 'certs', data_dir=tmp_path,
                          backup_dir=tmp_path / 'backups',
                          logs_dir=tmp_path / 'logs')


# --- the guarantee that is real ------------------------------------------

def test_a_reader_never_sees_a_partial_file(file_ops, tmp_path):
    """THE property. A large payload takes many write() calls to serialise; if
    publication were anything but a rename, a reader would catch one of them
    half done."""
    target = tmp_path / 'settings.json'
    # Big enough that json.dump cannot reach the disk in one syscall.
    payloads = [{'writer': n, 'blob': [f'{n}-{i}' for i in range(20000)]}
                for n in range(4)]
    file_ops.safe_file_write(target, payloads[0])

    stop = threading.Event()
    partial = []
    seen = set()

    def writer(payload):
        while not stop.is_set():
            file_ops.safe_file_write(target, payload)

    def reader():
        while not stop.is_set():
            got = file_ops.safe_file_read(target, is_json=True, default=None)
            if not isinstance(got, dict) or 'writer' not in got:
                partial.append(got)
                return
            if len(got['blob']) != 20000:
                partial.append(len(got['blob']))
                return
            seen.add(got['writer'])

    threads = ([threading.Thread(target=writer, args=(p,)) for p in payloads]
               + [threading.Thread(target=reader) for _ in range(4)])
    for thread in threads:
        thread.start()
    stop.wait(2.0)
    stop.set()
    for thread in threads:
        thread.join(timeout=10)

    assert not partial, f'a reader saw a file mid-write: {partial[:1]}'
    assert seen, 'the readers never read anything, so they proved nothing'


def test_every_concurrent_write_lands_whole(file_ops, tmp_path):
    """The other side of it: the loser of a race loses entirely, rather than
    contributing half its bytes to the winner's file."""
    target = tmp_path / 'settings.json'
    # Different lengths on purpose: equal-length payloads would hide a write
    # that overwrote another in place, since the survivor would be the right
    # size either way.
    payloads = {n: {'writer': n, 'blob': str(n) * (100000 + n * 9000)}
                for n in range(8)}

    threads = [threading.Thread(target=file_ops.safe_file_write,
                                args=(target, payloads[n]))
               for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    final = json.loads(target.read_text(encoding='utf-8'))
    assert final == payloads[final['writer']], (
        'the surviving file is not any one writer\'s payload, so two writes '
        'were interleaved')


def test_no_temporary_file_is_left_behind(file_ops, tmp_path):
    """CONTROL. The temp lives in the target's own directory — for settings
    that is the data volume — so a leak there is an operator's problem."""
    target = tmp_path / 'settings.json'

    for n in range(20):
        file_ops.safe_file_write(target, {'n': n})

    assert sorted(p.name for p in tmp_path.iterdir()) == ['settings.json']


def test_the_published_file_is_owner_only(file_ops, tmp_path):
    """CONTROL, unrelated to locking and easy to lose in this function: it
    holds API tokens and DNS provider credentials."""
    import stat

    target = tmp_path / 'settings.json'
    file_ops.safe_file_write(target, {'api_bearer_token': 'x'})

    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_a_reader_holding_the_old_file_is_not_disturbed(file_ops, tmp_path):
    """What a shared lock was supposed to buy, and what the rename gives for
    free: an open handle keeps resolving to the inode it opened."""
    target = tmp_path / 'settings.json'
    file_ops.safe_file_write(target, {'version': 'first'})

    with open(target, 'r', encoding='utf-8') as handle:
        file_ops.safe_file_write(target, {'version': 'second'})
        assert json.loads(handle.read())['version'] == 'first'

    assert file_ops.safe_file_read(target, is_json=True)['version'] == 'second'


# --- the decoration does not come back -----------------------------------

def test_this_module_does_not_claim_to_lock():
    """A guard, not a style rule. If a lock returns here it has to be one that
    excludes something — which means naming the file it is taken on and the
    other holder it waits for, neither of which the removed one had."""
    import inspect

    source = inspect.getsource(FileOperations)

    assert 'flock' not in source, (
        'a file lock is back in FileOperations. The one removed was taken on '
        'the private temporary file the same call had just created, so it '
        'excluded nobody; if this one is real, it is taken on the target and '
        'this test should say what it waits for.')


def test_the_docstrings_say_where_atomicity_comes_from():
    """The point of the change is that the next reader gets a true answer
    rather than a comment saying "for safety"."""
    assert 'rename' in FileOperations.safe_file_write.__doc__
    assert 'rename' in FileOperations.safe_file_read.__doc__


def test_the_data_reaches_disk_before_the_rename():
    """The ordering the removed lock sat next to and had nothing to do with:
    fsync on the content, then rename. Reversed, a power loss can leave the
    target pointing at an empty file."""
    import inspect

    source = inspect.getsource(FileOperations.safe_file_write)

    assert source.index('os.fsync') < source.index('temp_file.rename')
