"""The persistence check must confirm the property it advertises.

It wrote a marker file on first boot and logged "Persistent volume verified"
whenever the marker was still there. That only ever proved *something wrote
here before*. A plain ``docker restart`` keeps the container's writable layer,
so the marker survived and the check reported a verified volume on an instance
with **no volume mounted at all** — the reassuring line appeared precisely while
the data was ephemeral, and stayed right until the container was recreated and
the settings, certificates and private CA key were gone.

The check now asks the filesystem whether the data directory is on a mount of
its own, which the writable layer cannot fake (#656).
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.core.factory import _data_dir_is_on_its_own_mount

pytestmark = [pytest.mark.unit]


def _only_root_is_mounted():
    """Pin the mount layout so these controls do not depend on the host.

    pytest's tmp_path frequently sits under a directory that is its own mount
    (/tmp is tmpfs on many Linux hosts), which would report "persistent" for
    reasons unrelated to the behaviour being tested.
    """
    return patch('modules.core.factory.os.path.ismount',
                 side_effect=lambda p: Path(p) == Path('/'))


def test_a_plain_directory_is_not_reported_as_persistent(tmp_path):
    """The failure the old marker could not see: ordinary container storage."""
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    with _only_root_is_mounted():
        assert _data_dir_is_on_its_own_mount(data_dir) is False


def test_a_marker_left_by_a_previous_boot_does_not_make_it_persistent(tmp_path):
    """CONTROL: this is exactly the state that used to report 'verified'.

    A restart preserves the writable layer, so the marker is present. It must
    still not count as persistence.
    """
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    (data_dir / '.certmate_persistent').write_text('1')
    with _only_root_is_mounted():
        assert _data_dir_is_on_its_own_mount(data_dir) is False


def test_the_old_marker_rule_answers_wrongly_on_that_same_input(tmp_path):
    """Pins WHY the rule changed, so it cannot quietly come back.

    The previous logic was 'marker exists => persistent volume verified'. On a
    restarted container with no volume the marker is present and the data is
    ephemeral, so the two rules disagree — and the old one is the wrong answer.
    """
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    (data_dir / '.certmate_persistent').write_text('1')

    old_rule_says_persistent = (data_dir / '.certmate_persistent').exists()
    with _only_root_is_mounted():
        new_rule_says_persistent = _data_dir_is_on_its_own_mount(data_dir)

    assert old_rule_says_persistent is True
    assert new_rule_says_persistent is False, (
        "the marker heuristic reported persistence for storage that is lost "
        "on container recreation"
    )


def test_a_mounted_data_directory_is_reported_as_persistent(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    resolved = data_dir.resolve()

    with patch('modules.core.factory.os.path.ismount',
               side_effect=lambda p: Path(p) == resolved):
        assert _data_dir_is_on_its_own_mount(data_dir) is True


def test_a_mounted_parent_also_counts(tmp_path):
    """CONTROL: mounting /app rather than /app/data is still persistent.

    Checking only the directory itself would raise a false alarm on a
    perfectly good deployment.
    """
    parent = tmp_path / 'app'
    data_dir = parent / 'data'
    data_dir.mkdir(parents=True)
    resolved_parent = parent.resolve()

    with patch('modules.core.factory.os.path.ismount',
               side_effect=lambda p: Path(p) == resolved_parent):
        assert _data_dir_is_on_its_own_mount(data_dir) is True


def test_the_root_filesystem_alone_is_not_persistence(tmp_path):
    """CONTROL: '/' is always a mount point.

    Treating it as the answer would report every container as persistent —
    the same false reassurance in a new form.
    """
    data_dir = tmp_path / 'data'
    data_dir.mkdir()

    with patch('modules.core.factory.os.path.ismount',
               side_effect=lambda p: Path(p) == Path('/')):
        assert _data_dir_is_on_its_own_mount(data_dir) is False


def test_an_unreadable_path_does_not_claim_persistence(tmp_path):
    """A check that cannot answer must not answer optimistically."""
    with patch('modules.core.factory.os.path.ismount', side_effect=OSError):
        assert _data_dir_is_on_its_own_mount(tmp_path) is False
