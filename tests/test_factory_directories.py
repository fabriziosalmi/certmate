from pathlib import Path

import pytest

from modules.core.factory import AppContainer, setup_directories


pytestmark = [pytest.mark.unit]


def test_setup_directories_keeps_project_data_dir(tmp_path, monkeypatch):
    project_root = tmp_path / "certmate"
    module_dir = project_root / "modules" / "core"
    module_dir.mkdir(parents=True)
    fake_factory_file = module_dir / "factory.py"
    fake_factory_file.write_text("# test path anchor\n")

    monkeypatch.setattr("modules.core.factory.__file__", str(fake_factory_file))

    container = AppContainer()
    setup_directories(container)

    assert container.cert_dir == (project_root / "certificates").resolve()
    assert container.data_dir == (project_root / "data").resolve()
    assert container.backup_dir == (project_root / "backups").resolve()
    assert container.logs_dir == (project_root / "logs").resolve()
    assert container.data_dir.exists()
    assert not Path(str(container.data_dir)).name.startswith("certmate_data_")


def test_a_nested_directory_that_does_not_exist_yet_is_created(tmp_path):
    """CERTMATE_*_DIR exists so a volume can hold certificates in one tree
    and backups in another. The nested path is the ordinary first-boot case
    for a fresh volume, and mkdir() without parents turned it into ENOENT
    on the leaf — the same errno the write probe then reported as a host-mount
    permission error."""
    from modules.core import factory

    nested = tmp_path / 'state' / 'data'
    container = factory.AppContainer()
    factory.setup_directories(container, {
        'CERTMATE_DATA_DIR': str(nested),
        'CERTMATE_CERT_DIR': str(tmp_path / 'certs'),
        'CERTMATE_BACKUP_DIR': str(tmp_path / 'backups'),
        'CERTMATE_LOGS_DIR': str(tmp_path / 'logs'),
    })

    assert nested.is_dir()
    assert (tmp_path / 'backups' / 'unified').is_dir()


def test_enoent_during_the_write_probe_is_not_a_chmod_problem(tmp_path, monkeypatch):
    """exists() and is_dir() succeeding, then create failing with ENOENT, is
    a broken or SELinux-blocked mount. The old probe stringed the raw OSError
    and the boot error told the operator to chmod g+rwX, which cannot help."""
    import errno

    from modules.core import factory

    target = tmp_path / 'certs'
    target.mkdir()

    def boom(self, *args, **kwargs):
        raise FileNotFoundError(
            errno.ENOENT, 'No such file or directory', str(self))

    monkeypatch.setattr(Path, 'write_text', boom)

    reason = factory._verify_dir_writable(target)

    assert reason is not None
    assert 'chmod problem' in reason
    assert ':z' in reason
    assert 'not writable by the container user' not in reason
