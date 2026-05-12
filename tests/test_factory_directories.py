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
