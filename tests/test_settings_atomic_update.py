"""
Regression tests for the audit punch-list MUST-FIX items M1 and M3.

M1: every settings.json read-modify-write must run under the SettingsManager
lock. The old pattern (load_settings → mutate → save_settings) raced under
concurrent admin writes — two parallel user creations could lose one user;
two parallel cert creations could drop a domain entry; deploy-hook saves
could clobber DNS provider edits and vice versa. SettingsManager.update
serializes the whole sequence.

M3: the deploy hook command denylist (_DANGEROUS_SHELL) must reject
embedded newlines, since `sh -c` treats them as `;`.
"""

from pathlib import Path
import threading

import pytest

from modules.core.deployer import DeployManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager


pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir, data_dir=data_dir,
        backup_dir=backup_dir, logs_dir=logs_dir,
    )
    return SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")


# --- M1: SettingsManager.update -------------------------------------------


def test_update_runs_mutator_and_persists(settings_manager):
    settings_manager.load_settings()  # initialize
    ok = settings_manager.update(
        lambda s: s.__setitem__('email', 'test@example.com'),
        "test_update",
    )
    assert ok is True
    assert settings_manager.load_settings().get('email') == 'test@example.com'


def test_update_serializes_concurrent_writers(settings_manager):
    """Two threads each appending an item to settings['domains'] must both
    end up persisted. The pre-fix race could lose one of them.
    """
    settings = settings_manager.load_settings()
    settings['domains'] = []
    settings_manager.save_settings(settings, "seed")

    def add(domain):
        def _mutate(s):
            domains = s.get('domains', [])
            # Encourage interleaving — sleep with the lock held would
            # serialize, but the race we're guarding against is in the
            # caller's load/modify/save sequence, not inside the mutator.
            domains.append(domain)
            s['domains'] = domains
        settings_manager.update(_mutate, f"add-{domain}")

    threads = [threading.Thread(target=add, args=(f"d{i}.example.com",))
               for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = settings_manager.load_settings()
    domain_names = sorted(d if isinstance(d, str) else d.get('domain') for d in final['domains'])
    expected = sorted(f"d{i}.example.com" for i in range(20))
    assert domain_names == expected, (
        f"Expected all 20 domains, got {len(domain_names)}: {domain_names}"
    )


def test_update_can_write_users_unlike_atomic_update(settings_manager):
    """atomic_update protects users/api_keys/local_auth_enabled, but
    update() must be able to write them — auth.py relies on it.
    """
    ok = settings_manager.update(
        lambda s: s.__setitem__('users', {'admin': {'role': 'admin'}}),
        "user_management",
    )
    assert ok is True
    assert settings_manager.load_settings().get('users') == {'admin': {'role': 'admin'}}


# --- M3: newline injection in deploy-hook commands ------------------------


def _deploy_manager(settings_manager, tmp_path):
    return DeployManager(
        settings_manager=settings_manager,
        shell_executor=None,
        audit_logger=None,
        event_bus=None,
        cert_dir=tmp_path / "certs",
        data_dir=str(tmp_path / "data"),
    )


def test_save_config_rejects_newline_in_command(settings_manager, tmp_path):
    """sh -c interprets \\n as a statement separator just like ;, so the
    denylist must reject it."""
    dm = _deploy_manager(settings_manager, tmp_path)
    config = {
        'enabled': True,
        'global_hooks': [
            {'id': 'h1', 'name': 'Multiline',
             'command': "echo first\necho second",
             'enabled': True, 'timeout': 30, 'on_events': ['created']},
        ],
        'domain_hooks': {},
    }
    ok, err = dm.save_config(config)
    assert ok is False
    assert err is not None
    assert 'Multiline' in err
    assert 'metacharacter' in err.lower()


def test_save_config_rejects_carriage_return_in_command(settings_manager, tmp_path):
    dm = _deploy_manager(settings_manager, tmp_path)
    config = {
        'enabled': True,
        'global_hooks': [
            {'id': 'h1', 'name': 'CRLF',
             'command': "echo first\r\necho second",
             'enabled': True, 'timeout': 30, 'on_events': ['created']},
        ],
        'domain_hooks': {},
    }
    ok, err = dm.save_config(config)
    assert ok is False
    assert err is not None
    assert 'CRLF' in err


def test_save_config_accepts_normal_single_line_command(settings_manager, tmp_path):
    """Sanity check — the M3 fix must not break legitimate one-liners."""
    dm = _deploy_manager(settings_manager, tmp_path)
    config = {
        'enabled': True,
        'global_hooks': [
            {'id': 'h1', 'name': 'OK',
             'command': "/opt/scripts/deploy.sh --reload",
             'enabled': True, 'timeout': 30, 'on_events': ['created']},
        ],
        'domain_hooks': {},
    }
    ok, err = dm.save_config(config)
    assert ok is True
    assert err is None
