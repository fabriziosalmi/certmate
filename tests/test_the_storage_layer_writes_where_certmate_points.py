"""`CERTMATE_CERT_DIR` moves the storage layer too, not just half the app.

Item 3 of #876. The container passes its certificate directory to
`CertificateManager`, and `StorageManager` built the local backend from
`certificate_storage.cert_dir`, defaulting to the literal `'certificates'` —
a **relative** path, resolved against wherever the process was started.

That is not "the variable is ignored". It is a split: `get_certificate_info`
reads through the storage manager first and `_store_in_backend` writes to it,
so an instance pointed at a mounted volume kept a second tree under its working
directory, while the README described the half that moved. Measured before the
fix, with the variable set:

    CertificateManager -> /tmp/.../my-certs
    storage backend    -> certificates

Two things had to be true for the fix to work, and only the first was obvious:

1. `StorageManager` has to be told where CertMate keeps certificates.
2. The stored value cannot simply be honoured. The shipped defaults **persist**
   `cert_dir: 'certificates'` into every settings.json, so "the operator did
   not choose" is indistinguishable from "the operator chose this" by presence
   alone — the first attempt at this fix was inert for exactly that reason, on
   a default instance, which is the only kind that matters.

Hence the literal default is read as "follow CertMate", and anything else as a
directory somebody typed. That also avoids writing a machine-specific absolute
path into a settings file that gets backed up and restored somewhere else.

The three fallbacks matter as much as the configured path: landing on a
different tree when a cloud backend fails is how an instance loses sight of
certificates it already has, at the moment it is least able to cope.
"""
import pathlib

import pytest

from modules.core.storage_backends import LocalFileSystemBackend, StorageManager

pytestmark = [pytest.mark.unit]


class _Settings:
    """Just enough settings manager: the storage config, and a switch to make
    reading it fail, which is one of the fallback paths under test."""

    def __init__(self, storage_config=None, explode=False):
        self._storage = storage_config if storage_config is not None else {}
        self._explode = explode

    def load_settings(self):
        if self._explode:
            raise OSError('settings unreadable')
        return {'certificate_storage': self._storage}


def _backend_dir(manager):
    backend = manager.get_backend()
    assert isinstance(backend, LocalFileSystemBackend), type(backend)
    return pathlib.Path(backend.cert_dir)


DEFAULT = {'backend': 'local_filesystem', 'cert_dir': 'certificates'}


def test_the_shipped_default_is_still_what_this_compares_against():
    """Guard the guard. The rule below turns on the literal `'certificates'`
    being what an unconfigured instance carries. If the defaults ever ship a
    different string, the comparison silently stops matching and every
    instance goes back to the relative path."""
    settings_source = (pathlib.Path(__file__).resolve().parent.parent /
                       'modules' / 'core' / 'settings.py').read_text(encoding='utf-8')
    shipped = f"'cert_dir': '{StorageManager.DEFAULT_LOCAL_CERT_DIRNAME}'"
    assert shipped in settings_source, (
        f'the defaults no longer ship {shipped}, so reading that literal as '
        f'"follow CertMate" matches nothing and CERTMATE_CERT_DIR stops '
        f'moving the storage layer again'
    )


def test_an_unconfigured_instance_follows_certmate(tmp_path):
    """The case #876 is about: the value is present, and it is the default."""
    manager = StorageManager(_Settings(dict(DEFAULT)), default_cert_dir=tmp_path)
    assert _backend_dir(manager) == tmp_path


def test_a_missing_value_follows_certmate_too(tmp_path):
    """An instance whose settings predate the key at all."""
    manager = StorageManager(_Settings({'backend': 'local_filesystem'}),
                             default_cert_dir=tmp_path)
    assert _backend_dir(manager) == tmp_path


def test_a_directory_the_operator_typed_still_wins(tmp_path):
    """The rule reads a default as "follow CertMate" — it must not read a
    real choice that way, or configuring storage would stop working."""
    chosen = tmp_path / 'somewhere-else'
    manager = StorageManager(
        _Settings({'backend': 'local_filesystem', 'cert_dir': str(chosen)}),
        default_cert_dir=tmp_path)
    assert _backend_dir(manager) == chosen


def test_whitespace_is_not_a_choice(tmp_path):
    """`cert_dir: '  '` is somebody clearing the field, not naming the root."""
    manager = StorageManager(
        _Settings({'backend': 'local_filesystem', 'cert_dir': '   '}),
        default_cert_dir=tmp_path)
    assert _backend_dir(manager) == tmp_path


def test_without_a_default_the_old_relative_path_remains(tmp_path):
    """Nothing outside the factory passes one, and a caller that does not
    should get exactly what it got before rather than a surprise."""
    manager = StorageManager(_Settings(dict(DEFAULT)))
    assert _backend_dir(manager) == pathlib.Path('certificates')


# ── the fallbacks land in the same place ─────────────────────────────

def test_an_unknown_backend_falls_back_to_the_same_tree(tmp_path):
    manager = StorageManager(_Settings({'backend': 'nonsense-backend'}),
                             default_cert_dir=tmp_path)
    assert _backend_dir(manager) == tmp_path


def test_unreadable_settings_fall_back_to_the_same_tree(tmp_path):
    manager = StorageManager(_Settings(explode=True), default_cert_dir=tmp_path)
    assert _backend_dir(manager) == tmp_path


def test_a_broken_backend_falls_back_to_the_same_tree(tmp_path):
    """A cloud backend that cannot initialise. The instance keeps working on
    local disk — and it has to be the *right* local disk, or the fallback
    hides every certificate the instance already had."""
    manager = StorageManager(
        _Settings({'backend': 'azure_keyvault', 'azure_keyvault': {}}),
        default_cert_dir=tmp_path)
    assert _backend_dir(manager) == tmp_path


def test_no_relative_path_is_left_hardcoded_in_the_backend_selection():
    """Three sites carried `Path('certificates')`, and a survey that found
    two of them is how the first attempt at this shipped half-done. Exactly
    one stays: the constructor's own default, for callers that pass none."""
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules' /
              'core' / 'storage_backends.py').read_text(encoding='utf-8')
    assert source.count("Path('certificates')") == 1


def test_the_readme_states_the_rule_it_now_follows():
    """The row described the variable as moving where certificates live, and
    half the app disagreed. It now also says what beats it, because the
    interaction is the thing an operator configuring storage will hit."""
    readme = (pathlib.Path(__file__).resolve().parent.parent /
              'README.md').read_text(encoding='utf-8')
    assert 'The local storage backend follows it too' in readme
    assert 'certificate_storage.cert_dir' in readme


# ── the whole app, not just the manager ──────────────────────────────

@pytest.mark.unit
def test_the_app_wires_its_certificate_directory_through(tmp_path, monkeypatch):
    """The unit tests above would all pass with the factory never passing a
    default at all — which is the state this started in."""
    for var, sub in (('CERTMATE_CERT_DIR', 'my-certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)

    from modules.core.factory import create_app
    _, container = create_app()

    storage_dir = pathlib.Path(container.managers['storage'].get_backend().cert_dir)
    assert storage_dir.resolve() == pathlib.Path(container.cert_dir).resolve(), (
        'the storage layer writes somewhere other than where CertMate keeps '
        'certificates; that is the split #876 item 3 describes'
    )
