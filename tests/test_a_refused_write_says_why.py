"""A metadata write that does not happen has to say why it did not happen.

Reported as #757: configuring a deployment probe failed with

    Failed: Failed to update metadata for domain: *.xx.xx

and nothing else. The reporter, reasonably, concluded from the message that
wildcards were the problem, and looked at the domain field — which is a text
input with a `<datalist>`, not the dropdown its neighbour is — and concluded
that too. Neither was the cause.

`_save_metadata` returned a bare `False`. Two unrelated situations produced it:

- the file could not be written (a read-only volume, or a certificates
  directory owned by a different uid — the reporter runs on Kubernetes);
- the write was **refused by design**, because `metadata.json` on disk
  declares a newer schema than this build understands and overwriting it
  would drop the fields it cannot read, including which private key belongs
  to the certificate.

Both reasons were computed, written to the server log, and then thrown away
before reaching the person who had to act on one of them. Reproduced against
the running application, both returned the identical body and status:

    {"error": "Failed to update metadata for domain: X"}   HTTP 500

`write_metadata` raises instead, carrying the reason. `_save_metadata` stays
as the boolean wrapper for the six call sites that write metadata during
issuance and renewal and cannot act on a reason — a cosmetic metadata problem
must not become a failed issuance, which is why the split exists at all
rather than the whole thing being changed to raise.
"""
import json
import logging
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import (
    CertificateManager, MetadataWriteFailed, MetadataWriteRefused,
)
from modules.core.constants import METADATA_SCHEMA_VERSION
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

LOGGER = 'modules.core.certificates'


@pytest.fixture
def manager(tmp_path):
    cert_dir = tmp_path / 'certificates'
    data_dir = tmp_path / 'data'
    for directory in (cert_dir, data_dir, tmp_path / 'backups', tmp_path / 'logs'):
        directory.mkdir()
    file_ops = FileOperations(cert_dir=cert_dir, data_dir=data_dir,
                              backup_dir=tmp_path / 'backups',
                              logs_dir=tmp_path / 'logs')
    settings = SettingsManager(file_ops=file_ops,
                               settings_file=data_dir / 'settings.json')
    mgr = CertificateManager(cert_dir=cert_dir, settings_manager=settings,
                             dns_manager=MagicMock(),
                             shell_executor=MagicMock())
    (cert_dir / 'example.com').mkdir()
    return mgr


def _write_schema(manager, domain, version):
    path = manager.cert_dir / domain / 'metadata.json'
    path.write_text(json.dumps({'domain': domain,
                                'metadata_schema_version': version}))


# --- the ordinary case is untouched --------------------------------------

def test_a_normal_write_succeeds_and_stamps_the_schema(manager):
    manager.write_metadata('example.com', {'domain': 'example.com'})

    stored = json.loads(
        (manager.cert_dir / 'example.com' / 'metadata.json').read_text())
    assert stored['metadata_schema_version'] == METADATA_SCHEMA_VERSION
    assert stored['domain'] == 'example.com'


def test_the_caller_is_not_handed_the_dict_it_passed(manager):
    """CONTROL: the stamp is added to a copy. Mutating the caller's dict would
    put a schema version into whatever it does with it next."""
    original = {'domain': 'example.com'}

    manager.write_metadata('example.com', original)

    assert 'metadata_schema_version' not in original


# --- a write that cannot happen ------------------------------------------

def test_an_unwritable_directory_raises_with_the_path_and_the_reason(manager):
    directory = manager.cert_dir / 'example.com'
    directory.chmod(0o555)
    try:
        with pytest.raises(MetadataWriteFailed) as caught:
            manager.write_metadata('example.com', {'domain': 'example.com'})
    finally:
        directory.chmod(0o755)

    message = str(caught.value)
    assert 'metadata.json' in message, 'the message does not name the file'
    assert 'Permission denied' in message, 'the message does not say what failed'
    assert 'uid 1000' in message, (
        'the message does not point at the ownership of the mounted volume, '
        'which is the fix in a container deployment')


def test_a_record_from_a_newer_build_is_refused_with_both_versions(manager):
    _write_schema(manager, 'example.com', METADATA_SCHEMA_VERSION + 5)

    with pytest.raises(MetadataWriteRefused) as caught:
        manager.write_metadata('example.com', {'domain': 'example.com'})

    message = str(caught.value)
    assert str(METADATA_SCHEMA_VERSION + 5) in message
    assert str(METADATA_SCHEMA_VERSION) in message
    assert 'CERTMATE_ALLOW_SCHEMA_DOWNGRADE' in message, (
        'the refusal does not name its own override, so the operator has no '
        'way out of it')


def test_the_refusal_leaves_the_file_alone(manager):
    """The whole reason for refusing. A partial write would be worse than the
    error."""
    _write_schema(manager, 'example.com', METADATA_SCHEMA_VERSION + 5)
    before = (manager.cert_dir / 'example.com' / 'metadata.json').read_bytes()

    with pytest.raises(MetadataWriteRefused):
        manager.write_metadata('example.com', {'domain': 'other'})

    assert (manager.cert_dir / 'example.com' / 'metadata.json').read_bytes() == before


def test_the_override_lets_it_through(manager, monkeypatch):
    _write_schema(manager, 'example.com', METADATA_SCHEMA_VERSION + 5)
    monkeypatch.setenv('CERTMATE_ALLOW_SCHEMA_DOWNGRADE', '1')

    manager.write_metadata('example.com', {'domain': 'example.com'})

    stored = json.loads(
        (manager.cert_dir / 'example.com' / 'metadata.json').read_text())
    assert stored['metadata_schema_version'] == METADATA_SCHEMA_VERSION


@pytest.mark.parametrize('value', ['0', 'true', 'yes', ''])
def test_only_exactly_one_disables_the_refusal(manager, monkeypatch, value):
    """CONTROL: a guard that any truthy-looking value switches off is a guard
    that gets switched off by accident."""
    _write_schema(manager, 'example.com', METADATA_SCHEMA_VERSION + 5)
    monkeypatch.setenv('CERTMATE_ALLOW_SCHEMA_DOWNGRADE', value)

    with pytest.raises(MetadataWriteRefused):
        manager.write_metadata('example.com', {'domain': 'example.com'})


def test_an_older_record_is_written_without_complaint(manager):
    """CONTROL: only a record from the FUTURE is refused. Upgrading is the
    normal direction and must not be blocked."""
    _write_schema(manager, 'example.com', max(METADATA_SCHEMA_VERSION - 1, 0))

    manager.write_metadata('example.com', {'domain': 'example.com'})

    stored = json.loads(
        (manager.cert_dir / 'example.com' / 'metadata.json').read_text())
    assert stored['metadata_schema_version'] == METADATA_SCHEMA_VERSION


# --- the six callers that cannot act on a reason keep their boolean ------

def test_save_metadata_still_returns_true_on_success(manager):
    assert manager._save_metadata('example.com', {'domain': 'example.com'}) is True


@pytest.mark.parametrize('setup', ['unwritable', 'newer-schema'])
def test_save_metadata_still_returns_false_rather_than_raising(manager, setup):
    """THE compatibility property. Six call sites write metadata during
    issuance and renewal and ignore the result; if this started raising, a
    metadata problem would abort an issuance that had already obtained a
    certificate."""
    directory = manager.cert_dir / 'example.com'
    if setup == 'unwritable':
        directory.chmod(0o555)
    else:
        _write_schema(manager, 'example.com', METADATA_SCHEMA_VERSION + 5)
    try:
        assert manager._save_metadata(
            'example.com', {'domain': 'example.com'}) is False
    finally:
        directory.chmod(0o755)


def test_the_refusal_is_logged_at_error_with_the_domain_as_an_argument(
        manager, caplog):
    """It was logged at ERROR before the reason became an exception, and a
    data-custody refusal deserves that level. The domain stays a log ARGUMENT
    rather than being interpolated, so a handler can filter on it."""
    _write_schema(manager, 'example.com', METADATA_SCHEMA_VERSION + 5)

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        manager._save_metadata('example.com', {'domain': 'example.com'})

    refusals = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert refusals, 'the refusal was not logged at ERROR'
    assert 'example.com' in (refusals[0].args or ()), (
        'the domain is interpolated into the message rather than passed as an '
        'argument, so a log handler cannot filter on it')


def test_a_write_failure_is_logged_at_warning_not_error(manager, caplog):
    """CONTROL for the level above: an I/O failure is not the same kind of
    event as a refusal, and giving both ERROR would make the level say
    nothing."""
    directory = manager.cert_dir / 'example.com'
    directory.chmod(0o555)
    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            manager._save_metadata('example.com', {'domain': 'example.com'})
    finally:
        directory.chmod(0o755)

    assert caplog.records
    assert all(r.levelno == logging.WARNING for r in caplog.records)


# --- what the API layer relies on ----------------------------------------

def test_both_are_runtime_errors(manager):
    """The route already had an arm for RuntimeError returning 500. Both
    subclass it, so the change could not leave a path unhandled — the API
    layer narrows the refusal to 409 on top of that, it does not depend on
    doing so."""
    assert issubclass(MetadataWriteRefused, RuntimeError)
    assert issubclass(MetadataWriteFailed, RuntimeError)


def test_the_two_are_distinguishable(manager):
    """CONTROL: if one subclassed the other, the 409 arm would swallow the
    500 case or the reverse, depending on the order of the except clauses."""
    assert not issubclass(MetadataWriteRefused, MetadataWriteFailed)
    assert not issubclass(MetadataWriteFailed, MetadataWriteRefused)


def test_the_route_orders_the_refusal_before_the_generic_arm():
    """`except RuntimeError` first would make the 409 unreachable, and the
    tests above would still pass — this is the one that would not."""
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
              / 'api' / 'resources_certificates.py').read_text()
    refusal = source.index('except MetadataWriteRefused')
    generic = source.index('except RuntimeError as e:\n                    return')
    assert refusal < generic, (
        'the generic RuntimeError arm comes first, so a refused write is '
        'reported as a 500 again')
