"""A downgrade must not quietly strip the fields it does not understand.

`settings.json` was versioned for exactly this: an older build reads a file
written by a newer one, understands the fields it knows, writes it back without
the rest, and says nothing. `metadata.json` had no version at all — and it is
the file that records key custody:

* `private_key_state`, including the `external` value that stops a CSR-only
  certificate being reissued nightly (#599);
* the CSR fingerprint;
* the CA a private-CA certificate cannot renew without.

Losing it does not lose a certificate. It loses the instance's knowledge of
what that certificate is, which is worse, because nothing looks broken.

Two decisions worth stating, because both could reasonably have gone the other
way:

**The stamp is applied in `_save_metadata`, not by its seven callers.** #669
shipped the caller-stamps version of this for settings.json and it silently
stripped the field whenever a payload omitted it.

**The refusal is on the write, not at startup.** settings.json is one file and
refusing to boot is proportionate. Metadata is one file per domain: taking the
whole instance down over one certificate would turn a data-loss risk into an
outage. Reading a newer record destroys nothing and the UI should still show
the certificate, so reading warns and writing refuses — which is exactly the
operation that loses fields.
"""
import json
import logging
import tempfile
from pathlib import Path

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import METADATA_SCHEMA_VERSION

pytestmark = [pytest.mark.unit]

RECORD = {
    'domain': 'example.com',
    'private_key_state': 'external',
    'ca': 'private',
    'csr_fingerprint': 'ab' * 32,
}


@pytest.fixture
def manager():
    return CertificateManager(Path(tempfile.mkdtemp()), None, dns_manager=None)


def _domain_dir(manager, domain):
    """Real callers save into a directory certbot already created; a bare
    `_save_metadata` does not make one, and nothing here should pretend it
    does."""
    path = manager.cert_dir / domain
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write(manager, domain, record):
    path = manager.cert_dir / domain / 'metadata.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record))
    return path


def _read(manager, domain):
    return json.loads(
        (manager.cert_dir / domain / 'metadata.json').read_text())


# --- the stamp -----------------------------------------------------------

def test_a_saved_record_carries_the_schema_it_was_written_with(manager):
    _domain_dir(manager, 'example.com')
    assert manager._save_metadata('example.com', dict(RECORD))
    assert _read(manager, 'example.com')['metadata_schema_version'] == \
        METADATA_SCHEMA_VERSION


def test_the_stamp_does_not_depend_on_the_caller_passing_it(manager):
    """The #669 defect, applied to this file: a caller that assembles the dict
    without the field would strip it on every save."""
    _domain_dir(manager, 'example.com')
    assert manager._save_metadata('example.com', dict(RECORD))
    stored = _read(manager, 'example.com')
    assert 'metadata_schema_version' in stored
    assert stored['csr_fingerprint'] == RECORD['csr_fingerprint']


def test_stamping_does_not_mutate_the_caller_s_dict(manager):
    """CONTROL: several callers reuse the dict they passed — one of them
    writes it to a storage backend afterwards."""
    _domain_dir(manager, 'example.com')
    payload = dict(RECORD)
    manager._save_metadata('example.com', payload)
    assert 'metadata_schema_version' not in payload


def test_an_unstamped_record_is_stamped_on_the_next_write(manager):
    """Upgrade path: every existing installation has unstamped metadata."""
    _write(manager, 'example.com', dict(RECORD))
    assert manager._save_metadata('example.com', dict(RECORD, renewed_at='x'))
    assert _read(manager, 'example.com')['metadata_schema_version'] == \
        METADATA_SCHEMA_VERSION


# --- the refusal ---------------------------------------------------------

def test_a_record_from_the_future_is_not_overwritten(manager, caplog):
    """The failure this exists for. An older build must not write back a
    record whose fields it cannot see."""
    future = dict(RECORD, metadata_schema_version=METADATA_SCHEMA_VERSION + 1,
                  a_field_this_build_never_heard_of='keep me')
    _write(manager, 'example.com', future)

    with caplog.at_level(logging.ERROR):
        saved = manager._save_metadata('example.com', dict(RECORD))

    assert saved is False
    assert _read(manager, 'example.com') == future, (
        'the newer record was overwritten and its unknown field is gone'
    )
    assert any('example.com' in (r.args or ()) for r in caplog.records), (
        'the refusal was not logged at ERROR naming the domain'
    )


def test_the_refusal_can_be_overridden_deliberately(manager, monkeypatch):
    """Same variable and same meaning as settings.json's downgrade escape: an
    operator who understands the trade can proceed."""
    _write(manager, 'example.com',
           dict(RECORD, metadata_schema_version=METADATA_SCHEMA_VERSION + 1))
    monkeypatch.setenv('CERTMATE_ALLOW_SCHEMA_DOWNGRADE', '1')

    assert manager._save_metadata('example.com', dict(RECORD, ca='letsencrypt'))
    assert _read(manager, 'example.com')['ca'] == 'letsencrypt'


def test_an_older_record_is_written_normally(manager):
    """CONTROL: the check must only fire on NEWER. An off-by-one that refused
    equal or older versions would make every save fail after the first."""
    _write(manager, 'example.com',
           dict(RECORD, metadata_schema_version=METADATA_SCHEMA_VERSION))
    assert manager._save_metadata('example.com', dict(RECORD, ca='letsencrypt'))
    assert _read(manager, 'example.com')['ca'] == 'letsencrypt'


def test_a_first_write_with_nothing_on_disk_succeeds(manager):
    """CONTROL: no file means no declared schema, not a refusal."""
    _domain_dir(manager, 'brand-new.example.com')
    assert manager._save_metadata('brand-new.example.com', dict(RECORD))


@pytest.mark.parametrize('junk', ['not json at all', '[1, 2, 3]', '"a string"'])
def test_an_unreadable_file_does_not_block_the_write(manager, junk):
    """CONTROL: corruption is handled elsewhere (quarantine on load). The
    schema check must not turn it into a second, silent failure mode that
    stops issuance from recording anything."""
    path = manager.cert_dir / 'example.com' / 'metadata.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(junk)

    assert manager._save_metadata('example.com', dict(RECORD))


@pytest.mark.parametrize('version', ['2', 2.5, None, {'v': 2}])
def test_a_version_that_is_not_an_integer_is_not_a_version(manager, version):
    """A hand-edited or truncated field must not be read as "from the future"
    and lock the domain out of every future write."""
    _write(manager, 'example.com', dict(RECORD, metadata_schema_version=version))
    assert manager._save_metadata('example.com', dict(RECORD))


def test_the_check_reads_the_disk_not_the_dict_it_was_handed(manager):
    """The version that matters belongs to the bytes about to be replaced.
    A caller may have assembled its dict before a certbot run that took
    minutes, so trusting the in-memory copy would check a stale answer."""
    _write(manager, 'example.com',
           dict(RECORD, metadata_schema_version=METADATA_SCHEMA_VERSION + 1))

    # The dict being saved claims the current version. The file does not.
    assert manager._save_metadata(
        'example.com',
        dict(RECORD, metadata_schema_version=METADATA_SCHEMA_VERSION)) is False


# --- reading stays possible ---------------------------------------------

def test_a_record_from_the_future_can_still_be_read(manager, caplog):
    """Refusing to read would blank the certificate in the UI and in every
    API response, over a risk that only exists when writing."""
    future = dict(RECORD, metadata_schema_version=METADATA_SCHEMA_VERSION + 1)
    _write(manager, 'example.com', future)

    with caplog.at_level(logging.WARNING):
        loaded = manager._load_metadata('example.com')

    assert loaded == future
    assert any('refuse to write it back' in r.getMessage()
               for r in caplog.records), (
        'reading a newer record said nothing about what happens next'
    )


def test_reading_an_ordinary_record_is_silent(manager, caplog):
    """CONTROL: a warning on every load is a warning nobody reads."""
    _write(manager, 'example.com',
           dict(RECORD, metadata_schema_version=METADATA_SCHEMA_VERSION))
    with caplog.at_level(logging.WARNING):
        manager._load_metadata('example.com')
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
