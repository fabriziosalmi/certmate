"""HTTP layers go through the service, not around it (#672).

`CertificateService` was created to be the one place issuance and configuration
happen. It was half-adopted: create, renew and reissue went through it, while
the config-edit and probe-read handlers called
`certificate_manager._load_metadata` and `_save_metadata` — private methods —
and did the read-modify-write inline.

Two costs, and the second is the one that bit:

* the manager could not change how it stores metadata without breaking route
  handlers that were never supposed to know;
* validation and locking lived in the route, so a second HTTP surface could
  reach the same data with different rules. `test_patch_metadata_takes_domain_lock`
  documents what that already cost once — a PATCH landing inside a renewal
  window was silently reverted, and every later renewal used the decommissioned
  credential.

The read-modify-write, its validation and its lock now live in
`CertificateService.update_config`; reads go through `read_metadata`. These
assert both that nothing reaches around it again, and that the semantics the
route used to own survived the move — particularly absent-versus-null, which is
what stops a DNS-only edit from wiping a certificate's probe configuration.
"""
import re
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from modules.core.certificates import MetadataWriteFailed
from modules.core.cert_service import CertificateService

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent


def _service(stored=None, sink=None):
    manager = CertificateManager.__new__(CertificateManager)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    manager._domain_lock_timeout = lambda: 0.2
    manager._load_metadata = lambda domain: dict(stored or {})
    manager.write_metadata = (
        lambda domain, metadata: (sink.update(metadata) if sink is not None else None) or True)
    return CertificateService(manager, MagicMock(), MagicMock())


# ---------------------------------------------------------------------------
# Nothing reaches around the service
# ---------------------------------------------------------------------------

def test_no_http_layer_calls_the_managers_private_metadata_methods():
    offenders = []
    for path in sorted(list(ROOT.glob('modules/api/**/*.py'))
                       + list(ROOT.glob('modules/web/**/*.py'))):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r'\._(load|save)_metadata\s*\(', line):
                offenders.append(f'{path.relative_to(ROOT)}:{lineno}')

    assert not offenders, (
        'these reach past CertificateService into the manager\'s private '
        'methods, so the manager cannot change how it stores metadata:\n  '
        + '\n  '.join(offenders)
    )


def test_the_service_still_reads_through_the_manager():
    """CONTROL: the fix is a boundary, not a bypass.

    Opening `cert_dir/metadata.json` directly from the service would satisfy
    the scan above while losing what reading through the manager gives —
    the path built from the validated domain, and corrupt JSON quarantined
    rather than silently returning {}.
    """
    import inspect

    src = inspect.getsource(CertificateService.read_metadata)
    assert '_load_metadata' in src, (
        'the service no longer reads through the manager'
    )


# ---------------------------------------------------------------------------
# The semantics the route used to own
# ---------------------------------------------------------------------------

def test_an_absent_key_leaves_existing_probe_config_alone():
    """The one that matters. Keying off `is not None` instead of `in changes`
    would let a DNS-only edit silently wipe a certificate's probe config."""
    sink = {}
    service = _service(stored={'deployment_port': 8443,
                               'deployment_protocol': 'tls',
                               'deployment_host': 'www.example.com'},
                       sink=sink)

    metadata, _old = service.update_config('example.com',
                                           {'dns_provider': 'route53'})

    assert metadata['deployment_port'] == 8443
    assert metadata['deployment_protocol'] == 'tls'
    assert metadata['deployment_host'] == 'www.example.com'


@pytest.mark.parametrize('key,stored', [
    ('deployment_port', 8443),
    ('deployment_protocol', 'tls'),
    ('deployment_host', 'www.example.com'),
])
def test_an_explicit_null_deletes(key, stored):
    service = _service(stored={key: stored})
    metadata, _old = service.update_config('example.com', {key: None})
    assert key not in metadata


@pytest.mark.parametrize('changes,message', [
    ({'deployment_port': 'abc'}, 'must be an integer'),
    ({'deployment_port': 0}, 'must be 1-65535'),
    ({'deployment_port': 70000}, 'must be 1-65535'),
    ({'deployment_protocol': 'gopher'}, 'must be one of'),
    ({'deployment_host': 12}, 'must be a string'),
    ({'deployment_host': '*.example.com'}, 'bare hostname'),
    ({'deployment_host': 'https://example.com'}, 'bare hostname'),
    ({'deployment_host': 'a b'}, 'bare hostname'),
    ({'deployment_host': 'a/b'}, 'bare hostname'),
])
def test_invalid_values_are_refused_by_the_service(changes, message):
    """Validation moved with the write, so both HTTP surfaces get the same
    answer instead of whichever one the route implemented."""
    with pytest.raises(ValueError, match=message):
        _service().update_config('example.com', changes)


def test_a_valid_probe_config_is_stored():
    sink = {}
    service = _service(sink=sink)
    metadata, _old = service.update_config('example.com', {
        'deployment_port': '587',
        'deployment_protocol': 'smtp-starttls',
        'deployment_host': '  mail.example.com  ',
    })

    assert metadata['deployment_port'] == 587, 'a numeric string must coerce'
    assert metadata['deployment_protocol'] == 'smtp-starttls'
    assert metadata['deployment_host'] == 'mail.example.com', 'not trimmed'
    assert sink['deployment_host'] == 'mail.example.com', 'not persisted'


def test_a_failed_save_is_an_error_not_a_silent_success():
    manager = CertificateManager.__new__(CertificateManager)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    manager._domain_lock_timeout = lambda: 0.2
    manager._load_metadata = lambda domain: {}
    # Raises rather than returning False: a boolean could not say WHY, and a
    # write refused for a schema downgrade and one refused by a read-only
    # volume produced the same unactionable message (#757). The match below
    # now checks the reason survives to the caller, which is the point.
    def _explode(domain, metadata):
        raise MetadataWriteFailed(
            'could not write /x/metadata.json: Permission denied')
    manager.write_metadata = _explode

    service = CertificateService(manager, MagicMock(), MagicMock())
    with pytest.raises(RuntimeError, match='Permission denied'):
        service.update_config('example.com', {'dns_provider': 'route53'})
