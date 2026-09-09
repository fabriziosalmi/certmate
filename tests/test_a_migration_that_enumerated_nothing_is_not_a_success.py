"""A migration that could not read the source is not a migration of zero certificates.

`migrate_certificates` wrapped its whole body in `except Exception: log`, and
then returned the per-domain results it had accumulated. Everything inside that
body which can fail per certificate already records False for that certificate,
so the only thing that reaches the outer handler is the enumeration of the
source — an expired Vault token, a role without ListBucket, an endpoint that is
unreachable. It returned `{}`.

The route then computed `successful = 0`, `total = 0`, and answered:

    HTTP 200  {"success": true, "message": "Migration completed: 0/0 certificates migrated"}

with an audit record stamped `status='success'`. An operator moving off a
backend before decommissioning it was told the move had worked.

"Enumerated nothing" and "could not enumerate" are different answers and cannot
share a return value. The route already had the other arm — a 500, a failure
message and a failure audit record — and now reaches it.

The control matters as much as the fix: a source that genuinely holds no
certificates must still succeed, or this trades a false success for a false
failure.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.storage_backends import StorageManager

pytestmark = [pytest.mark.unit]


class _Source:
    """A source backend whose enumeration behaviour the test decides."""

    def __init__(self, domains=None, error=None):
        self._domains = domains or []
        self._error = error

    def list_certificates(self):
        if self._error:
            raise self._error
        return list(self._domains)

    def retrieve_certificate(self, domain):
        return ({'cert.pem': b'x'}, {'domain': domain})

    def get_backend_name(self):
        return 'source'


class _Target:
    def __init__(self, refuse=()):
        self.stored = []
        self._refuse = set(refuse)

    def store_certificate(self, domain, cert_files, metadata):
        if domain in self._refuse:
            return False
        self.stored.append(domain)
        return True

    def get_backend_name(self):
        return 'target'


@pytest.fixture
def manager():
    return StorageManager.__new__(StorageManager)


# --- THE regression ------------------------------------------------------

def test_an_unreadable_source_raises_rather_than_returning_nothing(manager):
    source = _Source(error=RuntimeError('permission denied: vault token expired'))

    with pytest.raises(RuntimeError, match='vault token expired'):
        manager.migrate_certificates(source, _Target())


# --- the controls, which are the point -----------------------------------

def test_a_source_with_no_certificates_still_succeeds(manager):
    """CONTROL. An empty source is a legitimate 0/0 and must stay one — a fix
    that turned this into a failure would be the same defect facing the other
    way."""
    results = manager.migrate_certificates(_Source(domains=[]), _Target())

    assert results == {}


def test_a_certificate_that_will_not_store_is_still_per_certificate(manager):
    """CONTROL. Per-item failure is reported per item and does not abort the
    run: the other certificates still move."""
    target = _Target(refuse={'b.example.com'})

    results = manager.migrate_certificates(
        _Source(domains=['a.example.com', 'b.example.com', 'c.example.com']),
        target)

    assert results == {'a.example.com': True, 'b.example.com': False,
                       'c.example.com': True}
    assert target.stored == ['a.example.com', 'c.example.com']


def test_a_certificate_that_cannot_be_read_does_not_stop_the_others(manager):
    """CONTROL. A failure retrieving ONE certificate is per-certificate too —
    only the enumeration is fatal, because only the enumeration means the
    result set itself is unknown."""
    source = _Source(domains=['ok.example.com', 'broken.example.com'])
    original = source.retrieve_certificate

    def retrieve(domain):
        if domain == 'broken.example.com':
            raise RuntimeError('unreadable')
        return original(domain)

    source.retrieve_certificate = retrieve

    results = manager.migrate_certificates(source, _Target())

    assert results == {'ok.example.com': True, 'broken.example.com': False}


# --- the connection to the route ------------------------------------------
#
# The route's failure arm is already exercised in tests/test_audit_hardening.py
# (`test_storage_migrate_failure`): a manager whose migrate_certificates raises
# produces HTTP 500, `success: false`, and an audit record stamped failure.
# What was missing was any way for the manager to GET there on the condition
# that matters, so the two tests below pin the type and the boundary rather
# than rebuilding the route harness here.

def test_the_exception_type_survives_for_the_operator(manager):
    """The route reports `type(e).__name__` to the operator, so the type has to
    mean something — a bare Exception would tell them nothing."""
    with pytest.raises(Exception) as caught:
        manager.migrate_certificates(
            _Source(error=RuntimeError('boom')), _Target())

    assert type(caught.value) is RuntimeError


def test_a_partial_migration_is_still_returned_not_raised(manager):
    """The boundary between the two behaviours, stated as a test: per-item
    failures return, enumeration failures raise."""
    results = manager.migrate_certificates(
        _Source(domains=['x.example.com']), _Target(refuse={'x.example.com'}))

    assert results == {'x.example.com': False}


def test_the_manager_used_here_is_the_real_one():
    """CONTROL for the whole file: MagicMock would let every assertion above
    pass without the code under test existing."""
    assert not isinstance(StorageManager.migrate_certificates, MagicMock)
    assert StorageManager.migrate_certificates.__doc__
