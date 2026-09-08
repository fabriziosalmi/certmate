"""Two files hold a domain's DNS provider, and they must never disagree.

`metadata.json` is what issuance reads. The domain's entry in `settings.json`
is what `get_domain_dns_provider` reads. Both are authoritative, and they were
updated by **two separate writes with the domain lock released between them**:
`CertificateService.update_config` wrote the metadata under the lock and
returned, and the route wrote the settings entry afterwards.

Nothing reconciled them. A renewal starting in that window read the **old**
provider from settings while the metadata already said the new one — and
neither file was wrong on its own, which is what makes it hard to see.

Both writes now happen inside the same `domain_lock` section, so the pair is
atomic with respect to a renewal.

**Lock ordering was checked before doing this**, because taking the settings
lock while holding the domain lock creates one. No settings mutate callback
anywhere in the codebase acquires a domain lock, so the reverse order does not
exist and this cannot deadlock. Anything that adds one would have to take the
domain lock first — which is why it is stated in the code and here.
"""
import threading
from unittest.mock import MagicMock

import pytest

from modules.core.cert_service import CertificateService

pytestmark = [pytest.mark.unit]


class _Certs:
    """A certificate manager with a real per-domain lock and metadata in
    memory, so the ordering of the two writes is observable."""

    def __init__(self, metadata=None):
        self.cert_dir = None
        self._metadata = metadata or {}
        self._lock = threading.RLock()
        self.depth = 0

    def domain_lock(self, domain):
        from contextlib import contextmanager

        @contextmanager
        def _held():
            self._lock.acquire()
            self.depth += 1
            try:
                yield
            finally:
                self.depth -= 1
                self._lock.release()

        return _held()

    def _save_metadata(self, domain, metadata):
        self._metadata = dict(metadata)
        return True


@pytest.fixture
def parts():
    certs = _Certs({'domain': 'example.com', 'dns_provider': 'cloudflare'})
    stored = {'domains': [{'domain': 'example.com',
                           'dns_provider': 'cloudflare',
                           'dns_account_id': 'old'}]}
    order = []

    settings = MagicMock()

    def _update(mutate, reason):
        # Record whether the DOMAIN lock is held at the moment of the settings
        # write. That is the property under test, and it is only observable
        # from inside the callback.
        order.append(('settings-write', reason, certs.depth))
        mutate(stored)

    settings.update.side_effect = _update
    service = CertificateService(certs, settings, MagicMock(), MagicMock())
    service.read_metadata = lambda domain: dict(certs._metadata)
    return service, certs, stored, order


# --- both writes happen, and both happen under the lock -----------------

def test_both_stores_are_updated(parts):
    service, certs, stored, _ = parts

    service.update_config('example.com', {'dns_provider': 'route53'})

    assert certs._metadata['dns_provider'] == 'route53'
    assert stored['domains'][0]['dns_provider'] == 'route53', (
        'the settings entry still names the old provider, so a renewal would '
        'use it'
    )


def test_the_settings_write_happens_while_the_domain_lock_is_held(parts):
    """The whole point, and the only assertion that actually pins it.

    An earlier version of this test checked that the write happened and that
    the lock was acquired and released — which is equally true of the broken
    ordering it replaces. What matters is the domain lock being held AT THE
    MOMENT of the settings write, because a renewal starting in a gap between
    the two would read a provider the metadata had already replaced.
    """
    service, certs, _, order = parts

    service.update_config('example.com', {'dns_provider': 'route53'})

    assert order, 'the settings entry was never written'
    _, _, depth_at_write = order[0]
    assert depth_at_write == 1, (
        'the settings entry was written with the domain lock NOT held, so a '
        'renewal can interleave between the two writes'
    )
    assert certs.depth == 0, 'the domain lock was not released afterwards'


def test_the_settings_write_carries_a_reason(parts):
    service, _, _, order = parts
    service.update_config('example.com', {'dns_provider': 'route53'})
    assert order[0][1] == 'dns_provider_change'


def test_the_account_id_is_mirrored_too(parts):
    service, certs, stored, _ = parts
    service.update_config('example.com',
                          {'dns_provider': 'route53', 'account_id': 'prod'})
    assert certs._metadata['account_id'] == 'prod'
    assert stored['domains'][0]['dns_account_id'] == 'prod'


# --- what must not be touched -------------------------------------------

def test_a_probe_only_edit_leaves_the_provider_alone(parts):
    """CONTROL: absent means "leave alone", the same rule the metadata write
    follows. Mirroring an absent key as empty would wipe the provider on a
    port change."""
    service, certs, stored, _ = parts

    service.update_config('example.com', {'deployment_port': 8443})

    assert certs._metadata['deployment_port'] == 8443
    assert stored['domains'][0]['dns_provider'] == 'cloudflare'
    assert stored['domains'][0]['dns_account_id'] == 'old'


def test_a_domain_with_no_settings_entry_is_not_invented(parts):
    """A certificate can exist without a settings entry — an adopted one, for
    instance. Creating a half-populated entry here would make it look managed
    when it is not."""
    service, _, stored, _ = parts
    stored['domains'] = []

    service.update_config('example.com', {'dns_provider': 'route53'})

    assert stored['domains'] == []


def test_a_malformed_domains_list_does_not_crash_the_edit(parts):
    """settings.json is hand-editable. A string entry among the dicts must
    not turn a config change into a 500."""
    service, _, stored, _ = parts
    stored['domains'] = ['example.com', {'domain': 'example.com'}]

    service.update_config('example.com', {'dns_provider': 'route53'})

    assert stored['domains'][1]['dns_provider'] == 'route53'


def test_a_failed_metadata_write_does_not_touch_settings(parts):
    """CONTROL: the two must not half-apply in the other direction either.
    Settings naming a provider whose metadata says otherwise is the same
    defect, mirrored."""
    service, certs, stored, order = parts
    certs._save_metadata = lambda domain, metadata: False

    with pytest.raises(RuntimeError):
        service.update_config('example.com', {'dns_provider': 'route53'})

    assert stored['domains'][0]['dns_provider'] == 'cloudflare'
    assert not order, 'settings were written after the metadata write failed'


# --- the route no longer does half the job ------------------------------

def test_the_route_no_longer_writes_settings_itself():
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
              / 'api' / 'resources_certificates.py').read_text()
    assert 'dns_provider_change' not in source, (
        'the route writes the settings entry again, outside the domain lock '
        'that update_config holds'
    )


def test_no_settings_mutate_callback_takes_a_domain_lock():
    """The precondition for holding the settings lock inside the domain lock.
    If one ever did, the two orders would exist and could deadlock — so the
    check that made this safe is kept rather than remembered."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / 'modules'
    offenders = []
    for path in root.rglob('*.py'):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.Lambda)):
                continue
            name = getattr(node, 'name', '<lambda>')
            body = ast.unparse(node)
            if ('domain_lock' in body
                    and name in ('_mutate', '_update_domain_provider',
                                 '_apply', '_write_domain_provider')):
                offenders.append(f'{path.name}:{node.lineno} {name}')

    assert not offenders, (
        'a settings mutate callback acquires a domain lock, so the two lock '
        'orders now both exist: ' + ', '.join(offenders))
