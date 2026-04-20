"""
Cross-validation tests that pin the contract between independent wiring
points for DNS providers.

Adding a new provider means touching at least: dns_strategies factory,
utils._DNS_PROVIDER_CREDENTIALS, settings.save_settings supported set,
settings propagation defaults, settings multi-account migration map.

It is easy to miss one — issue #99 is exactly this: edgedns shipped
with a working strategy and UI but no entry in the supported_providers
set, so save_settings() rejected the configuration with
"Invalid dns_provider: edgedns".

These tests assert the wiring sets stay in sync. When you add a new
provider, the test breaks until every wiring point is updated.
"""
import inspect

import pytest

from modules.core.dns_strategies import DNSStrategyFactory
from modules.core.utils import _DNS_PROVIDER_CREDENTIALS, _MULTI_PROVIDER_PLUGIN_FILES
from modules.core.settings import SettingsManager


# Strategies registered in the factory but intentionally NOT a real DNS
# provider (e.g. HTTP-01 webroot). They must not appear in the DNS
# provider validation surfaces.
_NON_DNS_STRATEGIES = {'http-01'}


def _factory_dns_providers():
    """All providers DNSStrategyFactory.get_strategy() can dispatch.

    This is the union of explicit strategy classes and the generic
    multi-provider plugin map (vultr, hetzner, porkbun, ...) which
    falls through to GenericMultiProviderStrategy."""
    explicit = set(DNSStrategyFactory._strategies.keys())
    generic = set(_MULTI_PROVIDER_PLUGIN_FILES.keys())
    return (explicit | generic) - _NON_DNS_STRATEGIES


def _supported_providers_set():
    """Extract the supported_providers literal from save_settings source."""
    src = inspect.getsource(SettingsManager.save_settings)
    # The literal is a single set on one line; pull it out by exec.
    namespace: dict = {}
    for line in src.splitlines():
        if 'supported_providers' in line and '=' in line and '{' in line:
            exec(line.strip(), namespace)
            return namespace['supported_providers']
    raise AssertionError('Could not locate supported_providers literal')


def test_every_factory_provider_is_supported_in_save_settings():
    """save_settings must accept every provider the factory can dispatch.
    Pinned by issue #99: edgedns shipped registered but unsupported."""
    factory = _factory_dns_providers()
    supported = _supported_providers_set()
    missing = factory - supported
    assert not missing, (
        f"Providers registered in DNSStrategyFactory but missing from "
        f"settings.save_settings supported_providers set: {sorted(missing)}. "
        f"Add them to the set in modules/core/settings.py or save will "
        f"reject configurations with 'Invalid dns_provider: <name>'."
    )


def test_every_factory_provider_has_credential_schema():
    """utils._DNS_PROVIDER_CREDENTIALS must declare required fields for
    every provider the factory can dispatch — otherwise validation
    silently passes garbage configurations."""
    factory = _factory_dns_providers()
    declared = set(_DNS_PROVIDER_CREDENTIALS.keys())
    missing = factory - declared
    assert not missing, (
        f"Providers registered in DNSStrategyFactory but missing from "
        f"_DNS_PROVIDER_CREDENTIALS in modules/core/utils.py: {sorted(missing)}"
    )


def test_no_supported_providers_orphaned_from_factory():
    """Reverse direction: every entry in supported_providers must
    correspond to a real factory strategy (catches typos / dead entries)."""
    factory = _factory_dns_providers()
    supported = _supported_providers_set()
    orphans = supported - factory
    assert not orphans, (
        f"supported_providers contains entries with no strategy in "
        f"DNSStrategyFactory: {sorted(orphans)}"
    )


