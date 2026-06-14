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


def test_dns_manager_advertised_providers_match_factory():
    """DNSManager.SUPPORTED_PROVIDERS feeds /api/web/certificates/dns-providers.
    Every advertised provider must be issuable (registered in the factory)
    and every issuable provider must be advertised. Pinned by the phantom
    'desec' entry: it was advertised by the endpoint but had no strategy,
    no credential schema and was rejected by save_settings."""
    from modules.core.dns_providers import DNSManager

    factory = _factory_dns_providers()
    advertised = set(DNSManager.SUPPORTED_PROVIDERS)

    phantom = advertised - factory
    assert not phantom, (
        f"DNSManager.SUPPORTED_PROVIDERS advertises providers with no "
        f"strategy in DNSStrategyFactory: {sorted(phantom)}. The UI/API "
        f"would offer a provider whose issuance can only fail."
    )

    hidden = factory - advertised
    assert not hidden, (
        f"Providers issuable via DNSStrategyFactory but missing from "
        f"DNSManager.SUPPORTED_PROVIDERS (invisible to the providers "
        f"endpoint): {sorted(hidden)}"
    )


# ---------------------------------------------------------------------------
# DNS-alias (CNAME-delegation) subsystem. A deliberately smaller subset of
# providers, wired through three more registries that must stay in lockstep:
#   certificates.DNS_ALIAS_SUPPORTED_PROVIDERS  (the gate),
#   certificates.DNS_ALIAS_REQUIRED_FIELDS      (per-provider creds),
#   dns_alias_hook.LEXICON_PROVIDER_MAP         (Lexicon adapter names),
# plus two providers (edgedns, acme-dns) dispatched to native, non-Lexicon
# adapters. These sets are consistent today but were UNGUARDED — the exact
# #99 failure mode (a provider added to one map and forgotten in another) was
# free to recur in the alias subsystem. These ratchets lock the contract.
# ---------------------------------------------------------------------------

# edgedns and acme-dns are alias-capable but handled by dedicated change
# functions (_edgedns_change / _acme_dns_change) rather than a Lexicon adapter,
# so they are intentionally absent from LEXICON_PROVIDER_MAP.
_ALIAS_NATIVE_ADAPTERS = {'edgedns', 'acme-dns'}


def test_dns_alias_supported_set_matches_required_fields():
    """DNS_ALIAS_SUPPORTED_PROVIDERS and DNS_ALIAS_REQUIRED_FIELDS are the
    exact symbol pair behind #99 (a provider gated as supported but with no
    field schema, or vice versa). They must list the same providers."""
    from modules.core.certificates import (
        DNS_ALIAS_SUPPORTED_PROVIDERS, DNS_ALIAS_REQUIRED_FIELDS)
    only_supported = DNS_ALIAS_SUPPORTED_PROVIDERS - set(DNS_ALIAS_REQUIRED_FIELDS)
    only_fields = set(DNS_ALIAS_REQUIRED_FIELDS) - DNS_ALIAS_SUPPORTED_PROVIDERS
    assert not (only_supported or only_fields), (
        f"DNS_ALIAS_SUPPORTED_PROVIDERS and DNS_ALIAS_REQUIRED_FIELDS disagree "
        f"(certificates.py): only-supported={sorted(only_supported)} "
        f"only-required-fields={sorted(only_fields)}"
    )


def test_dns_alias_providers_are_real_providers():
    """Every alias-capable provider must be a real, issuable DNS provider."""
    from modules.core.certificates import DNS_ALIAS_SUPPORTED_PROVIDERS
    orphans = DNS_ALIAS_SUPPORTED_PROVIDERS - _factory_dns_providers()
    assert not orphans, (
        f"DNS_ALIAS_SUPPORTED_PROVIDERS lists providers with no strategy in "
        f"DNSStrategyFactory: {sorted(orphans)}"
    )


def test_dns_alias_required_fields_match_credential_schema():
    """An alias provider's required fields must equal its canonical credential
    schema — otherwise alias setup validates against a different contract than
    normal issuance (a silent way to accept an unusable config)."""
    from modules.core.certificates import DNS_ALIAS_REQUIRED_FIELDS
    mismatched = {}
    for provider, alias_fields in DNS_ALIAS_REQUIRED_FIELDS.items():
        creds = _DNS_PROVIDER_CREDENTIALS.get(provider)
        if creds is None or tuple(creds) != tuple(alias_fields):
            mismatched[provider] = {'alias': tuple(alias_fields), 'credentials': creds}
    assert not mismatched, (
        f"DNS_ALIAS_REQUIRED_FIELDS diverged from _DNS_PROVIDER_CREDENTIALS: {mismatched}"
    )


def test_every_alias_provider_is_dispatchable():
    """Every alias provider must be dispatchable at change-time: it either has
    a Lexicon adapter name or is one of the native adapters. A provider in the
    supported set but neither would hit the 'Unsupported DNS alias provider'
    branch at runtime (the alias analogue of #99). Also pins that no Lexicon
    entry exists for a provider outside the alias set."""
    from modules.core.certificates import DNS_ALIAS_SUPPORTED_PROVIDERS
    from modules.core.dns_alias_hook import LEXICON_PROVIDER_MAP
    dispatchable = set(LEXICON_PROVIDER_MAP) | _ALIAS_NATIVE_ADAPTERS
    undispatchable = DNS_ALIAS_SUPPORTED_PROVIDERS - dispatchable
    dispatch_without_support = dispatchable - DNS_ALIAS_SUPPORTED_PROVIDERS
    assert not (undispatchable or dispatch_without_support), (
        f"alias dispatch coverage drifted from DNS_ALIAS_SUPPORTED_PROVIDERS: "
        f"undispatchable={sorted(undispatchable)} "
        f"dispatch-without-support={sorted(dispatch_without_support)}"
    )


