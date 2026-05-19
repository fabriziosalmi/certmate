"""
DNS-provider zone discovery for nested-subdomain wildcards.

Most certbot DNS plugins (cloudflare, route53, google, digitalocean, …)
walk parent labels internally to find the hosted zone for an ACME
challenge name. Azure DNS is the outlier: ``certbot-dns-azure`` requires
the caller to enumerate the candidate hosted zones in its ini file
(``dns_azure_zoneN = <zone>:<resource_id>``) and selects the longest
match per challenge.

That requirement bites operators who host the parent zone in Azure but
ask CertMate for a wildcard cert on a nested subdomain — e.g. Azure
holds ``example.com``, the user wants ``*.example2.example.com``. The
previous code derived the zone identity from the cert FQDN itself
(``example2.example.com``), which Azure DNS doesn't host, and the plugin
errored out.

This module gives CertMate a per-provider zone-discovery hook so the
cert-issuance path can ask the provider "what zones does this account
actually own?" and then pick the longest one that covers the cert's
FQDN. The default is a no-op (returns ``[]``), preserving today's
behaviour for every provider whose plugin already self-discovers.

Azure's implementation talks to Azure Resource Manager via
``azure.mgmt.dns.DnsManagementClient`` — both ``azure-identity`` and
``azure-mgmt-dns`` are already pinned by ``requirements-azure.txt``
because ``certbot-dns-azure`` depends on them transitively. No new
top-level dependency.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)


class ZoneDiscovery(Protocol):
    """Per-provider hook that returns the DNS zones an account hosts.

    Implementations should be side-effect-free apart from the necessary
    network call to the provider, and must NOT raise on a "no zones
    configured" response — return ``[]`` instead. They MAY raise on
    auth or connectivity errors; the caller (cert issuance path) wraps
    those in a user-facing error.
    """

    def list_zones(self, account_config: Dict) -> List[str]: ...


class _NullZoneDiscovery:
    """No-op discovery. Returned for providers whose certbot plugin
    handles zone resolution internally — calling code reads the empty
    list and falls back to the legacy ``_zone_domain`` shape."""

    def list_zones(self, account_config: Dict) -> List[str]:  # noqa: ARG002
        return []


class AzureZoneDiscovery:
    """Discover Azure DNS zones in the account's resource group.

    Uses the service-principal credentials already configured for
    ``certbot-dns-azure`` to call Azure Resource Manager and enumerate
    hosted zones. Result is the bare zone names (no resource ids,
    those get rebuilt by ``create_azure_config`` at write time).
    """

    def list_zones(self, account_config: Dict) -> List[str]:
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.dns import DnsManagementClient
        except ImportError as exc:
            # Mirrors the error operators already see when the Azure
            # extras aren't installed for cert issuance.
            raise RuntimeError(
                "Azure SDK not available — install requirements-azure.txt "
                "to enable zone discovery for Azure DNS accounts."
            ) from exc

        required = ('subscription_id', 'resource_group', 'tenant_id',
                    'client_id', 'client_secret')
        missing = [k for k in required if not account_config.get(k)]
        if missing:
            raise ValueError(
                "Azure account is missing credentials needed for zone "
                f"discovery: {', '.join(missing)}"
            )

        credential = ClientSecretCredential(
            tenant_id=account_config['tenant_id'],
            client_id=account_config['client_id'],
            client_secret=account_config['client_secret'],
        )
        client = DnsManagementClient(
            credential=credential,
            subscription_id=account_config['subscription_id'],
        )

        try:
            pager = client.zones.list_by_resource_group(
                resource_group_name=account_config['resource_group']
            )
            names = sorted({(z.name or '').rstrip('.').lower()
                            for z in pager
                            if getattr(z, 'name', None)})
            return [n for n in names if n]
        except Exception as exc:
            # Surface as a runtime error with the upstream cause; the
            # caller wraps this in a user-facing message including the
            # subscription/RG hint so the operator knows where to look.
            raise RuntimeError(
                f"Could not list Azure DNS zones for resource group "
                f"'{account_config['resource_group']}' in subscription "
                f"'{account_config['subscription_id']}': {exc}"
            ) from exc


# Registry of providers that need explicit zone resolution. Providers
# absent from this map use the legacy ``_zone_domain`` path (apex-derived
# from the cert FQDN) — that's safe because their certbot plugins walk
# parent labels internally. Add an entry here when a future provider
# (rfc2136, edgedns, …) needs the same treatment as Azure.
_ZONE_DISCOVERY: Dict[str, ZoneDiscovery] = {
    'azure': AzureZoneDiscovery(),
}

_NULL_DISCOVERY: ZoneDiscovery = _NullZoneDiscovery()


def get_zone_discovery(provider: str) -> ZoneDiscovery:
    """Return the discovery hook for *provider*, or a no-op if none
    is registered. Never raises."""
    return _ZONE_DISCOVERY.get(provider, _NULL_DISCOVERY)


def has_zone_discovery(provider: str) -> bool:
    """Whether *provider* has a non-trivial discovery hook registered.

    Callers use this to gate "did we attempt resolution?" telemetry and
    error wording — for providers without a hook the legacy code path
    stays in charge, so a missing match isn't a CertMate-level failure.
    """
    return provider in _ZONE_DISCOVERY


def _match_fqdns_to_zones(
    provider: str,
    zones: List[str],
    fqdns: List[str],
) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Shared matcher used by both the live-discovery and explicit-list
    paths. Returns the deduplicated longest-first list of matched zones
    and the per-FQDN ``(fqdn, zone)`` mapping (for caller logging).

    Raises ``ValueError`` when any FQDN is not covered, surfacing the
    full configured zone set so the operator can fix either the cert
    request or the zone configuration.
    """
    from .utils import find_covering_zone

    if not fqdns:
        raise ValueError(
            f"Cannot resolve DNS zones for provider '{provider}': no FQDNs "
            "supplied. This is a programming error in the caller — every "
            "cert request must include at least the primary domain."
        )

    matched: List[str] = []
    per_fqdn: List[Tuple[str, str]] = []
    unmatched: List[str] = []
    for fqdn in fqdns:
        zone = find_covering_zone(fqdn, zones)
        if zone is None:
            unmatched.append(fqdn)
            continue
        per_fqdn.append((fqdn, zone))
        if zone not in matched:
            matched.append(zone)

    if unmatched:
        raise ValueError(
            "The following certificate names are not covered by any "
            f"hosted DNS zone configured for provider '{provider}': "
            f"{', '.join(unmatched)}. Hosted zones configured: "
            f"{', '.join(zones) or '(none)'}."
        )

    # Sort longest-first so the resulting ``dns_azure_zoneN`` lines
    # encode the operator's intent stably and the plugin's longest-match
    # picks the most specific zone for each challenge.
    matched.sort(key=len, reverse=True)
    return matched, per_fqdn


def resolve_zones_for_domains(
    provider: str,
    account_config: Dict,
    fqdns: List[str],
    *,
    cache: Optional[Dict] = None,
) -> Tuple[List[str], List[Tuple[str, str]]]:
    """For a provider that needs explicit zone identity, resolve each
    FQDN in *fqdns* to its longest covering zone in the account and
    return ``(matched_zones, per_fqdn_map)``:

    * ``matched_zones`` — deduplicated longest-first list, ready to feed
      into ``dns_azure_zoneN`` lines.
    * ``per_fqdn_map`` — ordered list of ``(fqdn, zone)`` pairs so the
      caller can log a single concise INFO line with the full mapping.

    Raises:
        ValueError: if any FQDN is not covered by a hosted zone, or if
            *fqdns* is empty (a programming error in the caller).
        RuntimeError: if zone discovery itself failed (auth, network,
            missing SDK). The cert-issuance layer converts this into
            a 5xx-style error.
    """
    discovery = get_zone_discovery(provider)
    cache_key = None
    if cache is not None:
        cache_key = (
            provider,
            account_config.get('tenant_id'),
            account_config.get('client_id'),
            account_config.get('subscription_id'),
            account_config.get('resource_group'),
        )
        zones = cache.get(cache_key)
    else:
        zones = None
    if zones is None:
        zones = discovery.list_zones(account_config)
        if cache is not None:
            cache[cache_key] = zones

    if not zones:
        # Provider has no hosted zones at all. Report rather than
        # silently fall back — the operator's intent ("issue a cert
        # against this Azure account") cannot be honoured.
        raise ValueError(
            f"DNS provider '{provider}' returned no hosted zones for the "
            "configured account; verify the service principal has read "
            "access to the resource group and the resource group "
            "actually contains DNS zones."
        )

    return _match_fqdns_to_zones(provider, zones, fqdns)


def resolve_zones_against_explicit_list(
    provider: str,
    zones: List[str],
    fqdns: List[str],
) -> Tuple[List[str], List[Tuple[str, str]]]:
    """RBAC escape hatch: match *fqdns* against an operator-supplied
    zone list without hitting the provider's discovery API.

    Existed Azure service principals scoped to ``dnsZones/TXT/write``
    on specific zones lack the ``dnsZones/read`` permission on the
    resource group that the auto-discovery path needs. Operators in
    that position can declare their hosted zones on the account
    (``account_config['zone_domains']``) and CertMate uses that list
    directly. Same matching, fail-early, and longest-first semantics
    as :func:`resolve_zones_for_domains`.
    """
    cleaned = [str(z).strip() for z in (zones or []) if str(z or '').strip()]
    if not cleaned:
        raise ValueError(
            f"Explicit zone_domains list for provider '{provider}' is empty "
            "after sanitisation; remove the field to fall back to live "
            "zone discovery."
        )
    return _match_fqdns_to_zones(provider, cleaned, fqdns)
