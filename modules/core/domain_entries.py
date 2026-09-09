"""What an entry in ``settings['domains']`` is, in one place.

An entry is a bare domain string or an object carrying that domain plus
per-domain overrides. Both spellings are in the wild: the string form is what
early versions wrote, the object form is what everything since writes, and no
migration ever converted a list that held both. Seven modules decoded that
union independently, each with its own idea of what a third shape means.

Two rules, and the second is the one that had been broken.

**One decoder.** ``entry_domain`` and ``entry_auto_renew`` are the only places
that know an entry can be a string. Everything else asks them.

**Normalisation is lossless.** ``normalize_entry`` turns a string into
``{'domain': ...}`` and nothing else. It does not fill in ``dns_provider`` or
``account_id``, and that restraint is the point rather than an omission:

    the string 'a.example.com' means "this domain follows the global
    dns_provider setting", and {'domain': 'a.example.com'} means exactly the
    same thing, because get_domain_dns_provider falls back to the global when
    the entry names no provider.

    {'domain': 'a.example.com', 'dns_provider': 'cloudflare'} means something
    DIFFERENT: this domain is pinned to cloudflare whatever the global says.

The previous normaliser wrote the third form when it was given the first. It
ran inside settings mutators, so an unrelated operation -- flipping auto_renew
on one domain, or the renewal sweep re-registering a certificate -- rewrote
every string entry with the global provider of that moment baked into it. From
then on, changing the global DNS provider had no effect on any existing domain:
they all kept resolving to the value that had been frozen in. Nothing read
those injected fields (the provider is resolved by
``SettingsManager.get_domain_dns_provider``, the account by the certificate's
own metadata), so the injection bought nothing and cost that.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def entry_domain(raw: Any) -> Optional[str]:
    """The domain name an entry names, or None when it names none.

    None means "this is not a usable entry" for every caller: a malformed
    element must be skipped rather than making the whole certificate list
    unreachable.
    """
    if isinstance(raw, str):
        return raw or None
    if isinstance(raw, dict):
        domain = raw.get('domain')
        return domain if isinstance(domain, str) and domain else None
    return None


def entry_auto_renew(raw: Any) -> bool:
    """Whether unattended renewal is enabled for this entry.

    Absent means enabled, in both spellings — the string form cannot carry the
    flag at all, and a dict without it has always been read as True. This is
    the PER-DOMAIN switch; the global ``auto_renew`` setting is a separate gate
    checked before the sweep iterates.
    """
    if isinstance(raw, dict):
        return bool(raw.get('auto_renew', True))
    return True


def normalize_entry(raw: Any) -> Optional[dict]:
    """One entry in the object form, or None if it is not an entry at all.

    Lossless by construction: a string becomes ``{'domain': ...}`` and a dict
    is copied unchanged. No field is invented. See this module's docstring for
    why inventing ``dns_provider`` here is a semantic change rather than a
    tidy-up.
    """
    domain = entry_domain(raw)
    if domain is None:
        return None
    if isinstance(raw, dict):
        entry = dict(raw)
        entry['domain'] = domain
        return entry
    return {'domain': domain}


def normalize_domains(domains: Any) -> tuple[list, int]:
    """Normalise a whole list. Returns ``(entries, dropped)``.

    ``dropped`` counts elements that name no domain — a number rather than an
    exception, because one malformed entry must not make every other
    certificate unreachable, and a number is what the caller can report.
    """
    if not isinstance(domains, list):
        return [], 0
    entries = []
    dropped = 0
    for raw in domains:
        entry = normalize_entry(raw)
        if entry is None:
            dropped += 1
            continue
        entries.append(entry)
    return entries, dropped


def iter_domains(settings: Any):
    """``(domain, auto_renew)`` for every usable entry in *settings*."""
    domains = (settings or {}).get('domains') if isinstance(settings, dict) else None
    for raw in domains or []:
        domain = entry_domain(raw)
        if domain:
            yield domain, entry_auto_renew(raw)
