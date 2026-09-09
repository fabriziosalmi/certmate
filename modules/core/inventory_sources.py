"""What certificates exist — asked once, with the answer's provenance (#670).

Three things describe the inventory and none of them is authoritative: the
``domains`` list in ``settings.json``, the per-domain directories under the
certificate root, and certbot's own ``live/`` lineage. They drift, and the
historical lost-update and metadata-quarantine defects are symptoms of the
triple bookkeeping rather than separate bugs.

Choosing one authority is a larger change than this module. What it does is
smaller and is the prerequisite: give the question ONE implementation, and make
the divergence **visible** instead of silently unioned away.

Two endpoints each rebuilt the union inline — the certificate list and the
discovery scan — with the same loop, the same tolerance for a domain entry
being either a string or a dict, and one of them also collecting the
``auto_renew`` flag. A domain present in only one source came out of both
looking exactly like a domain present in all of them.

``DomainSources`` keeps that apart. Nothing is filtered on it yet; it exists so
a caller can say "registered but absent from disk" without recomputing, and so
the reconciliation this issue asks for has something to reconcile.
"""
from dataclasses import dataclass

from .constants import iter_cert_domain_dirs
from .domain_entries import iter_domains


@dataclass(frozen=True)
class DomainSources:
    """Which sources named a domain, and what settings said about it."""

    domain: str
    in_settings: bool
    on_disk: bool
    auto_renew: bool = True

    @property
    def only_in_settings(self):
        """Registered, with no directory. A certificate that was never issued,
        or whose data volume is not mounted."""
        return self.in_settings and not self.on_disk

    @property
    def only_on_disk(self):
        """Issued, but not registered. A restore that brought the certificates
        and not settings.json, which is the shape the boot-time warning in
        settings.py reports."""
        return self.on_disk and not self.in_settings


def _settings_domains(settings):
    """Yield ``(domain, auto_renew)`` from the settings list.

    Both spellings of an entry are still readable — load_settings normalises
    them to the object form, but this reads whatever it is given, including a
    settings dict assembled in a test or handed over by a restore that has not
    been through the boundary yet. The decoding itself lives in
    :mod:`modules.core.domain_entries`.
    """
    yield from iter_domains(settings)


def collect_domain_sources(settings, cert_dir):
    """Every domain either source knows about, with its provenance.

    Returns a dict keyed by domain. Sorted by name so two callers listing
    certificates cannot disagree about the order, which they could before —
    both iterated a set.
    """
    found = {}

    for domain, auto_renew in _settings_domains(settings):
        found[domain] = DomainSources(
            domain=domain, in_settings=True, on_disk=False,
            auto_renew=auto_renew)

    for path in iter_cert_domain_dirs(cert_dir):
        name = path.name
        existing = found.get(name)
        if existing is None:
            # Not registered: auto_renew defaults to True, matching what the
            # certificate list did for disk-only domains before this moved.
            found[name] = DomainSources(
                domain=name, in_settings=False, on_disk=True)
        else:
            found[name] = DomainSources(
                domain=name, in_settings=True, on_disk=True,
                auto_renew=existing.auto_renew)

    return {name: found[name] for name in sorted(found)}


def auto_renew_for(settings, domain):
    """The per-certificate auto-renew flag, defaulting to True.

    The single-certificate endpoint walked ``settings['domains']`` itself to
    answer this, with a comment saying it mirrored the list endpoint — and it
    handled only the dict spelling, so a domain stored as a plain string took a
    different path to the same answer. Same source, same defaulting, one
    implementation.
    """
    for name, auto_renew in _settings_domains(settings):
        if name == domain:
            return auto_renew
    return True
