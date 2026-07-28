"""Adopt a discovered certificate into CertMate management (#472).

When the inventory shows a discovered, unmanaged certificate that is about to
expire, an operator would otherwise have to switch context and retype the whole
create form. :func:`build_adoption_plan` turns an inventory record into a
ready-to-confirm create request — deriving the domain, SANs and key type from
the *observed* certificate — and reports whether adoption is actually possible
(CertMate can only take over renewal for a domain it can validate, i.e. one with
DNS credentials configured and an ACME account email set). The API layer renders
the plan for confirmation and, on adopt, feeds it straight into the normal
create/issue flow.

Pure and side-effect-free: it reads config through the DNS manager but issues
nothing, so it is safe to call for a live "can I adopt this?" affordance.
"""

# Key sizes / curves the create flow accepts. Anything else on the observed
# cert falls back to the configured defaults rather than being forced through.
_RSA_SIZES = {2048, 3072, 4096}
_EC_CURVES = {'secp256r1', 'secp384r1'}
# OpenSSL-style curve aliases mapped to the create form's canonical names, so an
# observed 'prime256v1' still pre-fills as 'secp256r1' instead of being dropped.
_EC_CURVE_ALIASES = {'prime256v1': 'secp256r1', 'prime384v1': 'secp384r1'}


def _derive_names(record):
    """Return (primary_domain, san_domains) from an inventory record.

    The subject CN is the primary when present, otherwise the first SAN. The
    remaining SANs (minus the primary) become san_domains.
    """
    san = [s for s in (record.get('san_dns') or []) if s]
    primary = record.get('subject_cn') or (san[0] if san else None)
    san_domains = [s for s in san if s != primary]
    return primary, san_domains


def _derive_key_options(record):
    """Map the observed public key to create-flow key options.

    Returns ``(key_type, key_size, elliptic_curve)``; any field CertMate's
    create form doesn't accept is left None so the configured default applies.
    """
    key = record.get('key') or {}
    ktype = (key.get('type') or '').upper()
    if ktype == 'RSA':
        size = key.get('size')
        return 'rsa', (size if size in _RSA_SIZES else None), None
    if ktype == 'ECDSA':
        curve = key.get('curve')
        curve = _EC_CURVE_ALIASES.get(curve, curve)
        return 'ecdsa', None, (curve if curve in _EC_CURVES else None)
    return None, None, None


def build_adoption_plan(record, dns_manager, settings=None):
    """Assess whether *record* can be adopted and pre-fill the create request.

    Returns a dict:
      - ``available`` (bool) — can CertMate take over this domain now?
      - ``reason`` (str) — when not available, why (shown in the UI).
      - ``domain`` / ``san_domains`` / ``key_type`` / ``key_size`` /
        ``elliptic_curve`` — the pre-filled create parameters.
      - ``dns_provider`` — the suggested provider (from existing config /
        pattern), and ``dns_provider_configured`` whether it has credentials.
      - ``email_configured`` — whether an ACME account email is set.
    """
    plan = {
        'available': False,
        'reason': None,
        'domain': None,
        'san_domains': [],
        'key_type': None,
        'key_size': None,
        'elliptic_curve': None,
        'dns_provider': None,
        'dns_provider_configured': False,
        'email_configured': False,
    }

    if record is None:
        plan['reason'] = 'Certificate not found in inventory.'
        return plan
    if record.get('managed'):
        plan['reason'] = 'This certificate is already managed by CertMate.'
        return plan

    domain, san_domains = _derive_names(record)
    if not domain:
        plan['reason'] = 'The certificate has no subject/SAN to derive a domain from.'
        return plan
    plan['domain'] = domain
    plan['san_domains'] = san_domains
    plan['key_type'], plan['key_size'], plan['elliptic_curve'] = _derive_key_options(record)

    if settings is None:
        settings = dns_manager.settings_manager.load_settings()

    plan['email_configured'] = bool(settings.get('email'))

    provider, _confidence = dns_manager.suggest_dns_provider_for_domain(domain, settings=settings)
    plan['dns_provider'] = provider
    if provider:
        configured = {
            p['name']: p.get('configured')
            for p in dns_manager.get_available_providers()
        }
        plan['dns_provider_configured'] = bool(configured.get(provider))

    # Feasibility: a validated domain needs DNS credentials AND an ACME email.
    if not plan['dns_provider_configured']:
        which = f" for {domain}" if domain else ""
        plan['reason'] = (
            f"No DNS provider with credentials is configured{which}. "
            "Add DNS credentials in Settings to enable adoption."
        )
        return plan
    if not plan['email_configured']:
        plan['reason'] = 'Set an ACME account email in Settings before adopting.'
        return plan

    plan['available'] = True
    return plan
