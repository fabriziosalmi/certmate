"""The frontend provider lists must cover every backend DNS provider.

The backend is a single, test-pinned source of truth
(test_provider_wiring_consistency.py), but the UI hand-maintains its own
provider lists in HTML/JS. They had silently drifted: arvancloud, infomaniak,
acme-dns and hetzner-cloud were issuable via the API but absent from the
settings picker entirely (a user could not configure them), and vultr had a
radio + Add-Account button but no modal field schema, so its modal rendered
empty.

These ratchets make that drift a build break: the provider picker and the
quick-add select must list exactly the canonical providers, and every
Add-Account button must have a credential schema to render.
"""
import re
from pathlib import Path

import pytest

from modules.core.dns_providers import DNSManager

pytestmark = [pytest.mark.unit]

_ROOT = Path(__file__).resolve().parent.parent
_SUPPORTED = set(DNSManager.SUPPORTED_PROVIDERS)


def _read(rel):
    return (_ROOT / rel).read_text()


def test_settings_dns_radio_picker_covers_all_providers():
    """templates/partials/settings_dns.html — the DNS provider radio picker
    must offer exactly the canonical provider set."""
    html = _read('templates/partials/settings_dns.html')
    radios = set(re.findall(r'name="dns_provider"\s+value="([a-z0-9-]+)"', html))
    missing = _SUPPORTED - radios
    extra = radios - _SUPPORTED
    assert not (missing or extra), (
        f"settings_dns.html provider radios drifted from "
        f"DNSManager.SUPPORTED_PROVIDERS: missing={sorted(missing)} "
        f"extra={sorted(extra)}"
    )


def test_settings_dns_radios_have_config_blocks():
    """Every provider radio must have a matching #<provider>-config block, or
    selecting it shows an empty configuration panel."""
    html = _read('templates/partials/settings_dns.html')
    radios = set(re.findall(r'name="dns_provider"\s+value="([a-z0-9-]+)"', html))
    config_blocks = set(re.findall(r'id="([a-z0-9-]+)-config"', html))
    missing = radios - config_blocks
    assert not missing, (
        f"provider radios with no #<provider>-config block: {sorted(missing)}"
    )


def test_index_quick_add_select_covers_all_providers():
    """templates/index.html — the quick-add domain DNS provider <select>
    must offer exactly the canonical provider set."""
    html = _read('templates/index.html')
    m = re.search(r'updateAccountSelection\(\).*?</select>', html, re.S)
    assert m, "could not locate the quick-add DNS provider <select> in index.html"
    options = set(re.findall(r'<option value="([a-z0-9-]+)"', m.group(0)))
    missing = _SUPPORTED - options
    extra = options - _SUPPORTED
    assert not (missing or extra), (
        f"index.html quick-add provider select drifted from "
        f"DNSManager.SUPPORTED_PROVIDERS: missing={sorted(missing)} "
        f"extra={sorted(extra)}"
    )


def test_add_account_buttons_have_modal_field_schema():
    """Every Add-Account button (showAddAccountModal('<provider>')) must have a
    credential schema in settings.js getProviderFields, or its modal renders
    no fields (the vultr bug)."""
    html = _read('templates/partials/settings_dns.html')
    button_providers = set(re.findall(r"showAddAccountModal\('([a-z0-9-]+)'\)", html))

    js = _read('static/js/settings.js')
    start = js.index('function getProviderFields')
    end = js.index('var fields = fieldMappings[provider]', start)
    schema_keys = set(re.findall(r"'([a-z0-9-]+)':\s*\[", js[start:end]))

    missing = button_providers - schema_keys
    assert not missing, (
        f"providers with an Add-Account button but no getProviderFields schema "
        f"(empty modal): {sorted(missing)}"
    )
