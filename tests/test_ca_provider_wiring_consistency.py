"""
Cross-validation tests that pin the contract between independent wiring
points for CA providers — the CA-side sibling of
test_provider_wiring_consistency.py (DNS).

Adding a new CA provider means touching at least: the CAManager
providers dict, the create-certificate API model enum, the
test-ca-provider endpoint, the settings UI (select option + config
panel + settings.js save/load/test wiring) and the per-certificate CA
dropdown on the dashboard.

It is easy to miss one — before Actalis landed, the create-cert enum
listed 3 of 7 providers and the test endpoint rejected 4 of them with
"Invalid CA provider type". These tests break until every wiring point
knows the new provider.
"""
import re
from pathlib import Path

import pytest

from modules.core.ca_manager import CAManager

pytestmark = [pytest.mark.unit]

REPO_ROOT = Path(__file__).resolve().parent.parent


def _ca_providers():
    return set(CAManager(settings_manager=None).ca_providers.keys())


def _read(rel_path):
    return (REPO_ROOT / rel_path).read_text(encoding='utf-8')


def _models_enum():
    """Extract the ca_provider enum literal from the create-cert model."""
    src = _read('modules/api/models.py')
    match = re.search(
        r"'ca_provider': fields\.String\(.*?enum=\[(.*?)\]",
        src, re.S,
    )
    assert match, 'ca_provider enum not found in modules/api/models.py'
    return set(re.findall(r"'([\w-]+)'", match.group(1)))


def test_models_enum_matches_ca_manager():
    providers = _ca_providers()
    enum = _models_enum()
    missing = providers - enum
    assert not missing, (
        f"CA providers missing from the create-certificate enum in "
        f"modules/api/models.py: {sorted(missing)}"
    )
    phantom = enum - providers
    assert not phantom, (
        f"create-certificate enum advertises CA providers CAManager "
        f"cannot dispatch: {sorted(phantom)}"
    )


def test_settings_select_offers_every_provider():
    html = _read('templates/partials/settings_ca.html')
    # Scope to the default-ca select: the file also contains the
    # letsencrypt environment dropdown and the private-ca preset select.
    match = re.search(r'<select id="default-ca".*?</select>', html, re.S)
    assert match, 'default-ca select not found in settings_ca.html'
    offered = set(re.findall(r'<option value="([\w-]+)"', match.group(0)))
    providers = _ca_providers()
    missing = providers - offered
    assert not missing, (
        f"CA providers missing from the default-ca select in "
        f"templates/partials/settings_ca.html: {sorted(missing)}"
    )
    # Reverse direction: no phantom CA options.
    phantom = offered - providers
    assert not phantom, (
        f"settings_ca.html offers CA options with no CAManager entry: "
        f"{sorted(phantom)}"
    )


def test_dashboard_cert_form_offers_every_provider():
    html = _read('templates/index.html')
    match = re.search(
        r'<select id="ca_provider_select".*?</select>', html, re.S,
    )
    assert match, 'ca_provider_select not found in templates/index.html'
    offered = set(re.findall(r'<option value="([\w-]+)"', match.group(0)))
    providers = _ca_providers()
    missing = providers - offered
    assert not missing, (
        f"CA providers missing from the per-certificate CA dropdown in "
        f"templates/index.html: {sorted(missing)}"
    )
    phantom = offered - providers
    assert not phantom, (
        f"templates/index.html offers CA options with no CAManager "
        f"entry: {sorted(phantom)}"
    )


def test_settings_js_panel_wiring_complete():
    js = _read('static/js/settings.js')
    html = _read('templates/partials/settings_ca.html')
    providers = _ca_providers()

    # caProviderToConfigId must map every provider...
    block = re.search(r'var caProviderToConfigId = \{(.*?)\};', js, re.S)
    assert block, 'caProviderToConfigId not found in settings.js'
    mapping = dict(re.findall(r"'([\w-]+)':\s*'([\w-]+)'", block.group(1)))
    missing = providers - set(mapping)
    assert not missing, (
        f"CA providers missing from caProviderToConfigId in "
        f"static/js/settings.js: {sorted(missing)}"
    )

    # ...to a panel that exists and is also in the hide-all list,
    # otherwise it leaks through when another CA is selected.
    hide_list_match = re.search(r'var caConfigs = \[(.*?)\];', js, re.S)
    assert hide_list_match, 'caConfigs list not found in settings.js'
    hide_list = set(re.findall(r"'([\w-]+)'", hide_list_match.group(1)))
    for provider in providers:
        panel_id = mapping[provider]
        assert f'id="{panel_id}"' in html, (
            f"Config panel #{panel_id} mapped for '{provider}' does not "
            f"exist in settings_ca.html"
        )
        assert panel_id in hide_list, (
            f"Config panel #{panel_id} for '{provider}' is missing from "
            f"the caConfigs hide-all list in settings.js"
        )


def test_settings_js_save_load_and_test_cover_every_provider():
    js = _read('static/js/settings.js')
    for provider in _ca_providers():
        assert re.search(rf'caProviders\.{provider}\s*=', js), (
            f"collectCAProviderSettings does not save '{provider}' — "
            f"its panel fields would be silently dropped on save"
        )
        assert re.search(rf'caProviders\.{provider}\s*\|\|', js), (
            f"loadCAProviderSettings does not load '{provider}' — "
            f"saved values would not repopulate the form"
        )
        assert re.search(rf"caProvider === '{provider}'", js), (
            f"testCAProvider has no branch for '{provider}' — the Test "
            f"CA Connection button would post an empty config"
        )


def test_dashboard_js_provider_info_covers_every_provider():
    js = _read('static/js/dashboard.js')
    for provider in _ca_providers():
        assert f"case '{provider}':" in js, (
            f"updateCAProviderInfo in static/js/dashboard.js has no info "
            f"text for '{provider}'"
        )


def test_test_endpoint_handles_every_provider():
    src = _read('modules/api/resources.py')
    start = src.index('class CAProviderTest')
    next_class = re.search(r'\n    class \w+', src[start + 1:])
    body = src[start:start + 1 + next_class.start()] if next_class else src[start:]
    for provider in _ca_providers():
        assert f"'{provider}'" in body, (
            f"POST /api/settings/test-ca-provider has no branch for "
            f"'{provider}' — it would answer 'Invalid CA provider type'"
        )


def test_actalis_provider_metadata_pinned():
    """Pin the Actalis facts that issuance correctness depends on.

    The other tests here derive expectations from the ca_providers dict
    itself, so an accidental edit of the entry (flipping requires_eab,
    typoing the directory URL) would self-consistently pass. These values
    come from the official Actalis ACME documentation and a registration
    without EAB — or against a wrong directory — fails outright.
    """
    actalis = CAManager(settings_manager=None).ca_providers['actalis']
    assert actalis['production_url'] == 'https://acme-api.actalis.com/acme/directory'
    assert actalis['requires_eab'] is True
    assert actalis['supports_wildcard'] is False
    assert actalis['certificate_types'] == ['DV']


def test_eab_validation_consistent_with_provider_flags():
    manager = CAManager(settings_manager=None)
    for provider, info in manager.ca_providers.items():
        if provider == 'private_ca':
            continue  # validated on acme_url, not EAB
        if info['requires_eab']:
            ok, msg = manager.validate_ca_configuration(provider, {})
            assert not ok and 'EAB' in msg, (
                f"'{provider}' requires EAB but validate_ca_configuration "
                f"accepted an empty config"
            )
            ok, msg = manager.validate_ca_configuration(provider, {
                'eab_kid': 'kid', 'eab_hmac': 'hmac',
            })
            assert ok, f"'{provider}' rejected UI-spelled EAB config: {msg}"
        else:
            ok, msg = manager.validate_ca_configuration(provider, {})
            assert ok, (
                f"'{provider}' does not require EAB but rejected an "
                f"empty config: {msg}"
            )
