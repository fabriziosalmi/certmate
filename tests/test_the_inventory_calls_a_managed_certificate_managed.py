"""The inventory calls a certificate at a managed domain managed, not issued.

The inventory groups a record by `managed`: a certificate found at the host of a
domain CertMate manages is managed whoever issued it (docs/discovery-inventory.md).
Since #1358 `source` says by fingerprint whether CertMate issued it, so a
certificate from another CA still served at a managed host, which is what
discovery is there to catch, is `managed` with `source=probed`. The page counted
it under "Issued" and listed it under "Issued by CertMate".

The group's key in the API answer stays `issued`, so nothing reading the API
changes; what the page and the docs call it is what changes.
"""
import re
from pathlib import Path

import pytest

from modules.core.inventory_view import build_inventory_view

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = (REPO / 'templates' / 'inventory.html').read_text(encoding='utf-8')
DOCS = (REPO / 'docs' / 'discovery-inventory.md').read_text(encoding='utf-8')

FOREIGN_AT_A_MANAGED_HOST = {
    'fingerprint': 'fp-foreign', 'subject_cn': 'shop.example.com', 'issuer_cn': 'Another CA',
    'not_after': '2027-01-01T00:00:00Z', 'source': 'probed', 'managed': True,
    'managed_domain': 'shop.example.com', 'san_dns': ['shop.example.com'], 'endpoints': [],
}


def _card_label(tile_id):
    match = re.search(r'<div class="text-xs text-muted">([^<]+)</div><div[^>]*id="' + tile_id + '"',
                      TEMPLATE)
    assert match, f'no summary card for {tile_id}'
    return match.group(1)


def _group_option(value):
    select = re.search(r'<select id="invGroup".*?</select>', TEMPLATE, re.S)
    assert select, 'no group filter'
    match = re.search(r'<option value="' + value + r'">([^<]+)</option>', select.group(0))
    assert match, f'no group option {value!r}'
    return match.group(1)


def test_a_certificate_another_ca_issued_at_a_managed_host_is_in_the_managed_group():
    view = build_inventory_view([FOREIGN_AT_A_MANAGED_HOST])
    (item,) = view['certificates']
    assert (item['group'], item['source']) == ('issued', 'probed')
    assert view['summary']['issued'] == 1


def test_the_page_calls_that_group_managed():
    assert _card_label('sumIssued') == 'Managed'
    assert _group_option('issued') == 'Managed by CertMate'
    assert 'Issued by CertMate' not in TEMPLATE


def test_the_docs_call_that_group_managed():
    assert 'Issued by CertMate' not in DOCS
    assert '**Managed by CertMate**' in DOCS
