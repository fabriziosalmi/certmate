"""With no client certificate at all, the client view offers to create one.

The client list opens with the "Active" status chip pressed (#562), so with
zero certificates it counted as a filtered view and said "No matching client
certificates. Try a different usage or status filter": on a fresh instance the
first visit blamed a filter, and the "New Client Certificate" button of the
empty state was never shown. A filter only explains an empty list when there is
something for it to hide.

Runs the shipped client-certs.js in node, as test_certificate_list_navigation.py does.
"""
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

JS = Path(__file__).resolve().parent.parent / 'static/js'

SCRIPT = r"""
const fs = require('fs');
global.window = global;
global.localStorage = {getItem() { return null; }, setItem() {}};
const body = {innerHTML: '', querySelectorAll() { return []; }};
const elements = {certTableBody: body, clientCertificatePageSummary: {},
  clientCertificatePreviousPage: {}, clientCertificateNextPage: {}};
global.document = {addEventListener() {}, querySelectorAll() { return []; },
  getElementById(id) { return elements[id] || null; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
CertMate.actions = () => {}; CertMate.globalActions = () => {};
const certs = JSON.parse(process.argv[3]);
global.fetch = () => Promise.resolve({json: () => Promise.resolve({certificates: certs})});
const source = fs.readFileSync(process.argv[2], 'utf8').replace(/\}\)\(\);\s*$/,
  'window.testLoad = ccLoadCertificates; })();');
eval(source);
// The chip the list opens with when nothing was saved (ccRestoreFilters).
window.ccSetStatusFilter('active');
window.testLoad().then(() => { console.log(body.innerHTML); })
  .catch(e => { console.error(e); process.exitCode = 1; });
"""


def _render(node, certificates):
    import json
    result = subprocess.run([node, '-e', SCRIPT, str(JS / 'certmate.js'), str(JS / 'client-certs.js'),
                             json.dumps(certificates)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_no_certificate_at_all_offers_the_first_one(node):
    html = _render(node, [])
    assert 'No client certificates yet' in html, html[:300]
    assert 'No matching client certificates' not in html
    assert 'openCertDrawer' in html  # the button that creates one


def test_certificates_the_filter_hides_still_say_so(node):
    """The other empty state is unchanged: there are certificates, all revoked,
    and the Active chip hides them."""
    revoked = [{'identifier': '1', 'common_name': 'old.example.com', 'email': 'a@example.com',
                'cert_usage': 'vpn', 'revoked': True, 'created_at': '2026-01-01', 'expires_at': '2027-01-01'}]
    html = _render(node, revoked)
    assert 'No matching client certificates' in html, html[:300]
    assert 'No client certificates yet' not in html
