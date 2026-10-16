"""The ⌘K palette finds a certificate by any name it covers (#1247).

The palette is the one place certificates are searched (#1226 kept the lists
without a search field of their own). It matched a certificate by its name, tags
and notes, and not by the other DNS names on it: an operator looking for
`www.example.com`, a SAN of the `example.com` certificate, found nothing.

These run the shipped `static/js/cmd-palette.js` in node, opened with ⌘K, over a
small DOM double, and read what it draws.
"""
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

JS = Path(__file__).resolve().parent.parent / 'static/js'

SCRIPT = r"""
const fs = require('fs');
global.window = global;
global.localStorage = {getItem() { return null; }, setItem() {}};
global.setInterval = () => 0;
global.setTimeout = () => 0;
window.innerHeight = 900;
window.addEventListener = () => {};
window.location = {pathname: '/elsewhere', href: '', hash: '', search: ''};
const classes = () => {
  const values = new Set(['hidden']);
  return {add(n) { values.add(n); }, remove(n) { values.delete(n); }, contains(n) { return values.has(n); }};
};
const listeners = {};
const input = {value: '', focus() {}, addEventListener(type, fn) { listeners['input:' + type] = fn; }};
const results = {innerHTML: '', style: {}, querySelectorAll() { return []; }};
const overlay = {addEventListener() {}};
const byId = {cmdPaletteInput: input, cmdPaletteResults: results, cmdPaletteOverlay: overlay};
global.document = {
  body: {appendChild() {}},
  activeElement: null,
  createElement() { return {classList: classes(), set innerHTML(v) {}}; },
  getElementById(id) { return byId[id] || null; },
  querySelectorAll() { return []; },
  addEventListener(type, fn) { listeners['doc:' + type] = fn; },
};
const certificates = [
  {domain: 'example.com', exists: true, expired: false, days_until_expiry: 40,
   san_domains: ['www.example.com', 'api.example.com'], tags: [], notes: ''},
  {domain: 'shop.example.net', exists: true, expired: false, days_until_expiry: 70,
   san_domains: [], tags: ['retail'], notes: 'ticket 4242'},
];
global.fetch = url => Promise.resolve({ok: true, json: () => Promise.resolve(
  url === '/api/certificates' ? certificates : {certificates: []})});
// The repository's own scripts, run as the page runs them; nothing else is evaluated.
eval(fs.readFileSync(process.argv[1], 'utf8'));
eval(fs.readFileSync(process.argv[2], 'utf8'));
function check(ok, message) { if (!ok) throw Error(message + '\n' + results.innerHTML); }
async function settle() { for (let i = 0; i < 20; i++) await Promise.resolve(); }
function search(text) { input.value = text; listeners['input:input'](); return results.innerHTML; }
const rows = html => (html.match(/class="cmd-result /g) || []).length;
(async () => {
  listeners['doc:keydown']({metaKey: true, key: 'k', preventDefault() {}});
  await settle();

  let html = search('www.example.com');
  check(rows(html) === 1 && html.includes('>example.com<'), 'A SAN did not find its certificate');
  check(html.includes('SAN www.example.com'), 'A result found by a SAN does not say which name matched');

  html = search('API.EXAMPLE');
  check(rows(html) === 1 && html.includes('SAN api.example.com'), 'A SAN is matched with case');

  html = search('example.com');
  check(html.includes('>example.com<') && !html.includes('SAN '), 'A name match was labelled as a SAN match');

  html = search('ticket 4242');
  check(rows(html) === 1 && html.includes('>shop.example.net<') && !html.includes('SAN '), 'Notes no longer find');

  html = search('other.example.org');
  check(html.includes('No results found'), 'A name no certificate covers found something');

  search('www.example.com');
  listeners['input:keydown']({key: 'Enter', preventDefault() {}});
  check(window.location.href === '/?flash=example.com', 'Choosing it did not open its certificate: ' + window.location.href);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


def test_a_certificate_is_found_by_any_name_it_covers(node):
    result = subprocess.run([node, '-e', SCRIPT, str(JS / 'certmate.js'), str(JS / 'cmd-palette.js')],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
