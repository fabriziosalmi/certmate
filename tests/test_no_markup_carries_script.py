"""No markup carries script: a control names what it does, and the name is registered.

An `onclick="..."` is inline script. A Content-Security-Policy that lets the
page's own run lets an injected one run too, which is why `script-src` still
carries 'unsafe-inline' (#314). The controls no longer need it: each says what
it does with a name,

    <button data-click="ccSortCertificates" data-args='["status"]'>

and one listener in static/js/certmate.js looks the name up among the actions
the page registered. The arguments are JSON, data and never code.

A control whose name is not registered does nothing, and says so only in the
console, at the click. So what a browser would find one control at a time is
checked here for all of them at once:

* no template and no script-built markup has an event-handler attribute, or a
  `javascript:` address;
* every name a control uses is registered, by the file that defines the
  function, and nothing is registered that no control uses;
* every `data-args` is a JSON array and every `data-pass` is one the listener
  knows.

tests/test_ui_controls_name_their_actions.py is the other half: that the
listener does with a name what the handler did.
"""
import html
import json
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = sorted((REPO / 'templates').rglob('*.html'))
SCRIPTS = sorted(p for p in (REPO / 'static' / 'js').glob('*.js')
                 if not p.name.endswith('.min.js') and 'redoc' not in p.name)

# An attribute whose name starts with `on`, in a tag: `<a onclick=`, ` onchange='`.
HANDLER = re.compile(r"""<[a-zA-Z][^<>]*?\s(on[a-z]+)\s*=\s*["']""")
# The same inside a string a script concatenates into markup.
HANDLER_IN_A_STRING = re.compile(
    r"""[\s'"`](on(?:click|dblclick|change|input|submit|key\w+|mouse\w+|focus|blur|load|error))\s*=\s*\\?["']""")
NAMED = re.compile(r"""data-(click|change|input)=\\?["']([^"'\\]+)""")
BUILT = re.compile(r"""(?:CertMate|CM)\.does\(\s*'(click|change|input)'\s*,\s*'([^']+)'""")
BUILT_BY_A_HELPER = re.compile(r"""\bact(?:Icon|IconDanger)\(\s*'([^']+)'""")
PASSES = {'el', 'event', 'value', 'checked'}


def _read(path):
    return path.read_text(encoding='utf-8')


def _used():
    """{action name: the files whose markup names it}"""
    used = {}
    for path in TEMPLATES + SCRIPTS:
        text = _read(path)
        for _type, name in NAMED.findall(text) + BUILT.findall(text):
            used.setdefault(name, set()).add(path.name)
        for name in BUILT_BY_A_HELPER.findall(text):
            used.setdefault(name, set()).add(path.name)
    return used


def _registrations():
    """[(action name, the file that registers it, whether it is looked up on `window`)]"""
    registrations = []
    for path in TEMPLATES + SCRIPTS:
        text = _read(path)
        for block in re.findall(r'CertMate\.globalActions\(\[(.*?)\]\)', text, re.S):
            registrations += [(name, path, True) for name in re.findall(r"'([^']+)'", block)]
        for block in re.findall(r'(?:CertMate|CM)\.actions\(\{(.*?)\n    \}\);', text, re.S):
            registrations += [(name, path, False)
                              for name in re.findall(r"^\s+'?([A-Za-z_$][\w$.]*)'?:\s*function", block, re.M)]
    return registrations


def _registered():
    return {name for name, _path, _looked_up in _registrations()}


def test_no_template_has_an_event_handler_attribute():
    found = []
    for path in TEMPLATES:
        # Markup only: what is between <script> tags is script, checked below.
        markup = re.sub(r'<script\b.*?</script>', '', _read(path), flags=re.S)
        found += [f'{path.name}: {attribute}' for attribute in HANDLER.findall(markup)]
    assert found == [], found


def test_no_script_builds_markup_with_an_event_handler():
    found = []
    for path in SCRIPTS:
        found += [f'{path.name}: {attribute}' for attribute in HANDLER_IN_A_STRING.findall(_read(path))]
    for path in TEMPLATES:
        for script in re.findall(r'<script\b[^>]*>(.*?)</script>', _read(path), flags=re.S):
            found += [f'{path.name}: {attribute}' for attribute in HANDLER_IN_A_STRING.findall(script)]
    assert found == [], found


def test_the_patterns_above_do_find_a_handler():
    """CONTROL: both patterns, on the shapes this repository used to have."""
    assert HANDLER.findall('<button type="button" onclick="closeCertDrawer()" class="x">') == ['onclick']
    assert HANDLER.findall("<select id='a' onchange='render()'>") == ['onchange']
    assert HANDLER.findall('<div x-on:click="open = true" data-on="1">') == []
    assert HANDLER_IN_A_STRING.findall("""'<button type="button" onclick="retry(\\'' + id + '\\')" class=""") == ['onclick']
    assert HANDLER_IN_A_STRING.findall("""+ 'onclick="InventoryPage.adoptFromEl(this)" '""") == ['onclick']
    assert HANDLER_IN_A_STRING.findall("sse.onerror = function() {") == []


def test_no_address_is_script():
    address = re.compile(r"""(?:href|src|action)\s*=\s*\\?["']\s*javascript:""", re.I)
    found = [path.name for path in TEMPLATES + SCRIPTS if address.search(_read(path))]
    assert found == [], found


def test_every_name_a_control_uses_is_registered_and_nothing_else_is():
    used, registered = _used(), _registered()
    assert len(used) >= 80, f'only {len(used)} actions found in the markup: the patterns have lost their subject'
    missing = {name: sorted(files) for name, files in used.items() if name not in registered}
    assert missing == {}, f'named by a control and registered nowhere, so the control does nothing: {missing}'
    unused = sorted(registered - set(used))
    assert unused == [], f'registered and named by no control: {unused}'
    names = [name for name, _path, _looked_up in _registrations()]
    twice = sorted({name for name in names if names.count(name) > 1})
    assert twice == [], f'registered more than once, and the last one loaded wins: {twice}'


def test_a_name_is_registered_by_the_file_that_has_the_function():
    """`CertMate.globalActions` looks each name up on `window` when the file
    loads, and throws if it is not there. The function has to be put there by
    the same file, or the page that loads this file without the other one
    stops at that line."""
    wrong = []
    looked_up = [(name, path) for name, path, on_window in _registrations() if on_window]
    assert len(looked_up) >= 70, len(looked_up)             # CONTROL: they were found
    for name, path in looked_up:
        text = _read(path)
        owner, _, function = name.rpartition('.')
        if owner:
            defined = (re.search(rf'window\.{re.escape(owner)}\s*=', text)
                       and re.search(rf'\b{re.escape(function)}\s*:', text))
        else:
            defined = re.search(
                rf'window\.{re.escape(function)}\s*=|(?:^|\n)\s*(?:async\s+)?function\s+{re.escape(function)}\s*\(', text)
        if not defined:
            wrong.append(f'{name} in {path.name}')
    assert wrong == [], wrong


def test_the_arguments_are_json_arrays_and_what_is_passed_is_known():
    arguments = passed = 0
    for path in TEMPLATES:
        text = _read(path)
        for raw in re.findall(r"""data-args='([^']*)'""", text) + re.findall(r'data-args="([^"]*)"', text):
            value = json.loads(html.unescape(raw))
            assert isinstance(value, list), f'{path.name}: data-args is not an array: {raw}'
            arguments += 1
    for path in TEMPLATES + SCRIPTS:
        for raw in re.findall(r"""data-pass=\\?["']([^"'\\]+)""", _read(path)):
            assert {part.strip() for part in raw.split(',')} <= PASSES, f'{path.name}: data-pass="{raw}"'
            passed += 1
    assert arguments >= 40 and passed >= 8, (arguments, passed)     # CONTROL: they were found


def test_a_control_with_arguments_or_something_passed_names_an_action():
    """`data-args` on an element with no `data-click` is a control somebody
    half converted."""
    orphans = []
    for path in TEMPLATES:
        markup = re.sub(r'<script\b.*?</script>', '', _read(path), flags=re.S)
        for tag in re.findall(r'<[a-zA-Z][^<>]*\sdata-(?:args|pass|self)\b[^<>]*>', markup):
            if not re.search(r'\sdata-(?:click|change|input)=', tag):
                orphans.append(f'{path.name}: {tag[:90]}')
    assert orphans == [], orphans
