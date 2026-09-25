"""#939: the inventory page painted every zero as an alarm.

On a healthy instance the page opened on a wall of red and amber zeros —
"Expired 0", "Revoked 0", "Weak 0", "Failing 0", "≤ 7 days 0" — which are the
best states this page can report. And "Modern 0" was painted **green**, which
is the same lie with the other palette: zero modern certificates is not good
news either.

It happened because the colour was written into the tile's `class` attribute,
so it belonged to the **label** rather than to the value:

    <div class="text-xs text-muted">Expired</div>
    <div class="text-xl font-semibold text-danger-fg" id="sumExpired">–</div>

The dashboard already did this correctly and said so in a comment — *"Status
colour is carried onto the counter itself ... so the colour encodes the state,
not just the expired/expiring alarm cases"* — so the two surfaces disagreed
about what a colour meant, and the one that was wrong is the one an operator
opens to check on an estate.

Zero is **neutral**, never green. On an instance that has scanned nothing,
"0 weak" is an absence of evidence rather than an achievement, and the
"nothing checked yet" copy under each table is where that distinction belongs.

The tiles declare the class they earn in `data-nonzero`, so the rule below is
derived from the template: a tile that declares one must be written through
the helper, and a tile added next year is covered without anyone editing a
list — the failure that let #938 through.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / 'templates/inventory.html'
SCRIPT = ROOT / 'static/js/inventory.js'

# id="x" ... data-nonzero="y", in either order on the element.
TILE = re.compile(r'<div[^>]*\bdata-nonzero="(?P<classes>[^"]+)"[^>]*\bid="(?P<id>[^"]+)"'
                  r'|<div[^>]*\bid="(?P<id2>[^"]+)"[^>]*\bdata-nonzero="(?P<classes2>[^"]+)"')


def _coloured_tiles():
    """Every tile that earns a colour, from the template."""
    found = {}
    for match in TILE.finditer(TEMPLATE.read_text(encoding='utf-8')):
        tile_id = match.group('id') or match.group('id2')
        classes = match.group('classes') or match.group('classes2')
        found[tile_id] = classes
    return found


# --- the instrument -------------------------------------------------------

def test_the_template_declares_the_colours():
    """CONTROL: with no tiles found, every rule below is vacuously true."""
    tiles = _coloured_tiles()

    assert len(tiles) >= 10, f'only found {sorted(tiles)}; the scan is broken'
    for expected in ('sumExpired', 'sumRevoked', 'cryptoWeak', 'healthFailing'):
        assert expected in tiles, f'{expected} no longer declares its colour'


def test_a_tile_starts_neutral():
    """The colour has to be absent until the value earns it, or the page still
    opens red — and the placeholder em-dash would be an alarm too."""
    source = TEMPLATE.read_text(encoding='utf-8')
    for tile_id in _coloured_tiles():
        element = re.search(r'<div[^>]*\bid="%s"[^>]*>' % re.escape(tile_id), source)
        assert element, tile_id
        assert 'text-foreground' in element.group(0), (
            f'{tile_id} carries its colour in `class`, so a zero is painted '
            f'with it before any value is loaded')


# --- the rule -------------------------------------------------------------

@pytest.mark.parametrize('tile_id', sorted(_coloured_tiles()))
def test_every_coloured_tile_is_written_through_the_helper(tile_id):
    source = SCRIPT.read_text(encoding='utf-8')

    assert f"setCount('{tile_id}'" in source, (
        f'{tile_id} declares a colour it earns but is not written through '
        f'setCount, so the colour never moves with the value')


@pytest.mark.parametrize('tile_id', sorted(_coloured_tiles()))
def test_no_coloured_tile_is_written_directly(tile_id):
    """Both directions: adding the helper call is not the same as removing the
    assignment that bypasses it, and a file could have both."""
    source = SCRIPT.read_text(encoding='utf-8')
    direct = re.compile(r"el\(\s*'%s'\s*\)\s*\.\s*textContent\s*=" % re.escape(tile_id))

    assert not direct.search(source), (
        f'{tile_id} is still assigned directly, which sets the number and '
        f'leaves the colour where it was')


def test_the_helper_clears_the_colour_as_well_as_setting_it():
    """A count that falls back to zero — the estate was fixed — must stop being
    an alarm. `classList.add` alone would leave it red forever."""
    source = SCRIPT.read_text(encoding='utf-8')
    body = source[source.index('function setCount('):]
    body = body[:body.index('\n    }')]

    assert 'classList.toggle' in body, (
        'setCount adds the class without a condition, so a tile that goes back '
        'to zero keeps the colour it earned')
    assert 'count > 0' in body


def test_the_neutral_class_comes_off_when_the_colour_goes_on():
    """The first fix added the earned class and left the neutral one in place.
    Both are `color` utilities of equal specificity, so the winner is whichever
    Tailwind emits later in the bundle — not whichever was added last to the
    element. "Expired 4" stayed white while "<= 7 days 1" went orange, because
    those two colours sit on opposite sides of `text-foreground` in the
    generated stylesheet.

    `classList.contains` was satisfied the whole time, which is why this is a
    test about the class coming OFF rather than about the class going on: the
    defect is invisible to any assertion that only looks at what was added.
    """
    source = SCRIPT.read_text(encoding='utf-8')
    body = source[source.index('function setCount('):]
    body = body[:body.index('\n    }')]

    assert "classList.toggle('text-foreground', count === 0)" in body, (
        'the neutral colour is never removed, so whether the earned one shows '
        'depends on the order Tailwind happened to emit them in')
