"""#854: the certificates table never said which CA issued anything.

It had a Provider column, and that column meant the *DNS* provider. An operator
running a private CA alongside Let's Encrypt — which is the whole reason the
private-CA support exists — could not tell an internally-trusted certificate
from a publicly-trusted one by looking at the dashboard. The data was already
there: `ca_provider` is written into metadata at issuance and carried all the
way out through `certificate_model`. Only the page ignored it.

**These tests run the shipped JavaScript.** The rest of this repository checks
front-end behaviour by reading the source, which is how a column can be
"covered" by a test that would pass just as happily if the cell rendered
nothing. `caDisplayName` and its map are sliced out of `static/js/dashboard.js`
and evaluated in node together with the real `escapeHtml` from
`static/js/certmate.js`, so what is asserted here is what the browser runs.

The structural half is still source inspection, because the row template is a
JavaScript template literal and the header is Jinja — but it checks the one
thing that inspection can prove and that nobody had been proving: that the
header, the rows and the full-width states agree on how many columns exist.
They did not. The skeleton rows said `colspan="7"` for a six-column table
before this change.
"""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

from modules.core.ca_manager import CAManager

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD_JS = (REPO / 'static' / 'js' / 'dashboard.js').read_text(encoding='utf-8')
CERTMATE_JS = (REPO / 'static' / 'js' / 'certmate.js').read_text(encoding='utf-8')
INDEX_HTML = (REPO / 'templates' / 'index.html').read_text(encoding='utf-8')


def _ca_block():
    """`CA_NAMES` and `caDisplayName`, lifted out of dashboard.js verbatim.

    Sliced between two named markers rather than matched by a regex over the
    function body: if either marker moves, this raises instead of quietly
    capturing the wrong region and testing nothing.
    """
    start = DASHBOARD_JS.index('var CA_NAMES = {')
    end = DASHBOARD_JS.index('var CA_NOT_RECORDED')
    return DASHBOARD_JS[start:end]


def _escape_html():
    """The real escaper, not a stand-in — half of what is under test here is
    that the CA label cannot carry markup out of metadata."""
    match = re.search(r'CM\.escapeHtml = (function\(str\) \{.*?\n    \};)',
                      CERTMATE_JS, re.S)
    assert match, 'CM.escapeHtml not found in static/js/certmate.js'
    return 'var escapeHtml = ' + match.group(1) + '\n'


def _run(expression):
    """Evaluate *expression* against the shipped code and return the result."""
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not available')
    script = (_escape_html() + _ca_block()
              + '\nconsole.log(JSON.stringify(' + expression + '));')
    result = subprocess.run([node, '-e', script], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# ── what the browser actually computes ───────────────────────────────


def test_the_extracted_block_is_the_real_one():
    """Guard the guard: an empty or truncated slice would make every
    assertion below pass against nothing."""
    block = _ca_block()
    assert 'function caDisplayName' in block
    assert "'private_ca'" in block
    assert len(block) > 300


def test_every_ca_certmate_issues_with_has_a_name_on_the_dashboard():
    """The drift guard, executed rather than grepped.

    A CA added to `CAManager.ca_providers` and not here would render as its
    bare key — `sslcom` instead of SSL.com — which is the state the DNS side
    of this page was in before `test_ca_provider_wiring_consistency`.
    """
    expected = {key: info['name']
                for key, info in CAManager(settings_manager=None).ca_providers.items()}
    got = _run('(' + json.dumps(list(expected)) + ').reduce('
               'function (acc, k) { acc[k] = caDisplayName(k); return acc; }, {})')
    # The dashboard escapes for HTML; compare like for like.
    escaped = {k: v.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                   .replace('"', '&quot;').replace("'", '&#39;')
               for k, v in expected.items()}
    assert got == escaped


def test_a_certificate_with_no_recorded_ca_gets_no_name():
    """Certificates issued before CertMate stored the CA have nothing to
    show. Defaulting to the common answer would put a "Let's Encrypt" label
    on a private-CA certificate — a guess, rendered as a fact, for exactly
    the operator who opened #854."""
    assert _run("[caDisplayName(''), caDisplayName(null), "
                "caDisplayName(undefined)]") == ['', '', '']


def test_a_ca_this_build_does_not_know_is_shown_not_swallowed():
    """Metadata naming an unrecognised CA is still evidence about that
    certificate. Hiding it would leave the row exactly as uninformative as
    before."""
    assert _run("caDisplayName('buypass')") == 'buypass'


def test_the_label_cannot_carry_markup_out_of_metadata():
    """`ca_provider` comes from a JSON file on disk that the API can write.
    The cell interpolates the label with escaping deliberately opted out
    (`rowRaw`), so the escaping has to have happened here."""
    hostile = '<img src=x onerror=alert(1)>'
    label = _run('caDisplayName(' + json.dumps(hostile) + ')')
    assert '<' not in label and '>' not in label
    assert label == '&lt;img src=x onerror=alert(1)&gt;'


# ── the column exists, and the table agrees with itself ──────────────


def _certificates_thead():
    table = INDEX_HTML[INDEX_HTML.index('id="certificatesTable"'):]
    return table[table.index('<thead'):table.index('</thead>')]


def _row_templates():
    """The two `<tr>` templates `displayCertificates` builds, by name."""
    body = DASHBOARD_JS[DASHBOARD_JS.index('function displayCertificates'):
                        DASHBOARD_JS.index('function certDetailSkeletonHtml')]
    rows = re.findall(r'rowHtml`(<tr\b.*?</tr>)`', body, re.S)
    assert len(rows) == 2, f'expected the missing-cert row and the normal row, got {len(rows)}'
    return rows


def test_the_table_has_a_ca_column():
    thead = _certificates_thead()
    assert 'id="sort-th-ca"' in thead
    assert "sortCertificates('ca')" in thead


def test_every_sortable_header_has_the_ids_the_sort_code_looks_up():
    """`sortCertificates` finds the glyph and the aria-sort target by
    `sort-icon-<field>` and `sort-th-<field>`. A field name that does not
    match its ids sorts correctly and silently stops announcing itself —
    working code, broken for anyone using a screen reader."""
    thead = _certificates_thead()
    for field in re.findall(r"sortCertificates\('(\w+)'\)", thead):
        assert f'id="sort-th-{field}"' in thead, field
        assert f'id="sort-icon-{field}"' in thead, field


def test_the_sort_comparator_knows_the_field_the_header_sends():
    """A header wired to a field `applySorting` does not handle returns 0 for
    every pair: the click lands, the arrow moves, nothing reorders."""
    comparator = DASHBOARD_JS[DASHBOARD_JS.index('function applySorting'):]
    comparator = comparator[:comparator.index('\n    }')]
    for field in re.findall(r"sortCertificates\('(\w+)'\)", _certificates_thead()):
        assert f"field === '{field}'" in comparator, (
            f"the {field} header sorts by nothing: applySorting has no branch for it"
        )


def test_the_header_and_the_rows_have_the_same_number_of_cells():
    """The check that was missing. Adding a column to the template and not to
    the row template shifts every cell after it one place to the left, which
    renders without error and reads as data under the wrong heading."""
    columns = len(re.findall(r'<th\b', _certificates_thead()))
    for row in _row_templates():
        assert len(re.findall(r'<td\b', row)) == columns, (
            f'the header has {columns} columns and this row has '
            f'{len(re.findall(r"<td\\b", row))}:\n{row[:200]}'
        )


def test_the_full_width_states_span_the_whole_table():
    """The skeleton and the two empty states are single cells meant to cover
    every column. The skeleton said 7 while the table had 6."""
    columns = len(re.findall(r'<th\b', _certificates_thead()))
    spans = (re.findall(r'colspan="(\d+)"', INDEX_HTML)
             + re.findall(r"data-empty-state><td colspan=\"(\d+)\"", DASHBOARD_JS))
    assert spans, 'no full-width rows found — this test is checking nothing'
    assert {int(s) for s in spans} == {columns}


@pytest.mark.parametrize('page', ['ca-providers.md', 'it/ca-providers.md'])
def test_the_page_that_promises_the_column_is_kept_honest(page):
    """`docs/ca-providers.md` used to send operators to the API response or the
    metadata file to find out which CA a fallback had actually used, because
    the interface could not tell them. It now points at this column. If the
    column goes, that sentence becomes the kind of claim #876 is a list of."""
    text = (REPO / 'docs' / page).read_text(encoding='utf-8')
    assert '**CA**' in text, f'docs/{page} no longer names the column'
    assert 'id="sort-th-ca"' in INDEX_HTML


def test_the_row_renders_the_ca_the_api_returns():
    """`ca_provider` is the field name in `certificate_model`; a row reading
    anything else would render an empty column against a populated API."""
    for row_source in _row_templates():
        assert 'caCell' in row_source
    assert 'caDisplayName(cert.ca_provider)' in DASHBOARD_JS
