"""Every endpoint the product serves must be findable in its documentation.

tests/test_advertised_endpoints_exist.py asks one direction: does every
endpoint the documentation advertises actually exist. It was written after a
`GET /{domain}/tls` that appeared twice in the README and returned 404, and it
is the right question.

It is not the only one. Nothing ever asked the reverse — is every endpoint that
exists written down anywhere — and the answer was that **49 of 102** `/api/`
routes were named in no document at all: not the README, not
`docs/api.md`, not the in-product help page. `GET /api/health` among them, on a
product people run in Kubernetes.

A gate that only checks one direction reads like coverage and is half of it.

The rule here is absolute rather than a ratchet, unlike the exception budget.
Growth in the API surface is normal and expected; growth in the *undocumented*
surface is not, and there is no number of undocumented endpoints that is the
right number. The remedy is also cheap: naming the path in `docs/api.md` is a
line.

`/api/web/` is excluded, with the reason rather than by habit. Those are the
dashboard's own calls, bound in `modules/web/` beside the pages that make them
and deliberately kept out of the flask-restx surface that generates
`/api/swagger.json` — `modules/web/cert_routes.py` says so where it explains
why the bare `/api/certificates/create` binding was removed and only the
`/api/web/...` one kept. They are reachable, so they are not secret; they are
not the interface the product offers to clients, and documenting them as though
they were would tell a reader to build against the dashboard.
"""
import pathlib
import re
import secrets

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent

# Where an endpoint may be written down. Four places rather than one because
# the product genuinely documents in four: the README is where most people
# look first, docs/api.md is the reference, the Docker Hub page is what someone
# reads before pulling, and the help page is in the product.
DOCUMENTS = (
    'README.md',
    'README.dockerhub.md',
    'docs/api.md',
    'templates/help.html',
)

# The dashboard's own surface; see the module docstring.
INTERNAL_PREFIX = '/api/web/'


def _normalise(path):
    """`/api/x/<string:id>/y` and `/api/x/{id}/y` name the same route."""
    path = re.sub(r'<[^>]+>', '<X>', path)
    path = re.sub(r'\{[^}]+\}', '<X>', path)
    return path.rstrip('/') or '/'


@pytest.fixture(scope='module')
def url_map():
    """The route table, built under a temporary root.

    Same anchoring trick as tests/test_advertised_endpoints_exist.py:
    `setup_directories()` creates data/, certificates/ and logs/ relative to
    `modules.core.factory.__file__`, so a test that only wants to read routes
    would otherwise write into the working tree.
    """
    import tempfile

    root = pathlib.Path(tempfile.mkdtemp()) / 'certmate'
    module_dir = root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    anchor = module_dir / 'factory.py'
    anchor.write_text('# test path anchor\n', encoding='utf-8')

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('TESTING', 'true')
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
        from modules.core.factory import create_app
        patch.setattr('modules.core.factory.__file__', str(anchor))
        result = create_app()
    app = result[0] if isinstance(result, tuple) else result
    return sorted({_normalise(str(rule)) for rule in app.url_map.iter_rules()})


@pytest.fixture(scope='module')
def documented():
    """Every /api/ path any document mentions, normalised."""
    found = set()
    for name in DOCUMENTS:
        path = REPO / name
        if not path.exists():
            continue
        text = path.read_text(encoding='utf-8')
        for match in re.finditer(r'/api/[A-Za-z0-9_{}<>:./-]*', text):
            found.add(_normalise(match.group(0).rstrip('.,);:')))
    return found


def _is_covered(route, documented):
    """Segment-wise, so a worked example with a real value counts.

    `/api/certificates/example.com/download` documents
    `/api/certificates/<X>/download`. A placeholder matches exactly one
    segment; letting it span several would make almost anything match and this
    file would prove nothing.

    Only the ROUTE's placeholder may stand for a documented value, never the
    other way round. It used to be symmetric, and then `/api/certificates/{domain}`
    in docs/api.md "documented" every literal sibling of it: `check-dns-alias`,
    `check-caa`, and anything else added under /api/certificates/ with a fixed
    name. Four real endpoints sat undocumented behind that, green, until
    test_a_documented_placeholder_does_not_cover_a_literal_route pinned it.
    """
    wanted = route.strip('/').split('/')
    for candidate in documented:
        parts = candidate.strip('/').split('/')
        if len(parts) != len(wanted):
            continue
        if all(w == '<X>' or p == w
               for p, w in zip(parts, wanted)):
            return True
    return False


def test_a_documented_placeholder_does_not_cover_a_literal_route():
    documented = {'/api/certificates/<X>', '/api/certificates/<X>/download'}
    # A worked example still documents the parameterised route...
    assert _is_covered('/api/certificates/<X>', {'/api/certificates/example.com'})
    assert _is_covered('/api/certificates/<X>/download', documented)
    # ...but a placeholder in the document says nothing about a fixed name.
    assert not _is_covered('/api/certificates/check-dns-alias', documented)
    assert not _is_covered('/api/certificates/<X>/deploy', {'/api/certificates/<X>/<X>'})


def test_every_public_api_route_is_written_down(url_map, documented):
    public = [r for r in url_map
              if r.startswith('/api/') and not r.startswith(INTERNAL_PREFIX)]
    missing = [r for r in public if not _is_covered(r, documented)]

    assert not missing, (
        f'{len(missing)} of {len(public)} public /api/ routes are named in no '
        f'document ({", ".join(DOCUMENTS)}). A reader cannot use what nothing '
        f'mentions, and a client generated from the reference will not know '
        f'these exist:\n  ' + '\n  '.join(missing)
    )


def test_the_route_table_is_not_empty(url_map):
    """CONTROL for the instrument. If the app stopped being built, or the
    prefix filter stopped matching, the list above would be empty and the real
    assertion would pass by having nothing to check."""
    public = [r for r in url_map
              if r.startswith('/api/') and not r.startswith(INTERNAL_PREFIX)]

    assert len(public) > 60, (
        f'only {len(public)} public /api/ routes found, which cannot be true '
        f'of this application: the measurement is broken, not the tree'
    )


def test_the_documents_are_actually_read(documented):
    """CONTROL for the other half. An extractor that returned nothing would
    report every route as undocumented, which fails loudly — but one that
    matched too much would report everything as covered, which fails
    silently."""
    assert len(documented) > 30, (
        f'only {len(documented)} /api/ paths extracted from '
        f'{len(DOCUMENTS)} documents; the extractor is not reading them'
    )
    assert '/api/certificates' in documented
