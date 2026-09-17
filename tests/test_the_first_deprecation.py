"""The deprecation mechanism, used for the first time, on the path it was
written for.

modules/api/deprecation.py shipped with `DEPRECATIONS` empty, deliberately:
the alternative was inventing the shape under time pressure in the release
where something had to go, which is the release where it gets skipped. This is
the first entry, and it is the case the module docstring describes.

`/api/dns-providers/accounts` is a second public address for the same
operation as `/api/dns/accounts`: same role, same behaviour, a different
implementation. Nothing in the product calls it. The cost is not that somebody
depends on it; it is that two implementations of one operation can drift and
answer differently, and a caller has no way to tell which one it reached.

The trap this file mostly exists to hold down is that the three paths SHARE a
view function. `DEPRECATIONS` is keyed by `request.endpoint`, so keying on the
shared name would have put Deprecation and Sunset headers on
`/api/web/settings/accounts` as well, which is the dashboard's own call and is
not going anywhere. The deprecated routes carry their own endpoint names for
exactly that reason, and the control below is the one that would catch it
coming back.
"""
import pathlib
import re
import secrets

import pytest

from modules.api.deprecation import DEPRECATIONS

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent

DEPRECATED = '/api/dns-providers/accounts'
CANONICAL = '/api/dns/accounts'
DASHBOARD = '/api/web/settings/accounts'


@pytest.fixture(scope='module')
def app():
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
    return result[0] if isinstance(result, tuple) else result


def test_the_deprecated_path_announces_itself(app):
    response = app.test_client().get(DEPRECATED)

    assert 'Deprecation' in response.headers, (
        f'{DEPRECATED} is in DEPRECATIONS and says nothing about it'
    )
    assert response.headers['Deprecation'].startswith('@'), (
        'RFC 9745 wants @<unix seconds>, not a date string'
    )
    assert 'Sunset' in response.headers
    assert 'rel="deprecation"' in response.headers.get('Link', '')


def test_the_dashboard_path_is_not_deprecated(app):
    """The control. These three paths share a view function, so keying the
    deprecation on the shared endpoint name would announce that the
    dashboard's own call is going away."""
    response = app.test_client().get(DASHBOARD)

    assert 'Deprecation' not in response.headers, (
        f'{DASHBOARD} is the dashboard calling itself and is not going '
        f'anywhere, but it is announcing a sunset'
    )
    assert 'Sunset' not in response.headers


def test_the_replacement_is_not_deprecated(app):
    response = app.test_client().get(CANONICAL)

    assert 'Deprecation' not in response.headers, (
        f'{CANONICAL} is what the deprecation tells people to use'
    )


def test_the_announcement_survives_a_refusal(app):
    """These requests carry no credential, so they are refused, and the
    headers are on the refusal. That is deliberate: a client learns the
    endpoint is going away from any response, including the one it is trying
    to understand."""
    response = app.test_client().get(DEPRECATED)

    assert response.status_code in (401, 403)
    assert 'Deprecation' in response.headers


def test_the_replacement_is_named_in_the_note():
    """A deprecation that does not say what to use instead is an announcement
    that the endpoint is going away and nothing else."""
    for name, entry in DEPRECATIONS.items():
        assert entry.get('note'), f'{name} has no note saying what to use instead'
        assert '/api/' in entry['note'], (
            f'{name}: the note does not name a replacement endpoint'
        )
        assert entry.get('link'), f'{name} has no link'


def test_the_link_points_at_a_section_that_exists():
    """The Link header sends a caller to docs/api.md. A fragment naming a
    heading that is not there is a link to the top of a 1,400-line file."""
    reference = (REPO / 'docs' / 'api.md').read_text(encoding='utf-8')
    headings = {
        re.sub(r'[^a-z0-9]+', '-', line.lstrip('#').strip().lower()).strip('-')
        for line in reference.splitlines() if line.startswith('#')
    }
    for name, entry in DEPRECATIONS.items():
        link = entry.get('link', '')
        if '#' not in link:
            continue
        fragment = link.rsplit('#', 1)[1]
        assert fragment in headings, (
            f'{name}: the link points at #{fragment}, and docs/api.md has no '
            f'heading with that anchor'
        )
