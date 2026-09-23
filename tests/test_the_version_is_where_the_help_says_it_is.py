"""The version an operator is told to look for is actually there.

`templates/help.html` has said, under *what to include when reporting a
problem*, that the CertMate version is in "the footer of every page, or
`/health`". Half of that was true: `/health` returns it, and there was no
footer on any page. #855 is an operator who went looking for it.

So the footer exists now, and this checks it on every page rather than on the
one that was most convenient to render — a version injected per view is a
version the next page forgets.

`/api/health` is checked too, and for a reason worth stating: the
unauthenticated `/health` carried the version while the authenticated API path
did not, so a client polling the documented endpoint could not see what it was
talking to.
"""
import re

import pytest

from modules import __version__

pytestmark = [pytest.mark.unit]

# Rendered without a credential where that is possible; the rest are driven
# with one. Listed explicitly rather than discovered, so a page added later
# shows up here as a decision rather than as silence.
PAGES = ['/', '/settings', '/inventory', '/activity', '/notifications', '/help']


@pytest.fixture(scope='module')
def client(tmp_path_factory):
    """The real app, rendering the real templates, built once.

    Two things this fixture works around, both of them the code being right:

    `factory.__file__` is NOT redirected, unlike the API-only fixtures in this
    suite. Moving it points Flask's template folder at a temporary directory
    and every page 500s with `TemplateNotFound`. The data directories are
    redirected instead, so nothing is written outside the tmp path.

    And it is module-scoped because the login rate limiter is process-global
    state — correctly, it is a per-IP limit — so signing in once per test
    returns 429 partway through the file.
    """
    import secrets

    from modules.core.factory import create_app

    tmp_path = tmp_path_factory.mktemp('version')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp_path / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
        application, container = create_app()
        container.managers['auth'].create_user(
            'ops', 'Str0ng-Passw0rd-For-A-Test!', 'admin')
        container.managers['auth'].enable_local_auth(True)
        test_client = application.test_client()
        # Signed in: an anonymous request is redirected to login.html, the one
        # page that does not extend base.html, so an anonymous run would test
        # the login screen six times over.
        signed_in = test_client.post(
            '/api/auth/login',
            json={'username': 'ops', 'password': 'Str0ng-Passw0rd-For-A-Test!'})
        assert signed_in.status_code == 200, signed_in.get_data(as_text=True)
        yield test_client


def test_the_version_under_test_is_a_version():
    """Guard the guard: an empty string would be 'in' every page."""
    assert re.fullmatch(r'\d+\.\d+\.\d+', __version__), __version__


@pytest.mark.parametrize('path', PAGES)
def test_every_page_shows_the_version(client, path):
    response = client.get(path, follow_redirects=True)
    assert response.status_code == 200, f'{path} did not render'
    body = response.get_data(as_text=True)
    assert f'v{__version__}' in body, (
        f'{path} renders without the version. help.html tells operators to '
        f'find it in the footer of every page.'
    )


@pytest.mark.parametrize('path', PAGES)
def test_the_version_is_in_a_footer_not_merely_somewhere(client, path):
    """`in body` would pass for a version hidden in a script tag or a
    comment. The claim is that it is visible at the bottom of the page."""
    body = client.get(path, follow_redirects=True).get_data(as_text=True)
    footer = re.search(r'<footer\b(?P<attrs>[^>]*)>(?P<inner>.*?)</footer>', body, re.S)
    assert footer, f'{path} has no footer'
    assert __version__ in footer.group('inner')
    # A rendered-HTML test cannot prove the footer is visible — that is
    # checked in a browser — but it can refuse the trivial way to hide it,
    # which a mutation that added `hidden` to the tag otherwise survived.
    attrs = footer.group('attrs')
    assert 'hidden' not in attrs, f'{path} renders the footer hidden'
    assert 'display:none' not in attrs.replace(' ', '')


def test_a_page_that_forgets_to_pass_it_still_has_it(client):
    """The point of a context processor rather than a per-view argument: no
    view passes `certmate_version`, and every page has it anyway."""
    import pathlib

    repo = pathlib.Path(__file__).resolve().parent.parent
    passed_by_hand = [
        path for path in (repo / 'modules' / 'web').glob('*.py')
        if 'certmate_version=' in path.read_text(encoding='utf-8')
    ]
    assert not passed_by_hand, (
        f'{passed_by_hand} passes the version by hand; it comes from the '
        f'context processor so a new page cannot omit it'
    )


def test_the_help_page_no_longer_promises_something_absent(client):
    """The claim that started this. It said footer *or* /health; both are
    true now, and if the footer is ever removed this fails rather than the
    sentence quietly going stale again."""
    body = client.get('/help', follow_redirects=True).get_data(as_text=True)
    assert 'footer of every page' in body
    assert re.search(r'<footer\b', body)


def test_health_reports_the_version(client):
    """Unauthenticated, and it always did — the half of help.html's claim
    that was true."""
    assert client.get('/health').get_json()['version'] == __version__
