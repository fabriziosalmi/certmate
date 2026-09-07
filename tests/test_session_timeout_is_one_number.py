"""SESSION_TIMEOUT_HOURS must reach the cookie, not just the server (#590).

The session lifetime existed as three different numbers:

    constants.py    DEFAULT_SESSION_TIMEOUT_HOURS = 24   (read by nobody)
    auth.py:107     os.getenv('SESSION_TIMEOUT_HOURS', '8')
    auth_routes.py  max_age=8 * 60 * 60                  (hardcoded)
    oidc_routes.py  max_age=8 * 60 * 60                  (hardcoded)

Only the second was configurable, and it governed only the server-side record.
The cookie the browser actually holds was pinned at eight hours regardless. So
an operator who set `SESSION_TIMEOUT_HOURS=24` was still logged out after eight
— the setting is read, documented, and does not do what it says. Setting it
*shorter* is the less visible half: the server rejects the session on time, but
the browser keeps presenting a dead id until its own eight hours are up.

The tests assert the property rather than the constant: whatever the operator
configures, the server record and the cookie agree.
"""
import pytest

from modules.core import constants
from modules.core.auth import AuthManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_manager(tmp_path):
    from modules.core.file_operations import FileOperations
    from modules.core.settings import SettingsManager

    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    manager = SettingsManager(FileOperations(*dirs), dirs[1] / 'settings.json')
    manager.load_settings()
    return manager


# ---------------------------------------------------------------------------
# One number
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('hours', [1, 8, 24])
def test_the_configured_value_drives_the_session_lifetime(
        settings_manager, monkeypatch, hours):
    monkeypatch.setenv('SESSION_TIMEOUT_HOURS', str(hours))
    auth = AuthManager(settings_manager)

    assert auth.session_timeout_seconds == hours * 60 * 60


def test_the_default_comes_from_constants(settings_manager, monkeypatch):
    """The point of a constants module. Before this, constants.py said 24 while
    the code used 8 and nothing read the file."""
    monkeypatch.delenv('SESSION_TIMEOUT_HOURS', raising=False)
    auth = AuthManager(settings_manager)

    assert auth.session_timeout_seconds == (
        constants.DEFAULT_SESSION_TIMEOUT_HOURS * 60 * 60)


def test_constants_records_the_value_the_code_actually_uses(
        settings_manager, monkeypatch):
    """CONTROL. The two assertions above would both pass if constants.py were
    edited to any value and auth.py followed it — which is right — but the
    declared default must also be the one shipped installs have been running.
    That is 8, not the 24 the file claimed.
    """
    assert constants.DEFAULT_SESSION_TIMEOUT_HOURS == 8


def test_a_nonsense_value_does_not_produce_a_zero_length_session(
        settings_manager, monkeypatch):
    """`max(1, ...)` was already there; keep it. A zero or negative timeout
    would expire every session at creation and lock everyone out."""
    monkeypatch.setenv('SESSION_TIMEOUT_HOURS', '0')
    auth = AuthManager(settings_manager)

    assert auth.session_timeout_seconds >= 60 * 60


# ---------------------------------------------------------------------------
# It reaches the cookie
# ---------------------------------------------------------------------------

def _cookie_max_age(response, name='certmate_session'):
    for header in response.headers.getlist('Set-Cookie'):
        if header.startswith(name + '='):
            for part in header.split(';'):
                part = part.strip()
                if part.lower().startswith('max-age='):
                    return int(part.split('=', 1)[1])
    return None


@pytest.mark.parametrize('hours', [1, 24])
def test_the_login_cookie_expires_when_the_session_does(
        tmp_path, monkeypatch, hours):
    """The reported defect: the cookie ignored the setting entirely."""
    from pathlib import Path

    monkeypatch.setenv('SESSION_TIMEOUT_HOURS', str(hours))
    project_root = tmp_path / 'certmate'
    module_dir = project_root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    (module_dir / 'factory.py').write_text('# test path anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__',
                        str(module_dir / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')

    from modules.core.factory import create_app
    app, container = create_app()
    assert Path(container.cert_dir).resolve().is_relative_to(tmp_path)

    client = app.test_client()
    client.post('/api/web/settings/users', json={
        'username': 'admin', 'password': 'Password123!', 'role': 'admin'})
    client.post('/api/auth/config', json={'local_auth_enabled': True})
    resp = client.post('/api/auth/login', json={
        'username': 'admin', 'password': 'Password123!'})

    assert resp.status_code == 200, resp.get_json()
    max_age = _cookie_max_age(resp)
    assert max_age == hours * 60 * 60, (
        f'SESSION_TIMEOUT_HOURS={hours} but the cookie lives {max_age}s; the '
        f'setting is read by the server and ignored by the browser'
    )


def test_both_cookie_mint_sites_use_the_configured_lifetime():
    """OIDC mints the same cookie in a second place, and its comment says it
    matches the local-login one "verbatim" — which is exactly how a hardcoded
    duration gets copied. Asserted on the source so a new mint site cannot
    reintroduce the literal.
    """
    import inspect
    import re

    from modules.web import auth_routes, oidc_routes

    for module in (auth_routes, oidc_routes):
        src = inspect.getsource(module)
        assert 'certmate_session' in src, f'{module.__name__} mints no session'
        literals = re.findall(r'max_age\s*=\s*(\d+\s*\*\s*\d+\s*\*\s*\d+)', src)
        assert not literals, (
            f'{module.__name__} hardcodes the session cookie lifetime '
            f'({literals}); it must follow SESSION_TIMEOUT_HOURS'
        )


# ---------------------------------------------------------------------------
# The rest of the file
# ---------------------------------------------------------------------------

def test_every_default_in_constants_has_a_reader():
    """A constants file that nothing reads is worse than none: it documents
    values the code does not use. Five of them had zero readers.

    `_FILESYSTEM_ARTIFACT_DIR_NAMES` is deliberately exempt — it is
    underscore-private and read inside its own module, which is what a private
    constant looks like rather than a defect.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    source = constants.__file__
    declared = [
        name for name in vars(constants)
        if name.isupper() and not name.startswith('_')
    ]

    unread = []
    for name in declared:
        found = False
        for path in root.glob('modules/**/*.py'):
            if str(path) == source:
                continue
            if re.search(rf'\b{name}\b', path.read_text()):
                found = True
                break
        if not found:
            unread.append(name)

    assert not unread, (
        f'these constants are declared and read by nothing, so they document '
        f'values the code does not use: {sorted(unread)}'
    )
