"""None means "no credentials file needed", never "I could not write one".

`create_multi_provider_config` builds the certbot plugin credentials file for
the twelve providers that use one — vultr, hetzner, hetzner-cloud, porkbun,
godaddy, he-ddns, dynudns, desec, scaleway, rfc2136, dnsmadeeasy, nsone. It
ended with

    except (KeyError, Exception):
        return None

and no log line anywhere in that arm.

`_create_config_file` opens the file with O_EXCL and can raise OSError: a
read-only config directory, a full disk, a permission the container lost. For
cloudflare and route53 that OSError propagates and the operator sees it,
because their builders have no such catch. For these twelve it was swallowed
and turned into the same `None` that legitimately means "this provider
authenticates through the environment" — the value `_build_issuance_command`
reads as "add no --credentials flag".

So the certbot command went out with `--authenticator dns-hetzner` and no
`--dns-hetzner-credentials`, certbot failed complaining about missing plugin
credentials, the operator went looking at their DNS account, and the OSError
that actually happened existed in no log, no metric and no response.

The `(KeyError, Exception)` tuple is the tell: someone meant to catch the
template lookup. That is what is caught now; everything else propagates to a
caller that already reports issuance failures with their cause.
"""
import errno
import logging
import stat

import pytest

from modules.core import utils

pytestmark = [pytest.mark.unit]

LOGGER = 'modules.core.utils'

# One provider from the twelve, with a credential set the validator accepts.
PROVIDER = 'hetzner'
CONFIG = {'api_token': 'a-token-that-is-long-enough'}


@pytest.fixture
def in_tmp_cwd(tmp_path, monkeypatch):
    """`_create_config_file` writes to a relative `letsencrypt/config`, so the
    working directory is what decides where these land."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --- the ordinary path is untouched --------------------------------------

def test_a_writable_directory_produces_the_file(in_tmp_cwd):
    path = utils.create_multi_provider_config(PROVIDER, CONFIG)

    assert path is not None and path.exists()
    assert 'dns_hetzner_api_token = a-token-that-is-long-enough' in path.read_text()


def test_the_file_is_owner_only(in_tmp_cwd):
    """CONTROL: it holds a DNS provider's API token."""
    path = utils.create_multi_provider_config(PROVIDER, CONFIG)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize('provider,config', [
    ('cloudflare', {'api_token': 'x'}),          # not a multi-provider plugin
    ('route53', {'access_key_id': 'a', 'secret_access_key': 'b'}),
])
def test_a_provider_that_does_not_use_one_still_returns_none(in_tmp_cwd, provider, config):
    """CONTROL. This None is the legitimate one — it means the plugin needs no
    credentials file — and it must keep meaning that."""
    assert utils.create_multi_provider_config(provider, config) is None


def test_an_unconfigured_account_still_returns_none(in_tmp_cwd):
    """CONTROL. The other legitimate None: nothing to write."""
    assert utils.create_multi_provider_config(PROVIDER, {}) is None


# --- THE regression ------------------------------------------------------

def test_a_directory_that_cannot_be_written_raises_rather_than_returning_none(in_tmp_cwd):
    """The whole point. An OSError here is not "no credentials needed"."""
    config_dir = in_tmp_cwd / 'letsencrypt' / 'config'
    config_dir.mkdir(parents=True)
    config_dir.chmod(0o500)
    try:
        with pytest.raises(OSError) as caught:
            utils.create_multi_provider_config(PROVIDER, CONFIG)
    finally:
        config_dir.chmod(0o700)

    assert caught.value.errno in (errno.EACCES, errno.EPERM)


def test_the_same_failure_already_propagated_for_cloudflare(in_tmp_cwd):
    """The asymmetry that made this a defect rather than a style question: the
    single-provider builders never swallowed it, so one operator saw the error
    and another did not, for the same broken volume."""
    config_dir = in_tmp_cwd / 'letsencrypt' / 'config'
    config_dir.mkdir(parents=True)
    config_dir.chmod(0o500)
    try:
        with pytest.raises(OSError):
            utils.create_cloudflare_config('a-token')
    finally:
        config_dir.chmod(0o700)


def test_a_template_gap_is_reported_and_still_returns_none(in_tmp_cwd, caplog, monkeypatch):
    """The KeyError the tuple was really about: a provider listed as using a
    credentials file with no template to build it from. That is a bug in this
    file, not in the operator's configuration, so it is logged as one — and the
    caller keeps the None it always got."""
    monkeypatch.setitem(utils._MULTI_PROVIDER_PLUGIN_FILES, 'ghost', 'ghost.ini')
    monkeypatch.setitem(utils._DNS_PROVIDER_CREDENTIALS, 'ghost', ['api_token'])

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        result = utils.create_multi_provider_config('ghost', {'api_token': 'x'})

    assert result is None
    assert any(record.args and record.args[0] == 'ghost'
               for record in caplog.records if record.levelno == logging.ERROR), (
        'the template gap was not reported with the provider as an argument')


def test_nothing_is_left_behind_when_the_write_fails(in_tmp_cwd):
    """CONTROL. A half-written credentials file in a directory certbot reads
    would be worse than the error: the token is in it."""
    config_dir = in_tmp_cwd / 'letsencrypt' / 'config'
    config_dir.mkdir(parents=True)
    config_dir.chmod(0o500)
    try:
        with pytest.raises(OSError):
            utils.create_multi_provider_config(PROVIDER, CONFIG)
    finally:
        config_dir.chmod(0o700)

    assert list(config_dir.iterdir()) == []


# --- the shape the caller depends on -------------------------------------

def test_the_twelve_providers_all_go_through_this_builder():
    """A control against the fix drifting: if a provider leaves this map, the
    reasoning above stops applying to it and somebody should notice here."""
    assert set(utils._MULTI_PROVIDER_PLUGIN_FILES) == set(utils._MULTI_PROVIDER_TEMPLATE_MAP)
    assert len(utils._MULTI_PROVIDER_PLUGIN_FILES) == 12


def test_the_builder_no_longer_catches_everything():
    """The source-level pin. The behavioural tests above cover the OSError
    case; this is what fails if a broad catch comes back for a different
    exception nobody thought about.

    The docstring is stripped first: it quotes the old line on purpose, and an
    assertion that reads the prose as code would fail on the explanation of the
    very thing it is checking.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(utils.create_multi_provider_config).lstrip())
    function = tree.body[0]
    if (isinstance(function.body[0], ast.Expr)
            and isinstance(function.body[0].value, ast.Constant)):
        function.body = function.body[1:]
    code = ast.unparse(function)

    assert 'except (KeyError, Exception)' not in code
    assert 'except Exception' not in code
    assert 'except KeyError' in code
