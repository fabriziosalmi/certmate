"""create builds its certbot command in one place (#666).

There were three: `ca_manager.build_certbot_command`, a TypeError fallback
"for an older build_certbot_command" that retried the call without SANs or key
flags, and a hand-built argv for Let's Encrypt with no saved CA config. Both
builders live in this repository, so the fallback's only reachable effect was
to retry past a real TypeError; and the command-contract test pinned only the
hand-built argv, not the one production runs.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.core.ca_manager import CAManager
from modules.core.shell import MockShellExecutor
from tests.test_caa import _cert_mgr


def _shell(returncode, stderr=''):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=returncode, stderr=stderr)
    return shell


def _manager(tmp_path, shell):
    mgr = _cert_mgr(tmp_path, shell)
    mgr._caa_explanation = lambda *a, **k: ''
    return mgr


def _create(mgr):
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(RuntimeError) as err:
            mgr.create_certificate(domain='www.example.com', email='t@example.com',
                                   dns_provider='duckdns', ca_provider='letsencrypt')
    return str(err.value)

pytestmark = [pytest.mark.unit]


def test_a_type_error_inside_the_builder_surfaces_instead_of_being_retried(tmp_path):
    mgr = _manager(tmp_path, _shell(0))
    calls = []

    def broken(*args, **kwargs):
        calls.append(kwargs)
        raise TypeError('a genuine defect inside the builder')

    mgr.ca_manager.get_ca_config.return_value = ({'email': 'a@example.com'}, 'default')
    mgr.ca_manager.build_certbot_command = broken
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(TypeError, match='a genuine defect inside the builder'):
            mgr.create_certificate(domain='www.example.com', email='t@example.com',
                                   dns_provider='duckdns', ca_provider='letsencrypt')
    assert len(calls) == 1, 'the builder was called again after it raised'


def test_no_saved_config_goes_through_the_same_builder(tmp_path):
    """Let's Encrypt with nothing saved: the builder is called with an empty
    account, not bypassed."""
    mgr = _manager(tmp_path, _shell(1, stderr='stop here'))
    real = CAManager(MagicMock())
    spy = MagicMock(side_effect=real.build_certbot_command)
    mgr.ca_manager.get_ca_config.return_value = (None, None)
    mgr.ca_manager.build_certbot_command = spy
    _create(mgr)
    assert spy.call_count == 1
    account = spy.call_args.args[5]
    assert account == {}


def test_without_a_ca_manager_the_command_names_its_directory(tmp_path):
    mgr = _manager(tmp_path, _shell(1, stderr='stop here'))
    mgr.ca_manager = None
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(RuntimeError):
            mgr.create_certificate(domain='www.example.com', email='t@example.com',
                                   dns_provider='duckdns', ca_provider='letsencrypt')
    cmd = mgr.shell_executor.commands_executed[0].split()
    assert cmd[cmd.index('--server') + 1] == 'https://acme-v02.api.letsencrypt.org/directory'
