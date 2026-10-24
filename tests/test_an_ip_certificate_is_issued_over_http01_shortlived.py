"""An IP-address certificate is issued with --ip-address, over HTTP-01, in the
short-lived profile (#1130).

Let's Encrypt issues a certificate for an IP address only in the short-lived
profile and only over HTTP-01. The identifier is passed to certbot as
``--ip-address``, not ``-d`` (which is for DNS names), and the certificate's
name on disk is the derived ``ip-<dashed>`` segment (utils.cert_name_for_ip),
since an IP cannot be a lineage name. These tests pin the command the builder
emits and the request shape ``create_certificate`` forces and refuses.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.core.ca_manager import CAManager
from modules.core.shell import MockShellExecutor
from tests.test_caa import _cert_mgr

pytestmark = [pytest.mark.unit]


def _shell(returncode, stderr=''):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=returncode, stderr=stderr)
    return shell


def _manager(tmp_path, shell):
    mgr = _cert_mgr(tmp_path, shell)
    mgr._caa_explanation = lambda *a, **k: ''
    return mgr


# --- the command builder, in isolation -------------------------------------

def test_an_ip_goes_in_ip_address_not_dash_d(tmp_path):
    mgr = CAManager(MagicMock())
    cmd, _env = mgr.build_certbot_command(
        'ip-1-1-1-1', 't@example.com', 'letsencrypt', 'http-01', {}, {},
        staging=False, cert_dir=tmp_path, acme_profile='shortlived',
        ip_address='1.1.1.1')
    assert '--ip-address' in cmd
    assert cmd[cmd.index('--ip-address') + 1] == '1.1.1.1'
    # -d is for DNS names: an IP certificate must not carry one.
    assert '-d' not in cmd
    # The lineage name stays the --cert-name and the config dir.
    assert cmd[cmd.index('--cert-name') + 1] == 'ip-1-1-1-1'
    assert cmd[cmd.index('--required-profile') + 1] == 'shortlived'


def test_a_dns_name_still_goes_in_dash_d(tmp_path):
    """The IP branch must not change the ordinary DNS-name command."""
    mgr = CAManager(MagicMock())
    cmd, _env = mgr.build_certbot_command(
        'www.example.com', 't@example.com', 'letsencrypt', 'cloudflare', {}, {},
        staging=False, cert_dir=tmp_path)
    assert '--ip-address' not in cmd
    assert cmd[cmd.index('-d') + 1] == 'www.example.com'


# --- the request shape create_certificate forces for an IP -------------------

def test_create_issues_an_ip_with_ip_address_http01_and_shortlived(tmp_path):
    """End to end through create_certificate: the raw address reaches certbot as
    --ip-address, the derived name is the --cert-name, the profile is forced to
    short-lived and the challenge to HTTP-01 webroot."""
    mgr = _manager(tmp_path, _shell(1, stderr='stop here'))
    mgr.ca_manager = None  # exercise the real builder
    with patch('modules.core.certificates.acme_webroot_dir', return_value=tmp_path):
        with pytest.raises(RuntimeError):
            mgr.create_certificate(domain='1.1.1.1', email='t@example.com',
                                   ca_provider='letsencrypt')
    cmd = mgr.shell_executor.commands_executed[0].split()
    assert cmd[cmd.index('--ip-address') + 1] == '1.1.1.1'
    assert '-d' not in cmd
    assert cmd[cmd.index('--cert-name') + 1] == 'ip-1-1-1-1'
    assert cmd[cmd.index('--required-profile') + 1] == 'shortlived'
    assert '--webroot' in cmd


def test_an_ip_refuses_dns_01(tmp_path):
    mgr = _manager(tmp_path, _shell(0))
    with pytest.raises(ValueError, match='HTTP-01 only'):
        mgr.create_certificate(domain='1.1.1.1', email='t@example.com',
                               ca_provider='letsencrypt', challenge_type='dns-01')


def test_an_ip_refuses_san_domains(tmp_path):
    mgr = _manager(tmp_path, _shell(0))
    with pytest.raises(ValueError, match='single address'):
        mgr.create_certificate(domain='1.1.1.1', email='t@example.com',
                               ca_provider='letsencrypt', san_domains=['example.com'])


def test_an_ip_refuses_a_dns_alias(tmp_path):
    mgr = _manager(tmp_path, _shell(0))
    with pytest.raises(ValueError, match='DNS alias'):
        mgr.create_certificate(domain='1.1.1.1', email='t@example.com',
                               ca_provider='letsencrypt',
                               domain_alias='validation.example.org')


def test_an_ip_refuses_a_non_shortlived_profile(tmp_path):
    mgr = _manager(tmp_path, _shell(0))
    with pytest.raises(ValueError, match='shortlived'):
        mgr.create_certificate(domain='1.1.1.1', email='t@example.com',
                               ca_provider='letsencrypt', acme_profile='classic')


@pytest.mark.parametrize('addr', ['10.0.0.1', '127.0.0.1', '192.0.2.1',
                                   '224.0.0.1', '::1', '2001:db8::1'])
def test_an_unroutable_or_ipv6_address_is_refused_before_issuance(tmp_path, addr):
    """A private, loopback, documentation, multicast or IPv6 address never
    reaches the issuance path: validate_ip_identifier refuses it with a reason."""
    mgr = _manager(tmp_path, _shell(0))
    with pytest.raises(ValueError):
        mgr.create_certificate(domain=addr, email='t@example.com',
                               ca_provider='letsencrypt')
    assert mgr.shell_executor.commands_executed == []
