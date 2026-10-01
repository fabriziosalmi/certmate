"""Route53 can use AWS identity or STS credentials without stored access keys."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager, _IssuanceArtifacts
from modules.core.dns_alias_hook import _lexicon_config
from modules.core.dns_providers import DNSManager
from modules.core.dns_strategies import Route53Strategy
from modules.core.shell import MockShellExecutor
from modules.core.settings import SettingsManager
from modules.core.utils import validate_dns_provider_account


pytestmark = pytest.mark.unit
ROLE = 'arn:aws:iam::123456789012:role/CertMateRoute53'


def test_iam_account_resolves_without_keys_and_uses_credential_chain():
    config = {'auth_mode': 'iam_role', 'region': 'eu-west-3',
              'access_key_id': 'old-key', 'secret_access_key': 'old-secret'}
    settings = MagicMock()
    settings.load_settings.return_value = {'dns_providers': {'route53': {
        'accounts': {'prod': config}}}}
    settings.migrate_dns_providers_to_multi_account.side_effect = lambda value: value
    manager = DNSManager(settings)
    resolved, account_id = manager.get_dns_provider_account_config('route53', 'prod')
    assert account_id == 'prod'
    assert resolved == {'auth_mode': 'iam_role', 'region': 'eu-west-3'}
    assert config['access_key_id'] == 'old-key'
    assert manager.test_provider('route53', config)[0]
    assert validate_dns_provider_account('route53', 'prod', config)[0]

    env = {'AWS_PROFILE': 'my-profile'}
    Route53Strategy().prepare_environment(env, resolved)
    assert env['AWS_PROFILE'] == 'my-profile'
    assert env['AWS_DEFAULT_REGION'] == 'eu-west-3'
    assert 'AWS_ACCESS_KEY_ID' not in env
    assert 'AWS_SECRET_ACCESS_KEY' not in env


def test_iam_ignores_unavailable_old_key_references(tmp_path, monkeypatch):
    monkeypatch.delenv('OLD_ROUTE53_SECRET', raising=False)
    config = {'auth_mode': 'iam_role', 'access_key_id_file': str(tmp_path / 'removed'),
              'secret_access_key_env': 'OLD_ROUTE53_SECRET',
              'access_key_id': 'old-key', 'secret_access_key': 'old-secret'}
    settings = MagicMock()
    settings.load_settings.return_value = {'dns_providers': {'route53': {
        'accounts': {'prod': config}}}, 'default_accounts': {'route53': 'prod'}}
    settings.migrate_dns_providers_to_multi_account.side_effect = lambda value: value
    manager = DNSManager(settings)

    resolved, account_id = manager.get_dns_provider_account_config('route53')
    assert account_id == 'prod'
    assert resolved == {'auth_mode': 'iam_role'}
    assert config['access_key_id_file'] == str(tmp_path / 'removed')  # Stored config is untouched.
    env = {}
    Route53Strategy().prepare_environment(env, resolved)
    assert 'AWS_ACCESS_KEY_ID' not in env

    config['auth_mode'] = 'access_keys'
    assert manager.get_dns_provider_account_config('route53') == (None, None)


def test_iam_prefers_inherited_default_region_before_us_east_1():
    env = {'AWS_DEFAULT_REGION': 'cn-north-1'}
    sts = MagicMock()
    sts.assume_role.return_value = {'Credentials': {
        'AccessKeyId': 'TEMP', 'SecretAccessKey': 'SECRET', 'SessionToken': 'TOKEN'}}
    with patch('modules.core.storage_backends._aws_storage_client', return_value=sts) as client:
        Route53Strategy().prepare_environment(env, {
            'auth_mode': 'iam_role', 'assume_role_arn':
            'arn:aws-cn:iam::123456789012:role/CertMateRoute53'})
    assert client.call_args.args[:2] == ('sts', 'cn-north-1')
    assert env['AWS_DEFAULT_REGION'] == 'cn-north-1'


@pytest.mark.parametrize('mode', ['access_keys', 'iam_role'])
def test_assume_role_exports_temporary_session_credentials(mode):
    config = {'auth_mode': mode, 'assume_role_arn': ROLE, 'region': 'eu-west-3'}
    if mode == 'access_keys':
        config.update(access_key_id='source', secret_access_key='source-secret')
    sts = MagicMock()
    sts.assume_role.return_value = {'Credentials': {
        'AccessKeyId': 'TEMP', 'SecretAccessKey': 'TEMPSECRET', 'SessionToken': 'TOKEN'}}
    env = {}
    with patch('modules.core.storage_backends._aws_storage_client', return_value=sts) as client:
        Route53Strategy().prepare_environment(env, config)
    client.assert_called_once_with('sts', 'eu-west-3', mode,
                                   config.get('access_key_id', ''), config.get('secret_access_key', ''))
    sts.assume_role.assert_called_once_with(RoleArn=ROLE, RoleSessionName='certmate-route53-dns')
    assert {key: env[key] for key in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')} == {
        'AWS_ACCESS_KEY_ID': 'TEMP', 'AWS_SECRET_ACCESS_KEY': 'TEMPSECRET', 'AWS_SESSION_TOKEN': 'TOKEN'}
    alias = _lexicon_config('route53', 'validation.example.com', config)
    assert 'auth_access_key' not in alias


def test_legacy_keys_still_work_without_an_inherited_session_token():
    config = {'access_key_id': 'key', 'secret_access_key': 'secret'}
    env = {'AWS_SESSION_TOKEN': 'unrelated-token'}
    Route53Strategy().prepare_environment(env, config)
    assert env['AWS_ACCESS_KEY_ID'] == 'key'
    assert env['AWS_SECRET_ACCESS_KEY'] == 'secret'
    assert 'AWS_SESSION_TOKEN' not in env
    alias = _lexicon_config('route53', 'validation.example.com', config)
    assert alias['auth_access_key'] == 'key'
    assert alias['auth_access_secret'] == 'secret'


@pytest.mark.parametrize('config', [
    {}, {'auth_mode': 'wrong'},
    {'auth_mode': 'iam_role', 'assume_role_arn': 'invalid'},
    {'access_key_id': 'key', 'secret_access_key': 'secret', 'assume_role_arn': 'invalid'},
])
def test_invalid_route53_config_is_rejected(config):
    assert not DNSManager._account_has_credentials('route53', config)
    assert not DNSManager(MagicMock()).test_provider('route53', config)[0]
    assert not validate_dns_provider_account('route53', 'prod', config)[0]
    with pytest.raises(ValueError):
        Route53Strategy().prepare_environment({}, config)


def test_alias_mode_accepts_iam_without_keys(tmp_path):
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=MagicMock(),
                                 dns_manager=MagicMock())
    cfg = {'auth_mode': 'iam_role', 'access_key_id': 'old', 'secret_access_key': 'old'}
    path = manager._create_dns_alias_hook_config('route53', cfg, 'validation.example.com', 10)
    try:
        assert 'old' not in path.read_text()
        assert _lexicon_config('route53', 'validation.example.com', cfg).get('auth_access_key') is None
    finally:
        path.unlink()


def test_alias_hook_uses_assumed_role_in_its_subprocess_environment(tmp_path):
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=MagicMock(),
                                 dns_manager=MagicMock())
    cfg = {'auth_mode': 'iam_role', 'assume_role_arn': ROLE,
           'access_key_id': 'old', 'secret_access_key': 'old-secret'}
    sts = MagicMock()
    sts.assume_role.return_value = {'Credentials': {
        'AccessKeyId': 'TEMP', 'SecretAccessKey': 'SECRET', 'SessionToken': 'TOKEN'}}
    artifacts = _IssuanceArtifacts()
    cmd, env = ['certbot'], {}
    try:
        with patch('modules.core.storage_backends._aws_storage_client', return_value=sts):
            manager._answer_through_alias_hook(
                cmd, env, artifacts, provider='route53', dns_config=cfg,
                alias='validation.example.com', settings={})
        assert env['AWS_ACCESS_KEY_ID'] == 'TEMP'
        assert env['AWS_SESSION_TOKEN'] == 'TOKEN'
        assert 'old-secret' not in artifacts.alias_hook_config.read_text()
        assert '--manual-auth-hook' in cmd
    finally:
        if artifacts.alias_hook_config:
            artifacts.alias_hook_config.unlink()


@pytest.mark.parametrize('config', [
    {'auth_mode': 'iam_role'},
    {'access_key_id': 'key', 'secret_access_key': 'secret'},
])
def test_route53_alias_hook_runs_as_standalone_script(tmp_path, config):
    """Certbot executes a file path, not 'python -m modules.core.dns_alias_hook'."""
    lexicon = tmp_path / 'lexicon'
    lexicon.mkdir()
    (lexicon / '__init__.py').write_text('')
    (lexicon / 'config.py').write_text(
        'class ConfigResolver:\n'
        '    def with_dict(self, value):\n'
        '        return self\n')
    (lexicon / 'client.py').write_text(
        'import os\n'
        'class Client:\n'
        '    def __init__(self, config): pass\n'
        '    def __enter__(self): return self\n'
        '    def __exit__(self, *args): pass\n'
        '    def create_record(self, *args):\n'
        '        open(os.environ["HOOK_MARKER"], "w").close()\n')
    cfg = tmp_path / 'alias.json'
    cfg.write_text(json.dumps({'provider': 'route53', 'config': config,
                               'domain_alias': 'validation.example.com',
                               'propagation_seconds': 0}))
    marker = tmp_path / 'hook-ran'
    script = Path(__file__).resolve().parent.parent / 'modules/core/dns_alias_hook.py'
    env = {**os.environ, 'PYTHONPATH': str(tmp_path), 'CERTBOT_VALIDATION': 'test-value',
           'HOOK_MARKER': str(marker)}
    result = subprocess.run([sys.executable, str(script), '--config', str(cfg),
                             '--action', 'auth'], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert marker.exists()


def test_renewal_prepares_today_iam_credentials(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {}
    dns = MagicMock()
    dns.get_dns_provider_account_config.return_value = ({
        'auth_mode': 'iam_role', 'assume_role_arn': ROLE}, 'prod')
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings, dns_manager=dns)
    cmd, env = ['certbot', 'renew'], {}
    sts = MagicMock()
    sts.assume_role.return_value = {'Credentials': {
        'AccessKeyId': 'TEMP', 'SecretAccessKey': 'SECRET', 'SessionToken': 'TOKEN'}}
    with patch('modules.core.storage_backends._aws_storage_client', return_value=sts), \
         patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        manager._prepare_renewal_dns('example.com', {
            'dns_provider': 'route53', 'account_id': 'prod',
            'challenge_type': 'dns-01'}, cmd, env, _IssuanceArtifacts())
    assert '--authenticator' in cmd and 'dns-route53' in cmd
    assert env['AWS_ACCESS_KEY_ID'] == 'TEMP'
    assert env['AWS_SESSION_TOKEN'] == 'TOKEN'


def test_creation_passes_iam_mode_to_certbot_without_stored_keys(tmp_path, monkeypatch):
    monkeypatch.delenv('AWS_ACCESS_KEY_ID', raising=False)
    monkeypatch.delenv('AWS_SECRET_ACCESS_KEY', raising=False)
    settings = MagicMock()
    settings.load_settings.return_value = {'dns_provider': 'route53'}
    dns = MagicMock()
    dns.get_dns_provider_account_config.return_value = ({'auth_mode': 'iam_role'}, 'prod')
    shell = MockShellExecutor()
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=dns, shell_executor=shell)
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        manager.create_certificate('example.com', 'ops@example.com', dns_provider='route53',
                                   account_id='prod', ca_provider='letsencrypt')
    assert '--authenticator dns-route53' in shell.commands_executed[0]
    assert 'AWS_ACCESS_KEY_ID' not in shell.envs_executed[0]
    assert manager._load_metadata('example.com')['account_id'] == 'prod'


def test_legacy_route53_iam_fields_migrate_into_the_account():
    stored = {'dns_providers': {'route53': {
        'auth_mode': 'iam_role', 'region': 'eu-west-3', 'assume_role_arn': ROLE}}}
    migrated = SettingsManager.__new__(SettingsManager).migrate_dns_providers_to_multi_account(stored)
    route53 = migrated['dns_providers']['route53']
    assert route53['accounts']['default']['auth_mode'] == 'iam_role'
    assert route53['accounts']['default']['assume_role_arn'] == ROLE
    assert 'auth_mode' not in route53
    assert 'assume_role_arn' not in route53

    settings = MagicMock()
    settings.load_settings.return_value = migrated
    settings.migrate_dns_providers_to_multi_account.side_effect = lambda value: value
    config, account_id = DNSManager(settings).get_dns_provider_account_config('route53')
    assert account_id == 'default'
    assert config['auth_mode'] == 'iam_role'
