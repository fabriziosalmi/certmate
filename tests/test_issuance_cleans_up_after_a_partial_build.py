"""A half-built issuance must not leave credentials on disk (#666).

Building a certbot command writes secrets to temp files: the DNS credentials
ini, whatever a provider writes beside it (Google's is the service-account
JSON — a live cloud private key), and the CA bundle behind
``REQUESTS_CA_BUNDLE``. ``create_certificate``'s ``finally`` removes them.

The guarantee that matters is the one for the *unhappy* path: the builder can
raise after writing the credentials file and before the command is finished —
a plugin config that fails validation, an alias zone the provider does not
support, a propagation value that will not parse. If cleanup depended on the
builder returning the paths, those failures would each leave a secret behind.

Before the decomposition this held because the paths were assigned to locals
partway down a 590-line function, where the ``finally`` could see them however
it exited. That is easy to lose when the code moves, and nothing tested it. So
it is tested now: the builder writes into an ``_IssuanceArtifacts`` record the
caller owns, and these assert the file is gone whether the build finishes or
blows up in the middle.
"""
import pathlib
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import (
    CertificateManager,
    DomainOperationInProgress,
    _IssuanceArtifacts,
)
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

SETTINGS = {
    'default_ca': 'letsencrypt',
    'challenge_type': 'dns-01',
    'dns_propagation_seconds': {'cloudflare': 30},
    'default_key_type': 'ecdsa',
    'default_elliptic_curve': 'secp384r1',
}


def _manager(tmp_path):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = dict(SETTINGS)
    settings_manager.get_domain_dns_provider.return_value = 'cloudflare'
    dns_manager = MagicMock()
    dns_manager.get_dns_provider_account_config.return_value = (
        {'api_token': 'cf-token'}, 'default')
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=settings_manager,
        dns_manager=dns_manager, storage_manager=None, ca_manager=None,
        shell_executor=shell)


def _issue(manager, **over):
    call = {'domain': 'example.com', 'email': 'a@b.com',
            'dns_provider': 'cloudflare'}
    call.update(over)
    return manager.create_certificate(**call)


# ---------------------------------------------------------------------------
# The record itself
# ---------------------------------------------------------------------------

def test_the_artifacts_record_starts_empty_and_is_per_issuance():
    """Mutable defaults shared between instances would make one issuance
    delete another's files."""
    a, b = _IssuanceArtifacts(), _IssuanceArtifacts()
    assert a.credentials_file is None
    assert a.extra_credential_files == [] and a.ca_extra_env == {}

    a.extra_credential_files.append('/tmp/x')
    a.ca_extra_env['REQUESTS_CA_BUNDLE'] = '/tmp/y'
    assert b.extra_credential_files == [], 'the list is shared between records'
    assert b.ca_extra_env == {}, 'the env dict is shared between records'


# ---------------------------------------------------------------------------
# The happy path still cleans up
# ---------------------------------------------------------------------------

def test_a_successful_issuance_leaves_no_credentials_file(tmp_path):
    written = []
    manager = _manager(tmp_path)
    # CloudflareStrategy overrides create_config_file, so spying on the base
    # class intercepts nothing — the first version of this test asserted on an
    # empty list and would have passed on any code at all.
    from modules.core.dns_strategies import CloudflareStrategy

    original = CloudflareStrategy.create_config_file

    def spy(self, config):
        path = original(self, config)
        written.append(path)
        return path

    CloudflareStrategy.create_config_file = spy
    try:
        _issue(manager)
    finally:
        CloudflareStrategy.create_config_file = original

    assert written, 'no credentials file was written, so this proves nothing'
    for path in written:
        assert not pathlib.Path(path).exists(), (
            f'{path} survived a successful issuance'
        )


# ---------------------------------------------------------------------------
# The path that matters: it blew up in the middle
# ---------------------------------------------------------------------------

def test_a_builder_failure_after_writing_credentials_still_removes_them(
        tmp_path, monkeypatch):
    """The reason the record exists.

    `configure_certbot_arguments` runs immediately after the credentials file
    is created. Making it raise puts the failure exactly in the window where
    a return-the-paths-on-success design would leak the file.
    """
    written = []
    from modules.core import dns_strategies
    from modules.core.dns_strategies import CloudflareStrategy

    original = CloudflareStrategy.create_config_file

    def spy(self, config):
        path = original(self, config)
        written.append(path)
        return path

    def boom(self, cmd, credentials_file, domain_alias=None):
        raise RuntimeError('plugin rejected the config')

    monkeypatch.setattr(CloudflareStrategy, 'create_config_file', spy)
    monkeypatch.setattr(dns_strategies.DNSProviderStrategy,
                        'configure_certbot_arguments', boom)

    manager = _manager(tmp_path)
    # create_certificate logs and re-raises, so the caller sees the failure.
    # What must NOT survive it is the credentials file.
    with pytest.raises(RuntimeError, match='plugin rejected'):
        _issue(manager)

    assert written, 'the failure was injected before any file was written'
    for path in written:
        assert not pathlib.Path(path).exists(), (
            f'{path} outlived a failed issuance — a live DNS credential left '
            f'on disk because the builder raised one line too early'
        )


def test_a_side_credential_file_is_removed_too(tmp_path, monkeypatch):
    """Google's provider writes the service-account JSON beside the ini and
    reports it in `extra_credential_files`. That one is a cloud private key,
    so it is the one that must not be missed."""
    side = tmp_path / 'service-account.json'
    side.write_text('{"private_key": "-----BEGIN PRIVATE KEY-----"}')

    from modules.core.dns_strategies import CloudflareStrategy
    original = CloudflareStrategy.create_config_file

    def spy(self, config):
        path = original(self, config)
        self.extra_credential_files = [str(side)]
        return path

    monkeypatch.setattr(CloudflareStrategy, 'create_config_file', spy)

    _issue(_manager(tmp_path))

    assert not side.exists(), (
        'the side credential file survived; for Google that is a live cloud '
        'private key left on disk'
    )


def test_the_ca_bundle_is_removed(tmp_path, monkeypatch):
    """The CA manager materialises a bundle for REQUESTS_CA_BUNDLE. It is not
    secret, but it is a temp file per issuance and they accumulate."""
    bundle = tmp_path / 'ca-bundle.pem'
    bundle.write_text('-----BEGIN CERTIFICATE-----')

    manager = _manager(tmp_path)
    ca_manager = MagicMock()
    ca_manager.build_certbot_command.return_value = (
        ['certbot', 'certonly', '--cert-name', 'example.com',
         '--config-dir', str(tmp_path / 'example.com')],
        {'REQUESTS_CA_BUNDLE': str(bundle)},
    )
    ca_manager.get_ca_config.return_value = ({'acme_url': 'https://x/dir'}, 'acct')
    manager.ca_manager = ca_manager

    _issue(manager)

    assert not bundle.exists(), 'the CA bundle temp file was not cleaned up'


def test_a_domain_already_issued_cleans_up_nothing_and_raises(tmp_path):
    """CONTROL: the finally runs on every exit, including the ones that never
    reached the builder. It must not trip over an empty record."""
    domain_dir = tmp_path / 'example.com'
    domain_dir.mkdir()
    (domain_dir / 'cert.pem').write_text('x')

    with pytest.raises(FileExistsError):
        _issue(_manager(tmp_path))


def test_a_busy_domain_raises_before_any_artifact_exists(tmp_path,
                                                         monkeypatch):
    """CONTROL: the lock is taken before the record is built. A caller that
    cannot get it must not blow up in the finally instead of getting
    DomainOperationInProgress."""
    manager = _manager(tmp_path)
    monkeypatch.setattr(manager, '_domain_lock_timeout', lambda: 0.01)
    lock = manager._get_domain_lock('example.com')
    lock.acquire()
    try:
        with pytest.raises(DomainOperationInProgress):
            _issue(manager)
    finally:
        lock.release()
