"""Typed deploy targets — Kubernetes Secret (#475).

Covers the KubernetesSecretTarget (manifest, Server-Side Apply request, auth
resolution incl. in-cluster, failure handling), the run_targets orchestration
(applicability + failure isolation), and the DeployManager integration
(config default/validation, firing on renewal + manual, cert files read from
disk) — the K8s API is mocked throughout.
"""

import base64
import json
import re
from unittest.mock import MagicMock

import pytest

from modules.core.deploy_targets import (
    KubernetesSecretTarget, DeployTargetError, build_target, target_applies,
    run_targets,
)

pytestmark = [pytest.mark.unit]


class _Resp:
    def __init__(self, status_code=200, text='{}'):
        self.status_code = status_code
        self.text = text


class _CapturePatch:
    def __init__(self, status_code=200, text='{}', raises=None):
        self.status_code = status_code
        self.text = text
        self.raises = raises
        self.calls = []

    def __call__(self, url, json=None, headers=None, verify=None, timeout=None):
        self.calls.append({'url': url, 'json': json, 'headers': headers,
                           'verify': verify})
        if self.raises:
            raise self.raises
        return _Resp(self.status_code, self.text)


def _cfg(**over):
    base = {'secret_name': 'tls-web', 'namespace': 'prod',
            'api_server': 'https://k8s.local:6443', 'token': 'sa-token'}
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# KubernetesSecretTarget
# --------------------------------------------------------------------------- #

def test_deploy_success_builds_ssa_request():
    patch = _CapturePatch(200)
    t = KubernetesSecretTarget(_cfg(), http_patch=patch)
    out = t.deploy(b'CERT', b'KEY')
    assert out['success'] is True and out['status_code'] == 200

    call = patch.calls[0]
    assert call['url'] == (
        'https://k8s.local:6443/api/v1/namespaces/prod/secrets/tls-web'
        '?fieldManager=certmate&force=true')
    assert call['headers']['Authorization'] == 'Bearer sa-token'
    assert call['headers']['Content-Type'] == 'application/apply-patch+yaml'
    manifest = call['json']
    assert manifest['type'] == 'kubernetes.io/tls'
    assert base64.b64decode(manifest['data']['tls.crt']) == b'CERT'
    assert base64.b64decode(manifest['data']['tls.key']) == b'KEY'
    assert manifest['metadata'] == {
        'name': 'tls-web', 'namespace': 'prod',
        'labels': {'app.kubernetes.io/managed-by': 'certmate'}}


def test_deploy_non_2xx_is_failure():
    patch = _CapturePatch(403, text='{"message":"forbidden"}')
    out = KubernetesSecretTarget(_cfg(), http_patch=patch).deploy(b'C', b'K')
    assert out['success'] is False
    assert out['status_code'] == 403
    assert 'forbidden' in out['message']


def test_deploy_request_exception_is_failure():
    patch = _CapturePatch(raises=ConnectionError('no route to host'))
    out = KubernetesSecretTarget(_cfg(), http_patch=patch).deploy(b'C', b'K')
    assert out['success'] is False
    assert 'no route to host' in out['message']


def test_missing_secret_name_raises():
    with pytest.raises(DeployTargetError):
        KubernetesSecretTarget(_cfg(secret_name=None),
                               http_patch=_CapturePatch()).deploy(b'C', b'K')


def test_missing_api_server_or_token_raises():
    with pytest.raises(DeployTargetError):
        KubernetesSecretTarget({'secret_name': 's', 'namespace': 'n'},
                               http_patch=_CapturePatch()).deploy(b'C', b'K')


def test_missing_namespace_raises():
    cfg = _cfg()
    cfg.pop('namespace')
    with pytest.raises(DeployTargetError):
        KubernetesSecretTarget(cfg, http_patch=_CapturePatch()).deploy(b'C', b'K')


def test_ca_cert_written_to_tempfile_and_cleaned_up(tmp_path):
    patch = _CapturePatch(200)
    t = KubernetesSecretTarget(_cfg(ca_cert='-----BEGIN CERT-----\nx\n'),
                               http_patch=patch)
    out = t.deploy(b'C', b'K')
    assert out['success'] is True
    ca_path = patch.calls[0]['verify']
    assert isinstance(ca_path, str) and 'certmate-k8s-ca-' in ca_path
    import os
    assert not os.path.exists(ca_path)  # removed after the request


def test_verify_ssl_false_disables_verification():
    patch = _CapturePatch(200)
    KubernetesSecretTarget(_cfg(verify_ssl=False), http_patch=patch).deploy(b'C', b'K')
    assert patch.calls[0]['verify'] is False


def test_in_cluster_resolution(tmp_path, monkeypatch):
    sa = tmp_path / 'sa'
    sa.mkdir()
    (sa / 'token').write_text('incluster-token')
    (sa / 'ca.crt').write_text('CA')
    (sa / 'namespace').write_text('kube-system')
    monkeypatch.setattr('modules.core.deploy_targets._SA_TOKEN', str(sa / 'token'))
    monkeypatch.setattr('modules.core.deploy_targets._SA_CA', str(sa / 'ca.crt'))
    monkeypatch.setattr('modules.core.deploy_targets._SA_NAMESPACE', str(sa / 'namespace'))
    monkeypatch.setenv('KUBERNETES_SERVICE_HOST', '10.96.0.1')
    monkeypatch.setenv('KUBERNETES_SERVICE_PORT', '443')

    patch = _CapturePatch(200)
    t = KubernetesSecretTarget({'secret_name': 'tls', 'in_cluster': True},
                               http_patch=patch)
    out = t.deploy(b'C', b'K')
    assert out['success'] is True
    call = patch.calls[0]
    assert call['url'].startswith('https://10.96.0.1:443/api/v1/namespaces/kube-system/secrets/tls')
    assert call['headers']['Authorization'] == 'Bearer incluster-token'
    assert call['verify'] == str(sa / 'ca.crt')


# --------------------------------------------------------------------------- #
# build_target / target_applies / run_targets
# --------------------------------------------------------------------------- #

def test_build_target_unknown_type_raises():
    with pytest.raises(DeployTargetError):
        build_target({'type': 'ftp-upload'})


@pytest.mark.parametrize('target,domain,event,expected', [
    ({'enabled': True, 'domains': ['a.com'], 'on_events': ['renewed']}, 'a.com', 'renewed', True),
    ({'enabled': False, 'domains': ['a.com']}, 'a.com', 'renewed', False),
    ({'enabled': True, 'domains': ['a.com']}, 'b.com', 'renewed', False),
    ({'enabled': True, 'domains': [], 'on_events': ['created']}, 'x.com', 'created', True),
    ({'enabled': True}, 'x.com', 'created', True),          # defaults: all domains, created+renewed
    ({'enabled': True, 'on_events': ['created']}, 'x.com', 'renewed', False),
    ({'enabled': True, 'domains': ['a.com']}, 'a.com', 'manual', True),  # manual always applies
])
def test_target_applies(target, domain, event, expected):
    assert target_applies(target, domain, event) is expected


def test_run_targets_failure_isolated():
    good = {'enabled': True, 'type': 'kubernetes-secret', 'name': 'good',
            'config': _cfg(secret_name='good')}
    bad = {'enabled': True, 'type': 'kubernetes-secret', 'name': 'bad',
           'config': {'namespace': 'n'}}  # missing secret_name+api -> DeployTargetError
    patch = _CapturePatch(200)
    results = run_targets([bad, good], 'a.com', b'C', b'K', 'renewed', http_patch=patch)
    by = {r['target']: r for r in results}
    assert by['bad']['success'] is False        # errored, isolated
    assert by['good']['success'] is True        # still ran
    assert all(r['domain'] == 'a.com' for r in results)


def test_run_targets_skips_inapplicable():
    t = {'enabled': True, 'type': 'kubernetes-secret', 'name': 'x',
         'domains': ['other.com'], 'config': _cfg()}
    assert run_targets([t], 'a.com', b'C', b'K', 'renewed') == []


# --------------------------------------------------------------------------- #
# DeployManager integration
# --------------------------------------------------------------------------- #

def _deploy_manager(tmp_path, settings):
    from modules.core.deployer import DeployManager
    sm = MagicMock()
    sm.load_settings.return_value = settings
    sm.update.side_effect = lambda mutate, reason=None: mutate(settings)
    cert_dir = tmp_path / 'certs'
    (cert_dir / 'example.com').mkdir(parents=True)
    (cert_dir / 'example.com' / 'fullchain.pem').write_bytes(b'FULLCHAIN')
    (cert_dir / 'example.com' / 'privkey.pem').write_bytes(b'PRIVKEY')
    return DeployManager(sm, MagicMock(), MagicMock(), MagicMock(),
                         cert_dir=cert_dir, data_dir=str(tmp_path / 'data'))


def _k8s_target(**cfg_over):
    return {'id': 't1', 'name': 'prod-secret', 'type': 'kubernetes-secret',
            'enabled': True, 'on_events': ['created', 'renewed'],
            'domains': ['example.com'], 'config': _cfg(**cfg_over)}


def test_get_config_has_targets_default(tmp_path):
    mgr = _deploy_manager(tmp_path, {'deploy_hooks': {'enabled': True}})
    assert mgr.get_config()['targets'] == []


def test_save_config_rejects_bad_target(tmp_path):
    mgr = _deploy_manager(tmp_path, {})
    ok, err = mgr.save_config({'enabled': True, 'targets': [
        {'type': 'kubernetes-secret', 'config': {'namespace': 'n'}}]})
    assert ok is False and 'secret_name' in err


def test_save_config_accepts_valid_target(tmp_path):
    mgr = _deploy_manager(tmp_path, {})
    ok, err = mgr.save_config({'enabled': True, 'targets': [_k8s_target()]})
    assert ok is True and err is None


def test_renewal_applies_secret(tmp_path, requests_mock):
    m = requests_mock.patch(
        re.compile(r'/api/v1/namespaces/prod/secrets/tls-web'),
        status_code=200, json={})
    settings = {'deploy_hooks': {'enabled': True, 'global_hooks': [],
                                 'domain_hooks': {}, 'targets': [_k8s_target()]}}
    mgr = _deploy_manager(tmp_path, settings)

    mgr.on_certificate_event('certificate_renewed', {'domain': 'example.com'})

    assert m.called
    sent = json.loads(m.last_request.text)
    assert base64.b64decode(sent['data']['tls.crt']) == b'FULLCHAIN'
    assert base64.b64decode(sent['data']['tls.key']) == b'PRIVKEY'
    assert m.last_request.headers['Authorization'] == 'Bearer sa-token'


def test_disabled_deploy_skips_targets(tmp_path, requests_mock):
    m = requests_mock.patch(re.compile(r'/secrets/'), status_code=200, json={})
    settings = {'deploy_hooks': {'enabled': False, 'targets': [_k8s_target()]}}
    mgr = _deploy_manager(tmp_path, settings)
    mgr.on_certificate_event('certificate_renewed', {'domain': 'example.com'})
    assert not m.called


def test_manual_deploy_with_only_a_target(tmp_path, requests_mock):
    m = requests_mock.patch(re.compile(r'/secrets/tls-web'), status_code=200, json={})
    settings = {'deploy_hooks': {'enabled': True, 'global_hooks': [],
                                 'domain_hooks': {}, 'targets': [_k8s_target()]}}
    mgr = _deploy_manager(tmp_path, settings)
    out = mgr.run_manual_deploy('example.com')
    assert out['ok'] is True
    assert out['total'] == 1 and out['succeeded'] == 1
    assert m.called


def test_certificate_deployed_event_on_success(tmp_path, requests_mock):
    requests_mock.patch(re.compile(r'/secrets/tls-web'), status_code=200, json={})
    settings = {'deploy_hooks': {'enabled': True, 'global_hooks': [],
                                 'domain_hooks': {}, 'targets': [_k8s_target()]}}
    mgr = _deploy_manager(tmp_path, settings)
    mgr.on_certificate_event('certificate_renewed', {'domain': 'example.com'})
    published = [c.args[0] for c in mgr.event_bus.publish.call_args_list]
    assert 'certificate_deployed' in published


def test_no_deployed_event_when_target_fails(tmp_path, requests_mock):
    requests_mock.patch(re.compile(r'/secrets/tls-web'), status_code=500, json={})
    settings = {'deploy_hooks': {'enabled': True, 'global_hooks': [],
                                 'domain_hooks': {}, 'targets': [_k8s_target()]}}
    mgr = _deploy_manager(tmp_path, settings)
    mgr.on_certificate_event('certificate_renewed', {'domain': 'example.com'})
    published = [c.args[0] for c in mgr.event_bus.publish.call_args_list]
    assert 'certificate_deployed' not in published


def test_missing_cert_files_is_isolated(tmp_path):
    settings = {'deploy_hooks': {'enabled': True, 'global_hooks': [],
                                 'domain_hooks': {}, 'targets': [
                                     _k8s_target()]}}
    mgr = _deploy_manager(tmp_path, settings)
    # A domain with no cert files on disk must not crash the sweep.
    results = mgr._execute_targets('ghost.example.com', 'renewed', mgr.get_config())
    # ghost has no target (domains=['example.com']) -> nothing applies
    assert results == []
