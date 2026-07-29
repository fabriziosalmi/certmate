"""Typed deploy targets (#475).

Deploy hooks are raw shell commands. A *typed* deploy target is a small,
declarative alternative for the common cases where hand-rolling a shell hook
(with kubectl + credentials) is friction. The first typed target writes a
renewed certificate straight into a **Kubernetes TLS Secret**.

Targets are configured under ``deploy_hooks.targets`` in settings and fire from
the same lifecycle points as shell hooks (issuance + every renewal), and are
equally failure-isolated: a target that fails logs and reports, but never blocks
the certificate operation.

Scope is deliberately narrow — typed targets only, no agent/fleet delegation.
Credentials (e.g. a Kubernetes API token) live in settings and are masked by the
existing secret machinery (the field name ``token`` matches the secret regex).
"""

import base64
import logging
import os
import tempfile

logger = logging.getLogger(__name__)

# Well-known in-cluster service-account locations (mounted into every pod).
_SA_DIR = '/var/run/secrets/kubernetes.io/serviceaccount'
_SA_TOKEN = f'{_SA_DIR}/token'
_SA_CA = f'{_SA_DIR}/ca.crt'
_SA_NAMESPACE = f'{_SA_DIR}/namespace'

# Recognised target types.
TARGET_KUBERNETES_SECRET = 'kubernetes-secret'
TARGET_TYPES = (TARGET_KUBERNETES_SECRET,)


class DeployTargetError(Exception):
    """A typed deploy target could not be built or executed."""


class KubernetesSecretTarget:
    """Publish a certificate to a Kubernetes ``kubernetes.io/tls`` Secret.

    Uses **Server-Side Apply** (a single idempotent PATCH that creates or
    updates the Secret), so issuance and every renewal converge the Secret to
    the current cert without create-vs-update bookkeeping.

    Config keys:
      - ``secret_name`` (required), ``namespace`` (required unless in-cluster
        default is used).
      - ``in_cluster`` (bool): read the API server, token, CA and default
        namespace from the mounted service account. Otherwise:
      - ``api_server`` (e.g. ``https://10.0.0.1:6443``), ``token`` (bearer),
        ``ca_cert`` (PEM string, optional), ``verify_ssl`` (bool, default True).
    """

    def __init__(self, config, http_patch=None):
        self.config = config or {}
        # Injection point for tests; defaults to requests.patch.
        self._http_patch = http_patch

    # --- connection resolution --------------------------------------------- #

    def _resolve_connection(self):
        """Return (api_server, token, verify, namespace).

        ``verify`` is either a CA-bundle file path, True (system CAs) or False.
        Raises DeployTargetError when required pieces are missing.
        """
        cfg = self.config
        if cfg.get('in_cluster'):
            host = os.getenv('KUBERNETES_SERVICE_HOST')
            port = os.getenv('KUBERNETES_SERVICE_PORT', '443')
            if not host:
                raise DeployTargetError(
                    'in_cluster set but KUBERNETES_SERVICE_HOST is not present')
            try:
                with open(_SA_TOKEN) as f:
                    token = f.read().strip()
            except OSError as e:
                raise DeployTargetError(f'cannot read in-cluster token: {e}')
            verify = _SA_CA if os.path.exists(_SA_CA) else True
            namespace = cfg.get('namespace')
            if not namespace and os.path.exists(_SA_NAMESPACE):
                with open(_SA_NAMESPACE) as f:
                    namespace = f.read().strip()
            return f'https://{host}:{port}', token, verify, namespace

        api_server = (cfg.get('api_server') or '').rstrip('/')
        token = cfg.get('token')
        if not api_server or not token:
            raise DeployTargetError(
                'kubernetes-secret target needs api_server + token '
                '(or in_cluster)')
        verify = self._resolve_verify()
        return api_server, token, verify, cfg.get('namespace')

    def _resolve_verify(self):
        """Return a CA path / True / False for TLS verification."""
        ca_pem = self.config.get('ca_cert')
        if ca_pem:
            # requests needs a file path for a custom CA bundle.
            fd, path = tempfile.mkstemp(suffix='.crt', prefix='certmate-k8s-ca-')
            with os.fdopen(fd, 'w') as f:
                f.write(ca_pem)
            return path
        if self.config.get('verify_ssl', True) is False:
            return False
        return True

    # --- manifest ---------------------------------------------------------- #

    @staticmethod
    def build_manifest(secret_name, namespace, cert_pem, key_pem):
        """Return the Secret manifest (dict) for Server-Side Apply."""
        return {
            'apiVersion': 'v1',
            'kind': 'Secret',
            'metadata': {
                'name': secret_name,
                'namespace': namespace,
                'labels': {'app.kubernetes.io/managed-by': 'certmate'},
            },
            'type': 'kubernetes.io/tls',
            'data': {
                'tls.crt': base64.b64encode(cert_pem).decode('ascii'),
                'tls.key': base64.b64encode(key_pem).decode('ascii'),
            },
        }

    # --- deploy ------------------------------------------------------------ #

    def deploy(self, cert_pem, key_pem):
        """Apply the certificate to the configured Secret.

        Returns a result dict ``{success, message, status_code}``. Never raises
        for an operational failure — the caller (DeployManager) is
        failure-isolated — but a misconfiguration raises DeployTargetError so
        it surfaces at save time / manual test.
        """
        secret_name = self.config.get('secret_name')
        if not secret_name:
            raise DeployTargetError('kubernetes-secret target needs secret_name')

        api_server, token, verify, namespace = self._resolve_connection()
        if not namespace:
            raise DeployTargetError('kubernetes-secret target needs a namespace')

        manifest = self.build_manifest(secret_name, namespace, cert_pem, key_pem)
        url = (f'{api_server}/api/v1/namespaces/{namespace}/secrets/{secret_name}'
               '?fieldManager=certmate&force=true')
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/apply-patch+yaml',
            'Accept': 'application/json',
        }

        patch = self._http_patch or _default_patch
        ca_tempfile = verify if isinstance(verify, str) and 'certmate-k8s-ca-' in str(verify) else None
        try:
            resp = patch(url, json=manifest, headers=headers, verify=verify, timeout=15)
        except Exception as e:
            return {'success': False, 'status_code': None,
                    'message': f'Kubernetes API request failed: {e}'}
        finally:
            if ca_tempfile:
                try:
                    os.remove(ca_tempfile)
                except OSError:
                    pass

        status = getattr(resp, 'status_code', None)
        if status is not None and 200 <= status < 300:
            return {'success': True, 'status_code': status,
                    'message': f'Applied Secret {namespace}/{secret_name}'}
        body = _safe_body(resp)
        return {'success': False, 'status_code': status,
                'message': f'Kubernetes API returned {status}: {body}'}


def _default_patch(url, timeout=15, **kwargs):
    import requests
    return requests.patch(url, timeout=timeout, **kwargs)


def _safe_body(resp):
    try:
        return (resp.text or '')[:300]
    except Exception:
        return '<unreadable response>'


def build_target(target, http_patch=None):
    """Instantiate a typed deploy target from its config dict."""
    ttype = (target or {}).get('type')
    if ttype == TARGET_KUBERNETES_SECRET:
        return KubernetesSecretTarget(target.get('config') or {}, http_patch=http_patch)
    raise DeployTargetError(f'unknown deploy target type: {ttype!r}')


def target_applies(target, domain, event_type):
    """True if *target* is enabled, covers *domain*, and fires on *event_type*.

    ``domains`` empty/absent means "all managed domains". ``on_events`` empty
    means "created + renewed".
    """
    if not target.get('enabled'):
        return False
    domains = target.get('domains') or []
    if domains and domain not in domains:
        return False
    on_events = target.get('on_events') or ['created', 'renewed']
    return event_type in on_events or event_type == 'manual'


def run_targets(targets, domain, cert_pem, key_pem, event_type, http_patch=None):
    """Run every applicable typed target for *domain*, failure-isolated.

    Returns a list of per-target result dicts. A build/deploy error for one
    target is captured and never aborts the others (or the cert operation).
    """
    results = []
    for target in targets or []:
        if not target_applies(target, domain, event_type):
            continue
        name = target.get('name') or target.get('id') or target.get('type')
        try:
            instance = build_target(target, http_patch=http_patch)
            outcome = instance.deploy(cert_pem, key_pem)
        except DeployTargetError as e:
            outcome = {'success': False, 'status_code': None, 'message': str(e)}
        except Exception as e:  # pragma: no cover - defensive isolation
            logger.exception('Deploy target %s crashed', name)
            outcome = {'success': False, 'status_code': None,
                       'message': f'unexpected error: {e}'}
        outcome.update({'target': name, 'type': target.get('type'), 'domain': domain})
        results.append(outcome)
    return results
