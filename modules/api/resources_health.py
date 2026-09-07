"""Liveness, metrics and the diagnostics snapshot.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; the managers they used to capture now arrive as an explicit
`ApiContext`, which is what lets them be imported — and tested — without
building the whole graph.
"""
import logging
from pathlib import Path

from flask import current_app
from flask_restx import Resource

from ..core.constants import iter_cert_domain_dirs
from ..core.metrics import get_metrics_summary, is_prometheus_available
from .resource_context import ApiContext

logger = logging.getLogger(__name__)


def create_health_resources(api, models, ctx: ApiContext) -> dict:
    """Build the health, metrics and diagnostics resources against *ctx*."""

    class HealthCheck(Resource):
        def get(self):
            """Health check: settings readable + background scheduler running."""
            checks = {}
            overall = 'healthy'
            try:
                ctx.settings.load_settings()
                checks['settings'] = 'ok'
            except Exception as e:
                logger.error(f"Health check failed (settings): {e}")
                checks['settings'] = 'error'
                overall = 'unhealthy'

            scheduler = ctx.managers.get('scheduler')
            scheduler_running = bool(scheduler and getattr(scheduler, 'running', False))
            checks['scheduler'] = 'running' if scheduler_running else 'not_running'
            if not scheduler_running:
                # The scheduler being down means renewals stop firing — surface it
                # as 'degraded' so monitoring catches it without flapping liveness.
                if overall == 'healthy':
                    overall = 'degraded'

            # Surface a storage-backend fallback: if the configured cloud/remote
            # backend failed to initialise, CertMate silently uses local disk —
            # the operator thinks certs are in Azure/Vault/S3 but they are not.
            # Only a log line signalled this before; make monitoring see it.
            storage = ctx.managers.get('storage')
            if storage is not None and hasattr(storage, 'get_fallback_backend'):
                try:
                    fell_back_from = storage.get_fallback_backend()
                except Exception:
                    fell_back_from = None
                if fell_back_from:
                    checks['storage'] = f'fallback_to_local (configured backend: {fell_back_from})'
                    if overall == 'healthy':
                        overall = 'degraded'
                else:
                    checks['storage'] = 'ok'

            status_code = 200 if overall != 'unhealthy' else 500
            return {'status': overall, 'checks': checks}, status_code

    class MetricsList(Resource):
        # Gated like its sibling info endpoints (CacheStats, BackupList).
        # This JSON summary lives in the authenticated API and must require at
        # least a viewer credential, not be reachable unauthenticated. The
        # Prometheus scrape target is the separate '/metrics' route, which is
        # NOT public: it carries the same viewer requirement, because its
        # series enumerate every managed domain.
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self):
            """Get available metrics information"""
            try:
                if not is_prometheus_available():
                    return {'error': 'Prometheus metrics not available'}, 503

                summary = get_metrics_summary()
                return {
                    'available': True,
                    'metrics_endpoint': '/metrics',
                    'summary': summary
                }
            except Exception as e:
                logger.error(f"Error getting metrics info: {e}")
                return {'error': 'Failed to get metrics information'}, 500

    class DiagnosticsSnapshot(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def get(self):
            """Build a sanitized diagnostic snapshot for bug-report use."""
            import platform
            import shutil
            import sys
            import os
            import ssl
            import json

            from .. import __version__ as _certmate_version

            errors = {}

            # --- System info ---
            cryptography_version = None
            try:
                import cryptography
                cryptography_version = cryptography.__version__
            except Exception as e:
                logger.warning(f"Diagnostic: failed to read cryptography version: {e}")
                errors['cryptography_version'] = 'unavailable'

            openssl_version = None
            try:
                openssl_version = ssl.OPENSSL_VERSION
            except Exception as e:
                logger.warning(f"Diagnostic: failed to read OpenSSL version: {e}")
                errors['openssl_version'] = 'unavailable'

            shell_executor = ctx.managers.get('shell_executor') or (ctx.certificates and getattr(ctx.certificates, 'shell_executor', None))
            certbot_version = None
            if shell_executor:
                try:
                    res = shell_executor.run(['.venv/bin/certbot', '--version'], timeout=5)
                    if res and hasattr(res, 'stdout') and isinstance(res.stdout, str):
                        stdout_str = res.stdout or ''
                        stderr_str = res.stderr or '' if isinstance(res.stderr, str) else ''
                        out = stdout_str + stderr_str
                        if out.strip():
                            certbot_version = out.strip()
                except Exception as e:
                    logger.debug("Failed to run .venv/bin/certbot --version: %s", e)
                if not certbot_version:
                    try:
                        res = shell_executor.run(['certbot', '--version'], timeout=5)
                        if res and hasattr(res, 'stdout') and isinstance(res.stdout, str):
                            stdout_str = res.stdout or ''
                            stderr_str = res.stderr or '' if isinstance(res.stderr, str) else ''
                            out = stdout_str + stderr_str
                            if out.strip():
                                certbot_version = out.strip()
                    except Exception as e:
                        logger.debug("Failed to run certbot --version fallback: %s", e)
            if not certbot_version:
                errors['certbot_version'] = 'unavailable'

            # --- Storage health ---
            cert_dir = getattr(ctx.certificates, 'cert_dir', None)
            data_dir = current_app.config.get('DATA_DIR') or '.'

            cert_dir_path = cert_dir if isinstance(cert_dir, (str, Path)) else None
            data_dir_path = data_dir if isinstance(data_dir, (str, Path)) else None

            storage_permissions = {
                'cert_dir_readable': os.access(str(cert_dir_path), os.R_OK) if cert_dir_path else False,
                'cert_dir_writable': os.access(str(cert_dir_path), os.W_OK) if cert_dir_path else False,
                'data_dir_readable': os.access(str(data_dir_path), os.R_OK) if data_dir_path else False,
                'data_dir_writable': os.access(str(data_dir_path), os.W_OK) if data_dir_path else False,
            }

            # --- Application / runtime identity ---
            payload = {
                'certmate_version': _certmate_version,
                'python_version': sys.version.split()[0],
                'os_platform': platform.platform(),
                'container': Path('/.dockerenv').exists(),
                'cryptography_version': cryptography_version,
                'openssl_version': openssl_version,
                'certbot_version': certbot_version,
                'storage_permissions': storage_permissions,
            }

            # --- Background scheduler liveness ---
            scheduler = ctx.managers.get('scheduler')
            payload['scheduler_running'] = bool(
                scheduler and getattr(scheduler, 'running', False)
            )

            # --- Certificate inventory cardinality ---
            # Count on-disk cert stores the same way the rest of the codebase
            # discovers them. CertificateManager has no list_certificates()
            # method (that lives on storage backends), so the old call always
            # raised and reported a null count.
            try:
                payload['certificate_count'] = sum(
                    1 for _ in iter_cert_domain_dirs(ctx.certificates.cert_dir)
                )
            except Exception as e:
                logger.warning(f"Diagnostic: failed to count certificates: {e}")
                payload['certificate_count'] = None
                errors['certificate_count'] = 'failed_to_enumerate'

            # --- Configuration scalars & summary ---
            try:
                settings = ctx.settings.load_settings() or {}
                payload['dns_provider'] = settings.get('dns_provider')
                payload['default_ca'] = settings.get('default_ca')
                payload['challenge_type'] = settings.get('challenge_type')
                cert_storage = settings.get('certificate_storage') or {}
                payload['storage_backend'] = cert_storage.get('backend')
                payload['configured_domains_count'] = len(settings.get('domains', [])) if isinstance(settings.get('domains'), list) else 0

                # Active DNS providers (by type, with credentials omitted)
                active_dns_providers = {}
                dns_providers = settings.get('dns_providers', {})
                if isinstance(dns_providers, dict):
                    for provider_name, provider_config in dns_providers.items():
                        if not provider_config or not isinstance(provider_config, dict):
                            continue
                        accounts_list = []
                        if 'accounts' in provider_config and isinstance(provider_config['accounts'], dict):
                            for acc_id, acc_config in provider_config['accounts'].items():
                                if isinstance(acc_config, dict):
                                    accounts_list.append({
                                        'id': acc_id,
                                        'name': acc_config.get('name', acc_id),
                                        'description': acc_config.get('description', '')
                                    })
                        else:
                            accounts_list.append({
                                'id': 'default',
                                'name': provider_config.get('name', 'Default Account'),
                                'description': provider_config.get('description', 'Legacy single-account config')
                            })
                        if accounts_list:
                            active_dns_providers[provider_name] = accounts_list
                payload['active_dns_providers'] = active_dns_providers

            except Exception as e:
                logger.warning(f"Diagnostic: failed to read settings scalars: {e}")
                errors['settings'] = 'failed_to_read'

            # SSO / OIDC status
            try:
                oidc_manager = ctx.managers.get('oidc')
                if oidc_manager:
                    enabled_val = oidc_manager.is_enabled()
                    payload['sso_oidc_enabled'] = bool(enabled_val) if isinstance(enabled_val, bool) else False
                else:
                    payload['sso_oidc_enabled'] = False
            except Exception as e:
                logger.warning(f"Diagnostic: failed to query OIDC status: {e}")
                payload['sso_oidc_enabled'] = False
                errors['sso_oidc'] = 'failed_to_query'

            # --- Free disk on the data partition ---
            try:
                data_dir_path = current_app.config.get('DATA_DIR') or '.'
                usage = shutil.disk_usage(str(data_dir_path))
                payload['disk_free_bytes'] = usage.free
                payload['disk_total_bytes'] = usage.total
            except Exception as e:
                logger.warning(f"Diagnostic: disk_usage failed: {e}")
                payload['disk_free_bytes'] = None
                payload['disk_total_bytes'] = None
                errors['disk_usage'] = 'permission_or_path_unavailable'

            # --- Backup history ---
            backup_count = 0
            backup_total_size = 0
            file_ops = ctx.managers.get('file_ops')
            if file_ops:
                try:
                    backups = ctx.file_ops.list_backups()
                    if isinstance(backups, dict):
                        unified_list = backups.get('unified', [])
                        if isinstance(unified_list, list):
                            backup_count = len(unified_list)
                            backup_total_size = sum(item.get('metadata', {}).get('size', 0) for item in unified_list if isinstance(item, dict))
                except Exception as e:
                    logger.warning(f"Diagnostic: failed to read backup metrics: {e}")
                    errors['backups'] = 'failed_to_list'
            payload['backup_count'] = backup_count
            payload['backup_total_size'] = backup_total_size

            # --- Sanitized Logs (last 50 lines) ---
            sanitized_logs = []
            if file_ops and getattr(ctx.file_ops, 'logs_dir', None) and isinstance(ctx.file_ops.logs_dir, (str, Path)):
                try:
                    log_file = ctx.file_ops.logs_dir / 'certmate.log'
                    if log_file.exists() and log_file.is_file():
                        from collections import deque
                        with open(log_file, 'r', encoding='utf-8') as f:
                            last_lines = list(deque(f, maxlen=50))

                        from modules.core.structured_logging import JSONFormatter
                        formatter = JSONFormatter()

                        for line in last_lines:
                            line_str = line.strip()
                            if not line_str:
                                continue
                            try:
                                parsed = json.loads(line_str)
                                sanitized_parsed = formatter.sanitize_data(parsed)
                                sanitized_logs.append(sanitized_parsed)
                            except Exception:
                                sanitized_str = formatter.sanitize_data(line_str)
                                sanitized_logs.append(sanitized_str)
                except Exception as e:
                    logger.warning(f"Diagnostic: failed to read sanitized logs: {e}")
                    errors['sanitized_logs'] = 'failed_to_read'
            payload['sanitized_logs'] = sanitized_logs

            # --- Recent audit (sanitized: identifiers stripped) ---
            # Only timestamp / operation / resource_type / status survive
            # the round-trip. Domain names, usernames, IP addresses, and
            # the audit details payload are all dropped before
            # serialization. Anyone reading the resulting bug report
            # sees operational tempo without learning who did what to
            # which domain from which IP.
            try:
                raw_entries = ctx.audit.get_recent_entries(limit=5) if ctx.audit else []
                if isinstance(raw_entries, list):
                    payload['recent_audit'] = [
                        {
                            'timestamp': (e or {}).get('timestamp'),
                            'operation': (e or {}).get('operation'),
                            'resource_type': (e or {}).get('resource_type'),
                            'status': (e or {}).get('status'),
                        }
                        for e in raw_entries[:5] if isinstance(e, dict)
                    ]
                else:
                    payload['recent_audit'] = []
            except Exception as e:
                logger.warning(f"Diagnostic: audit log read failed: {e}")
                payload['recent_audit'] = []
                errors['recent_audit'] = 'failed_to_read'

            if errors:
                payload['errors'] = errors
            return payload, 200

    return {
        'HealthCheck': HealthCheck,
        'MetricsList': MetricsList,
        'DiagnosticsSnapshot': DiagnosticsSnapshot,
    }
