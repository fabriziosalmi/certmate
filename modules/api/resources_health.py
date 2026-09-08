"""Liveness, metrics and the diagnostics snapshot.

Extracted from the `create_api_resources` closure (#667). The managers these
resources used to capture now arrive as an explicit `ApiContext`, which is what
lets them be imported — and tested — without building the whole graph.

`create_health_resources` was then the single most complex unit in the
repository: cyclomatic complexity 64, higher than the certificate renewal path
it reports on. The complexity was not one hard decision, it was **twelve
independent try/except sections inlined into two request handlers**, each
contributing branches to a function nothing could enter except through Flask.

They are now one function per subsystem, at module level:

- a **check** answers "is this subsystem healthy" and returns a `Check` —
  a name, the string the API reports, and a severity. `HealthCheck.get` is a
  fixed loop over `HEALTH_CHECKS` that takes the worst severity. Adding a
  check is appending to a list, and the set of reportable states is
  enumerable rather than spread across an if-ladder.
- a **collector** contributes to the diagnostics payload and returns
  `(fields, errors)`. `DiagnosticsSnapshot.get` is a fixed loop over
  `DIAGNOSTIC_COLLECTORS` that merges both. A collector that raises anyway
  cannot take the snapshot down with it — the loop catches, records the
  section as failed, and goes on to the next, which is the property the
  twelve hand-written try/except blocks were each implementing separately.

Every one of these takes `ctx` and returns data, so a check can be tested by
calling it with a stub context. That was the practical cost of the old shape:
exercising the storage-fallback branch meant building an app.
"""
import json
import logging
import os
import platform
import shutil
import ssl
import sys
from collections import deque
from pathlib import Path
from typing import NamedTuple

from flask import current_app
from flask_restx import Resource

from ..core.constants import iter_cert_domain_dirs
from ..core.metrics import get_metrics_summary, is_prometheus_available
from .resource_context import ApiContext

logger = logging.getLogger(__name__)

# Severity ordering. `HealthCheck.get` reports the worst any check returned,
# which is the same precedence the previous if-ladder implemented by only
# degrading `if overall == 'healthy'` — written once here instead of repeated
# at each branch, where it was possible to forget it.
HEALTHY = 0
DEGRADED = 1
UNHEALTHY = 2

_OVERALL = {HEALTHY: 'healthy', DEGRADED: 'degraded', UNHEALTHY: 'unhealthy'}


class Check(NamedTuple):
    """One subsystem's answer.

    `state` is the string the API reports verbatim, so a check owns its own
    wording. `severity` is what the aggregate is computed from. `name` may be
    None, which means "nothing to report" — that is how the storage check
    stays absent from the response on an instance with no remote backend,
    rather than reporting a state that would mean nothing.
    """
    name: str | None
    state: str | None
    severity: int


NOTHING_TO_REPORT = Check(None, None, HEALTHY)


# --- health checks -------------------------------------------------------

def check_settings(ctx: ApiContext) -> Check:
    """Settings must be readable. Nothing else works if they are not."""
    try:
        ctx.settings.load_settings()
    except Exception as e:
        logger.error(f"Health check failed (settings): {e}")
        return Check('settings', 'error', UNHEALTHY)
    return Check('settings', 'ok', HEALTHY)


def check_scheduler(ctx: ApiContext) -> Check:
    """Degraded, not unhealthy: the scheduler being down means renewals stop
    firing, which monitoring must see — but the instance still serves, and
    flapping liveness on it would take a working install out of rotation."""
    scheduler = ctx.managers.get('scheduler')
    if scheduler and getattr(scheduler, 'running', False):
        return Check('scheduler', 'running', HEALTHY)
    return Check('scheduler', 'not_running', DEGRADED)


def check_storage(ctx: ApiContext) -> Check:
    """Surface a storage-backend fallback.

    If the configured cloud/remote backend failed to initialise, CertMate
    silently uses local disk — the operator believes certificates are in
    Azure/Vault/S3 and they are not. Only a log line signalled this before.
    """
    storage = ctx.managers.get('storage')
    if storage is None or not hasattr(storage, 'get_fallback_backend'):
        return NOTHING_TO_REPORT
    try:
        fell_back_from = storage.get_fallback_backend()
    except Exception:
        fell_back_from = None
    if fell_back_from:
        return Check('storage',
                     f'fallback_to_local (configured backend: {fell_back_from})',
                     DEGRADED)
    return Check('storage', 'ok', HEALTHY)


HEALTH_CHECKS = (check_settings, check_scheduler, check_storage)


def run_health_checks(ctx: ApiContext) -> tuple[dict, str]:
    """Every check, and the worst severity any of them returned."""
    checks = {}
    worst = HEALTHY
    for check in HEALTH_CHECKS:
        result = check(ctx)
        if result.name is not None:
            checks[result.name] = result.state
        worst = max(worst, result.severity)
    return checks, _OVERALL[worst]


# --- diagnostics collectors ---------------------------------------------
#
# Each returns (fields, errors). Both are merged into the snapshot by the
# fixed loop in DiagnosticsSnapshot.get, which also catches anything a
# collector lets escape — so a new one cannot take the whole snapshot down,
# which is what a bug report is being collected for in the first place.

def collect_library_versions(ctx: ApiContext) -> tuple[dict, dict]:
    fields, errors = {}, {}
    try:
        import cryptography
        fields['cryptography_version'] = cryptography.__version__
    except Exception as e:
        logger.warning(f"Diagnostic: failed to read cryptography version: {e}")
        fields['cryptography_version'] = None
        errors['cryptography_version'] = 'unavailable'
    try:
        fields['openssl_version'] = ssl.OPENSSL_VERSION
    except Exception as e:
        logger.warning(f"Diagnostic: failed to read OpenSSL version: {e}")
        fields['openssl_version'] = None
        errors['openssl_version'] = 'unavailable'
    return fields, errors


def _certbot_version_from(shell_executor, command) -> str | None:
    try:
        res = shell_executor.run(command, timeout=5)
    except Exception as e:
        logger.debug("Failed to run %s: %s", ' '.join(command), e)
        return None
    if not (res and hasattr(res, 'stdout') and isinstance(res.stdout, str)):
        return None
    stderr = res.stderr if isinstance(res.stderr, str) else ''
    out = (res.stdout or '') + (stderr or '')
    return out.strip() or None


def collect_certbot_version(ctx: ApiContext) -> tuple[dict, dict]:
    """The venv's certbot first, then whatever is on PATH.

    Both are tried because an image built one way has it in only one of those
    places, and reporting "unavailable" for a certbot that answers perfectly
    well sends whoever reads the bug report after the wrong thing.
    """
    shell_executor = (ctx.managers.get('shell_executor')
                      or (ctx.certificates
                          and getattr(ctx.certificates, 'shell_executor', None)))
    version = None
    if shell_executor:
        version = (_certbot_version_from(shell_executor,
                                         ['.venv/bin/certbot', '--version'])
                   or _certbot_version_from(shell_executor,
                                            ['certbot', '--version']))
    if version:
        return {'certbot_version': version}, {}
    return {'certbot_version': None}, {'certbot_version': 'unavailable'}


def collect_storage_permissions(ctx: ApiContext) -> tuple[dict, dict]:
    cert_dir = getattr(ctx.certificates, 'cert_dir', None)
    data_dir = current_app.config.get('DATA_DIR') or '.'
    cert_path = cert_dir if isinstance(cert_dir, (str, Path)) else None
    data_path = data_dir if isinstance(data_dir, (str, Path)) else None
    return {'storage_permissions': {
        'cert_dir_readable': (os.access(str(cert_path), os.R_OK)
                              if cert_path else False),
        'cert_dir_writable': (os.access(str(cert_path), os.W_OK)
                              if cert_path else False),
        'data_dir_readable': (os.access(str(data_path), os.R_OK)
                              if data_path else False),
        'data_dir_writable': (os.access(str(data_path), os.W_OK)
                              if data_path else False),
    }}, {}


def collect_runtime(ctx: ApiContext) -> tuple[dict, dict]:
    from .. import __version__ as certmate_version
    return {
        'certmate_version': certmate_version,
        'python_version': sys.version.split()[0],
        'os_platform': platform.platform(),
        'container': Path('/.dockerenv').exists(),
    }, {}


def collect_scheduler(ctx: ApiContext) -> tuple[dict, dict]:
    scheduler = ctx.managers.get('scheduler')
    return {'scheduler_running': bool(
        scheduler and getattr(scheduler, 'running', False))}, {}


def collect_certificate_count(ctx: ApiContext) -> tuple[dict, dict]:
    """Counted the way the rest of the codebase discovers cert stores.

    CertificateManager has no list_certificates() — that lives on storage
    backends — so the call this replaced always raised and reported null.
    """
    try:
        return {'certificate_count': sum(
            1 for _ in iter_cert_domain_dirs(ctx.certificates.cert_dir))}, {}
    except Exception as e:
        logger.warning(f"Diagnostic: failed to count certificates: {e}")
        return ({'certificate_count': None},
                {'certificate_count': 'failed_to_enumerate'})


def _active_dns_providers(settings: dict) -> dict:
    """Providers by type, with credentials omitted — names and descriptions
    only. This ends up in a bug report."""
    active = {}
    dns_providers = settings.get('dns_providers', {})
    if not isinstance(dns_providers, dict):
        return active
    for provider_name, provider_config in dns_providers.items():
        if not provider_config or not isinstance(provider_config, dict):
            continue
        accounts = provider_config.get('accounts')
        if isinstance(accounts, dict):
            listed = [{'id': account_id,
                       'name': account.get('name', account_id),
                       'description': account.get('description', '')}
                      for account_id, account in accounts.items()
                      if isinstance(account, dict)]
        else:
            listed = [{
                'id': 'default',
                'name': provider_config.get('name', 'Default Account'),
                'description': provider_config.get(
                    'description', 'Legacy single-account config'),
            }]
        if listed:
            active[provider_name] = listed
    return active


def collect_settings_scalars(ctx: ApiContext) -> tuple[dict, dict]:
    try:
        settings = ctx.settings.load_settings() or {}
    except Exception as e:
        logger.warning(f"Diagnostic: failed to read settings scalars: {e}")
        return {}, {'settings': 'failed_to_read'}
    domains = settings.get('domains')
    cert_storage = settings.get('certificate_storage') or {}
    return {
        'dns_provider': settings.get('dns_provider'),
        'default_ca': settings.get('default_ca'),
        'challenge_type': settings.get('challenge_type'),
        'storage_backend': cert_storage.get('backend'),
        'configured_domains_count': (len(domains)
                                     if isinstance(domains, list) else 0),
        'active_dns_providers': _active_dns_providers(settings),
    }, {}


def collect_oidc_status(ctx: ApiContext) -> tuple[dict, dict]:
    try:
        oidc_manager = ctx.managers.get('oidc')
        if not oidc_manager:
            return {'sso_oidc_enabled': False}, {}
        enabled = oidc_manager.is_enabled()
        return {'sso_oidc_enabled': enabled if isinstance(enabled, bool)
                else False}, {}
    except Exception as e:
        logger.warning(f"Diagnostic: failed to query OIDC status: {e}")
        return {'sso_oidc_enabled': False}, {'sso_oidc': 'failed_to_query'}


def collect_disk_usage(ctx: ApiContext) -> tuple[dict, dict]:
    try:
        usage = shutil.disk_usage(str(current_app.config.get('DATA_DIR') or '.'))
    except Exception as e:
        logger.warning(f"Diagnostic: disk_usage failed: {e}")
        return ({'disk_free_bytes': None, 'disk_total_bytes': None},
                {'disk_usage': 'permission_or_path_unavailable'})
    return {'disk_free_bytes': usage.free,
            'disk_total_bytes': usage.total}, {}


def collect_backup_metrics(ctx: ApiContext) -> tuple[dict, dict]:
    """`ctx.managers.get('file_ops')` gates access to `ctx.file_ops`.

    Preserved from the code this replaced. The two are separate attributes and
    an instance can have one without the other, so the guard is on the one
    that says whether file operations were wired at all.
    """
    fields = {'backup_count': 0, 'backup_total_size': 0}
    if not ctx.managers.get('file_ops'):
        return fields, {}
    try:
        backups = ctx.file_ops.list_backups()
    except Exception as e:
        logger.warning(f"Diagnostic: failed to read backup metrics: {e}")
        return fields, {'backups': 'failed_to_list'}
    if isinstance(backups, dict):
        unified = backups.get('unified', [])
        if isinstance(unified, list):
            fields['backup_count'] = len(unified)
            fields['backup_total_size'] = sum(
                item.get('metadata', {}).get('size', 0)
                for item in unified if isinstance(item, dict))
    return fields, {}


def collect_sanitized_logs(ctx: ApiContext) -> tuple[dict, dict]:
    """The last 50 log lines, run through the structured logger's own
    sanitizer — the same one that keeps secrets out of the log file, reused
    here so the snapshot cannot be a way around it."""
    logs_dir = getattr(ctx.file_ops, 'logs_dir', None)
    if not ctx.managers.get('file_ops') or not isinstance(logs_dir, (str, Path)):
        return {'sanitized_logs': []}, {}
    sanitized = []
    try:
        log_file = Path(logs_dir) / 'certmate.log'
        if log_file.exists() and log_file.is_file():
            with open(log_file, 'r', encoding='utf-8') as handle:
                last_lines = list(deque(handle, maxlen=50))

            from modules.core.structured_logging import JSONFormatter
            formatter = JSONFormatter()
            for line in last_lines:
                text = line.strip()
                if not text:
                    continue
                try:
                    sanitized.append(formatter.sanitize_data(json.loads(text)))
                except Exception:
                    sanitized.append(formatter.sanitize_data(text))
    except Exception as e:
        logger.warning(f"Diagnostic: failed to read sanitized logs: {e}")
        return {'sanitized_logs': sanitized}, {'sanitized_logs': 'failed_to_read'}
    return {'sanitized_logs': sanitized}, {}


def collect_recent_audit(ctx: ApiContext) -> tuple[dict, dict]:
    """Only timestamp / operation / resource_type / status survive.

    Domain names, usernames, IP addresses and the audit details payload are
    dropped before serialization. Anyone reading the resulting bug report sees
    operational tempo without learning who did what to which domain from which
    IP.
    """
    try:
        raw = ctx.audit.get_recent_entries(limit=5) if ctx.audit else []
    except Exception as e:
        logger.warning(f"Diagnostic: audit log read failed: {e}")
        return {'recent_audit': []}, {'recent_audit': 'failed_to_read'}
    if not isinstance(raw, list):
        return {'recent_audit': []}, {}
    return {'recent_audit': [{'timestamp': entry.get('timestamp'),
                              'operation': entry.get('operation'),
                              'resource_type': entry.get('resource_type'),
                              'status': entry.get('status')}
                             for entry in raw[:5]
                             if isinstance(entry, dict)]}, {}


DIAGNOSTIC_COLLECTORS = (
    collect_runtime,
    collect_library_versions,
    collect_certbot_version,
    collect_storage_permissions,
    collect_scheduler,
    collect_certificate_count,
    collect_settings_scalars,
    collect_oidc_status,
    collect_disk_usage,
    collect_backup_metrics,
    collect_sanitized_logs,
    collect_recent_audit,
)


def build_diagnostics_snapshot(ctx: ApiContext) -> dict:
    """Every collector, merged. A collector that raises is recorded as a
    failed section rather than being allowed to end the snapshot: this is
    what somebody attaches to a bug report, and losing all of it because one
    subsystem is broken is the case it is most needed in."""
    payload, errors = {}, {}
    for collector in DIAGNOSTIC_COLLECTORS:
        try:
            fields, section_errors = collector(ctx)
        except Exception as e:
            logger.warning("Diagnostic: %s raised: %s", collector.__name__, e)
            errors[collector.__name__] = 'collector_failed'
            continue
        payload.update(fields)
        errors.update(section_errors)
    if errors:
        payload['errors'] = errors
    return payload


def create_health_resources(api, models, ctx: ApiContext) -> dict:
    """Build the health, metrics and diagnostics resources against *ctx*."""

    class HealthCheck(Resource):
        def get(self):
            """Health check: settings readable + background scheduler running."""
            checks, overall = run_health_checks(ctx)
            return ({'status': overall, 'checks': checks},
                    500 if overall == 'unhealthy' else 200)

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

                return {
                    'available': True,
                    'metrics_endpoint': '/metrics',
                    'summary': get_metrics_summary(),
                }
            except Exception as e:
                logger.error(f"Error getting metrics info: {e}")
                return {'error': 'Failed to get metrics information'}, 500

    class DiagnosticsSnapshot(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def get(self):
            """Build a sanitized diagnostic snapshot for bug-report use."""
            return build_diagnostics_snapshot(ctx), 200

    return {
        'HealthCheck': HealthCheck,
        'MetricsList': MetricsList,
        'DiagnosticsSnapshot': DiagnosticsSnapshot,
    }
