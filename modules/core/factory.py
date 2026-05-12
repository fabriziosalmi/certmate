import os
import secrets
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from flask import Flask, request
from flask_cors import CORS
from flask_restx import Api, Namespace

from modules.core import (
    FileOperations, SettingsManager, AuthManager,
    CertificateManager, DNSManager, CacheManager, StorageManager,
    PrivateCAGenerator, CSRHandler, ClientCertificateManager,
    OCSPResponder, CRLManager, AuditLogger,
    RateLimitConfig, SimpleRateLimiter,
    get_certmate_logger
)
from modules.core.shell import ShellExecutor
from modules.core.notifier import Notifier
from modules.core.events import EventBus
from modules.core.digest import WeeklyDigest
from modules.core.deployer import DeployManager
from modules.core.ca_manager import CAManager
from modules.api import create_api_models, create_api_resources
from modules.api.client_certificates import create_client_certificate_resources
from modules.web import register_web_routes

logger = get_certmate_logger('factory')
request_logger = get_certmate_logger('request-watchdog')


class AppContainer:
    """DI Container holding all managers and application state"""
    def __init__(self):
        self.app = None
        self.api = None
        self.scheduler = None
        self.managers = {}
        self.cert_dir = None
        self.data_dir = None
        self.backup_dir = None
        self.logs_dir = None
        self.request_watchdog = None


def _env_float(name: str, default: float, min_value: float = 0.0) -> float:
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning(f"Invalid {name} value '{raw}'; using default {default}")
        return default
    return max(value, min_value)


def _format_thread_stack(thread_id: int) -> str:
    frame = sys._current_frames().get(thread_id)
    if frame is None:
        return ''
    return ''.join(traceback.format_stack(frame))


def setup_slow_request_logging(app: Flask, container: AppContainer):
    """Track long-running requests and log thread stacks when they linger."""
    enabled = os.getenv('CERTMATE_SLOW_REQUEST_LOGGING', 'true').lower() in ('1', 'true', 'yes', 'on')
    if not enabled:
        return

    slow_after = _env_float('CERTMATE_SLOW_REQUEST_THRESHOLD_SECONDS', 30.0, 0.1)
    scan_every = _env_float('CERTMATE_SLOW_REQUEST_SCAN_SECONDS', 10.0, 1.0)
    repeat_every = _env_float('CERTMATE_SLOW_REQUEST_REPEAT_SECONDS', slow_after, 0.1)

    active_requests: dict[int, dict[str, object]] = {}
    lock = threading.Lock()
    stop_event = threading.Event()

    @app.before_request
    def _track_request_start():
        thread = threading.current_thread()
        with lock:
            active_requests[thread.ident or 0] = {
                'started_at': time.perf_counter(),
                'method': getattr(request, 'method', None),
                'path': getattr(request, 'path', None),
                'remote_addr': getattr(request, 'remote_addr', None),
                'request_id': request.headers.get('X-Request-Id'),
                'thread_name': thread.name,
                'last_reported_at': None,
            }

    @app.after_request
    def _log_slow_request(response):
        thread = threading.current_thread()
        started = None
        meta = None
        with lock:
            meta = active_requests.pop(thread.ident or 0, None)
        if meta:
            started = meta.get('started_at')
        if started is not None:
            duration_ms = (time.perf_counter() - float(started)) * 1000
            if duration_ms >= slow_after * 1000:
                request_logger.warning(
                    "Slow request completed",
                    method=meta.get('method'),
                    path=meta.get('path'),
                    remote_addr=meta.get('remote_addr'),
                    request_id=meta.get('request_id'),
                    thread_name=meta.get('thread_name'),
                    thread_id=thread.ident,
                    status_code=getattr(response, 'status_code', None),
                    duration_ms=round(duration_ms, 2),
                    threshold_seconds=slow_after,
                )
        return response

    @app.teardown_request
    def _clear_active_request(_exc):
        thread = threading.current_thread()
        with lock:
            active_requests.pop(thread.ident or 0, None)

    def _watchdog():
        while not stop_event.wait(scan_every):
            now = time.perf_counter()
            snapshots = []
            with lock:
                for thread_id, meta in active_requests.items():
                    started_at = float(meta.get('started_at', now))
                    age = now - started_at
                    last_reported = meta.get('last_reported_at')
                    if age < slow_after:
                        continue
                    if last_reported is not None and (now - float(last_reported)) < repeat_every:
                        continue
                    meta['last_reported_at'] = now
                    snapshots.append((thread_id, dict(meta), age))

            for thread_id, meta, age in snapshots:
                stack = _format_thread_stack(thread_id)
                request_logger.warning(
                    "Request still running",
                    method=meta.get('method'),
                    path=meta.get('path'),
                    remote_addr=meta.get('remote_addr'),
                    request_id=meta.get('request_id'),
                    thread_name=meta.get('thread_name'),
                    thread_id=thread_id,
                    duration_ms=round(age * 1000, 2),
                    threshold_seconds=slow_after,
                    stack=stack or None,
                )

    watcher = threading.Thread(
        target=_watchdog,
        name='certmate-request-watchdog',
        daemon=True,
    )
    watcher.start()
    container.request_watchdog = {
        'thread': watcher,
        'stop_event': stop_event,
    }


def _verify_dir_writable(directory: Path) -> Optional[str]:
    """Probe a directory for write access. Returns None on success, or a
    short reason string on failure. Used at boot (#121) so a Docker setup
    with non-writable host mounts fails fast with a clear message instead
    of silently corrupting state later in the wizard.
    """
    try:
        if not directory.exists():
            return f"does not exist (and could not be created)"
        if not directory.is_dir():
            return f"exists but is not a directory"
        probe = directory / f".certmate_writeprobe_{os.getpid()}"
        try:
            probe.write_text('ok', encoding='utf-8')
        finally:
            try:
                probe.unlink()
            except FileNotFoundError:
                pass
    except PermissionError:
        return "not writable by the container user (check host mount permissions)"
    except OSError as e:
        return f"OS error during write probe: {e}"
    return None


def setup_directories(container: AppContainer, test_config=None):
    _base = Path(__file__).resolve().parent.parent.parent
    container.cert_dir = (_base / "certificates").resolve()
    container.data_dir = (_base / "data").resolve()
    container.backup_dir = (_base / "backups").resolve()
    container.logs_dir = (_base / "logs").resolve()

    required = [
        ('certificates', container.cert_dir),
        ('data', container.data_dir),
        ('backups', container.backup_dir),
        ('logs', container.logs_dir),
    ]

    # Best-effort create. If the parent is read-only this raises;
    # we'd rather hit the writable probe below for a single clean error.
    for _, directory in required:
        try:
            directory.mkdir(exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create {directory}: {e}")

    try:
        (container.backup_dir / "unified").mkdir(exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create {container.backup_dir / 'unified'}: {e}")

    # Boot-time writeability check (#121). Surface a clear error so the
    # operator knows exactly which host mount is wrong instead of having
    # the setup wizard half-succeed.
    failures = []
    for label, directory in required:
        reason = _verify_dir_writable(directory)
        if reason is not None:
            failures.append(f"  - {label} ({directory}): {reason}")

    if failures:
        msg = (
            "Required directories are not writable by the CertMate process. "
            "Fix host-mount permissions (the container runs as UID/GID 1000:1000) "
            "and restart:\n" + "\n".join(failures)
        )
        logger.error(msg)
        raise RuntimeError(msg)

    # Clean up any orphan .tmp files left by a previous hard crash
    for _search_dir in (container.cert_dir, container.data_dir):
        try:
            if _search_dir.exists():
                for _tmp in _search_dir.rglob('*.tmp'):
                    try:
                        _tmp.unlink()
                        logger.debug(f"Cleaned up orphan temp file: {_tmp}")
                    except OSError:
                        pass
        except Exception:
            pass

    # Docker volume persistence check (#130). Warn loudly if /app/data
    # appears to be ephemeral container storage rather than a persistent
    # volume. This catches the most common deployment mistake: forgetting
    # to mount ./data:/app/data in docker-compose.yml.
    _in_docker = Path('/.dockerenv').exists() or os.getenv('container') is not None
    if _in_docker:
        sentinel = container.data_dir / '.certmate_persistent'
        if sentinel.exists():
            logger.info("Persistent volume verified — data directory survives container restarts")
        else:
            # First boot on this volume: create sentinel. If the sentinel
            # doesn't survive the next restart, the volume wasn't mounted.
            try:
                sentinel.write_text('1')
            except OSError:
                pass
            logger.warning(
                "PERSISTENCE CHECK: This appears to be the first boot on this data directory. "
                "If you see this message on every restart, your /app/data volume is NOT "
                "persistent and ALL configuration (admin account, settings, certificates) "
                "will be LOST on container recreation. Mount a persistent volume: "
                "-v ./data:/app/data:rw (Docker) or a PVC (Kubernetes). "
                "Required volumes: /app/data, /app/certificates, /app/logs, /app/backups"
            )


def _secret_key_from_env_or_generate(data_dir: Path) -> str:
    """Return a Flask secret key.

    Resolution order (mutually exclusive):
    1. SECRET_KEY_FILE — if set, read the key from that file. Any read error
       or empty result generates a fresh key immediately; SECRET_KEY is never
       consulted (to avoid encouraging both vars).
    2. SECRET_KEY — only checked when SECRET_KEY_FILE is absent. Insecure
       defaults ('', 'your-secret-key-here', 'change-me', 'secret') are
       treated as unset and fall through to step 3.
    3. Persisted generated key — reads data_dir/.secret_key if it exists so
       sessions survive restarts, otherwise generates secrets.token_hex(32)
       and attempts to persist it. A persistence failure is logged but does
       not block startup; sessions will not survive restarts in that case.
    """
    insecure_defaults = {'', 'your-secret-key-here', 'change-me', 'secret'}

    explicit_key_file = os.getenv('SECRET_KEY_FILE')
    if explicit_key_file:
        try:
            key = Path(explicit_key_file).read_text().strip()
            if key:
                return key
            logger.warning(f"SECRET_KEY_FILE ({explicit_key_file}) is empty; generating a fresh secret key.")
        except Exception as e:
            logger.warning(f"Could not read SECRET_KEY_FILE ({explicit_key_file}): {e}; generating a fresh secret key.")
        return secrets.token_hex(32)

    env_key = os.getenv('SECRET_KEY', '')
    if env_key and env_key not in insecure_defaults:
        return env_key

    if env_key in insecure_defaults and env_key != '':
        logger.warning(f"SECRET_KEY is set to an insecure default; ignoring it.")

    implicit_key_file = data_dir / '.secret_key'
    if implicit_key_file.exists():
        return implicit_key_file.read_text().strip()

    key = secrets.token_hex(32)
    try:
        implicit_key_file.write_text(key)
        implicit_key_file.chmod(0o600)
    except OSError as e:
        logger.warning(f"Could not persist SECRET_KEY to {implicit_key_file}: {e}. Sessions will not survive restarts.")
    return key

def configure_app(container: AppContainer, app, test_config=None):
    app.secret_key = _secret_key_from_env_or_generate(container.data_dir)
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

    if test_config:
        app.config.update(test_config)

    if os.getenv('BEHIND_PROXY', '').lower() in ('true', '1', 'yes'):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    cors_origins_env = os.getenv('CORS_ORIGINS', '').strip()
    if cors_origins_env:
        cors_origins = [o.strip() for o in cors_origins_env.split(',') if o.strip()]
    else:
        cors_origins = []  # empty list = deny all cross-origin requests (safe default)

    CORS(app,
         origins=cors_origins,
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         allow_headers=['Authorization', 'Content-Type'],
         supports_credentials=bool(cors_origins),
         max_age=3600)


def initialize_managers(container: AppContainer, app):
    file_ops = FileOperations(
        cert_dir=container.cert_dir,
        data_dir=container.data_dir,
        backup_dir=container.backup_dir,
        logs_dir=container.logs_dir
    )

    settings_manager = SettingsManager(file_ops, container.data_dir / "settings.json")
    dns_manager = DNSManager(settings_manager)
    auth_manager = AuthManager(settings_manager)
    auth_manager.set_hmac_key(app.secret_key)
    # Let SettingsManager hash the legacy api_bearer_token on save using the
    # same HMAC scheme as scoped API keys.
    settings_manager.set_token_hasher(auth_manager.hash_api_token)
    cache_manager = CacheManager(settings_manager)
    storage_manager = StorageManager(settings_manager)
    ca_manager = CAManager(settings_manager)

    ca_dir = container.data_dir / "certs" / "ca"
    private_ca = PrivateCAGenerator(ca_dir)
    private_ca.initialize()

    client_certs_dir = container.data_dir / "certs" / "client"
    client_cert_manager = ClientCertificateManager(client_certs_dir, private_ca)
    ocsp_responder = OCSPResponder(private_ca, client_cert_manager)

    crl_dir = container.data_dir / "certs" / "crl"
    crl_manager = CRLManager(private_ca, client_cert_manager, crl_dir)

    shell_executor = ShellExecutor()

    certificate_manager = CertificateManager(
        cert_dir=container.cert_dir,
        settings_manager=settings_manager,
        dns_manager=dns_manager,
        storage_manager=storage_manager,
        ca_manager=ca_manager,
        shell_executor=shell_executor
    )

    audit_dir = container.logs_dir / "audit"
    audit_logger = AuditLogger(audit_dir)
    # Let AuthManager emit RBAC + scope denials through the same audit
    # surface the rest of the app uses (2026-05-12 API auth audit, F-2).
    auth_manager.set_audit_logger(audit_logger)

    rate_limit_config = RateLimitConfig()
    rate_limiter = SimpleRateLimiter(rate_limit_config)

    notifier = Notifier(settings_manager, data_dir=str(container.data_dir))
    event_bus = EventBus()

    def _on_event(event, data):
        event_titles = {
            'certificate_created': 'Certificate Created',
            'certificate_renewed': 'Certificate Renewed',
            'certificate_failed': 'Certificate Failed',
        }
        title = event_titles.get(event)
        if not title:
            return
        domain = data.get('domain', 'unknown')
        message = f"{title}: {domain}"
        notifier.notify(event, title, message, details=data)

    event_bus.add_listener(_on_event)

    deploy_manager = DeployManager(
        settings_manager=settings_manager,
        shell_executor=shell_executor,
        audit_logger=audit_logger,
        event_bus=event_bus,
        cert_dir=container.cert_dir,
        data_dir=str(container.data_dir),
    )
    event_bus.add_listener(deploy_manager.on_certificate_event)
    app.config['EVENT_BUS'] = event_bus
    # DATA_DIR is the partition the DiagnosticsSnapshot endpoint queries
    # for disk_free / disk_total. Stored on the Flask app config so the
    # RESTX resource can resolve it via current_app without holding a
    # reference to the container.
    app.config['DATA_DIR'] = str(container.data_dir)

    container.managers = {
        'file_ops': file_ops,
        'settings': settings_manager,
        'auth': auth_manager,
        'certificates': certificate_manager,
        'client_certificates': client_cert_manager,
        'dns': dns_manager,
        'cache': cache_manager,
        'storage': storage_manager,
        'ca': ca_manager,
        'private_ca': private_ca,
        'csr': CSRHandler,
        'ocsp': ocsp_responder,
        'crl': crl_manager,
        'audit': audit_logger,
        'rate_limiter': rate_limiter,
        'shell_executor': shell_executor,
        'notifier': notifier,
        'events': event_bus,
        'digest': WeeklyDigest(
            certificate_manager, client_cert_manager,
            audit_logger, notifier, settings_manager
        ),
        'deployer': deploy_manager,
    }


def _certificate_renewal_job():
    """Picklable wrapper for certificate renewal check"""
    from flask import current_app
    managers = current_app.config.get('MANAGERS')
    if managers and 'certificates' in managers:
        managers['certificates'].check_renewals()


def _client_certificate_renewal_job():
    """Picklable wrapper for client certificate renewal check"""
    from flask import current_app
    managers = current_app.config.get('MANAGERS')
    if managers and 'client_certificates' in managers:
        managers['client_certificates'].check_renewals()


def _weekly_digest_job():
    """Picklable wrapper for weekly digest"""
    from flask import current_app
    managers = current_app.config.get('MANAGERS')
    if managers and 'digest' in managers:
        managers['digest'].send()


def setup_scheduler(container: AppContainer):
    """Set up APScheduler for background tasks with persistent store."""
    try:
        from sqlalchemy import create_engine, event as _sa_event
        _db_path = container.data_dir / 'scheduler_jobs.sqlite'
        _engine = create_engine(f'sqlite:///{_db_path}', connect_args={'check_same_thread': False})

        @_sa_event.listens_for(_engine, 'connect')
        def _set_wal_mode(dbapi_conn, _record):
            dbapi_conn.execute('PRAGMA journal_mode=WAL')
            dbapi_conn.execute('PRAGMA synchronous=NORMAL')

        jobstores = {
            'default': SQLAlchemyJobStore(engine=_engine)
        }
        scheduler = BackgroundScheduler(jobstores=jobstores)
        scheduler.start()

        scheduler.add_job(
            func=_certificate_renewal_job,
            trigger="cron", hour=2, minute=0,
            id='certificate_renewal_check', replace_existing=True
        )
        scheduler.add_job(
            func=_client_certificate_renewal_job,
            trigger="cron", hour=3, minute=0,
            id='client_certificate_renewal_check', replace_existing=True
        )
        scheduler.add_job(
            func=_weekly_digest_job,
            trigger="cron", day_of_week='sun', hour=0, minute=0,
            id='weekly_digest', replace_existing=True
        )
        container.scheduler = scheduler
        container.managers['scheduler'] = scheduler
    except Exception as e:
        logger.error(f"Scheduler setup failed — automatic certificate renewal will NOT run: {e}")
        import warnings
        warnings.warn(
            f"CertMate scheduler failed to start: {e}. "
            "Automatic certificate renewal is DISABLED.",
            RuntimeWarning, stacklevel=2,
        )


def setup_api(container: AppContainer, app):
    from modules import __version__
    api = Api(app, version=__version__, title='CertMate API',
              description='SSL Certificate API', doc='/docs/', prefix='/api')

    api.authorizations = {
        'Bearer': {'type': 'apiKey', 'in': 'header', 'name': 'Authorization', 'description': 'Bearer token'}
    }

    api_models = create_api_models(api)
    api_resources = create_api_resources(api, api_models, container.managers)
    api_resources.update(create_client_certificate_resources(api, container.managers))

    ns_certificates = Namespace('certificates', description='Certificate operations')
    ns_client_certs = Namespace('client-certs', description='Client certificate operations')
    ns_ocsp = Namespace('ocsp', description='OCSP certificate status')
    ns_crl = Namespace('crl', description='Certificate Revocation List')
    ns_settings = Namespace('settings', description='Settings operations')
    ns_health = Namespace('health', description='Health check')
    ns_backups = Namespace('backups', description='Backup and restore')
    ns_cache = Namespace('cache', description='Cache management operations')
    ns_metrics = Namespace('metrics', description='Prometheus metrics and monitoring')
    ns_diagnostics = Namespace('diagnostics', description='Sanitized diagnostic snapshot for bug reports')

    namespaces = [
        ns_certificates, ns_client_certs, ns_ocsp, ns_crl, ns_settings,
        ns_health, ns_backups, ns_cache, ns_metrics, ns_diagnostics
    ]
    for ns in namespaces:
        api.add_namespace(ns)

    ns_health.add_resource(api_resources['HealthCheck'], '')
    ns_metrics.add_resource(api_resources['MetricsList'], '')
    ns_diagnostics.add_resource(api_resources['DiagnosticsSnapshot'], '/snapshot')
    ns_settings.add_resource(api_resources['Settings'], '')
    ns_settings.add_resource(api_resources['DNSProviders'], '/dns-providers')
    ns_settings.add_resource(api_resources['CAProviderTest'], '/test-ca-provider')
    ns_cache.add_resource(api_resources['CacheStats'], '/stats')
    ns_cache.add_resource(api_resources['CacheClear'], '/clear')
    ns_certificates.add_resource(api_resources['CertificateList'], '')
    ns_certificates.add_resource(api_resources['CreateCertificate'], '/create')
    ns_certificates.add_resource(api_resources['CheckDNSAlias'], '/check-dns-alias')
    ns_certificates.add_resource(api_resources['CertificateDetail'], '/<string:domain>')
    ns_certificates.add_resource(api_resources['CertificateDNSAliasCheck'], '/<string:domain>/dns-alias-check')
    ns_certificates.add_resource(api_resources['DownloadCertificate'], '/<string:domain>/download')
    ns_certificates.add_resource(api_resources['RenewCertificate'], '/<string:domain>/renew')
    ns_certificates.add_resource(api_resources['CertificateAutoRenew'], '/<string:domain>/auto-renew')
    ns_certificates.add_resource(api_resources['CertificateRunDeploy'], '/<string:domain>/deploy')
    ns_backups.add_resource(api_resources['BackupList'], '')
    ns_backups.add_resource(api_resources['BackupCreate'], '/create')
    ns_backups.add_resource(api_resources['BackupDownload'], '/download/<backup_type>/<filename>')
    ns_backups.add_resource(api_resources['BackupRestore'], '/restore/<backup_type>')
    ns_backups.add_resource(api_resources['BackupDelete'], '/delete/<backup_type>/<filename>')

    ns_client_certs.add_resource(api_resources['ClientCertificateList'], '')
    ns_client_certs.add_resource(api_resources['ClientCertificateCreate'], '/create')
    ns_client_certs.add_resource(api_resources['ClientCertificateDetail'], '/<string:identifier>')
    ns_client_certs.add_resource(api_resources['ClientCertificateDownload'],
                                 '/<string:identifier>/download/<string:file_type>')
    ns_client_certs.add_resource(api_resources['ClientCertificateRevoke'], '/<string:identifier>/revoke')
    ns_client_certs.add_resource(api_resources['ClientCertificateRenew'], '/<string:identifier>/renew')
    ns_client_certs.add_resource(api_resources['ClientCertificateStatistics'], '/stats')
    ns_client_certs.add_resource(api_resources['ClientCertificateBatch'], '/batch')

    ns_ocsp.add_resource(api_resources['OCSPStatus'], '/status/<int:serial_number>')
    ns_crl.add_resource(api_resources['CRLDistribution'], '/download/<string:format_type>')

    container.api = api


def setup_csrf_protection(app):
    """Reject cookie-authenticated state-changing requests whose Origin/Referer
    doesn't match the host. Bearer-token API clients are unaffected. Combined
    with SameSite=Strict on the session cookie, this is a defense-in-depth
    backstop against CSRF — it blocks the attack on browsers whose SameSite
    enforcement was bypassed (e.g. via subdomain confusion or legacy issues).
    """
    from urllib.parse import urlparse
    SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}
    DEFAULT_PORTS = {'http': 80, 'https': 443}

    def _normalize(scheme: str, netloc: str) -> str:
        """Return a canonical "host:port" string with default ports stripped.

        Same-origin comparison must treat https://example.com and
        https://example.com:443 as identical — and similarly for http on :80.
        """
        netloc = (netloc or '').lower()
        scheme = (scheme or '').lower()
        if ':' in netloc:
            host, _, port = netloc.partition(':')
            try:
                port_int = int(port)
            except ValueError:
                return netloc
            if DEFAULT_PORTS.get(scheme) == port_int:
                return host
            return f'{host}:{port_int}'
        return netloc

    @app.before_request
    def _csrf_origin_check():
        if request.method in SAFE_METHODS:
            return None
        # Bearer-token requests are API clients, not browsers — they pick the
        # token themselves and aren't subject to ambient cookie auth.
        auth_header = request.headers.get('Authorization', '')
        if auth_header.lower().startswith('bearer '):
            return None
        # Only enforce for cookie-authenticated sessions. Unauthenticated
        # requests are rejected later by the auth decorators if needed.
        if not request.cookies.get('certmate_session'):
            return None

        expected = _normalize(request.scheme, request.host or '')
        origin = request.headers.get('Origin') or ''
        referer = request.headers.get('Referer') or ''
        source = origin or referer
        if not source:
            from flask import jsonify
            return jsonify({'error': 'CSRF protection: missing Origin/Referer'}), 403
        try:
            parsed = urlparse(source)
            source_host = _normalize(parsed.scheme, parsed.netloc)
        except Exception:
            source_host = ''
        if source_host != expected:
            from flask import jsonify
            return jsonify({'error': 'CSRF protection: Origin/Referer mismatch'}), 403
        return None


def setup_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        if 'Content-Security-Policy' not in response.headers:
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                # Alpine.js v3 requires 'unsafe-eval' (uses new Function() for expression
                # evaluation). Removing it breaks the UI. The risk is mitigated by
                # 'unsafe-inline' already being required for inline <script> blocks.
                # To eliminate unsafe-eval, migrate to the @alpinejs/csp build.
                #
                # ReDoc and its Montserrat/Roboto fonts used to require a CDN
                # script-src/style-src/font-src whitelist. v2.4.15 self-hosts the
                # redoc.standalone.js bundle under static/js/ and pins ReDoc's
                # typography to the system-font stack, removing the need for
                # cdn.redoc.ly, fonts.googleapis.com, fonts.gstatic.com — the
                # /redoc/ page is now air-gapped clean.
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "font-src 'self'; "
                "img-src 'self' data:; "
                # Deployment-status checks (#125) cross-fetch every monitored
                # domain to verify it's serving the expected cert — these are
                # by definition NOT same-origin. Allow https: + a websocket
                # scheme for any future real-time push. data: stays excluded.
                "connect-src 'self' https: wss:; "
                "frame-ancestors 'self'; "
                "form-action 'self'; "
                "base-uri 'self'; "
                "object-src 'none'"
            )
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'

        hsts_enabled = os.getenv('CERTMATE_ENABLE_HSTS', '').lower() == 'true'
        is_https = (request.is_secure or app.config.get('PREFERRED_URL_SCHEME') == 'https')

        if is_https or hsts_enabled:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        return response


def setup_rate_limiting(app, container: AppContainer):
    from flask import request as flask_request, jsonify as flask_jsonify
    rate_limiter = container.managers.get('rate_limiter')
    if not rate_limiter:
        return

    @app.before_request
    def check_rate_limit():
        path = flask_request.path
        if not path.startswith('/api/'):
            return None
        # Only skip rate limiting for auth endpoints (login needs its own limiter)
        if path.startswith('/api/auth/'):
            return None

        client_ip = flask_request.remote_addr or '0.0.0.0'  # nosec B104
        endpoint = 'default'
        if 'certificates' in path and 'create' in path:
            endpoint = 'certificate_create'
        elif 'certificates' in path and 'batch' in path:
            endpoint = 'certificate_batch'
        elif 'certificates' in path and 'renew' in path:
            endpoint = 'certificate_renew'
        elif 'certificates' in path and 'revoke' in path:
            endpoint = 'certificate_revoke'
        elif 'certificates' in path:
            endpoint = 'certificate_list'
        elif 'ocsp' in path:
            endpoint = 'ocsp_status'
        elif 'crl' in path:
            endpoint = 'crl_download'

        if not rate_limiter.is_allowed(client_ip, endpoint):
            return flask_jsonify({
                'error': 'Rate limit exceeded',
                'message': 'Too many requests.',
                'retry_after': 60
            }), 429


def create_app(test_config=None):
    """Application Factory for CertMate"""
    container = AppContainer()
    setup_directories(container, test_config)

    # Resolve project root (three levels up from modules/core/factory.py)
    # Using absolute paths to ensure reliability across environments (Docker, local, tests)
    factory_path = Path(__file__).resolve()
    base_dir = factory_path.parent.parent.parent
    template_dir = (base_dir / "templates").resolve()
    static_dir = (base_dir / "static").resolve()

    if not template_dir.exists():
        logger.warning(f"Template directory not found at {template_dir}")
    if not static_dir.exists():
        logger.warning(f"Static directory not found at {static_dir}")

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir)
    )
    container.app = app

    configure_app(container, app, test_config)
    initialize_managers(container, app)
    setup_api(container, app)
    register_web_routes(app, container.managers)
    setup_csrf_protection(app)
    setup_security_headers(app)
    setup_rate_limiting(app, container)
    setup_slow_request_logging(app, container)
    setup_scheduler(container)

    return app, container
