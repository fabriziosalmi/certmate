import os
import tempfile
import secrets
from pathlib import Path
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


def setup_directories(container: AppContainer, test_config=None):
    try:
        _base = Path(__file__).resolve().parent.parent.parent
        container.cert_dir = (_base / "certificates").resolve()
        container.data_dir = (_base / "data").resolve()
        container.backup_dir = (_base / "backups").resolve()
        container.logs_dir = (_base / "logs").resolve()

        for directory in [
            container.cert_dir, container.data_dir,
            container.backup_dir, container.logs_dir
        ]:
            directory.mkdir(exist_ok=True)

        (container.backup_dir / "unified").mkdir(exist_ok=True)

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
    except Exception as e:
        logger.error(f"Failed to create dirs: {e}")
        container.cert_dir = Path(tempfile.mkdtemp(prefix="certmate_certs_"))
        container.data_dir = Path(tempfile.mkdtemp(prefix="certmate_data_"))
        container.backup_dir = Path(tempfile.mkdtemp(
            prefix="certmate_backups_"))
        container.logs_dir = Path(tempfile.mkdtemp(prefix="certmate_logs_"))


def configure_app(container: AppContainer, app, test_config=None):
    secret_key = os.getenv('SECRET_KEY', '')
    insecure_defaults = {'', 'your-secret-key-here', 'change-me', 'secret'}
    if secret_key in insecure_defaults:
        key_file = container.data_dir / '.secret_key'
        if key_file.exists():
            secret_key = key_file.read_text().strip()
        else:
            secret_key = secrets.token_hex(32)
            try:
                key_file.write_text(secret_key)
                key_file.chmod(0o600)
            except OSError as e:
                logger.warning(f"Could not persist SECRET_KEY to {key_file}: {e}. Sessions will not survive restarts.")
    app.secret_key = secret_key
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
    settings_manager.set_token_hasher(auth_manager._hash_api_token)
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

    namespaces = [
        ns_certificates, ns_client_certs, ns_ocsp, ns_crl, ns_settings,
        ns_health, ns_backups, ns_cache, ns_metrics
    ]
    for ns in namespaces:
        api.add_namespace(ns)

    ns_health.add_resource(api_resources['HealthCheck'], '')
    ns_metrics.add_resource(api_resources['MetricsList'], '')
    ns_settings.add_resource(api_resources['Settings'], '')
    ns_settings.add_resource(api_resources['DNSProviders'], '/dns-providers')
    ns_settings.add_resource(api_resources['CAProviderTest'], '/test-ca-provider')
    ns_cache.add_resource(api_resources['CacheStats'], '/stats')
    ns_cache.add_resource(api_resources['CacheClear'], '/clear')
    ns_certificates.add_resource(api_resources['CertificateList'], '')
    ns_certificates.add_resource(api_resources['CreateCertificate'], '/create')
    ns_certificates.add_resource(api_resources['CertificateDetail'], '/<string:domain>')
    ns_certificates.add_resource(api_resources['DownloadCertificate'], '/<string:domain>/download')
    ns_certificates.add_resource(api_resources['RenewCertificate'], '/<string:domain>/renew')
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

        expected_host = (request.host or '').lower()
        origin = request.headers.get('Origin') or ''
        referer = request.headers.get('Referer') or ''
        source = origin or referer
        if not source:
            from flask import jsonify
            return jsonify({'error': 'CSRF protection: missing Origin/Referer'}), 403
        try:
            source_host = urlparse(source).netloc.lower()
        except Exception:
            source_host = ''
        if source_host != expected_host:
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
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.redoc.ly; "
                "style-src 'self' 'unsafe-inline' cdn.redoc.ly fonts.googleapis.com; "
                "font-src 'self' fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
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
    setup_scheduler(container)

    return app, container
