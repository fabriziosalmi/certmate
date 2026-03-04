
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

import logging
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
        container.cert_dir = Path("certificates")
        container.data_dir = Path("data")
        container.backup_dir = Path("backups")
        container.logs_dir = Path("logs")
        
        for directory in [container.cert_dir, container.data_dir, container.backup_dir, container.logs_dir]:
            directory.mkdir(exist_ok=True)
            
        (container.backup_dir / "unified").mkdir(exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create dirs: {e}")
        container.cert_dir = Path(tempfile.mkdtemp(prefix="certmate_certs_"))
        container.data_dir = Path(tempfile.mkdtemp(prefix="certmate_data_"))
        container.backup_dir = Path(tempfile.mkdtemp(prefix="certmate_backups_"))
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
            except OSError:
                pass
    app.secret_key = secret_key
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
    
    if test_config:
        app.config.update(test_config)

    if os.getenv('BEHIND_PROXY', '').lower() in ('true', '1', 'yes'):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    cors_origins_env = os.getenv('CORS_ORIGINS', '').strip()
    cors_origins = [o.strip() for o in cors_origins_env.split(',') if o.strip()] if cors_origins_env else None

    CORS(app,
         origins=cors_origins if cors_origins else [],
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
    
    settings_file = container.data_dir / "settings.json"
    settings_manager = SettingsManager(file_ops, settings_file)
    dns_manager = DNSManager(settings_manager)
    auth_manager = AuthManager(settings_manager)
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


def setup_scheduler(container: AppContainer):
    try:
        jobstores = {
            'default': SQLAlchemyJobStore(url=f'sqlite:///{container.data_dir}/scheduler_jobs.sqlite')
        }
        scheduler = BackgroundScheduler(jobstores=jobstores)
        scheduler.start()
        
        scheduler.add_job(
            func=container.managers['certificates'].check_renewals,
            trigger="cron", hour=2, minute=0, id='certificate_renewal_check', replace_existing=True
        )
        scheduler.add_job(
            func=container.managers['client_certificates'].check_renewals,
            trigger="cron", hour=3, minute=0, id='client_certificate_renewal_check', replace_existing=True
        )
        scheduler.add_job(
            func=container.managers['digest'].send,
            trigger="cron", day_of_week='sun', hour=0, minute=0, id='weekly_digest', replace_existing=True
        )
        container.scheduler = scheduler
        container.managers['scheduler'] = scheduler
    except Exception as e:
        logger.error(f"Scheduler error: {e}")


def setup_api(container: AppContainer, app):
    from app import __version__
    api = Api(app, version=__version__, title='CertMate API', description='SSL Certificate API', doc='/docs/', prefix='/api')
    
    api.authorizations = {
        'Bearer': { 'type': 'apiKey', 'in': 'header', 'name': 'Authorization', 'description': 'Bearer token' }
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
    ns_backups = Namespace('backups', description='Backup and restore operations')
    ns_cache = Namespace('cache', description='Cache management operations')
    ns_metrics = Namespace('metrics', description='Prometheus metrics and monitoring')

    api.add_namespace(ns_certificates)
    api.add_namespace(ns_client_certs)
    api.add_namespace(ns_ocsp)
    api.add_namespace(ns_crl)
    api.add_namespace(ns_settings)
    api.add_namespace(ns_health)
    api.add_namespace(ns_backups)
    api.add_namespace(ns_cache)
    api.add_namespace(ns_metrics)
    
    ns_health.add_resource(api_resources['HealthCheck'], '')
    ns_metrics.add_resource(api_resources['MetricsList'], '')
    ns_settings.add_resource(api_resources['Settings'], '')
    ns_settings.add_resource(api_resources['DNSProviders'], '/dns-providers')
    ns_settings.add_resource(api_resources['CAProviderTest'], '/test-ca-provider')
    ns_cache.add_resource(api_resources['CacheStats'], '/stats')
    ns_cache.add_resource(api_resources['CacheClear'], '/clear')
    ns_certificates.add_resource(api_resources['CertificateList'], '')
    ns_certificates.add_resource(api_resources['CreateCertificate'], '/create')
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
    ns_client_certs.add_resource(api_resources['ClientCertificateDownload'], '/<string:identifier>/download/<string:file_type>')
    ns_client_certs.add_resource(api_resources['ClientCertificateRevoke'], '/<string:identifier>/revoke')
    ns_client_certs.add_resource(api_resources['ClientCertificateRenew'], '/<string:identifier>/renew')
    ns_client_certs.add_resource(api_resources['ClientCertificateStatistics'], '/stats')
    ns_client_certs.add_resource(api_resources['ClientCertificateBatch'], '/batch')

    ns_ocsp.add_resource(api_resources['OCSPStatus'], '/status/<int:serial_number>')
    ns_crl.add_resource(api_resources['CRLDistribution'], '/download/<string:format_type>')
    
    container.api = api


def setup_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        if 'Content-Security-Policy' not in response.headers:
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'self'; form-action 'self'; "
                "base-uri 'self'; object-src 'none'"
            )
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
        
        if request.is_secure or app.config.get('PREFERRED_URL_SCHEME') == 'https' or os.getenv('CERTMATE_ENABLE_HSTS', '').lower() == 'true':
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
        if path.startswith(('/api/web/', '/api/auth/', '/api/users', '/api/backups')):
            return None
            
        client_ip = flask_request.remote_addr or '0.0.0.0'
        endpoint = 'default'
        if 'certificates' in path and 'create' in path: endpoint = 'certificate_create'
        elif 'certificates' in path and 'batch' in path: endpoint = 'certificate_batch'
        elif 'certificates' in path and 'renew' in path: endpoint = 'certificate_renew'
        elif 'certificates' in path and 'revoke' in path: endpoint = 'certificate_revoke'
        elif 'certificates' in path: endpoint = 'certificate_list'
        elif 'ocsp' in path: endpoint = 'ocsp_status'
        elif 'crl' in path: endpoint = 'crl_download'
        
        if not rate_limiter.is_allowed(client_ip, endpoint):
            return flask_jsonify({'error': 'Rate limit exceeded', 'message': 'Too many requests.', 'retry_after': 60}), 429


def create_app(test_config=None):
    """Application Factory for CertMate"""
    container = AppContainer()
    setup_directories(container, test_config)
    
    app = Flask(__name__)
    container.app = app
    
    configure_app(container, app, test_config)
    initialize_managers(container, app)
    setup_scheduler(container)
    setup_api(container, app)
    
    register_web_routes(app, container.managers)
    setup_security_headers(app)
    setup_rate_limiting(app, container)
    
    return app, container
