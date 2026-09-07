"""
API endpoints module for CertMate
Defines Flask-RESTX Resource classes for REST API endpoints
"""

import logging

from .resources_cache import create_cache_resources
from .resources_backup import create_backup_resources
from .resources_inventory import create_inventory_resources
from .resources_lifecycle import create_lifecycle_resources
from .resources_certificates import create_certificates_resources
from .resources_deployment import create_deployment_resources
from .resources_discovery import create_discovery_resources
from .resources_downloads import create_download_resources
from .resources_ca import create_ca_resources
from .resources_settings import create_settings_resources
from .resources_storage import create_storage_resources
# Re-exported: it moved to resources_backup with the endpoints that use it,
# and tests import it from here.
from .resources_backup import _validate_backup_filename  # noqa: F401
from .resources_health import create_health_resources
from .resource_context import build_context
# Re-exported: moved to path_validation with the endpoints that use them, and
# thirteen former call sites plus the existing tests reach for these names.
from .path_validation import (  # noqa: F401
    DOMAIN_RE as _DOMAIN_RE,
    validate_domain_path as _validate_domain_path,
)
# Re-exported: these moved to tls_probe with the endpoints that use them, and
# several tests import them from here. A test that STUBS one of them must patch
# it in the module that calls it — rebinding this copy leaves the call site
# untouched, which is a test that runs and verifies nothing.
from .tls_probe import (  # noqa: F401
    _PROBE_PROTOCOLS, _certificate_fingerprint, _certificate_subject_summary,
    _https_proxy_for, _probe_smtp_starttls, _probe_tls_certificate,
    _san_dns_names, _tls_probe_timeout_seconds,
)









def _privkey_to_pkcs1(pem_bytes):
    """Re-serialize a PEM private key into the legacy PKCS#1/SEC1
    ("TraditionalOpenSSL") form for stacks that don't accept the PKCS#8
    that certbot writes (issue #233).

    Raises ValueError/TypeError for key types that have no traditional
    encoding (e.g. Ed25519); the caller maps that to a 422.
    """
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem_bytes, password=None)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )














logger = logging.getLogger(__name__)


def create_api_resources(api, models, managers):
    """Create and register all API resource classes

    Args:
        api: Flask-RESTX Api instance
        models: Dictionary of API models
        managers: Dictionary of manager instances (auth, settings, certificates, etc.)
    """

    # The manager set and the helpers that used to be captured here now live
    # in modules/api/resource_context.py, so a resource class can be moved into
    # a module of its own without dragging this closure with it (#667). The
    # local names below are aliases kept during the decomposition: call sites
    # move group by group, not all at once.
    ctx = build_context(managers)
    # Groups that have moved into modules of their own build here and
    # are merged into the returned mapping below (#667).
    settings_resources = create_settings_resources(api, models, ctx)
    extracted = {
        # Only the two factory.py registers from the returned mapping; the
        # DNS account resources are bound to a namespace below instead, and
        # adding them here would change what this function hands back.
        'Settings': settings_resources['Settings'],
        'DNSProviders': settings_resources['DNSProviders'],
        **create_cache_resources(api, models, ctx),
        **create_health_resources(api, models, ctx),
        **create_backup_resources(api, models, ctx),
        **create_inventory_resources(api, models, ctx),
        **create_ca_resources(api, models, ctx),
        **create_download_resources(api, models, ctx, _privkey_to_pkcs1),
        **create_lifecycle_resources(api, models, ctx),
        **create_certificates_resources(api, models, ctx),
        **create_deployment_resources(api, models, ctx),
        **create_discovery_resources(api, models, ctx),
    }
    # The manager aliases and helper wrappers that used to live here are gone
    # with the last resource class: every group now takes the context and
    # builds its own. What remains of this function is composition — build the
    # groups, bind the two namespaces that are created here rather than by
    # factory.py, and hand back the mapping (#667).

    # Health check endpoint

    # Metrics endpoints

    # Diagnostic snapshot endpoint — closes #150. Powers the "Report this
    # issue" button in the error toast: when an admin hits a recoverable
    # API error, the UI fetches this snapshot, merges it with the
    # client-side context (browser, page, error envelope), formats the
    # whole thing as Markdown, copies it to the clipboard, and opens
    # github.com/issues/new pre-filled. Operators reading the resulting
    # issue see an actionable bug report instead of "doesn't work".
    #
    # Security stance: admin-only via require_role('admin'). The response
    # is built from a fixed allowlist of scalar fields plus a sanitized
    # tail of the audit log — never the full settings tree, never any
    # secret, never resource identifiers from the audit entries
    # (resource_id / user / ip_address / details / error are stripped).
    # Sanitization is enforced inline in this handler, not deferred to a
    # generic mask helper, so a future contributor adding a field is
    # forced to think about whether to include it.

    # Settings endpoints

    # DNS Providers endpoint

    # Cache management endpoints


    # Certificate endpoints

    # --- Certificate inventory (discovery) -------------------------------- #
    # The inventory is populated by the deep TLS probe (#467), scheduled
    # endpoint discovery (#469) and CT-log monitoring (#470). These endpoints
    # expose it to the dashboard (#471). cert_inventory / cert_discovery /
    # ct_monitor are optional managers (absent in minimal-manager unit setups),
    # so every handler guards for their absence with a 503.










    # Files containing private-key material. A viewer-role caller is
    # permitted to download public certificate material (cert, chain,
    # fullchain) but anything that exposes the private key requires
    # operator role. The default ZIP includes privkey.pem and is
    # therefore also operator-gated. (2026-05-12 API auth audit
    # follow-up: viewer-can-pull-privkey was an information-disclosure
    # surface that the original endpoint exposed.)












    # Backup endpoints (Unified backup system for atomic consistency)


    # DNS Accounts management





    # Storage Backend Management






    # Register storage backend endpoints. Unlike the health, cache and backup
    # groups — which factory.py registers from the returned mapping — these
    # build their namespace here, so the classes are taken from `extracted`
    # rather than from the local scope they no longer occupy (#667).
    # Built here rather than merged into `extracted` above: unlike the health,
    # cache and backup groups, these are registered on a namespace of their own
    # right here instead of by factory.py from the returned mapping. Adding
    # them to that mapping would change what create_api_resources hands back,
    # which the resource contract test pins deliberately (#667).
    storage_resources = create_storage_resources(api, models, ctx)
    storage_ns = api.namespace('storage', description='Storage Backend Operations')
    storage_ns.add_resource(storage_resources['StorageBackendInfo'], '/info')
    storage_ns.add_resource(storage_resources['StorageBackendConfig'], '/config')
    storage_ns.add_resource(storage_resources['StorageBackendTest'], '/test')
    storage_ns.add_resource(storage_resources['StorageBackendMigrate'], '/migrate')
    storage_ns.add_resource(storage_resources['StorageAzureKeyVaultBackfill'],
                            '/azure-keyvault/backfill-certificates')

    # Register DNS management endpoints
    dns_ns = api.namespace('dns', description='DNS Provider Account Management')
    dns_ns.add_resource(settings_resources['DNSAccounts'], '/<string:provider>/accounts', endpoint='dns_accounts_provider')
    dns_ns.add_resource(settings_resources['DNSAccounts'], '/accounts', endpoint='dns_accounts_global')
    dns_ns.add_resource(settings_resources['DNSAccountDetail'], '/<string:provider>/accounts/<string:account_id>')

    # Return all resource classes (CA provider test will be registered in app.py)
    return {
        **extracted,
    }
