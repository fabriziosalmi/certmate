"""
API endpoints module for CertMate
Defines Flask-RESTX Resource classes for REST API endpoints
"""

import logging
import re
import tempfile
import zipfile
import os
import io
from pathlib import Path
from flask import send_file, after_this_request, current_app, request, jsonify
from flask_restx import Resource, fields

from ..core.metrics import get_metrics_summary, is_prometheus_available
from ..core.constants import CERTIFICATE_FILES, iter_cert_domain_dirs
from ..core.auth import ROLE_HIERARCHY

_DOMAIN_RE = re.compile(r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def _validate_backup_filename(filename):
    """Reject path traversal attempts in backup filenames. Returns error string or None."""
    if not filename:
        return 'Filename is required'
    if '..' in filename or '/' in filename or '\\' in filename or '\x00' in filename:
        return 'Invalid filename'
    if not filename.endswith('.zip'):
        return 'Invalid backup file format'
    return None


def _validate_domain_path(domain, cert_base_dir):
    """Validate domain name to prevent path traversal. Returns (Path, error_msg)."""
    if not domain or '..' in domain or '/' in domain or '\\' in domain or '\x00' in domain:
        return None, 'Invalid domain name'
    if not _DOMAIN_RE.match(domain):
        return None, 'Invalid domain format'
    cert_dir = Path(cert_base_dir) / domain
    try:
        resolved = cert_dir.resolve()
        base_resolved = Path(cert_base_dir).resolve()
        if not str(resolved).startswith(str(base_resolved) + os.sep) and resolved != base_resolved:
            return None, 'Invalid domain path'
    except (OSError, ValueError):
        return None, 'Invalid domain path'
    return cert_dir, None


logger = logging.getLogger(__name__)


def create_api_resources(api, models, managers):
    """Create and register all API resource classes

    Args:
        api: Flask-RESTX Api instance
        models: Dictionary of API models
        managers: Dictionary of manager instances (auth, settings, certificates, etc.)
    """

    auth_manager = managers['auth']
    settings_manager = managers['settings']
    certificate_manager = managers['certificates']
    file_ops = managers['file_ops']
    cache_manager = managers['cache']
    dns_manager = managers['dns']
    deploy_manager = managers.get('deployer')
    audit_logger = managers.get('audit')

    def _check_domain_scope(domain, operation):
        """Reject the request if the caller's API-key allowed_domains does
        not cover *domain*. Returns (response_body, http_status) on denial,
        or None when access is permitted.

        Sessions and legacy bearer tokens have no allowed_domains set on
        request.current_user → unrestricted (existing behavior preserved).
        Only scoped API keys, which now carry an allowed_domains list,
        will hit a 403.
        """
        user = getattr(request, 'current_user', None) or {}
        if auth_manager.user_can_access_domain(user, domain):
            return None
        logger.warning(
            "Scope denial: user=%s op=%s domain=%s scope=%s",
            user.get('username'), operation, domain,
            user.get('allowed_domains'),
        )
        if audit_logger:
            audit_logger.log_authz_denied(
                operation=operation,
                resource_type='certificate',
                resource_id=domain,
                reason='domain outside scoped key allowed_domains',
                user=user.get('username'),
                ip_address=request.remote_addr,
            )
        return {
            'error': f'API key not authorized for domain {domain}',
            'code': 'DOMAIN_OUT_OF_SCOPE',
        }, 403

    # Health check endpoint
    class HealthCheck(Resource):
        def get(self):
            """Health check: settings readable + background scheduler running."""
            checks = {}
            overall = 'healthy'
            try:
                settings_manager.load_settings()
                checks['settings'] = 'ok'
            except Exception as e:
                logger.error(f"Health check failed (settings): {e}")
                checks['settings'] = 'error'
                overall = 'unhealthy'

            scheduler = managers.get('scheduler')
            scheduler_running = bool(scheduler and getattr(scheduler, 'running', False))
            checks['scheduler'] = 'running' if scheduler_running else 'not_running'
            if not scheduler_running:
                # The scheduler being down means renewals stop firing — surface it
                # as 'degraded' so monitoring catches it without flapping liveness.
                if overall == 'healthy':
                    overall = 'degraded'

            status_code = 200 if overall != 'unhealthy' else 500
            return {'status': overall, 'checks': checks}, status_code

    # Metrics endpoints
    class MetricsList(Resource):
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

    # Settings endpoints
    class Settings(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        @api.marshal_with(models['settings_model'])
        def get(self):
            """Get current settings"""
            try:
                settings = settings_manager.load_settings()
                if not settings:
                    return {}, 200
                return settings
            except ValueError as e:
                logger.error(f"Invalid settings format: {e}")
                return {'error': 'Invalid settings data'}, 500
            except Exception as e:
                logger.error(f"Error getting settings: {e}")
                return {'error': 'Failed to load settings'}, 500

        @api.doc(security='Bearer')
        @api.expect(models['settings_model'])
        @auth_manager.require_role('admin')
        def post(self):
            """Update settings.

            Accepts only fields in PUBLIC_SETTINGS_WRITABLE_KEYS. Sensitive
            fields (api_bearer_token, deploy_hooks, users, api_keys,
            local_auth_enabled) have dedicated endpoints and are rejected
            here even from admin callers — defense-in-depth against
            payload-style privilege escalation or RCE injection.
            """
            from ..core.settings import (
                validate_settings_post,
                diff_settings_keys,
                SETTINGS_REJECT_KEYS,
            )
            try:
                new_settings = api.payload
                # Load *before* validating: validate_settings_post uses the
                # current state to drop no-op echoes (a GET-then-POST-back
                # round-trip would otherwise hit the reject list for fields
                # like users/api_keys/api_bearer_token_hash that the UI did
                # not intend to mutate).
                before = settings_manager.load_settings() or {}
                try:
                    filtered, rejected, unknown = validate_settings_post(
                        new_settings, current=before)
                except ValueError as e:
                    return {'error': str(e)}, 400

                if rejected:
                    user = getattr(request, 'current_user', {}) or {}
                    logger.warning(
                        "Rejected POST /api/settings: caller tried to write "
                        "blocked fields %s (user=%s)",
                        rejected, user.get('username'),
                    )
                    if audit_logger:
                        for field in rejected:
                            audit_logger.log_authz_denied(
                                operation='update',
                                resource_type='settings',
                                resource_id=field,
                                reason=f'field {field} requires a dedicated endpoint',
                                user=user.get('username'),
                                ip_address=request.remote_addr,
                            )
                    return {
                        'error': 'Forbidden fields in payload',
                        'rejected': sorted(rejected),
                        'hint': 'Use the dedicated endpoint for these fields '
                                '(e.g. /api/deploy/config, /api/users, '
                                '/api/keys, /api/auth/config).',
                    }, 400

                if unknown:
                    return {
                        'error': 'Unknown fields in payload',
                        'unknown': sorted(unknown),
                        'hint': 'Only documented settings keys are accepted.',
                    }, 400

                # Required fields are checked at load_settings + save_settings
                # layers (validate_email, validate_api_token, supported_providers).
                # Enforcing them per POST was incompatible with no-op round-trip
                # echoes — a UI updating cache_ttl shouldn't be required to
                # resend email + dns_provider that didn't change. The defaults
                # in load_settings still seed both fields on first run.
                success = settings_manager.atomic_update(filtered)
                if not success:
                    return {'error': 'Failed to save settings'}, 500

                after = settings_manager.load_settings() or {}
                changed = diff_settings_keys(before, after)
                if audit_logger and changed:
                    user = getattr(request, 'current_user', {}) or {}
                    sensitive_changed = [
                        k for k in changed if k in audit_logger._SENSITIVE_SETTINGS_KEYS
                    ]
                    audit_logger.log_settings_changed(
                        changed_keys=changed,
                        sensitive_changed=sensitive_changed,
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {'message': 'Settings updated successfully'}, 200

            except Exception as e:
                logger.error(f"Error updating settings: {e}")
                return {'error': 'Failed to update settings'}, 500

    # DNS Providers endpoint
    class DNSProviders(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        @api.marshal_with(models['dns_providers_model'])
        def get(self):
            """Get DNS provider configurations"""
            try:
                settings = settings_manager.load_settings()
                return settings.get('dns_providers', {})
            except Exception as e:
                logger.error(f"Error getting DNS providers: {e}")
                return {'error': 'Failed to load DNS providers'}, 500

    # Cache management endpoints
    class CacheStats(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['cache_stats_model'])
        @auth_manager.require_role('viewer')
        def get(self):
            """Get cache statistics"""
            try:
                stats = cache_manager.get_cache_stats()
                return stats
            except Exception as e:
                logger.error(f"Error getting cache stats: {e}")
                return {'error': 'Failed to get cache statistics'}, 500

    class CacheClear(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['cache_clear_response_model'])
        @auth_manager.require_role('admin')
        def post(self):
            """Clear deployment cache"""
            try:
                cleared_count = cache_manager.clear_cache()
                return {
                    'success': True,
                    'message': 'Cache cleared successfully',
                    'cleared_entries': cleared_count
                }
            except Exception as e:
                logger.error(f"Error clearing cache: {e}")
                return {
                    'success': False,
                    'message': 'Failed to clear cache',
                    'cleared_entries': 0
                }, 500

    # Certificate endpoints
    class CertificateList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_list_with(models['certificate_model'])
        @auth_manager.require_role('viewer')
        def get(self):
            """List all certificates.

            Scoped API keys with allowed_domains only see certificates
            within their scope. Unrestricted callers (legacy keys, local
            users) see every certificate.
            """
            try:
                user = getattr(request, 'current_user', None) or {}
                scope = user.get('allowed_domains')
                settings = settings_manager.load_settings()
                certificates = []

                # Map domain -> per-cert auto_renew flag (default True). Domains
                # that exist only on disk and are not in settings get True too.
                auto_renew_by_domain = {}
                all_domains = set()

                # Add domains from settings
                for domain_entry in settings.get('domains', []):
                    if isinstance(domain_entry, str):
                        domain = domain_entry
                        per_cert_auto_renew = True
                    elif isinstance(domain_entry, dict):
                        domain = domain_entry.get('domain')
                        per_cert_auto_renew = domain_entry.get('auto_renew', True)
                    else:
                        continue
                    if domain:
                        all_domains.add(domain)
                        auto_renew_by_domain[domain] = bool(per_cert_auto_renew)

                # Also check for certificates that exist on disk but might not be in settings.
                # Use iter_cert_domain_dirs so FS artifacts (lost+found, hidden dirs,
                # non-cert subdirectories when cert_dir is a volume mount point) don't
                # surface as ghost "Not Found" entries in the dashboard.
                for cert_dir_path in iter_cert_domain_dirs(certificate_manager.cert_dir):
                    all_domains.add(cert_dir_path.name)

                # Get certificate info for all domains, filtered by the
                # caller's API-key scope. domain_matches_scope(d, None) is
                # always True so unrestricted callers see everything.
                for domain in all_domains:
                    if not domain:
                        continue
                    if not auth_manager.domain_matches_scope(domain, scope):
                        continue
                    cert_info = certificate_manager.get_certificate_info(domain)
                    if cert_info:
                        cert_info['auto_renew'] = auto_renew_by_domain.get(domain, True)
                        certificates.append(cert_info)

                return certificates
            except Exception as e:
                logger.error(f"Error listing certificates: {e}")
                return {'error': 'Failed to list certificates'}, 500

    class CreateCertificate(Resource):
        @api.doc(security='Bearer')
        @api.expect(models['create_cert_model'])
        @auth_manager.require_role('operator')
        def post(self):
            """Create a new certificate"""
            try:
                data = api.payload
                domain = (data.get('domain') or '').strip()
                san_domains = data.get('san_domains', [])  # Optional SAN domains
                dns_provider = data.get('dns_provider')
                account_id = data.get('account_id')
                ca_provider = data.get('ca_provider')
                challenge_type = data.get('challenge_type')  # Optional: 'dns-01' or 'http-01'
                domain_alias = data.get('domain_alias')  # Optional domain alias
                if domain_alias:
                    from ..core.utils import validate_domain
                    alias_valid, alias_msg = validate_domain(domain_alias)
                    if not alias_valid:
                        return {'error': f'Invalid domain_alias: {alias_msg}'}, 400

                # Optional per-cert key shape overrides. Validated up-front so
                # the caller gets a clean 400 (with the field-specific reason)
                # instead of a generic certbot stack trace later.
                key_type = data.get('key_type')
                key_size = data.get('key_size')
                elliptic_curve = data.get('elliptic_curve')
                if key_type is not None or key_size is not None or elliptic_curve is not None:
                    from ..core.utils import validate_key_options
                    ok, key_err = validate_key_options(key_type, key_size, elliptic_curve)
                    if not ok:
                        return {'error': key_err}, 400

                # Validate domain
                if not domain:
                    return {
                        'error': 'Domain is required',
                        'hint': 'Please provide a valid domain name (e.g., example.com or *.example.com for wildcard)'
                    }, 400

                # Basic domain validation
                if ' ' in domain:
                    return {
                        'error': 'Invalid domain format',
                        'hint': 'Enter only ONE primary domain. Use san_domains array for additional domains.'
                    }, 400

                # Check for common domain format issues
                if domain.startswith('http://') or domain.startswith('https://'):
                    return {
                        'error': 'Invalid domain format',
                        'hint': 'Provide domain name only (e.g., example.com), not the full URL.'
                    }, 400

                # Validate SAN domains if provided
                if san_domains:
                    if not isinstance(san_domains, list):
                        return {
                            'error': 'Invalid san_domains format',
                            'hint': 'san_domains must be an array of domain strings.'
                        }, 400

                    # Validate each SAN domain
                    for san in san_domains:
                        san = san.strip() if isinstance(san, str) else ''
                        if san and (san.startswith('http://') or san.startswith('https://')):
                            return {
                                'error': f'Invalid SAN domain format: {san}',
                                'hint': 'SAN domains should be domain names only, not URLs.'
                            }, 400

                # Scope check: the requested domain AND every SAN must be
                # within the API key's allowed_domains. Reject the entire
                # creation if any one is out of scope — partial creates
                # would leak data across tenants.
                scope_err = _check_domain_scope(domain, 'create')
                if scope_err:
                    return scope_err
                for san in (san_domains or []):
                    san_clean = san.strip() if isinstance(san, str) else ''
                    if san_clean:
                        scope_err = _check_domain_scope(san_clean, 'create_san')
                        if scope_err:
                            return scope_err

                settings = settings_manager.load_settings()
                email = settings.get('email')

                if not email:
                    return {
                        'error': 'Email not configured',
                        'hint': 'Configure email in settings first. Required for CA notifications.'
                    }, 400

                # Resolve CA provider from settings if not provided
                if not ca_provider:
                    ca_provider = settings.get('default_ca', 'letsencrypt')

                # Resolve challenge type from settings if not provided
                if not challenge_type:
                    challenge_type = settings.get('challenge_type', 'dns-01')

                # DNS provider validation (skip for HTTP-01)
                if challenge_type != 'http-01':
                    if not dns_provider:
                        dns_provider = settings.get('dns_provider')

                    if not dns_provider:
                        return {
                            'error': 'No DNS provider specified',
                            'hint': 'Specify a provider or set a default in settings.'
                        }, 400

                # Create certificate with SAN domains
                result = certificate_manager.create_certificate(
                    domain=domain,
                    email=email,
                    dns_provider=dns_provider,
                    account_id=account_id,
                    ca_provider=ca_provider,
                    domain_alias=domain_alias,
                    san_domains=san_domains,
                    challenge_type=challenge_type,
                    key_type=key_type,
                    key_size=key_size,
                    elliptic_curve=elliptic_curve,
                )

                # Append the new domain to settings under the manager's
                # lock so two parallel cert creations for different domains
                # cannot race and silently drop one of the entries.
                _resolved_dns_provider = dns_provider or settings.get('dns_provider')

                def _add_domain(s):
                    domains_list = s.get('domains', []) or []
                    already_present = any(
                        (d == domain if isinstance(d, str) else d.get('domain') == domain)
                        for d in domains_list
                    )
                    if already_present:
                        return
                    entry = {
                        'domain': domain,
                        'dns_provider': _resolved_dns_provider,
                        'dns_account_id': account_id,
                    }
                    # Only persist key overrides the operator picked
                    # explicitly. Inheriting from the global default keeps
                    # the entry small and lets later changes to the global
                    # apply to certs that never specified a per-cert shape.
                    # Renewals still preserve the original shape because
                    # certbot persists --key-type/--rsa-key-size/--elliptic-curve
                    # in its own renewal/<domain>.conf at create time.
                    if key_type is not None:
                        entry['key_type'] = key_type
                    if key_size is not None:
                        entry['key_size'] = key_size
                    if elliptic_curve is not None:
                        entry['elliptic_curve'] = elliptic_curve
                    domains_list.append(entry)
                    s['domains'] = domains_list

                settings_manager.update(_add_domain, "certificate_created")
                logger.info(f"Ensured domain {domain} is in settings after certificate creation")

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_created', {
                        'domain': domain,
                        'san_domains': san_domains,
                        'dns_provider': result.get('dns_provider'),
                        'ca_provider': result.get('ca_provider')
                    })

                return {
                    'message': f'Certificate created successfully for {domain}',
                    'domain': domain,
                    'dns_provider': result.get('dns_provider'),
                    'ca_provider': result.get('ca_provider'),
                    'duration': result.get('duration')
                }, 201

            except ValueError as e:
                # Validation errors from certificate_manager
                error_msg = str(e)
                hint = None
                if 'not configured' in error_msg.lower():
                    hint = 'Check your DNS provider settings and ensure credentials are properly configured.'
                elif 'domain' in error_msg.lower() and 'email' in error_msg.lower():
                    hint = 'Both domain and email are required. Configure email in settings.'
                return {
                    'error': error_msg,
                    'hint': hint
                }, 400
            except RuntimeError as e:
                # Certbot execution errors
                error_msg = str(e)
                hint = 'Check DNS provider credentials and ensure DNS records can be created.'
                if 'unauthorized' in error_msg.lower() or 'auth' in error_msg.lower():
                    hint = 'DNS provider authentication failed. Verify your API credentials in settings.'
                elif 'timeout' in error_msg.lower():
                    hint = 'DNS propagation timed out. Try increasing DNS propagation time in settings.'
                elif 'rate limit' in error_msg.lower():
                    hint = "You've hit the certificate authority's rate limit. Wait before trying again."
                return {
                    'error': f'Certificate creation failed: {error_msg}',
                    'hint': hint
                }, 422
            except Exception as e:
                logger.error(f"Certificate creation failed: {str(e)}")
                return {
                    'error': 'Certificate creation failed unexpectedly',
                    'hint': 'Check application logs for detailed error information.'
                }, 500

    class CheckDNSAlias(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def post(self):
            """Check DNS-01 alias CNAME records before creating a certificate."""
            data = api.payload or {}
            domain = (data.get('domain') or '').strip()
            domain_alias = (data.get('domain_alias') or '').strip()
            san_domains = data.get('san_domains') or []
            if not isinstance(san_domains, list):
                return {'error': 'san_domains must be an array'}, 400

            wildcard = bool(data.get('wildcard'))
            if wildcard and domain:
                wildcard_domain = '*.' + domain.lstrip('*.')
                if wildcard_domain not in san_domains:
                    san_domains.append(wildcard_domain)

            if not domain or not domain_alias:
                return {'error': 'domain and domain_alias are required'}, 400

            return certificate_manager.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=san_domains,
            ), 200

    class CertificateDNSAliasCheck(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self, domain):
            """Check DNS-01 alias CNAME records for an existing certificate."""
            scope_err = _check_domain_scope(domain, 'dns_alias_check')
            if scope_err:
                return scope_err
            cert_info = certificate_manager.get_certificate_info(domain)
            if not cert_info or not cert_info.get('exists'):
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            domain_alias = cert_info.get('domain_alias')
            if not domain_alias:
                return {'error': f'Certificate {domain} is not using DNS-01 alias mode'}, 400

            return certificate_manager.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=cert_info.get('san_domains') or [],
            ), 200

    class CertificateDetail(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        def patch(self, domain):
            """Update DNS provider for an existing certificate (issue #129).

            Allows changing the DNS provider (and optionally the alias DNS
            provider) used for future renewals of this certificate without
            deleting and re-creating it. Updates both the on-disk
            metadata.json and the domain entry in settings.

            Body: {"dns_provider": "route53", "account_id": "default",
                   "alias_dns_provider": "cloudflare"}
            """
            scope_err = _check_domain_scope(domain, 'update_dns_provider')
            if scope_err:
                return scope_err
            cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            if not cert_dir or not cert_dir.exists():
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            data = api.payload or {}
            new_dns_provider = data.get('dns_provider')
            new_account_id = data.get('account_id')
            new_alias_dns_provider = data.get('alias_dns_provider')

            if not new_dns_provider and not new_alias_dns_provider:
                return {
                    'error': 'At least one of dns_provider or alias_dns_provider is required',
                    'hint': 'Provide the new DNS provider name to use for future renewals.'
                }, 400

            # Validate the new provider has credentials configured
            if new_dns_provider:
                settings = settings_manager.load_settings()
                dns_config, _ = dns_manager.get_dns_provider_account_config(
                    new_dns_provider,
                    new_account_id,
                    settings,
                )
                if not dns_config:
                    return {
                        'error': f"DNS provider '{new_dns_provider}' account "
                                 f"'{new_account_id or 'default'}' is not configured",
                        'hint': 'Configure the DNS provider credentials in Settings first.'
                    }, 400

            try:
                import json as _json

                # 1. Update on-disk metadata.json
                metadata_file = cert_dir / 'metadata.json'
                metadata = {}
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata = _json.load(f)
                    except Exception:
                        pass

                old_provider = metadata.get('dns_provider')
                if new_dns_provider:
                    metadata['dns_provider'] = new_dns_provider
                if new_account_id:
                    metadata['account_id'] = new_account_id
                if new_alias_dns_provider:
                    metadata['alias_dns_provider'] = new_alias_dns_provider

                certificate_manager._atomic_json_write(metadata_file, metadata)
                logger.info(
                    f"Updated DNS provider for {domain}: "
                    f"{old_provider} → {new_dns_provider or old_provider}"
                )

                # 2. Update domain entry in settings
                def _update_domain_provider(s):
                    for entry in s.get('domains', []):
                        if isinstance(entry, dict) and entry.get('domain') == domain:
                            if new_dns_provider:
                                entry['dns_provider'] = new_dns_provider
                            if new_account_id:
                                entry['dns_account_id'] = new_account_id
                            break

                settings_manager.update(_update_domain_provider, "dns_provider_change")

                return {
                    'message': f'DNS provider updated for {domain}',
                    'domain': domain,
                    'dns_provider': metadata.get('dns_provider'),
                    'alias_dns_provider': metadata.get('alias_dns_provider'),
                    'account_id': metadata.get('account_id'),
                }, 200

            except Exception as e:
                logger.error(f"Failed to update DNS provider for {domain}: {e}")
                return {'error': 'Failed to update DNS provider'}, 500

        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def delete(self, domain):
            """Delete a certificate's files from disk.

            Refuses if a create or renew is currently holding the domain lock.
            Does NOT revoke the certificate at the CA — call the CA's revoke
            endpoint separately if revocation is required.
            """
            scope_err = _check_domain_scope(domain, 'delete')
            if scope_err:
                return scope_err
            # Path is only validated for the side-effect of rejecting
            # traversal attempts; the actual delete is keyed on the domain
            # name and handled by certificate_manager.
            _, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            try:
                deleted = certificate_manager.delete_certificate(domain)
                if not deleted:
                    return {'error': f'Certificate not found for domain: {domain}'}, 404

                # Best-effort: drop the domain from settings so the dashboard
                # stops listing it.
                try:
                    settings = settings_manager.load_settings()
                    domains = settings.get('domains', []) or []
                    new_domains = [
                        d for d in domains
                        if (isinstance(d, str) and d != domain)
                        or (isinstance(d, dict) and d.get('domain') != domain)
                    ]
                    if len(new_domains) != len(domains):
                        settings_manager.atomic_update({'domains': new_domains})
                except Exception as e:
                    logger.warning(f"Removed cert for {domain} but failed to update settings: {e}")

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_deleted', {'domain': domain})

                if audit_logger:
                    user = getattr(request, 'current_user', None) or {}
                    audit_logger.log_operation(
                        operation='delete',
                        resource_type='certificate',
                        resource_id=domain,
                        status='success',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {'message': f'Certificate deleted for {domain}', 'domain': domain}, 200
            except RuntimeError as e:
                return {'error': str(e)}, 409
            except Exception as e:
                logger.error(f"Certificate deletion failed for {domain}: {e}")
                return {'error': 'Certificate deletion failed'}, 500

    # Files containing private-key material. A viewer-role caller is
    # permitted to download public certificate material (cert, chain,
    # fullchain) but anything that exposes the private key requires
    # operator role. The default ZIP includes privkey.pem and is
    # therefore also operator-gated. (2026-05-12 API auth audit
    # follow-up: viewer-can-pull-privkey was an information-disclosure
    # surface that the original endpoint exposed.)
    _PRIVATE_KEY_FILES = frozenset({'privkey.pem', 'combined.pem'})
    _PUBLIC_DOWNLOAD_FILES = frozenset({'cert.pem', 'chain.pem', 'fullchain.pem'})

    def _user_has_role(user, min_role):
        level = ROLE_HIERARCHY.get((user or {}).get('role'), -1)
        return level >= ROLE_HIERARCHY.get(min_role, 999)

    class DownloadCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self, domain):
            """Download certificate files as ZIP, JSON, or individual file.

            Role gating is per-file: viewers can pull public material
            (cert.pem, chain.pem, fullchain.pem) and the public-only ZIP
            (?include_private=0); anything that exposes the private key
            (privkey.pem, combined.pem, format=json, default ZIP)
            requires operator role.
            """
            try:
                scope_err = _check_domain_scope(domain, 'download')
                if scope_err:
                    return scope_err
                cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
                if err:
                    return {'error': err}, 400
                if not cert_dir.exists():
                    return {'error': f'Certificate not found for domain: {domain}'}, 404

                user = getattr(request, 'current_user', None) or {}
                download_format = request.args.get('format')
                # Check for the optional 'file' parameter
                requested_file = request.args.get('file')
                include_private = str(request.args.get('include_private', '1')).lower() not in ('0', 'false', 'no', 'off')

                if download_format and download_format not in ['json']:
                    return {'error': 'Invalid format requested.'}, 400

                def _privkey_denied(file_label):
                    """Emit audit + return 403 for viewer trying to pull privkey."""
                    if audit_logger:
                        audit_logger.log_authz_denied(
                            operation='download',
                            resource_type='certificate',
                            resource_id=domain,
                            reason=f'viewer cannot download private-key material ({file_label})',
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {
                        'error': 'operator role required to download private key material',
                        'code': 'PRIVKEY_REQUIRES_OPERATOR',
                        'hint': f'Use ?file=fullchain.pem or ?include_private=0 to download public material as a viewer.',
                    }, 403

                if download_format == 'json':
                    # format=json always returns private_key_pem inline.
                    # Restrict to operator+; viewer must use ?file=... for
                    # the specific public-material file they need.
                    if not _user_has_role(user, 'operator'):
                        return _privkey_denied('format=json')
                    if requested_file:
                        return {'error': 'format=json cannot be combined with file.'}, 400

                    required_files = {
                        'cert_pem': 'cert.pem',
                        'chain_pem': 'chain.pem',
                        'fullchain_pem': 'fullchain.pem',
                        'private_key_pem': 'privkey.pem',
                    }

                    try:
                        payload = {'domain': domain}
                        for response_key, filename in required_files.items():
                            file_path = cert_dir / filename
                            if not file_path.exists():
                                return {'error': f'Required cert file not found for domain {domain}: {filename}'}, 404
                            payload[response_key] = file_path.read_text(encoding='utf-8')

                        return jsonify(payload)
                    except FileNotFoundError:
                        return {'error': f'Required cert file not found for domain {domain}'}, 404

                if requested_file:
                    # Security check: only allow specific certificate files
                    allowed_files = _PUBLIC_DOWNLOAD_FILES | _PRIVATE_KEY_FILES
                    if requested_file not in allowed_files:
                        return {'error': 'Invalid file requested.'}, 400

                    # Private-key files require operator+; public files
                    # remain viewer-accessible.
                    if requested_file in _PRIVATE_KEY_FILES and not _user_has_role(user, 'operator'):
                        return _privkey_denied(requested_file)

                    if requested_file == 'combined.pem':
                        try:
                            # Read both files and join them
                            fullchain = (cert_dir / 'fullchain.pem').read_text(encoding='utf-8')
                            privkey = (cert_dir / 'privkey.pem').read_text(encoding='utf-8')
                            combined_data = io.BytesIO(f"{fullchain}{privkey}".encode())

                            return send_file(
                                combined_data,
                                as_attachment=True,
                                download_name=f'{domain}_combined.pem',
                                mimetype='application/x-pem-file'
                            )
                        except FileNotFoundError:
                            return {'error': f'Required cert files not found for domain {domain}'}, 404

                    file_path = cert_dir / requested_file
                    if not file_path.exists():
                        return {'error': f'File {requested_file} not found for domain {domain}'}, 404

                    return send_file(
                        file_path,
                        as_attachment=True,
                        download_name=f'{domain}_{requested_file}',
                        mimetype='application/x-pem-file'
                    )

                # Fallback ZIP. Two flavors:
                #   include_private=1 (default)  -> all 4 PEMs, operator+
                #   include_private=0            -> public material only,
                #                                   safe for viewer
                if include_private and not _user_has_role(user, 'operator'):
                    return _privkey_denied('default ZIP')

                files_to_zip = (
                    CERTIFICATE_FILES if include_private
                    else tuple(f for f in CERTIFICATE_FILES if f not in _PRIVATE_KEY_FILES)
                )
                zip_suffix = 'certificates' if include_private else 'certificates_public'

                # Create temporary ZIP file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
                    tmp_path = tmp_file.name
                    with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for cert_file in files_to_zip:
                            file_path = cert_dir / cert_file
                            if file_path.exists():
                                zipf.write(file_path, cert_file)

                    @after_this_request
                    def remove_file(response):
                        try:
                            os.remove(tmp_path)
                        except Exception as e:
                            logger.debug(f"Could not remove temp file {tmp_path}: {e}")
                        return response

                    return send_file(
                        tmp_path,
                        as_attachment=True,
                        download_name=f'{domain}_{zip_suffix}.zip',
                        mimetype='application/zip'
                    )

            except Exception as e:
                logger.error(f"Error downloading certificate for {domain}: {e}")
                return {'error': 'Failed to download certificate'}, 500

    class RenewCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        def post(self, domain):
            """Renew an existing certificate"""
            try:
                scope_err = _check_domain_scope(domain, 'renew')
                if scope_err:
                    return scope_err
                result = certificate_manager.renew_certificate(domain)

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_renewed', {'domain': domain})

                return {
                    'message': f'Certificate renewed successfully for {domain}',
                    'domain': domain,
                    'dns_provider': result.get('dns_provider'),
                    'duration': result.get('duration')
                }, 200

            except Exception as e:
                logger.error(f"Certificate renewal failed for {domain}: {str(e)}")
                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_failed', {'domain': domain, 'error': str(e)})
                return {'error': 'Certificate renewal failed'}, 500

    class CertificateAutoRenew(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        def put(self, domain):
            """Enable or disable automatic renewal for a single certificate (issue #111).

            Body: {"enabled": true|false}
            """
            scope_err = _check_domain_scope(domain, 'set_auto_renew')
            if scope_err:
                return scope_err
            _, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            try:
                data = api.payload or {}
                if 'enabled' not in data:
                    return {'error': 'Missing "enabled" boolean in request body'}, 400
                enabled = bool(data.get('enabled'))

                updated = certificate_manager.set_auto_renew(domain, enabled)
                if not updated:
                    return {
                        'error': f'Domain {domain} not found in settings',
                        'hint': 'Only domains tracked in settings can have auto-renew toggled.'
                    }, 404

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_auto_renew_changed', {
                        'domain': domain,
                        'enabled': enabled,
                    })

                return {
                    'message': f'Auto-renew {"enabled" if enabled else "disabled"} for {domain}',
                    'domain': domain,
                    'auto_renew': enabled,
                }, 200
            except Exception as e:
                logger.error(f"Failed to toggle auto-renew for {domain}: {e}")
                return {'error': 'Failed to update auto-renew setting'}, 500

    class CertificateRunDeploy(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def post(self, domain):
            """Manually run all enabled deploy hooks for a domain (issue #109).

            Aligns with the role of /api/deploy/* (admin-only). Hooks run
            with CERTMATE_EVENT=manual; the on_events filter is ignored
            since the user explicitly requested execution.
            """
            scope_err = _check_domain_scope(domain, 'run_deploy')
            if scope_err:
                return scope_err
            if deploy_manager is None:
                return {'error': 'Deploy manager not available'}, 503

            cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            if not cert_dir.exists():
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            try:
                summary = deploy_manager.run_manual_deploy(domain)
            except Exception as e:
                logger.error(f"Manual deploy hook run failed for {domain}: {e}")
                return {'error': 'Manual deploy hook run failed'}, 500

            event_bus = current_app.config.get('EVENT_BUS')
            if event_bus:
                event_bus.publish('certificate_deploy_manual', {
                    'domain': domain,
                    'ok': summary.get('ok'),
                    'total': summary.get('total'),
                    'succeeded': summary.get('succeeded'),
                    'failed': summary.get('failed'),
                })

            # 200 even when ok=False (e.g. no hooks configured) so the
            # client can read the structured summary; the route only
            # returns non-2xx for path validation / server errors.
            return summary, 200

    # Backup endpoints (Unified backup system for atomic consistency)
    class BackupList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['backup_list_model'])
        @auth_manager.require_role('viewer')
        def get(self):
            """List all available backups"""
            try:
                backups = file_ops.list_backups()
                return backups
            except Exception as e:
                logger.error(f"Error listing backups: {e}")
                return {'error': 'Failed to list backups'}, 500

    class BackupCreate(Resource):
        @api.doc(security='Bearer')
        @api.expect(api.model('BackupCreateRequest', {
            'type': fields.String(required=True, enum=['unified', 'settings', 'certificates', 'both'],
                                  description='Type of backup to create (unified recommended for data consistency)'),
            'reason': fields.String(description='Reason for backup creation', default='manual')
        }))
        @auth_manager.require_role('admin')
        def post(self):
            """Create a new backup (unified format recommended)"""
            try:
                data = api.payload
                backup_type = data.get('type', 'unified')  # Default to unified
                reason = data.get('reason', 'manual')

                created_backups = []

                # Only support unified backup (legacy removed)
                settings = settings_manager.load_settings()
                filename = file_ops.create_unified_backup(settings, reason)
                if filename:
                    created_backups.append({'type': 'unified', 'filename': filename})
                    logger.info(f"Created unified backup: {filename}")

                if created_backups:
                    if audit_logger:
                        user = getattr(request, 'current_user', None) or {}
                        audit_logger.log_operation(
                            operation='create',
                            resource_type='backup',
                            resource_id=created_backups[0].get('filename', 'unknown'),
                            status='success',
                            details={'type': 'unified', 'reason': reason},
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {
                        'message': 'Backup created successfully',
                        'backups': created_backups,
                        'recommendation': 'Use unified backup' if backup_type != 'unified' else None
                    }, 201
                else:
                    return {'error': 'Failed to create backup'}, 500

            except Exception as e:
                logger.error(f"Error creating backup: {e}")
                return {'error': 'Failed to create backup'}, 500

    # DNS Accounts management
    class DNSAccounts(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def get(self, provider=None):
            """List DNS provider accounts"""
            try:
                accounts = dns_manager.list_accounts()
                if provider:
                    accounts = [a for a in accounts if a.get('provider') == provider]
                return accounts
            except Exception as e:
                logger.error(f"Error listing DNS accounts: {e}")
                return {'error': 'Failed to list DNS accounts'}, 500

        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def post(self, provider=None):
            """Add new DNS provider account"""
            try:
                data = api.payload
                name = data.get('name') or data.get('account_id')
                req_provider = provider or data.get('provider')
                config = data.get('config', {})

                if not name or not req_provider:
                    return {'error': 'Account name and provider required'}, 400

                if dns_manager.add_account(name, req_provider, config):
                    return {'success': True, 'message': 'Account created', 'id': name}, 200
                return {'error': 'Failed to add account'}, 500
            except Exception as e:
                logger.error(f"Error adding DNS account: {e}")
                return {'error': str(e)}, 500

    class DNSAccountDetail(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def put(self, provider, account_id):
            """Update a DNS provider account"""
            try:
                data = api.payload or {}
                settings = dns_manager.settings_manager.load_settings()
                settings = dns_manager.settings_manager.migrate_dns_providers_to_multi_account(settings)
                existing = (settings.get('dns_providers', {})
                            .get(provider, {})
                            .get('accounts', {})
                            .get(account_id, {}))
                # Merge: keep existing masked/secret values when placeholder is sent
                set_as_default = data.get('set_as_default', False)
                merged = dict(existing)
                for k, v in data.items():
                    if k == 'set_as_default':
                        continue
                    if v != '********':
                        merged[k] = v
                if dns_manager.add_account(account_id, provider, merged):
                    if set_as_default:
                        dns_manager.set_default_account(provider, account_id)
                    return {'success': True, 'message': 'Account updated'}
                return {'error': 'Failed to update account'}, 500
            except Exception as e:
                logger.error(f"Error updating DNS account: {e}")
                return {'error': str(e)}, 500

        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def delete(self, provider, account_id):
            """Delete a DNS provider account"""
            try:
                if dns_manager.delete_account(provider, account_id):
                    return {'success': True, 'message': 'Account deleted'}
                return {'error': 'Failed to delete account'}, 500
            except Exception as e:
                logger.error(f"Error deleting DNS account: {e}")
                return {'error': str(e)}, 500

    class BackupDownload(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def get(self, backup_type, filename):
            """Download a backup file"""
            try:
                if backup_type != 'unified':
                    return {'error': 'Only unified backup download is supported'}, 400

                err = _validate_backup_filename(filename)
                if err:
                    return {'error': err}, 400

                backup_path = Path(file_ops.backup_dir) / backup_type / filename

                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404

                # Security check
                if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                    return {'error': 'Access denied'}, 403

                return send_file(
                    str(backup_path.resolve()),
                    as_attachment=True,
                    download_name=filename,
                    mimetype='application/octet-stream'
                )

            except FileNotFoundError:
                return {'error': 'Backup file not found'}, 404
            except PermissionError:
                return {'error': 'Access denied to backup file'}, 403
            except Exception as e:
                logger.error(f"Error downloading backup: {e}")
                return {'error': 'Failed to download backup'}, 500

    class BackupRestore(Resource):
        @api.doc(security='Bearer')
        @api.expect(api.model('BackupRestoreRequest', {
            'filename': fields.String(required=True, description='Backup filename to restore from'),
            'create_backup_before_restore': fields.Boolean(description='Create backup before restore', default=True)
        }))
        @auth_manager.require_role('admin')
        def post(self, backup_type):
            """Restore from a unified backup file (only unified backups supported)"""
            try:
                if backup_type != 'unified':
                    return {'error': 'Only unified backup restoration is supported'}, 400

                data = api.payload
                filename = data.get('filename')
                create_backup = data.get('create_backup_before_restore', True)

                err = _validate_backup_filename(filename)
                if err:
                    return {'error': err}, 400

                backup_path = Path(file_ops.backup_dir) / "unified" / filename

                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404

                # Security check
                if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                    return {'error': 'Access denied'}, 403

                # Create backup of current state if requested
                pre_restore_backup = None
                if create_backup:
                    current_settings = settings_manager.load_settings()
                    pre_restore_backup = file_ops.create_unified_backup(current_settings, "pre_restore")
                    logger.info(f"Created pre-restore backup: {pre_restore_backup}")

                # Restore from unified backup
                success = file_ops.restore_unified_backup(str(backup_path))
                restore_msg = "Settings and certificates restored atomically"

                if success:
                    if audit_logger:
                        user = getattr(request, 'current_user', None) or {}
                        # Restore wholesale-replaces settings + certificates;
                        # the audit entry must surface both source filename
                        # and the pre-restore backup (if one was created) so
                        # an admin can roll back via the audit trail alone.
                        audit_logger.log_operation(
                            operation='restore',
                            resource_type='backup',
                            resource_id=filename,
                            status='success',
                            details={
                                'backup_type': 'unified',
                                'pre_restore_backup': pre_restore_backup,
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    response = {
                        'message': f'{restore_msg} successfully from {filename}',
                        'restored_from': filename,
                        'backup_type': 'unified'
                    }
                    if pre_restore_backup:
                        response['pre_restore_backup'] = pre_restore_backup
                        response['note'] = 'A backup of the previous state was created before restore'

                    return response, 200
                else:
                    return {'error': 'Failed to restore unified backup'}, 500

            except FileNotFoundError:
                return {'error': 'Backup file not found'}, 404
            except ValueError as e:
                logger.warning(f"Backup restore validation error: {e}")
                return {'error': 'Invalid backup data'}, 400
            except Exception as e:
                logger.error(f"Error restoring backup: {e}")
                return {'error': 'Failed to restore backup'}, 500

    class BackupDelete(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def delete(self, backup_type, filename):
            """Delete a unified backup file"""
            try:
                file_ops_manager = managers.get('file_ops')
                if not file_ops_manager:
                    return {'error': 'File operations manager not available'}, 500

                if backup_type != 'unified':
                    return {'error': 'Only unified backup deletion is supported'}, 400

                err = _validate_backup_filename(filename)
                if err:
                    return {'error': err}, 400

                backup_dir = file_ops_manager.backup_dir / backup_type
                backup_path = backup_dir / filename

                # Validate the backup file exists and is within the backup directory
                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404

                if not str(backup_path.resolve()).startswith(str(backup_dir.resolve())):
                    return {'error': 'Invalid backup path'}, 400

                # Delete the backup file
                backup_path.unlink()

                logger.info(f"Backup deleted: {backup_type}/{filename}")
                if audit_logger:
                    user = getattr(request, 'current_user', None) or {}
                    audit_logger.log_operation(
                        operation='delete',
                        resource_type='backup',
                        resource_id=filename,
                        status='success',
                        details={'backup_type': backup_type},
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {
                    'message': f'Backup {filename} deleted successfully',
                    'deleted_file': filename,
                    'backup_type': backup_type
                }, 200

            except Exception as e:
                logger.error(f"Error deleting backup: {e}")
                return {'error': 'Failed to delete backup'}, 500

    # Storage Backend Management
    class StorageBackendInfo(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self):
            """Get current storage backend information"""
            try:
                storage_manager = managers.get('storage')
                if not storage_manager:
                    return {'error': 'Storage manager not available'}, 500

                backend_name = storage_manager.get_backend_name()
                settings = settings_manager.load_settings()
                storage_config = settings.get('certificate_storage', {})

                return {
                    'current_backend': backend_name,
                    'available_backends': [
                        'local_filesystem',
                        'azure_keyvault',
                        'aws_secrets_manager',
                        'hashicorp_vault',
                        'infisical'
                    ],
                    'configuration': {
                        'backend': storage_config.get('backend', 'local_filesystem'),
                        'cert_dir': storage_config.get('cert_dir', 'certificates')
                    }
                }
            except Exception as e:
                logger.error(f"Error getting storage backend info: {e}")
                return {'error': 'Failed to get storage backend info'}, 500

    class StorageBackendConfig(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        @api.expect(models['storage_config_model'])
        def post(self):
            """Update storage backend configuration"""
            try:
                data = api.payload
                backend_type = data.get('backend')
                valid_backends = [
                    'local_filesystem', 'azure_keyvault', 'aws_secrets_manager',
                    'hashicorp_vault', 'infisical'
                ]
                if backend_type not in valid_backends:
                    return {'error': 'Invalid backend type'}, 400

                # Build only the storage subtree and merge atomically so we
                # don't race with concurrent writes or wipe other settings keys.
                current = settings_manager.load_settings()
                storage = dict(current.get('certificate_storage') or {})
                storage['backend'] = backend_type

                if backend_type == 'local_filesystem':
                    storage['cert_dir'] = data.get('cert_dir', 'certificates')
                elif backend_type == 'azure_keyvault':
                    storage['azure_keyvault'] = data.get('azure_keyvault', {})
                elif backend_type == 'aws_secrets_manager':
                    storage['aws_secrets_manager'] = data.get('aws_secrets_manager', {})
                elif backend_type == 'hashicorp_vault':
                    storage['hashicorp_vault'] = data.get('hashicorp_vault', {})
                elif backend_type == 'infisical':
                    storage['infisical'] = data.get('infisical', {})

                success = settings_manager.atomic_update({'certificate_storage': storage})

                if success:
                    return {
                        'success': True,
                        'message': f'Storage backend updated to {backend_type}',
                        'backend': backend_type
                    }
                else:
                    return {'error': 'Failed to save storage configuration'}, 500

            except Exception as e:
                logger.error(f"Error updating storage backend config: {e}")
                return {'error': 'Failed to update storage backend configuration'}, 500

    class StorageBackendTest(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        @api.expect(models['storage_test_config_model'])
        def post(self):
            """Test storage backend connection"""
            try:
                data = api.payload
                backend_type = data.get('backend')
                config = data.get('config', {})

                # Import storage backends
                from ..core.storage_backends import (
                    LocalFileSystemBackend, AzureKeyVaultBackend,
                    AWSSecretsManagerBackend, HashiCorpVaultBackend,
                    InfisicalBackend
                )

                # Test connection based on backend type
                try:
                    if backend_type == 'local_filesystem':
                        test_backend = LocalFileSystemBackend(Path(config.get('cert_dir', 'certificates')))

                    elif backend_type == 'azure_keyvault':
                        test_backend = AzureKeyVaultBackend(config)

                    elif backend_type == 'aws_secrets_manager':
                        test_backend = AWSSecretsManagerBackend(config)

                    elif backend_type == 'hashicorp_vault':
                        test_backend = HashiCorpVaultBackend(config)

                    elif backend_type == 'infisical':
                        test_backend = InfisicalBackend(config)

                    else:
                        return {'error': 'Invalid backend type'}, 400

                    # Test by trying to list certificates (should not fail for auth issues)
                    domains = test_backend.list_certificates()

                    return {
                        'success': True,
                        'message': f'Successfully connected to {backend_type}',
                        'backend': backend_type,
                        'certificate_count': len(domains)
                    }

                except Exception as test_error:
                    logger.error(f"Storage backend connection test failed: {test_error}")
                    return {
                        'success': False,
                        'message': 'Connection test failed',
                        'backend': backend_type
                    }

            except Exception as e:
                logger.error(f"Error testing storage backend: {e}")
                return {'error': 'Failed to test storage backend'}, 500

    class CAProviderTest(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        @api.expect(models['ca_test_config_model'])
        def post(self):
            """Test CA provider connection"""
            try:
                data = api.payload
                ca_provider = data.get('ca_provider')
                config = data.get('config', {})

                # Import CA manager
                ca_manager = managers.get('ca')
                if not ca_manager:
                    return {'error': 'CA manager not available'}, 500

                # Test connection based on CA provider type
                try:
                    if ca_provider == 'letsencrypt':
                        # Test Let's Encrypt connection
                        environment = config.get('environment', 'production')
                        email = config.get('email', '')

                        if not email:
                            return {
                                'success': False,
                                'message': 'Email is required for Let\'s Encrypt',
                                'ca_provider': ca_provider
                            }

                        # Test by getting the directory URL
                        directory_url = ca_manager._get_letsencrypt_directory_url(environment)

                        return {
                            'success': True,
                            'message': f'Let\'s Encrypt {environment} endpoint is accessible',
                            'ca_provider': ca_provider,
                            'directory_url': directory_url
                        }

                    elif ca_provider == 'digicert':
                        # Test DigiCert ACME connection
                        acme_url = config.get('acme_url', '')
                        eab_kid = config.get('eab_kid', '')
                        eab_hmac = config.get('eab_hmac', '')
                        email = config.get('email', '')

                        if not acme_url:
                            return {
                                'success': False,
                                'message': 'ACME URL is required for DigiCert',
                                'ca_provider': ca_provider
                            }

                        if not eab_kid or not eab_hmac:
                            return {
                                'success': False,
                                'message': 'EAB credentials (Key ID and HMAC Key) are required for DigiCert',
                                'ca_provider': ca_provider
                            }

                        if not email:
                            return {
                                'success': False,
                                'message': 'Email is required for DigiCert',
                                'ca_provider': ca_provider
                            }

                        # Test by attempting to validate EAB credentials format
                        if len(eab_kid) < 10 or len(eab_hmac) < 32:
                            return {
                                'success': False,
                                'message': 'EAB credentials appear to be invalid (too short)',
                                'ca_provider': ca_provider
                            }

                        return {
                            'success': True,
                            'message': 'DigiCert configuration appears valid',
                            'ca_provider': ca_provider,
                            'acme_url': acme_url
                        }

                    elif ca_provider == 'private_ca':
                        # Test Private CA connection
                        acme_url = config.get('acme_url', '')
                        ca_cert = config.get('ca_cert', '')
                        email = config.get('email', '')

                        if not acme_url:
                            return {
                                'success': False,
                                'message': 'ACME URL is required for Private CA',
                                'ca_provider': ca_provider
                            }

                        if not email:
                            return {
                                'success': False,
                                'message': 'Email is required for Private CA',
                                'ca_provider': ca_provider
                            }

                        # Basic URL validation
                        if not (acme_url.startswith('http://') or acme_url.startswith('https://')):
                            return {
                                'success': False,
                                'message': 'ACME URL must be a valid HTTP/HTTPS URL',
                                'ca_provider': ca_provider
                            }

                        # If CA cert is provided, validate it's PEM format
                        if ca_cert and not (ca_cert.strip().startswith('-----BEGIN CERTIFICATE-----') and
                                            ca_cert.strip().endswith('-----END CERTIFICATE-----')):
                            return {
                                'success': False,
                                'message': 'CA certificate must be in PEM format',
                                'ca_provider': ca_provider
                            }

                        # Test actual connectivity to the ACME endpoint
                        try:
                            import requests
                            # import ssl # unused
                            # from urllib.parse import urljoin # unused

                            # Test if the ACME directory is accessible
                            timeout = 10

                            # Build SSL verification argument.
                            # If the user supplied a custom CA certificate (typical for private CAs
                            # with self-signed roots), write it to a temp file and pass it as the
                            # `verify` argument so requests can validate the server certificate.
                            # Without this, requests falls back to the system CA bundle and will
                            # reject self-signed / private-root certificates.
                            _ca_bundle_tmp = None
                            if ca_cert:
                                try:
                                    _ca_bundle_tmp = tempfile.NamedTemporaryFile(
                                        mode='w', suffix='.pem', delete=False
                                    )
                                    _ca_bundle_tmp.write(ca_cert.strip())
                                    _ca_bundle_tmp.flush()
                                    _ca_bundle_tmp.close()
                                    verify_ssl = _ca_bundle_tmp.name
                                    logger.info("Using provided CA certificate for ACME endpoint SSL verification")
                                except Exception as tmp_err:
                                    logger.warning(f"Could not write CA cert to temp file: {tmp_err}")
                                    verify_ssl = True
                            else:
                                verify_ssl = True

                            directory_response = requests.get(
                                acme_url,
                                timeout=timeout,
                                verify=verify_ssl,
                                allow_redirects=False
                            )

                            if directory_response.status_code == 200:
                                try:
                                    directory_data = directory_response.json()
                                except Exception:
                                    return {
                                        'success': False,
                                        'message': 'Endpoint is accessible but returned invalid JSON',
                                        'ca_provider': ca_provider
                                    }
                                # Check if it looks like an ACME directory
                                if 'newAccount' in directory_data or 'keyChange' in directory_data:
                                    return {
                                        'success': True,
                                        'message': 'ACME endpoint appears valid',
                                        'ca_provider': ca_provider,
                                        'acme_url': acme_url,
                                        'has_ca_cert': bool(ca_cert),
                                        'urls': list(directory_data.keys()) if directory_data else []
                                    }
                                return {
                                    'success': False,
                                    'message': 'Endpoint does not appear to be a valid ACME directory',
                                    'ca_provider': ca_provider
                                }
                            return {
                                'success': False,
                                'message': f'ACME endpoint returned HTTP {directory_response.status_code}',
                                'ca_provider': ca_provider
                            }

                        except requests.exceptions.Timeout:
                            return {
                                'success': False,
                                'message': 'Connection timeout - ACME endpoint is not accessible',
                                'ca_provider': ca_provider
                            }
                        except requests.exceptions.ConnectionError:
                            return {
                                'success': False,
                                'message': 'Connection failed - ACME endpoint is not accessible. '
                                           'Ensure the CertMate server can reach the ACME host on the required port.',
                                'ca_provider': ca_provider
                            }
                        except requests.exceptions.SSLError:
                            hint = (
                                ' Provide CA cert for verification.' if not ca_cert else
                                ' Provided CA cert could not verify server. Check PEM format.'
                            )
                            return {
                                'success': False,
                                'message': f'SSL verification failed.{hint}',
                                'ca_provider': ca_provider
                            }
                        except Exception as conn_error:
                            logger.error(f"CA provider connection test failed: {conn_error}")
                            return {
                                'success': False,
                                'message': f'Connection test failed: {conn_error}',
                                'ca_provider': ca_provider
                            }
                        finally:
                            # Always remove the temporary CA bundle file if we created one
                            try:
                                if _ca_bundle_tmp is not None:
                                    import os as _os
                                    _os.unlink(_ca_bundle_tmp.name)
                            except (NameError, OSError):
                                pass

                    else:
                        return {'error': 'Invalid CA provider type'}, 400

                except Exception as test_error:
                    logger.error(f"CA provider test failed: {test_error}")
                    return {
                        'success': False,
                        'message': 'CA provider test failed',
                        'ca_provider': ca_provider
                    }

            except Exception as e:
                logger.error(f"Error testing CA provider: {e}")
                return {'success': False, 'message': str(e)}, 500

    class StorageBackendMigrate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        @api.expect(models['storage_migration_config_model'])
        def post(self):
            """Migrate certificates between storage backends"""
            try:
                data = api.payload
                source_backend_type = data.get('source_backend')
                target_backend_type = data.get('target_backend')
                source_config = data.get('source_config', {})
                target_config = data.get('target_config', {})

                # Import storage backends
                from ..core.storage_backends import (
                    LocalFileSystemBackend, AzureKeyVaultBackend,
                    AWSSecretsManagerBackend, HashiCorpVaultBackend,
                    InfisicalBackend
                )

                # Create backend instances
                backend_classes = {
                    'local_filesystem': LocalFileSystemBackend,
                    'azure_keyvault': AzureKeyVaultBackend,
                    'aws_secrets_manager': AWSSecretsManagerBackend,
                    'hashicorp_vault': HashiCorpVaultBackend,
                    'infisical': InfisicalBackend
                }

                if source_backend_type not in backend_classes or target_backend_type not in backend_classes:
                    return {'error': 'Invalid backend type'}, 400

                try:
                    # Initialize backends
                    if source_backend_type == 'local_filesystem':
                        source_backend = LocalFileSystemBackend(Path(source_config.get('cert_dir', 'certificates')))
                    else:
                        source_backend = backend_classes[source_backend_type](source_config)

                    if target_backend_type == 'local_filesystem':
                        target_backend = LocalFileSystemBackend(Path(target_config.get('cert_dir', 'certificates')))
                    else:
                        target_backend = backend_classes[target_backend_type](target_config)

                    # Perform migration using storage manager
                    storage_manager = managers.get('storage')
                    if not storage_manager:
                        return {'error': 'Storage manager not available'}, 500

                    migration_results = storage_manager.migrate_certificates(source_backend, target_backend)

                    successful = sum(1 for success in migration_results.values() if success)
                    total = len(migration_results)

                    return {
                        'success': True,
                        'message': f'Migration completed: {successful}/{total} certificates migrated',
                        'migration_results': migration_results,
                        'source_backend': source_backend_type,
                        'target_backend': target_backend_type
                    }

                except Exception as migration_error:
                    logger.error(f"Storage migration failed: {migration_error}")
                    return {
                        'success': False,
                        'message': 'Migration failed',
                        'source_backend': source_backend_type,
                        'target_backend': target_backend_type
                    }

            except Exception as e:
                logger.error(f"Error during storage migration: {e}")
                return {'error': 'Failed to perform storage migration'}, 500

    # Register storage backend endpoints
    storage_ns = api.namespace('storage', description='Storage Backend Operations')
    storage_ns.add_resource(StorageBackendInfo, '/info')
    storage_ns.add_resource(StorageBackendConfig, '/config')
    storage_ns.add_resource(StorageBackendTest, '/test')
    storage_ns.add_resource(StorageBackendMigrate, '/migrate')

    # Register DNS management endpoints
    dns_ns = api.namespace('dns', description='DNS Provider Account Management')
    dns_ns.add_resource(DNSAccounts, '/<string:provider>/accounts', endpoint='dns_accounts_provider')
    dns_ns.add_resource(DNSAccounts, '/accounts', endpoint='dns_accounts_global')
    dns_ns.add_resource(DNSAccountDetail, '/<string:provider>/accounts/<string:account_id>')

    # Return all resource classes (CA provider test will be registered in app.py)
    return {
        'HealthCheck': HealthCheck,
        'MetricsList': MetricsList,
        'Settings': Settings,
        'DNSProviders': DNSProviders,
        'CacheStats': CacheStats,
        'CacheClear': CacheClear,
        'CertificateList': CertificateList,
        'CreateCertificate': CreateCertificate,
        'CheckDNSAlias': CheckDNSAlias,
        'CertificateDNSAliasCheck': CertificateDNSAliasCheck,
        'CertificateDetail': CertificateDetail,
        'DownloadCertificate': DownloadCertificate,
        'RenewCertificate': RenewCertificate,
        'CertificateAutoRenew': CertificateAutoRenew,
        'CertificateRunDeploy': CertificateRunDeploy,
        'BackupList': BackupList,
        'BackupCreate': BackupCreate,
        'BackupDownload': BackupDownload,
        'BackupRestore': BackupRestore,
        'BackupDelete': BackupDelete,
        'CAProviderTest': CAProviderTest
    }
