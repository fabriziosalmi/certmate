"""Application settings and DNS provider account management.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as an
explicit `ApiContext`, which is what makes them importable — and therefore
testable — without constructing the whole manager graph.

The four are grouped by what they configure, not by how they are registered:
`Settings` and `DNSProviders` are registered by factory.py from the mapping
`create_api_resources` returns, while `DNSAccounts` and `DNSAccountDetail` are
bound to a namespace inside that function. Both are handled explicitly at the
call site rather than splitting a coherent module along that seam.
"""
from flask import request
from flask_restx import Resource

import logging

from .resource_context import ApiContext, instance_wide

logger = logging.getLogger(__name__)


def _failed_delete(dns, provider, account_id):
    """The answer for a delete that did not delete: 404 when there was nothing to delete.

    `delete_account` returns False for an account that does not exist and for a settings file
    that could not be written, and both were a 500 (#1106). A 500 is for the second. Module
    level: `create_settings_resources` is a closure with a complexity budget that only comes down.
    """
    if not dns.has_account(provider, account_id):
        return {'error': f"No DNS account called '{account_id}' for provider '{provider}'",
                'code': 'DNS_ACCOUNT_NOT_FOUND'}, 404
    return {'error': 'Failed to delete account'}, 500


def create_settings_resources(api, models, ctx: ApiContext) -> dict:
    """Build the settings and DNS-account resources against *ctx*."""

    # The settings are the instance's: its contact address, its DNS provider
    # accounts, its storage and sign-in configuration. None of it is filed
    # under a domain, so a key restricted to domains is refused here, as it is
    # for backups. What such a key may know about its own domains it reads from
    # the certificate routes.
    not_for_restricted_keys = instance_wide(ctx, 'settings', 'the instance settings')

    class Settings(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        @not_for_restricted_keys
        @api.marshal_with(models['settings_model'])
        def get(self):
            """Get current settings. A key restricted with `allowed_domains` is refused."""
            try:
                return ctx.settings.load_settings() or {}
            except ValueError as e:
                logger.error(f"Invalid settings format: {e}")
                return {'error': 'Invalid settings data'}, 500
            except Exception as e:
                logger.error(f"Error getting settings: {e}")
                return {'error': 'Failed to load settings'}, 500

        @api.doc(security='Bearer')
        @api.expect(models['settings_model'])
        @ctx.auth.require_role('admin')
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
            )
            try:
                new_settings = api.payload
                # Load *before* validating: validate_settings_post uses the
                # current state to drop no-op echoes (a GET-then-POST-back
                # round-trip would otherwise hit the reject list for fields
                # like users/api_keys/api_bearer_token_hash that the UI did
                # not intend to mutate).
                before = ctx.settings.load_settings() or {}
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
                    if ctx.audit:
                        for field in rejected:
                            ctx.audit.log_authz_denied(
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
                success = ctx.settings.atomic_update(filtered)
                if not success:
                    return {'error': 'Failed to save settings'}, 500

                after = ctx.settings.load_settings() or {}
                changed = diff_settings_keys(before, after)
                if ctx.audit and changed:
                    user = getattr(request, 'current_user', {}) or {}
                    sensitive_changed = [
                        k for k in changed if k in ctx.audit._SENSITIVE_SETTINGS_KEYS
                    ]
                    ctx.audit.log_settings_changed(
                        changed_keys=changed,
                        sensitive_changed=sensitive_changed,
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {'message': 'Settings updated successfully'}, 200

            except Exception as e:
                logger.error(f"Error updating settings: {e}")
                return {'error': 'Failed to update settings'}, 500

    class DNSProviders(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        @instance_wide(ctx, 'dns_providers', 'the DNS provider accounts')
        @api.marshal_with(models['dns_providers_model'])
        def get(self):
            """Get DNS provider configurations. A key restricted with `allowed_domains` is refused."""
            try:
                settings = ctx.settings.load_settings()
                return settings.get('dns_providers', {})
            except Exception as e:
                logger.error(f"Error getting DNS providers: {e}")
                return {'error': 'Failed to load DNS providers'}, 500

    class DNSAccounts(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def get(self, provider=None):
            """List DNS provider accounts"""
            try:
                accounts = ctx.dns.list_accounts()
                if provider:
                    accounts = [a for a in accounts if a.get('provider') == provider]
                return accounts
            except Exception as e:
                logger.error(f"Error listing DNS accounts: {e}")
                return {'error': 'Failed to list DNS accounts'}, 500

        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def post(self, provider=None):
            """Add new DNS provider account"""
            try:
                data = api.payload
                name = data.get('name') or data.get('account_id')
                req_provider = provider or data.get('provider')
                config = data.get('config', {})
                set_as_default = data.get('set_as_default', False)

                if not name or not req_provider:
                    return {'error': 'Account name and provider required'}, 400

                if ctx.dns.add_account(name, req_provider, config):
                    # Honour the operator's explicit "set as default" choice on
                    # create, mirroring the update path — the flag the UI sends
                    # was previously dropped here.
                    if set_as_default:
                        ctx.dns.set_default_account(req_provider, name)
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='create_account',
                            resource_type='dns_provider',
                            resource_id=f"{req_provider}:{name}",
                            status='success',
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {'success': True, 'message': 'Account created', 'id': name}, 200

                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='create_account',
                        resource_type='dns_provider',
                        resource_id=f"{req_provider}:{name}" if req_provider and name else 'unknown',
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {'error': 'Failed to add account'}, 500
            except Exception as e:
                logger.error(f"Error adding DNS account: {e}")
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='create_account',
                        resource_type='dns_provider',
                        resource_id=f"{req_provider}:{name}" if 'req_provider' in locals() and 'name' in locals() else 'unknown',
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                        error=str(e)
                    )
                return {'error': str(e)}, 500

    class DNSAccountDetail(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def put(self, provider, account_id):
            """Update a DNS provider account"""
            try:
                data = api.payload or {}
                settings = ctx.dns.settings_manager.load_settings()
                settings = ctx.dns.settings_manager.migrate_dns_providers_to_multi_account(settings)
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
                if ctx.dns.add_account(account_id, provider, merged):
                    if set_as_default:
                        ctx.dns.set_default_account(provider, account_id)
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='update_account',
                            resource_type='dns_provider',
                            resource_id=f"{provider}:{account_id}",
                            status='success',
                            details={
                                'set_as_default': set_as_default
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {'success': True, 'message': 'Account updated'}

                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='update_account',
                        resource_type='dns_provider',
                        resource_id=f"{provider}:{account_id}",
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {'error': 'Failed to update account'}, 500
            except Exception as e:
                logger.error(f"Error updating DNS account: {e}")
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='update_account',
                        resource_type='dns_provider',
                        resource_id=f"{provider}:{account_id}",
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                        error=str(e)
                    )
                return {'error': str(e)}, 500

        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def delete(self, provider, account_id):
            """Delete a DNS provider account"""
            try:
                if ctx.dns.delete_account(provider, account_id):
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='delete_account',
                            resource_type='dns_provider',
                            resource_id=f"{provider}:{account_id}",
                            status='success',
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {'success': True, 'message': 'Account deleted'}

                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='delete_account',
                        resource_type='dns_provider',
                        resource_id=f"{provider}:{account_id}",
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return _failed_delete(ctx.dns, provider, account_id)
            except Exception as e:
                logger.error(f"Error deleting DNS account: {e}")
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='delete_account',
                        resource_type='dns_provider',
                        resource_id=f"{provider}:{account_id}",
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                        error=str(e)
                    )
                return {'error': str(e)}, 500

    return {
        'Settings': Settings,
        'DNSProviders': DNSProviders,
        'DNSAccounts': DNSAccounts,
        'DNSAccountDetail': DNSAccountDetail,
    }
