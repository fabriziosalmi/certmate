"""Administration of the ACME server (#476): turn it on, issue EAB keys.

The protocol itself is served under /acme/ (modules/web/acme_routes.py) and
authenticates with JWS; this is CertMate's own API around it, admin only,
because an EAB key is the right to enrol and turning the server on exposes a
CA. Every change is in the audit log, and an EAB key's HMAC key is returned
once, in the answer that creates it, and never again.
"""
import logging

from flask import request
from flask_restx import Resource

from ..core.acme_server import AcmeAdminError
from .resource_context import ApiContext, instance_wide

logger = logging.getLogger(__name__)


def _refusal(error):
    return {'error': error.message, 'code': error.code}, error.status


def _audit(ctx, operation, resource_id, details):
    if ctx.audit:
        user = getattr(request, 'current_user', None) or {}
        ctx.audit.log_operation(operation=operation, resource_type='acme_server', resource_id=resource_id,
                                status='success', details=details, user=user.get('username'),
                                ip_address=request.remote_addr)


def _server_view(server):
    view = server.admin_view()
    view['directory_url'] = request.url_root.rstrip('/') + '/acme/directory'
    return view


def create_acme_resources(api, models, ctx: ApiContext) -> dict:
    """Build the ACME administration resources against *ctx*."""
    server = ctx.managers.get('acme_server')

    class AcmeServerConfig(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME server')
        @api.marshal_with(models['acme_server_model'])
        def get(self):
            """The ACME server's options, its directory URL and its EAB keys (never their HMAC keys)."""
            return _server_view(server)

        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME server')
        @api.expect(models['acme_server_update_model'])
        def patch(self):
            """Change enabled, allow_http, eab_required, or allowed_identifiers for accounts without an EAB key."""
            changes = request.get_json(silent=True)
            if not isinstance(changes, dict) or not changes:
                return {'error': 'Send a JSON object with enabled, allow_http, eab_required or allowed_identifiers',
                        'code': 'ACME_ADMIN_INVALID'}, 400
            try:
                server.set_options(changes)
            except AcmeAdminError as error:
                return _refusal(error)
            _audit(ctx, 'update_config', 'options', changes)
            return _server_view(server)

    class AcmeEabKeys(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME EAB keys')
        @api.marshal_with(models['acme_eab_keys_model'])
        def get(self):
            """The EAB keys, with how many accounts each one enrolled. Never their HMAC keys."""
            return {'eab_keys': server.admin_view()['eab_keys']}

        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME EAB keys')
        @api.expect(models['acme_eab_key_create_model'])
        def post(self):
            """Create an EAB key. Its hmac_key is in this answer and nowhere else, ever."""
            data = request.get_json(silent=True) or {}
            try:
                created = server.create_eab_key(kid=data.get('kid'),
                                                allowed_identifiers=data.get('allowed_identifiers'),
                                                note=data.get('note', ''))
            except AcmeAdminError as error:
                return _refusal(error)
            _audit(ctx, 'create_eab_key', created['kid'],
                   {'allowed_identifiers': created['allowed_identifiers']})
            return created, 201

    class AcmeEabKey(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME EAB keys')
        def delete(self, kid):
            """Disable an EAB key: it enrols no one again, and the accounts it enrolled keep working."""
            try:
                disabled = server.disable_eab_key(kid)
            except AcmeAdminError as error:
                return _refusal(error)
            _audit(ctx, 'disable_eab_key', kid, {'accounts': disabled['accounts']})
            return disabled

    class AcmeCertificates(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        @instance_wide(ctx, 'acme_server', 'the ACME certificates')
        @api.marshal_with(models['acme_certificates_model'])
        def get(self):
            """The certificates issued over ACME, newest first, with the account and EAB key behind each."""
            return {'certificates': server.certificates_view()}

    class AcmeCertificateRevoke(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME certificates')
        @api.expect(models['acme_revoke_model'])
        def post(self, certificate_id):
            """Revoke a certificate issued over ACME; the CRL at /acme/crl lists it from then on."""
            reason = (request.get_json(silent=True) or {}).get('reason', 0)
            try:
                revoked = server.admin_revoke(certificate_id, reason)
            except AcmeAdminError as error:
                return _refusal(error)
            _audit(ctx, 'revoke_certificate', certificate_id,
                   {'names': revoked['names'], 'reason': revoked['revocation_reason']})
            return revoked

    class AcmeAccounts(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME accounts')
        @api.marshal_with(models['acme_accounts_model'])
        def get(self):
            """The ACME accounts, with the EAB key that enrolled each and what it ordered."""
            return {'accounts': server.accounts_view()}

    class AcmeAccountDeactivate(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @instance_wide(ctx, 'acme_server', 'the ACME accounts')
        def post(self, account_id):
            """Deactivate an account for good: it orders nothing again. Its certificates stay valid."""
            try:
                deactivated = server.admin_deactivate(account_id)
            except AcmeAdminError as error:
                return _refusal(error)
            _audit(ctx, 'deactivate_account', account_id, {'eab_kid': deactivated['eab_kid']})
            return deactivated

    return {
        'AcmeServerConfig': AcmeServerConfig,
        'AcmeEabKeys': AcmeEabKeys,
        'AcmeEabKey': AcmeEabKey,
        'AcmeCertificates': AcmeCertificates,
        'AcmeCertificateRevoke': AcmeCertificateRevoke,
        'AcmeAccounts': AcmeAccounts,
        'AcmeAccountDeactivate': AcmeAccountDeactivate,
    }
