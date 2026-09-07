"""Certificate discovery and inventory: listing, scanning, adoption.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as an
explicit `ApiContext`, which is what makes them importable — and therefore
testable — without constructing the whole manager graph.

This is the first group whose classes use the scope helpers. Those are already
module-level functions taking a context, but they take it as their first
argument, so the thin wrappers the closure prologue defines are reproduced here
rather than rewriting every call site — the call sites move verbatim, which is
the property that makes an extraction reviewable.
"""
from flask import Response, request
from flask_restx import Resource

import logging

from ..core.audit_context import audit_context_from_request
from ..core.cert_service import DomainOutOfScope
from ..core.certificates import DomainOperationInProgress
from ..core.inventory_view import build_inventory_view
from ..core.utils import utc_now_iso
from .resource_context import (
    ApiContext,
    check_domain_scope,
    is_record_in_scope,
    scope_filter_records,
)

logger = logging.getLogger(__name__)


def create_inventory_resources(api, models, ctx: ApiContext) -> dict:
    """Build the inventory resources against *ctx*."""

    def _check_domain_scope(domain, operation):
        return check_domain_scope(ctx, domain, operation)

    def _record_in_scope(record):
        return is_record_in_scope(ctx, record)

    def _scope_filter_records(records):
        return scope_filter_records(ctx, records)

    class InventoryList(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self):
            """List the certificate inventory (issued + discovered) with an
            expiry forecast. Optional filters: ?managed=true/false, ?source=."""
            inventory = ctx.managers.get('cert_inventory')
            if inventory is None:
                return {'error': 'Certificate inventory not available'}, 503
            try:
                managed = request.args.get('managed')
                managed_filter = None
                if managed is not None and managed != '':
                    managed_filter = managed.strip().lower() in ('1', 'true', 'yes', 'on')
                source = request.args.get('source') or None
                records = inventory.list_all(managed=managed_filter, source=source)
                return build_inventory_view(_scope_filter_records(records))
            except Exception as e:
                logger.error(f"Error listing inventory: {e}")
                return {'error': 'Failed to list inventory'}, 500

    class InventoryConfig(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self):
            """Return discovery + CT-log monitoring configuration."""
            discovery = ctx.managers.get('cert_discovery')
            ct_monitor = ctx.managers.get('ct_monitor')
            if discovery is None or ct_monitor is None:
                return {'error': 'Certificate discovery not available'}, 503
            return {
                'discovery': discovery.get_config(),
                'ct_monitoring': ct_monitor.get_config(),
            }

        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def post(self):
            """Update discovery and/or CT-log monitoring configuration.

            Body may carry a ``discovery`` and/or ``ct_monitoring`` object; each
            is validated and persisted by its manager (a bad endpoint spec is a
            400). Returns the effective configuration after the update.
            """
            discovery = ctx.managers.get('cert_discovery')
            ct_monitor = ctx.managers.get('ct_monitor')
            if discovery is None or ct_monitor is None:
                return {'error': 'Certificate discovery not available'}, 503
            payload = request.get_json(silent=True) or {}
            try:
                if isinstance(payload.get('discovery'), dict):
                    discovery.save_config(payload['discovery'])
                if isinstance(payload.get('ct_monitoring'), dict):
                    ct_monitor.save_config(payload['ct_monitoring'])
            except ValueError as e:
                return {'error': str(e)}, 400
            return {
                'discovery': discovery.get_config(),
                'ct_monitoring': ct_monitor.get_config(),
            }

    class InventoryScan(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def post(self):
            """Run a discovery sweep and a CT-log poll now, returning their
            summaries. Both are failure-isolated and no-ops when disabled."""
            discovery = ctx.managers.get('cert_discovery')
            ct_monitor = ctx.managers.get('ct_monitor')
            if discovery is None or ct_monitor is None:
                return {'error': 'Certificate discovery not available'}, 503
            result = {}
            try:
                result['discovery'] = discovery.run_discovery()
            except Exception as e:
                logger.error(f"Discovery scan failed: {e}")
                result['discovery'] = {'error': 'discovery failed'}
            try:
                result['ct_monitoring'] = ct_monitor.run_poll()
            except Exception as e:
                logger.error(f"CT-log poll failed: {e}")
                result['ct_monitoring'] = {'error': 'ct poll failed'}
            return result

    class InventoryCryptoReport(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self):
            """Cryptographic algorithm inventory & readiness report over every
            managed + discovered certificate. ``?format=csv`` downloads a CSV;
            otherwise JSON is returned."""
            from ..core.crypto_report import build_crypto_report, report_to_csv
            inventory = ctx.managers.get('cert_inventory')
            if inventory is None:
                return {'error': 'Certificate inventory not available'}, 503
            try:
                records = _scope_filter_records(inventory.list_all())
                report = build_crypto_report(records, generated_at=utc_now_iso())
            except Exception as e:
                logger.error(f"Error building crypto report: {e}")
                return {'error': 'Failed to build crypto report'}, 500

            if request.args.get('format', '').strip().lower() == 'csv':
                return Response(
                    report_to_csv(report),
                    mimetype='text/csv',
                    headers={'Content-Disposition':
                             'attachment; filename=crypto-readiness-report.csv'},
                )
            return report

    class InventoryAdopt(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self, fingerprint):
            """Return the adoption plan for a discovered certificate: the
            pre-filled create parameters and whether adoption is possible."""
            from ..core.cert_adopt import build_adoption_plan
            inventory = ctx.managers.get('cert_inventory')
            dns_mgr = ctx.managers.get('dns')
            if inventory is None or dns_mgr is None:
                return {'error': 'Certificate inventory not available'}, 503
            record = inventory.get(fingerprint)
            if record is None or not _record_in_scope(record):
                return {'error': 'Certificate not found in inventory'}, 404
            return build_adoption_plan(record, dns_mgr)

        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def post(self, fingerprint):
            """Adopt a discovered certificate: issue/manage it from the observed
            metadata, then flag the inventory record managed. Refuses (400) when
            the domain cannot be validated (no DNS credentials / no email)."""
            from ..core.cert_adopt import build_adoption_plan
            inventory = ctx.managers.get('cert_inventory')
            dns_mgr = ctx.managers.get('dns')
            svc = ctx.managers.get('cert_service')
            if inventory is None or dns_mgr is None or svc is None:
                return {'error': 'Certificate adoption not available'}, 503

            record = inventory.get(fingerprint)
            if record is None or not _record_in_scope(record):
                return {'error': 'Certificate not found in inventory'}, 404

            plan = build_adoption_plan(record, dns_mgr)
            if not plan['available']:
                return {'error': plan['reason'], 'code': 'ADOPTION_UNAVAILABLE'}, 400

            # Scope check: the caller's API key must cover the adopted domain.
            denied = _check_domain_scope(plan['domain'], 'adopt')
            if denied is not None:
                return denied

            try:
                svc.create(
                    domain=plan['domain'],
                    san_domains=plan['san_domains'],
                    dns_provider=plan['dns_provider'],
                    key_type=plan['key_type'],
                    key_size=plan['key_size'],
                    elliptic_curve=plan['elliptic_curve'],
                    user=getattr(request, 'current_user', None),
                    ip_address=request.remote_addr,
                    audit_ctx=audit_context_from_request(),
                )
            except DomainOutOfScope as e:
                return {'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}, 403
            except DomainOperationInProgress:
                return {'error': 'An operation is already in progress for this domain'}, 409
            except ValueError as e:
                return {'error': str(e)}, 400
            except Exception as e:
                logger.error(f"Adoption issuance failed for {plan['domain']}: {e}")
                return {'error': 'Adoption failed during issuance'}, 500

            inventory.mark_managed(fingerprint, plan['domain'])
            return {'status': 'adopted', 'domain': plan['domain'],
                    'managed': True}, 201

    return {
        'InventoryList': InventoryList,
        'InventoryConfig': InventoryConfig,
        'InventoryScan': InventoryScan,
        'InventoryCryptoReport': InventoryCryptoReport,
        'InventoryAdopt': InventoryAdopt,
    }
