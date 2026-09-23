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
from flask import Response, current_app, request
from flask_restx import Resource

import logging

from ..core.audit_context import audit_context_from_request
from ..core.cert_service import DomainOutOfScope
from ..core.certificates import DomainOperationInProgress
from ..core.inventory_view import build_inventory_view, build_registrations_view
from ..core.utils import utc_now_iso
from .resource_context import (
    ApiContext,
    check_domain_scope,
    is_record_in_scope,
    scope_filter_records,
)

logger = logging.getLogger(__name__)


def _config_view(discovery, ct_monitor, registration, health=None, settings=None):
    """The discovery configuration as GET and POST both answer it."""
    from ..core.dns_resolver import configured_nameservers

    view = {
        'discovery': discovery.get_config(),
        'ct_monitoring': ct_monitor.get_config(),
        # Not a discovery setting as such — it governs every lookup CertMate
        # makes for itself, CAA included — but this is the page an operator is
        # on when a refused blocklist tells them to change it.
        'dns_resolver': {'nameservers': configured_nameservers(settings or {})},
    }
    if registration is not None:
        view['domain_registration'] = registration.get_config()
    if health is not None:
        view['domain_health'] = health.get_config()
    return view


def _save_registration_config(registration, payload):
    """Persist the ``domain_registration`` section of a config POST, if any.
    Raises ValueError for a name no registry holds, like the other sections."""
    section = payload.get('domain_registration')
    if registration is not None and isinstance(section, dict):
        registration.save_config(section)


def _save_resolver_config(settings_manager, payload):
    """Persist the ``dns_resolver`` section of a config POST, if any.
    Raises ValueError for anything that is not an IP address."""
    from ..core.dns_resolver import parse_nameservers

    section = payload.get('dns_resolver')
    if settings_manager is None or not isinstance(section, dict):
        return
    nameservers = parse_nameservers(section.get('nameservers'))
    settings_manager.update(
        lambda s: s.__setitem__('dns_resolver', {'nameservers': nameservers}),
        'dns_resolver_save',
    )


def _save_health_config(health, payload):
    """Persist the ``domain_health`` section of a config POST, if any.
    Raises ValueError for an extra name that is not a domain."""
    section = payload.get('domain_health')
    if health is not None and isinstance(section, dict):
        health.save_config(section)


def _scan_registrations(registration, result):
    """Run the registration check as the last step of a scan, isolated like
    the discovery and CT steps: its failure is reported, not propagated."""
    if registration is None:
        return
    try:
        result['domain_registration'] = registration.run_check()
    except Exception as e:
        logger.error(f"Domain registration check failed: {e}")
        result['domain_registration'] = {'error': 'domain registration check failed'}


def _scan_domain_health(health, result):
    """Run the name-level checks as part of a scan, isolated the same way."""
    if health is None:
        return
    try:
        result['domain_health'] = health.run_check()
    except Exception as e:
        logger.error(f"Domain health check failed: {e}")
        result['domain_health'] = {'error': 'domain health check failed'}


def _registrations_response(ctx):
    """GET /api/inventory/domains: registrations the caller's scope covers."""
    inventory = ctx.managers.get('cert_inventory')
    if inventory is None:
        return {'error': 'Certificate inventory not available',
                'code': 'INVENTORY_UNAVAILABLE'}, 503
    records = [r for r in inventory.list_registrations()
               if is_record_in_scope(ctx, {'subject_cn': r['domain'], 'san_dns': []})]
    return build_registrations_view(records)


def _health_response(ctx):
    """GET /api/inventory/health: name-level checks the caller's scope covers."""
    inventory = ctx.managers.get('cert_inventory')
    if inventory is None:
        return {'error': 'Certificate inventory not available',
                'code': 'INVENTORY_UNAVAILABLE'}, 503
    records = [r for r in inventory.list_domain_health()
               if is_record_in_scope(ctx, {'subject_cn': r['name'], 'san_dns': []})]
    summary = {'total': len(records),
               'by_status': {'failing': 0, 'warning': 0, 'unknown': 0, 'ok': 0}}
    for record in records:
        status = record.get('status') or 'unknown'
        summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
    return {'names': records, 'summary': summary}


def _inventory_health_resource(api, ctx):
    """Build the GET /api/inventory/health resource.

    Outside create_inventory_resources for the same reason as the domains
    resource: the closure's complexity ceiling only ever comes down.
    """
    class InventoryHealth(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self):
            """What the name-level checks last found for each tracked name.

            SPF, DMARC and MX, the blocklists, the HSTS and protective headers
            the host serves, what its response discloses, and — when it is
            switched on — whether it still accepts TLS 1.0 or 1.1. A check
            that could not be completed reports ``unknown``, which is not a
            pass: a blocklist that refused the query has said nothing about
            the address. A scoped key sees only its own names.
            """
            return _health_response(ctx)

    return InventoryHealth


def _inventory_domains_resource(api, ctx):
    """Build the GET /api/inventory/domains resource.

    Outside create_inventory_resources so the closure's complexity budget —
    a ceiling that only comes down — pays nothing for it.
    """
    class InventoryDomains(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self):
            """When each tracked domain's registration expires.

            One row per registrable domain, from RDAP, or WHOIS where the TLD
            has no RDAP. A scoped key sees only the domains its scope covers.
            """
            return _registrations_response(ctx)

    return InventoryDomains


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

    class InventoryRecord(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def delete(self, fingerprint):
            """Forget a discovered certificate (#634).

            The inventory was append-only: taking a domain out of the discovery
            configuration stopped future scans from finding it, but every row
            already recorded stayed, with no way to remove it.

            This forgets an observation rather than suppressing one. A
            certificate whose domain is still configured for discovery will be
            recorded again on the next scan, so the response says so instead of
            leaving the operator to discover it by repeating the deletion.
            """
            inventory = ctx.managers.get('cert_inventory')
            if inventory is None:
                return {'error': 'Certificate inventory not available'}, 503

            record = inventory.get(fingerprint)
            # Scope first: an out-of-scope record must be indistinguishable
            # from one that does not exist, exactly as the read paths treat it.
            if record is None or not _record_in_scope(record):
                return {'error': 'Certificate not found in inventory'}, 404

            if not inventory.delete(fingerprint):
                return {'error': 'Certificate not found in inventory'}, 404

            return {
                'status': 'deleted',
                'fingerprint': fingerprint,
                'note': ('Removed from the inventory. It will be recorded '
                         'again on the next scan if its domain is still in '
                         'the discovery configuration.'),
            }, 200

    class InventoryConfig(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self):
            """Return discovery + CT-log monitoring configuration."""
            discovery = ctx.managers.get('cert_discovery')
            ct_monitor = ctx.managers.get('ct_monitor')
            if discovery is None or ct_monitor is None:
                return {'error': 'Certificate discovery not available'}, 503
            return _config_view(discovery, ct_monitor,
                                ctx.managers.get('domain_registration'),
                                ctx.managers.get('domain_health'),
                                ctx.managers['settings'].load_settings() or {})

        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def post(self):
            """Update the discovery configuration.

            Body may carry a ``discovery``, ``ct_monitoring``,
            ``domain_registration`` and/or ``domain_health`` object; each is
            validated and persisted by its own manager, and anything it
            refuses — a bad endpoint spec, a name no registry holds, an extra
            name that is not a domain — is a 400. Returns the effective
            configuration after the update.
            """
            discovery = ctx.managers.get('cert_discovery')
            ct_monitor = ctx.managers.get('ct_monitor')
            if discovery is None or ct_monitor is None:
                return {'error': 'Certificate discovery not available'}, 503
            payload = request.get_json(silent=True) or {}
            registration = ctx.managers.get('domain_registration')
            health = ctx.managers.get('domain_health')
            try:
                if isinstance(payload.get('discovery'), dict):
                    discovery.save_config(payload['discovery'])
                if isinstance(payload.get('ct_monitoring'), dict):
                    ct_monitor.save_config(payload['ct_monitoring'])
                _save_registration_config(registration, payload)
                _save_health_config(health, payload)
                _save_resolver_config(ctx.managers.get('settings'), payload)
            except ValueError as e:
                return {'error': str(e)}, 400
            return _config_view(discovery, ct_monitor, registration, health,
                                ctx.managers['settings'].load_settings() or {})

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
            # Last, so it sees what discovery and the CT poll just added.
            _scan_registrations(ctx.managers.get('domain_registration'), result)
            _scan_domain_health(ctx.managers.get('domain_health'), result)
            return result

    InventoryDomains = _inventory_domains_resource(api, ctx)
    InventoryHealth = _inventory_health_resource(api, ctx)

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

            # Adoption is a real issuance, so it has to announce itself like
            # every other one (#640). Three subscribers hang off this event —
            # the notifier bridge, the deploy hooks, and the deployment-status
            # cache — and without the publish an adopted certificate ran no
            # hook and left the dashboard reporting a stale "deployed &
            # matching" verdict while the load balancer still served the OLD
            # certificate, with nothing to tell the operator.
            #
            # It reuses 'certificate_created' rather than introducing
            # 'certificate_adopted' precisely because all three subscribers
            # filter on the name and ignore what they do not know: a new name
            # would have to reach all of them, and missing one would restore
            # the silence. The 'adopted' marker keeps the alert truthful —
            # see factory.build_notification_message.
            event_bus = current_app.config.get('EVENT_BUS')
            if event_bus:
                event_bus.publish('certificate_created', {
                    'domain': plan['domain'],
                    'san_domains': plan['san_domains'],
                    'dns_provider': plan['dns_provider'],
                    'adopted': True,
                    'fingerprint': fingerprint,
                })

            return {'status': 'adopted', 'domain': plan['domain'],
                    'managed': True}, 201

    return {
        'InventoryList': InventoryList,
        'InventoryRecord': InventoryRecord,
        'InventoryConfig': InventoryConfig,
        'InventoryScan': InventoryScan,
        'InventoryDomains': InventoryDomains,
        'InventoryHealth': InventoryHealth,
        'InventoryCryptoReport': InventoryCryptoReport,
        'InventoryAdopt': InventoryAdopt,
    }
