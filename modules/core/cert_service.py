"""Application-level certificate orchestration shared by the REST API
(flask-restx resources) and the web blueprint.

Before this module the create/renew request handling — primary-domain
validation, API-key scope enforcement, settings-driven defaults, the certbot
call and the settings.json write-back — was copied into both
``modules/api/resources.py`` and ``modules/web/cert_routes.py``. The two
copies drifted, and security fixes (e.g. the ``validate_domain`` write-boundary
gate) had to be applied by hand in both places. ``CertificateService`` is the
single owner of that orchestration; the HTTP layers are thin adapters that
parse the request, call the service, and format the response.

The service is framework-agnostic: it never touches ``flask.request``. Callers
pass the resolved auth context (``user`` dict + ``ip_address``) so a scope
denial can be audited here and raised as :class:`DomainOutOfScope`, which the
adapters map to HTTP 403.
"""
import logging

from .utils import validate_domain, validate_key_options

logger = logging.getLogger(__name__)


class DomainOutOfScope(PermissionError):
    """Raised when a scoped API key's ``allowed_domains`` does not cover the
    requested domain. Adapters map this to HTTP 403 with the machine code
    ``DOMAIN_OUT_OF_SCOPE``. It subclasses ``PermissionError`` (not
    ``ValueError`` / ``RuntimeError``) so the adapters' existing
    ``ValueError -> 400`` and ``RuntimeError -> 422`` handlers never swallow a
    scope denial.
    """

    def __init__(self, domain):
        self.domain = domain
        super().__init__(f'API key not authorized for domain {domain}')


class CertificateService:
    """Owns create/renew orchestration on top of ``CertificateManager``."""

    def __init__(self, certificate_manager, settings_manager, auth_manager,
                 audit_logger=None):
        self._certs = certificate_manager
        self._settings = settings_manager
        self._auth = auth_manager
        self._audit = audit_logger

    def _enforce_scope(self, domain, operation, user, ip_address):
        """Raise :class:`DomainOutOfScope` (after an audit entry) when *user*
        may not act on *domain*. Sessions and legacy bearer tokens carry no
        ``allowed_domains`` and are therefore unrestricted, preserving the
        pre-RBAC behaviour.
        """
        user = user or {}
        if self._auth.user_can_access_domain(user, domain):
            return
        logger.warning(
            "Scope denial: user=%s op=%s domain=%s scope=%s",
            user.get('username'), operation, domain, user.get('allowed_domains'),
        )
        if self._audit:
            self._audit.log_authz_denied(
                operation=operation,
                resource_type='certificate',
                resource_id=domain,
                reason='domain outside scoped key allowed_domains',
                user=user.get('username'),
                ip_address=ip_address,
            )
        raise DomainOutOfScope(domain)

    def create(self, *, domain, san_domains=None, dns_provider=None,
               account_id=None, ca_provider=None, challenge_type=None,
               domain_alias=None, key_type=None, key_size=None,
               elliptic_curve=None, user=None, ip_address=None):
        """Validate, scope-check, resolve defaults, issue, and persist a new
        certificate; returns the ``CertificateManager.create_certificate``
        result dict. Raises ``ValueError`` (bad input / missing config),
        :class:`DomainOutOfScope` (403), ``DomainOperationInProgress`` (409) or
        ``RuntimeError`` (certbot failure).

        Equivalent to ``issue_create(prepare_create(...))``. The two phases are
        exposed separately so async callers can run the cheap ``prepare_create``
        synchronously (for an immediate 4xx on bad input) and defer the
        blocking ``issue_create`` (certbot) to a background job.
        """
        return self.issue_create(self.prepare_create(
            domain=domain, san_domains=san_domains, dns_provider=dns_provider,
            account_id=account_id, ca_provider=ca_provider,
            challenge_type=challenge_type, domain_alias=domain_alias,
            key_type=key_type, key_size=key_size, elliptic_curve=elliptic_curve,
            user=user, ip_address=ip_address,
        ))

    def prepare_create(self, *, domain, san_domains=None, dns_provider=None,
                        account_id=None, ca_provider=None, challenge_type=None,
                        domain_alias=None, key_type=None, key_size=None,
                        elliptic_curve=None, user=None, ip_address=None):
        """Validate, authorize and resolve a create request WITHOUT side
        effects, returning the resolved kwargs for :meth:`issue_create`. Raises
        ``ValueError`` / :class:`DomainOutOfScope`. Cheap (no certbot, no disk
        write) so it is safe to run inline before deferring issuance.
        """
        domain = (domain or '').strip()
        san_domains = san_domains or []

        # Structural validation runs BEFORE any side effect (directory
        # creation, settings write, certbot): a poisoned primary domain
        # ("../poisoned") would otherwise be persisted into settings.json and
        # replayed by the renewal loop. SAN *content* is validated one layer
        # down in create_certificate; here we only guard the container type.
        ok, msg = validate_domain(domain)
        if not ok:
            raise ValueError(f'Invalid domain: {msg}')
        if domain_alias:
            ok, msg = validate_domain(domain_alias)
            if not ok:
                raise ValueError(f'Invalid domain_alias: {msg}')
        if san_domains and not isinstance(san_domains, list):
            raise ValueError('Invalid san_domains format')

        # Scope: the primary AND every SAN must be in the key's
        # allowed_domains — a partial create would leak one tenant's domain
        # into another tenant's certificate.
        self._enforce_scope(domain, 'create', user, ip_address)
        for san in san_domains:
            san_clean = san.strip() if isinstance(san, str) else ''
            if san_clean:
                self._enforce_scope(san_clean, 'create_san', user, ip_address)

        # Key-option validation runs after the scope checks so its
        # field-specific messages never reach a caller who could not see the
        # target domain in the first place.
        if key_type is not None or key_size is not None or elliptic_curve is not None:
            ok, key_err = validate_key_options(key_type, key_size, elliptic_curve)
            if not ok:
                raise ValueError(key_err)

        settings = self._settings.load_settings()
        email = settings.get('email')
        if not email:
            raise ValueError('Email not configured')
        if not ca_provider:
            ca_provider = settings.get('default_ca', 'letsencrypt')
        if not challenge_type:
            challenge_type = settings.get('challenge_type', 'dns-01')
        if challenge_type != 'http-01' and not dns_provider:
            dns_provider = settings.get('dns_provider')
            if not dns_provider:
                raise ValueError('No DNS provider specified')

        return {
            'domain': domain,
            'email': email,
            'dns_provider': dns_provider,
            'account_id': account_id,
            'ca_provider': ca_provider,
            'domain_alias': domain_alias,
            'san_domains': san_domains,
            'challenge_type': challenge_type,
            'key_type': key_type,
            'key_size': key_size,
            'elliptic_curve': elliptic_curve,
            # Fallback used only to label the persisted domain entry.
            '_settings_dns_provider': settings.get('dns_provider'),
        }

    def issue_create(self, prepared):
        """Perform the certbot issuance + settings persistence for a prepared
        create request. This is the blocking, deferrable half. Raises
        ``DomainOperationInProgress`` (409), ``RuntimeError`` or
        ``FileExistsError``.
        """
        domain = prepared['domain']
        result = self._certs.create_certificate(
            domain=domain,
            email=prepared['email'],
            dns_provider=prepared['dns_provider'],
            account_id=prepared['account_id'],
            ca_provider=prepared['ca_provider'],
            domain_alias=prepared['domain_alias'],
            san_domains=prepared['san_domains'],
            challenge_type=prepared['challenge_type'],
            key_type=prepared['key_type'],
            key_size=prepared['key_size'],
            elliptic_curve=prepared['elliptic_curve'],
        )

        # Append the new domain under the settings manager's lock so two
        # parallel creates for different domains cannot race and drop an entry.
        resolved_dns_provider = prepared['dns_provider'] or prepared['_settings_dns_provider']
        self._settings.update(
            _make_add_domain(domain, resolved_dns_provider, prepared['account_id']),
            'certificate_created',
        )
        logger.info("Ensured domain %s is in settings after certificate creation", domain)
        return result

    def renew(self, *, domain, force=False, user=None, ip_address=None):
        """Scope-check then renew an existing certificate, returning the
        manager's result dict. Path/sanitisation of *domain* is the adapter's
        responsibility (it owns ``cert_dir`` resolution); here we enforce scope
        and delegate. Raises :class:`DomainOutOfScope` (403),
        ``DomainOperationInProgress`` (409) or ``RuntimeError``.

        Equivalent to ``issue_renew(prepare_renew(...), force=force)``; split so
        async callers can authorize synchronously and defer the certbot call.
        """
        return self.issue_renew(
            self.prepare_renew(domain=domain, user=user, ip_address=ip_address),
            force=force,
        )

    def prepare_renew(self, *, domain, user=None, ip_address=None):
        """Authorize a renew request (scope check) with no side effects.
        Raises :class:`DomainOutOfScope`. Returns the resolved kwargs for
        :meth:`issue_renew`.
        """
        self._enforce_scope(domain, 'renew', user, ip_address)
        return {'domain': domain}

    def issue_renew(self, prepared, *, force=False):
        """Run the (blocking, deferrable) certbot renewal for a prepared renew
        request. Raises ``DomainOperationInProgress`` (409) or ``RuntimeError``.
        """
        return self._certs.renew_certificate(prepared['domain'], force=force)


def _make_add_domain(domain, dns_provider, account_id):
    """Build the idempotent ``settings_manager.update`` mutator that appends
    *domain* to the tracked domains list unless it is already present."""

    def _add_domain(s):
        domains_list = s.get('domains', []) or []
        already_present = any(
            (d == domain if isinstance(d, str) else d.get('domain') == domain)
            for d in domains_list
        )
        if already_present:
            return
        domains_list.append({
            'domain': domain,
            'dns_provider': dns_provider,
            'dns_account_id': account_id,
        })
        s['domains'] = domains_list

    return _add_domain
