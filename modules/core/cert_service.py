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
import threading
import time
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes

from .structured_logging import scrub_log_value
from . import acme_profiles
from .ca_manager import resolve_ca_account
from .cert_labels import normalize_notes, normalize_tags
from .constants import PROBE_PROTOCOLS
from .csr_issuance import CSRError, csr_domains, read_csr
from .cert_import import (INVALID_IMPORT_BUNDLE, CertificateImportError, validate_external_identity,
                          validate_import_bundle, validate_import_renewability)
from .utils import utc_now_iso, validate_domain, validate_key_options
from .domain_paths import certificate_dir
from .domain_entries import entry_domain, entry_external, normalize_entry
from .certificates import (DNS_ALIAS_SUPPORTED_PROVIDERS, CertificateNamesUnknown, ExternalCertificate,
                           ReplacementRefused)
from .inventory_sources import collect_domain_sources

logger = logging.getLogger(__name__)

# Per-request bounds, because the global MAX_CONTENT_LENGTH is 50 MB and
# exists for the backup upload. Without these, the ceiling on a certificate
# request was "however many names fit in fifty megabytes" and "however large a
# PEM fits in fifty megabytes" — neither of which is a limit anyone chose, and
# neither of which any endpoint stated.
#
# 100 is Let's Encrypt's cap on names per certificate, so a request naming more
# cannot be satisfied by the CA regardless of what CertMate does with it.
MAX_SAN_DOMAINS = 100

# A PEM CSR for a 4096-bit key carrying a hundred names is a few kilobytes.
# 64 KB is generous by more than an order of magnitude and still refuses long
# before anything reaches the parser.
MAX_CSR_BYTES = 64 * 1024


# Kept as a local alias: this module's call sites read better with the short
# name, but the implementation now lives once, in the logging module.
_scrub_log = scrub_log_value



def _checked_profile(value):
    """An ACME profile from a request (#395): None when not given (the account's default, or
    the certificate's own on a reissue), '' when the caller asked for the CA's default, the
    normalized name otherwise. A malformed one is a ValueError, a 400, before anything runs."""
    if value is None or value == '':
        return value
    ok, profile = acme_profiles.validate_profile(value)
    if not ok:
        raise ValueError(profile)
    return profile

# Serialises the external imports' check that their names are free with
# storing them, so two imports sharing a name cannot both pass the check. Imports
# are rare and brief, so one lock for all of them costs nothing. It does not
# cover an ACME issuance in flight, whose SANs are on record only once it
# completes; that window is the one #854's name reservation would close.
_EXTERNAL_IMPORT_LOCK = threading.Lock()

# The fields that configure renewal through a CA. An external certificate has
# none, and sending one with it is refused rather than ignored.
_RENEWAL_FIELDS = ('ca_provider', 'ca_account_id', 'challenge_type', 'dns_provider',
                   'account_id', 'domain_alias', 'alias_dns_provider', 'acme_profile')


class CertificateNamesTaken(ValueError):
    """An import names a DNS name a certificate CertMate manages already covers,
    as its primary name or a SAN.

    The message lists only the import's own names, which the caller sent and
    passed the scope check for. It never names the other certificate, which may
    be outside a scoped key's domains. ``unknown`` is the fail-closed case: the
    names of a managed certificate could not be read, so nothing proves the
    import's names are free.
    """
    code = 'NAMES_ALREADY_MANAGED'

    def __init__(self, names=(), *, unknown=False):
        self.names = list(names)
        self.unknown = unknown
        if unknown:
            message = ('CertMate could not read the names of every certificate it manages, '
                       'so it cannot confirm these names are free. The server log names the certificate.')
        else:
            message = ('These names are already covered by a certificate CertMate manages: '
                       + ', '.join(self.names))
        super().__init__(message)


class EmailNotConfigured(ValueError):
    """Neither the selected CA account nor global settings supplies an email."""


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
                 audit_logger=None, event_bus=None):
        self._certs = certificate_manager
        self._settings = settings_manager
        self._auth = auth_manager
        self._audit = audit_logger
        # The lifecycle events used to be published by the RESTX resources and
        # by nothing else, so a certificate created or renewed through the
        # dashboard fired no deploy hook and no webhook — the `/api/web/...`
        # routes call this service directly. Measured before this: the RESTX
        # create emitted `certificate_created`, its web twin emitted nothing.
        #
        # Publishing here puts it where every adapter passes: web, RESTX and
        # the async IssuanceExecutor. `None` keeps the service usable in the
        # tests and tools that build it without a bus.
        self._events = event_bus

    def _publish(self, event, payload):
        """Announce a lifecycle event, if this instance has a bus.

        Deliberately swallowing nothing: `EventBus.publish` queues and
        returns, so a slow or failing listener cannot reach here. A bus that
        raises is a defect worth seeing rather than hiding behind issuance
        that already succeeded.
        """
        if self._events is not None:
            self._events.publish(event, payload)

    def _enforce_scope(self, domain, operation, user, ip_address):
        """Raise :class:`DomainOutOfScope` (after an audit entry) when *user*
        may not act on *domain*. Sessions and legacy bearer tokens carry no
        ``allowed_domains`` and are therefore unrestricted, preserving the
        pre-RBAC behaviour.
        """
        user = user or {}
        if self._auth.user_can_access_domain(user, domain):
            return
        self._deny_scope(domain, operation, user, ip_address)

    def _enforce_certificate_scope(self, domain, operation, user, ip_address):
        """`_enforce_scope` for the certificate that exists as *domain*.

        Renewing or reissuing it acts on every name it covers, so each must be
        in scope (see `CertificateManager.names_covered`). The refusal and the
        audit entry name *domain* only; the certificate's names are on record
        for whoever administers it.
        """
        self._enforce_scope(domain, operation, user, ip_address)
        user = user or {}
        if user.get('allowed_domains') is None:
            return
        if not self._certs.every_name_matches(
                domain, lambda name: self._auth.user_can_access_domain(user, name)):
            self._deny_scope(
                domain, operation, user, ip_address,
                reason='certificate covers a name outside scoped key allowed_domains, or its names could not be read')

    def _deny_scope(self, domain, operation, user, ip_address,
                    reason='domain outside scoped key allowed_domains'):
        logger.warning(
            "Scope denial: user=%s op=%s domain=%s scope=%s",
            _scrub_log(user.get('username')), operation,
            _scrub_log(domain), _scrub_log(user.get('allowed_domains')),
        )
        if self._audit:
            self._audit.log_authz_denied(
                operation=operation,
                resource_type='certificate',
                resource_id=domain,
                reason=reason,
                user=user.get('username'),
                ip_address=ip_address,
            )
        raise DomainOutOfScope(domain)

    def _audit_emit(self, audit_ctx, operation, domain, status,
                    details=None, error=None):
        """Emit a certificate-lifecycle audit entry, carrying the structured
        actor/trigger attribution captured at request time. No-op when no audit
        logger is wired. Never raises (auditing must not break issuance)."""
        if not self._audit:
            return
        ctx = audit_ctx or {}
        try:
            self._audit.log_operation(
                operation=operation,
                resource_type='certificate',
                resource_id=domain,
                status=status,
                details=details or {},
                user=ctx.get('user'),
                ip_address=ctx.get('ip'),
                error=(str(error)[:500] if error else None),
                actor=ctx.get('actor'),
                trigger=ctx.get('trigger'),
            )
        except Exception:  # pragma: no cover - defensive
            # Operation type is enough to diagnose; the domain adds no value
            # here and only feeds CodeQL's clear-text-logging heuristic (it is
            # field-insensitive on the `prepared` dict, conflating the domain
            # with the attribution context).
            logger.debug("Audit emit failed for operation=%s", operation)

    def create(self, *, domain, san_domains=None, dns_provider=None,
               account_id=None, ca_provider=None, ca_account_id=None, challenge_type=None,
               domain_alias=None, alias_dns_provider=None, key_type=None,
               key_size=None, elliptic_curve=None, user=None, ip_address=None,
               audit_ctx=None, csr_pem=None, acme_profile=None, event_details=None):
        """Validate, scope-check, resolve defaults, issue, and persist a new
        certificate; returns the ``CertificateManager.create_certificate``
        result dict. Raises ``ValueError`` (bad input / missing config),
        :class:`DomainOutOfScope` (403), ``DomainOperationInProgress`` (409) or
        ``RuntimeError`` (certbot failure).

        Equivalent to ``issue_create(prepare_create(...))``. The two phases are
        exposed separately so async callers can run the cheap ``prepare_create``
        synchronously (for an immediate 4xx on bad input) and defer the
        blocking ``issue_create`` (certbot) to a background job.

        ``audit_ctx`` is the structured attribution context (see
        ``audit_context_from_request``); it is carried into ``issue_create`` so
        the success/failure audit record names the actor and trigger even on the
        deferred async path.

        ``event_details`` are extra fields for the ``certificate_created``
        announcement this create makes. Adoption passes its ``adopted`` marker
        and the inventory fingerprint here instead of announcing a second time
        itself, which ran every deploy hook twice. They never replace a field
        the issuance itself reports.
        """
        prepared = self.prepare_create(
            domain=domain, san_domains=san_domains, dns_provider=dns_provider,
            account_id=account_id, ca_provider=ca_provider, ca_account_id=ca_account_id,
            challenge_type=challenge_type, domain_alias=domain_alias,
            alias_dns_provider=alias_dns_provider,
            key_type=key_type, key_size=key_size, elliptic_curve=elliptic_curve,
            user=user, ip_address=ip_address, audit_ctx=audit_ctx,
            csr_pem=csr_pem, acme_profile=acme_profile,
        )
        if event_details:
            prepared['_event_details'] = dict(event_details)
        return self.issue_create(prepared)

    def prepare_create(self, *, domain, san_domains=None, dns_provider=None,
                        account_id=None, ca_provider=None, ca_account_id=None, challenge_type=None,
                        domain_alias=None, alias_dns_provider=None,
                        key_type=None, key_size=None,
                        elliptic_curve=None, user=None, ip_address=None,
                        audit_ctx=None, csr_pem=None, acme_profile=None):
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
        # down in create_certificate.
        #
        # validate_domain returns the NORMALISED name as its second value on
        # success (the URL netloc extracted, lowercased) — and we now use it
        # instead of discarding it. Keeping the caller's raw string was the
        # bug: "https://x/../../y" has a perfectly good netloc, passed
        # validation, and was then used verbatim as a path component, escaping
        # cert_dir. Rebinding to the normalised name means everything
        # downstream — the cert dir, the certbot --cert-name, _seed_acme_account
        # — sees a bare hostname that can never contain '/' or '..'.
        ok, normalized = validate_domain(domain)
        if not ok:
            raise ValueError(f'Invalid domain: {normalized}')
        domain = normalized
        if domain_alias:
            ok, normalized_alias = validate_domain(domain_alias)
            if not ok:
                raise ValueError(f'Invalid domain_alias: {normalized_alias}')
            domain_alias = normalized_alias
        # The alias zone may live with a different provider than the primary
        # (#129). PATCH and reissue have always read this; create accepted it
        # in the request body, answered 201, and dropped it — so the only way
        # to create an alias certificate with a separate alias provider was
        # to create it wrong and then PATCH it.
        if not domain_alias:
            alias_dns_provider = None
        if san_domains and not isinstance(san_domains, list):
            raise ValueError('Invalid san_domains format')
        if san_domains and len(san_domains) > MAX_SAN_DOMAINS:
            # The global 50 MB body limit exists for the backup upload, and
            # applied to this endpoint too — so the ceiling on a certificate
            # request was "however many names fit in fifty megabytes", which
            # is not a limit anyone chose. Let's Encrypt caps a certificate at
            # 100 names, so a request naming more cannot be satisfied by the
            # CA regardless; refusing it here says so, instead of building a
            # certbot command line with thousands of -d flags and letting the
            # CA reject it after the DNS challenges have been set up.
            raise ValueError(
                f'Too many san_domains: {len(san_domains)}. A certificate can '
                f'carry at most {MAX_SAN_DOMAINS} names, including the primary '
                f'domain.')

        # A CSR is signed over its own subject and SANs, and carries its own
        # public key. A request that also names SANs or a key shape is asking
        # for something the CA will not deliver, so it is refused rather than
        # silently ignored — the certificate would come back different from
        # what the caller asked for, with nothing to say why (#599).
        csr_names = None
        if csr_pem is not None:
            csr_names = self._check_csr(csr_pem, domain, san_domains=san_domains,
                                        key_type=key_type, key_size=key_size,
                                        elliptic_curve=elliptic_curve,
                                        scope_action='create_san',
                                        user=user, ip_address=ip_address)

        # Scope: the primary AND every SAN must be in the key's
        # allowed_domains — a partial create would leak one tenant's domain
        # into another tenant's certificate.
        self._enforce_scope(domain, 'create', user, ip_address)
        for san in san_domains:
            san_clean = san.strip() if isinstance(san, str) else ''
            if san_clean:
                self._enforce_scope(san_clean, 'create_san', user, ip_address)
        # A create over an external certificate is refused as that, here so an
        # async request does not answer 202 first. The manager refuses it again
        # under the lock.
        self._certs.refuse_external(domain)
        self._refuse_external_names(csr_names or [domain, *san_domains])

        # Key-option validation runs after the scope checks so its
        # field-specific messages never reach a caller who could not see the
        # target domain in the first place.
        if key_type is not None or key_size is not None or elliptic_curve is not None:
            ok, key_err = validate_key_options(key_type, key_size, elliptic_curve)
            if not ok:
                raise ValueError(key_err)
        acme_profile = _checked_profile(acme_profile)

        settings = self._settings.load_settings()
        if not ca_provider:
            ca_provider = settings.get('default_ca', 'letsencrypt')
        email = self.resolve_ca_email(settings, ca_provider, ca_account_id)
        if not challenge_type:
            challenge_type = settings.get('challenge_type', 'dns-01')
        if challenge_type == 'prevalidated':
            if ca_provider != 'sectigo':
                raise ValueError('Prevalidated ACME is available only for Sectigo')
            if dns_provider or account_id or domain_alias or alias_dns_provider:
                raise ValueError('Prevalidated ACME does not use DNS providers, accounts or aliases')
        if challenge_type not in ('http-01', 'prevalidated') and not dns_provider:
            dns_provider = settings.get('dns_provider')
            if not dns_provider:
                raise ValueError('No DNS provider specified')

        return {
            'domain': domain,
            'email': email,
            'dns_provider': dns_provider,
            'account_id': account_id,
            'ca_provider': ca_provider,
            'ca_account_id': ca_account_id,
            'domain_alias': domain_alias,
            'alias_dns_provider': alias_dns_provider,
            'san_domains': san_domains,
            'challenge_type': challenge_type,
            'key_type': key_type,
            'key_size': key_size,
            'elliptic_curve': elliptic_curve,
            'acme_profile': acme_profile,
            'csr_pem': csr_pem,
            # Fallback used only to label the persisted domain entry.
            '_settings_dns_provider': settings.get('dns_provider'),
            # Attribution captured synchronously so the deferred async issuance
            # still audits the original actor/trigger.
            '_audit_ctx': audit_ctx,
        }

    def issue_create(self, prepared):
        """Perform the certbot issuance + settings persistence for a prepared
        create request. This is the blocking, deferrable half. Raises
        ``DomainOperationInProgress`` (409), ``RuntimeError`` or
        ``FileExistsError``.
        """
        return self._issue_create(prepared, register=True)

    def _issue_create(self, prepared, *, register):
        """Issue one certificate, audit it, announce it: what every create owes.

        ``register=False`` leaves the settings entry to the caller: a batch
        registers all its domains in ONE write, because every settings save
        takes a full unified backup (settings plus every certificate) and one
        write per domain would zip the whole store N times. Everything else,
        the account, the audit record and the event, is this method's, so a
        batch cannot skip any of it again (#666, D9).
        """
        domain = prepared['domain']
        audit_ctx = prepared.get('_audit_ctx')
        try:
            result = self._certs.create_certificate(
                domain=domain,
                email=prepared['email'],
                dns_provider=prepared['dns_provider'],
                account_id=prepared['account_id'],
                ca_provider=prepared['ca_provider'],
                ca_account_id=prepared.get('ca_account_id'),
                domain_alias=prepared['domain_alias'],
                alias_dns_provider=prepared.get('alias_dns_provider'),
                san_domains=prepared['san_domains'],
                challenge_type=prepared['challenge_type'],
                key_type=prepared['key_type'],
                key_size=prepared['key_size'],
                elliptic_curve=prepared['elliptic_curve'],
                csr_pem=prepared.get('csr_pem'),
                acme_profile=prepared.get('acme_profile'),
            )

            # Append the new domain under the settings manager's lock so two
            # parallel creates for different domains cannot race and drop an entry.
            if register:
                self._settings.update(_add_domain_entry(prepared), 'certificate_created')
        except Exception as e:
            self._audit_emit(audit_ctx, 'create', domain, 'failure', error=e)
            raise
        if register:
            logger.info("Ensured domain %s is in settings after certificate creation",
                        _scrub_log(domain))
        self._audit_emit(audit_ctx, 'create', domain, 'success', details={
            'ca_provider': prepared.get('ca_provider'),
            'challenge_type': prepared.get('challenge_type'),
            'san_count': len(prepared.get('san_domains') or []),
        })
        announcement = {
            'domain': domain,
            'san_domains': prepared.get('san_domains') or [],
            'dns_provider': result.get('dns_provider'),
            'ca_provider': result.get('ca_provider'),
        }
        for key, value in (prepared.get('_event_details') or {}).items():
            announcement.setdefault(key, value)
        self._publish('certificate_created', announcement)
        return result

    def import_certificate(self, *, certificate, chain, private_key, domain=None,
                           dns_provider=None, account_id=None, ca_provider=None,
                           ca_account_id=None, challenge_type=None, domain_alias=None,
                           alias_dns_provider=None, acme_profile=None, auto_renew=True,
                           external=False, user=None, ip_address=None, audit_ctx=None):
        """Check, store and register an existing certificate, never issue one.

        ``external=True`` imports one no CA here renews; see :meth:`_import_external`.
        """
        if external:
            return self._import_external(
                certificate=certificate, chain=chain, private_key=private_key, domain=domain,
                renewal={'dns_provider': dns_provider, 'account_id': account_id,
                         'ca_provider': ca_provider, 'ca_account_id': ca_account_id,
                         'challenge_type': challenge_type, 'domain_alias': domain_alias,
                         'alias_dns_provider': alias_dns_provider, 'acme_profile': acme_profile},
                auto_renew=auto_renew, user=user, ip_address=ip_address, audit_ctx=audit_ctx)
        try:
            bundle = validate_import_bundle(certificate, chain, private_key)
            bundle.update(validate_import_renewability(bundle))
        except CertificateImportError:
            raise
        except (ValueError, x509.DuplicateExtension, UnsupportedAlgorithm):
            raise CertificateImportError(INVALID_IMPORT_BUNDLE) from None
        if not isinstance(auto_renew, bool):
            raise ValueError('auto_renew must be a boolean')
        normalized = _primary_name(bundle['names'], domain)
        prepared = self.prepare_create(
            domain=normalized, san_domains=[n for n in bundle['names'] if n != normalized],
            dns_provider=dns_provider, account_id=account_id, ca_provider=ca_provider,
            ca_account_id=ca_account_id, challenge_type=challenge_type,
            domain_alias=domain_alias, alias_dns_provider=alias_dns_provider,
            acme_profile=acme_profile, user=user, ip_address=ip_address)
        if prepared['challenge_type'] not in ('dns-01', 'http-01', 'prevalidated'):
            raise ValueError('Unsupported challenge type')
        if prepared['challenge_type'] == 'http-01' and any(n.startswith('*.') for n in bundle['names']):
            raise ValueError('HTTP-01 cannot renew wildcard certificates')
        if prepared['challenge_type'] != 'dns-01' and prepared['domain_alias']:
            raise ValueError('DNS aliases require DNS-01')
        ca = self._certs.ca_manager
        if ca is None:
            raise ValueError('CA manager is unavailable')
        settings = self._settings.load_settings()
        try:
            ca_config, used_ca_account = ca.get_ca_config(prepared['ca_provider'], ca_account_id)
        except ValueError:
            # A global email is sufficient for Let's Encrypt, as in ordinary issuance.
            configured = settings.get('ca_providers', {}).get(prepared['ca_provider'])
            if prepared['ca_provider'] == 'letsencrypt_staging':
                configured = configured or settings.get('ca_providers', {}).get('letsencrypt')
            if (prepared['ca_provider'] not in ('letsencrypt', 'letsencrypt_staging')
                    or ca_account_id not in (None, '', 'default') or configured):
                raise
            ca_config, used_ca_account = {'email': prepared['email']}, 'default'
        ca.get_acme_server_url(prepared['ca_provider'], account_config=ca_config)
        ca.get_eab_credentials(prepared['ca_provider'], ca_config)
        if (any(n.startswith('*.') for n in bundle['names'])
                and not ca.ca_providers[prepared['ca_provider']]['supports_wildcard']):
            raise ValueError('Selected CA does not support wildcard certificates')
        if ca_account_id and used_ca_account != ca_account_id:
            raise ValueError('Selected CA account is not configured')
        prepared['ca_account_id'] = used_ca_account
        prepared['acme_profile'] = self._certs._resolve_acme_profile(
            normalized, False, prepared['acme_profile'], ca_config)
        if prepared['challenge_type'] == 'dns-01':
            dns_config, used_account = self._certs.dns_manager.get_dns_provider_account_config(
                prepared['dns_provider'], account_id, settings)
            if (not dns_config or (account_id and used_account != account_id)
                    or not self._certs.dns_manager._account_has_credentials(prepared['dns_provider'], dns_config)):
                raise ValueError('Selected DNS provider account is not configured')
            prepared['account_id'] = used_account
            if prepared['domain_alias']:
                alias_provider = prepared['alias_dns_provider'] or prepared['dns_provider']
                if alias_provider not in DNS_ALIAS_SUPPORTED_PROVIDERS:
                    raise ValueError('DNS alias mode does not support this DNS provider yet')
                alias_config, _ = self._certs.dns_manager.get_dns_provider_account_config(
                    alias_provider, account_id, settings)
                if (not alias_config or
                        not self._certs.dns_manager._account_has_credentials(alias_provider, alias_config)):
                    raise ValueError('Alias DNS provider account is not configured')
                if alias_provider != prepared['dns_provider']:
                    # An omitted account means each provider uses its own default.
                    prepared['account_id'] = account_id
        metadata = {k: prepared[k] for k in (
            'domain', 'email', 'san_domains', 'ca_provider', 'ca_account_id',
            'challenge_type', 'dns_provider', 'account_id', 'domain_alias',
            'alias_dns_provider', 'acme_profile')}
        metadata.update(bundle['key_options'], created_at=bundle['created_at'], imported_at=utc_now_iso())
        metadata['auto_renew'] = prepared['auto_renew'] = auto_renew
        with self._certs.domain_lock(normalized):
            warning = self._certs.store_imported_certificate(normalized, bundle['files'], metadata)
            try:
                if not self._settings.update(_add_domain_entry(prepared), 'certificate_imported'):
                    raise RuntimeError('Renewal registration was not saved')
            except (OSError, RuntimeError):
                # Keep the valid bundle: a settings failure must not destroy the upload.
                self._audit_emit(audit_ctx, 'import', normalized, 'failure',
                                 error='Certificate stored but renewal registration failed')
                raise RuntimeError('Certificate imported, but registering it in settings failed. '
                                    'The certificate files are preserved; restore settings persistence '
                                    'so the renewal sweep can recover registration.') from None
        self._audit_emit(audit_ctx, 'import', normalized, 'success', details={
            'ca_provider': metadata['ca_provider'], 'challenge_type': metadata['challenge_type'],
            'san_count': len(metadata['san_domains'])})
        self._publish('certificate_created', {
            'domain': normalized, 'san_domains': metadata['san_domains'],
            'dns_provider': metadata['dns_provider'], 'ca_provider': metadata['ca_provider'],
            'imported': True})
        return {'success': True, 'domain': normalized, 'san_domains': metadata['san_domains'],
                'storage_warning': warning}

    def _import_external(self, *, certificate, chain, private_key, domain, renewal,
                         auto_renew, user, ip_address, audit_ctx):
        """Store and register a certificate no CA here can renew (#1159).

        CertMate keeps it, deploys it and warns before it expires, and never
        issues, renews or reissues it: the owner replaces it. So nothing about a
        CA is asked or accepted, and the checks are the bundle's integrity and
        what CertMate needs to hold it, not whether it could issue the same.

        Every name must be free: a name a managed certificate already covers,
        as its primary name or a SAN, refuses the import, so an external
        certificate never shares a name with one CertMate issues. The check and
        the store run under one lock, so two imports sharing a name cannot both
        pass.
        """
        sent = sorted(k for k in _RENEWAL_FIELDS if renewal.get(k) not in (None, ''))
        if sent:
            raise ValueError('An external certificate has no CA, so it takes no renewal '
                             'configuration: remove ' + ', '.join(sent))
        if auto_renew is not False:
            raise ValueError('An external certificate is never renewed by CertMate: '
                             'auto_renew must be false')
        try:
            bundle = validate_import_bundle(certificate, chain, private_key)
            bundle.update(validate_external_identity(bundle))
        except CertificateImportError:
            raise
        except (ValueError, x509.DuplicateExtension, UnsupportedAlgorithm):
            raise CertificateImportError(INVALID_IMPORT_BUNDLE) from None
        normalized = _primary_name(bundle['names'], domain)
        self._enforce_scope(normalized, 'import', user, ip_address)
        for name in bundle['names']:
            if name != normalized:
                self._enforce_scope(name, 'import_san', user, ip_address)
        san_domains = [n for n in bundle['names'] if n != normalized]
        metadata = _external_metadata(normalized, san_domains)
        metadata.update(bundle['key_options'], created_at=bundle['created_at'],
                        imported_at=utc_now_iso())
        with _EXTERNAL_IMPORT_LOCK:
            taken = self._names_already_managed(bundle['names'])
            if taken:
                raise CertificateNamesTaken(taken)
            with self._certs.domain_lock(normalized):
                warning = self._certs.store_imported_certificate(normalized, bundle['files'], metadata)
                try:
                    if not self._settings.update(_add_external_entry(normalized), 'certificate_imported'):
                        raise RuntimeError('Registration was not saved')
                except (OSError, RuntimeError):
                    # The files stay, as for any import, and their metadata
                    # marks them external, so nothing renews them meanwhile.
                    self._audit_emit(audit_ctx, 'import', normalized, 'failure',
                                     error='Certificate stored but registration failed')
                    raise RuntimeError('Certificate imported, but registering it in settings failed. '
                                       'The certificate files are preserved and marked external, '
                                       'so nothing renews them.') from None
        self._audit_emit(audit_ctx, 'import', normalized, 'success', details={
            'external': True, 'san_count': len(san_domains)})
        self._publish('certificate_created', {
            'domain': normalized, 'san_domains': san_domains, 'dns_provider': None,
            'ca_provider': None, 'imported': True, 'external': True})
        return {'success': True, 'domain': normalized, 'san_domains': san_domains,
                'external': True, 'storage_warning': warning}

    def replace_external(self, *, domain, certificate, chain, private_key,
                         allow_earlier_expiry=False, user=None, ip_address=None, audit_ctx=None):
        """Put an uploaded bundle in place of the external certificate *domain*.

        What a renewal is for a certificate a CA renews, done by its owner: the
        same certificate, by name, with a new certificate and key, announced as
        a renewal so deploy hooks ship it. The bundle is checked as an external
        import is, and must still name *domain*: the name is the certificate's
        identity. Its other names may change, and one another certificate
        covers refuses it, as for an import.

        Two refusals guard against uploading the wrong file: the certificate
        already in place, and one that expires before it, unless
        *allow_earlier_expiry* says that is meant. A certificate that is not
        external is refused: its CA renews it, and an upload would put it out
        of step with what the CA issued.
        """
        if not isinstance(allow_earlier_expiry, bool):
            raise ValueError('allow_earlier_expiry must be a boolean')
        self._enforce_certificate_scope(domain, 'replace', user, ip_address)
        # Asked first, so a name with no certificate is not found whatever the
        # upload; asked again under the lock, where it counts.
        if not self._certs.has_certificate(domain):
            raise FileNotFoundError(f'No certificate found for domain: {domain}')
        try:
            bundle = validate_import_bundle(certificate, chain, private_key)
            bundle.update(validate_external_identity(bundle))
        except CertificateImportError:
            raise
        except (ValueError, x509.DuplicateExtension, UnsupportedAlgorithm):
            raise CertificateImportError(INVALID_IMPORT_BUNDLE) from None
        key = _name_key(domain)
        if key not in {_name_key(name) for name in bundle['names']}:
            raise ValueError(f'The uploaded certificate does not name {domain}, so it cannot replace it')
        san_domains = [name for name in bundle['names'] if _name_key(name) != key]
        for name in san_domains:
            self._enforce_scope(name, 'replace_san', user, ip_address)
        fingerprint = bundle['certificate'].fingerprint(hashes.SHA256()).hex()
        replaced_at = utc_now_iso()
        # Every key field is named, so a new key of another type leaves no
        # field of the previous one behind.
        owned = _external_metadata(domain, san_domains)
        owned.update({'key_type': None, 'key_size': None, 'elliptic_curve': None},
                     **bundle['key_options'], replaced_at=replaced_at)
        with _EXTERNAL_IMPORT_LOCK:
            with self._certs.domain_lock(domain):
                current = self._certs.served_certificate(domain)
                if not self._certs.is_external(domain):
                    raise ReplacementRefused(ReplacementRefused.NOT_EXTERNAL, domain)
                taken = self._names_already_managed(bundle['names'], owner=domain)
                if taken:
                    raise CertificateNamesTaken(taken)
                previous = None
                if current is not None:
                    # An unreadable served certificate is no reason to keep it:
                    # the upload is how it gets repaired, so only a readable one
                    # is compared.
                    previous = current.fingerprint(hashes.SHA256()).hex()
                    if previous == fingerprint:
                        raise ReplacementRefused(ReplacementRefused.UNCHANGED, domain)
                    if (bundle['certificate'].not_valid_after_utc < current.not_valid_after_utc
                            and not allow_earlier_expiry):
                        raise ReplacementRefused(ReplacementRefused.EXPIRES_EARLIER, domain)
                # A metadata file that was lost comes back whole.
                recorded = self._certs._load_metadata(domain)
                for field, value in (('imported_at', replaced_at), ('created_at', bundle['created_at'])):
                    if not recorded.get(field):
                        owned[field] = value
                warning = self._certs.replace_external_certificate(domain, bundle['files'], owned)
                self._register_external(domain)
        self._audit_emit(audit_ctx, 'replace', domain, 'success', details={
            'external': True, 'san_count': len(san_domains),
            'previous_fingerprint': previous, 'fingerprint': fingerprint})
        # A renewal to everything that listens: deploy hooks run with
        # CERTMATE_EVENT=renewed and the cached reads are dropped.
        self._publish('certificate_renewed', {
            'domain': domain, 'san_domains': san_domains, 'replaced': True, 'external': True})
        return {'success': True, 'domain': domain, 'san_domains': san_domains,
                'replaced_at': replaced_at, 'storage_warning': warning}

    def _register_external(self, domain):
        """Restore the settings entry's marker when it was lost, and write
        nothing when it is there. Best effort: the metadata carries the same
        marker, and either one keeps every issuing path off the certificate."""
        domains = self._settings.load_settings().get('domains') or []
        if any(entry_domain(raw) == domain and entry_external(raw) for raw in domains):
            return
        try:
            if self._settings.update(_add_external_entry(domain), 'certificate_replaced'):
                return
        except (OSError, RuntimeError):
            pass
        logger.error("Replaced %s, but its settings entry could not be restored; "
                     "its metadata still marks it external", _scrub_log(domain))

    def external_conflict(self, domain, san_domains=()):
        """Why CertMate must not issue a certificate for these names, or None:
        the domain is an external certificate, or one of the names is covered
        by one (#1159). Said rather than raised, for an adoption plan, which is
        shown before anything is asked. A name that is not a domain is left to
        the checks that refuse it.
        """
        ok, normalized = validate_domain(domain) if isinstance(domain, str) else (False, None)
        if not ok:
            return None
        try:
            self._certs.refuse_external(normalized)
            self._refuse_external_names([normalized, *san_domains])
        except (ExternalCertificate, CertificateNamesTaken) as refusal:
            return str(refusal)
        return None

    def _refuse_external_names(self, names, owner=None):
        """Refuse a certificate CertMate would issue that names what an
        external certificate covers (#1159).

        The other half of the import's rule: an external certificate takes no
        name a managed one covers, and a create, reissue, adoption or import
        through a CA takes none an external one covers. Names compare as they
        do for the import, a wildcard only with the same wildcard. Only
        external certificates count: two certificates CertMate issues may share
        a name today (#854). *owner* is the certificate being reissued.

        Not under the import lock: an issuance is long, and holding the lock
        across it would stop every import for its duration. An external import
        and a create of the same name started together can both pass; #854's
        name reservation is what closes that.
        """
        wanted = {_name_key(n): n for n in names if isinstance(n, str) and n.strip()}
        settings = self._settings.load_settings()
        taken = []
        for source in collect_domain_sources(settings, self._certs.cert_dir).values():
            if source.domain == owner or not self._certs.is_external(source.domain, settings=settings):
                continue
            covered = [source.domain]
            if source.on_disk:
                try:
                    covered = self._certs.names_covered(source.domain)
                except CertificateNamesUnknown:
                    # Its own name is still its own. Refusing every create
                    # until it is readable would stop all issuance for one
                    # unreadable file.
                    logger.warning("The names covered by external certificate %s could not be read; "
                                   "only its own name is protected", _scrub_log(source.domain))
            for name in covered:
                key = _name_key(name)
                if key in wanted and wanted[key] not in taken:
                    taken.append(wanted[key])
        if taken:
            raise CertificateNamesTaken(taken)

    def _names_already_managed(self, names, owner=None):
        """The import's names a managed certificate already covers.

        Exact names, compared without case or a trailing dot. A wildcard
        conflicts only with the same wildcard: a wildcard and a name it matches
        are two certificates today, and #854 keeps that possible. A registered
        name with nothing on disk covers only itself, since settings record no
        SANs. A certificate whose names cannot be read refuses the import
        rather than letting it through on the names that could be read.
        *owner* is the certificate a replacement replaces: its own names are
        not taken from it.
        """
        wanted = {_name_key(n): n for n in names}
        settings = self._settings.load_settings()
        taken = []
        for source in collect_domain_sources(settings, self._certs.cert_dir).values():
            if owner is not None and source.domain == owner:
                continue
            if not source.on_disk:
                covered = [source.domain]
            else:
                try:
                    covered = self._certs.names_covered(source.domain)
                except CertificateNamesUnknown:
                    logger.warning("Refused an import: the names covered by %s could not be read",
                                   _scrub_log(source.domain))
                    raise CertificateNamesTaken(unknown=True) from None
            for name in covered:
                key = _name_key(name)
                if key in wanted and wanted[key] not in taken:
                    taken.append(wanted[key])
        return taken

    def create_batch(self, *, domains, dns_provider=None, account_id=None,
                     ca_provider=None, ca_account_id=None, challenge_type=None,
                     user=None, ip_address=None, audit_ctx=None):
        """Create a certificate per domain; register them in one write.

        Each domain goes through ``prepare_create`` and ``_issue_create``, the
        same steps as a single create: normalisation, the scope check and its
        audit record, the settings defaults, the account the caller named, the
        success/failure audit and the ``certificate_created`` event. The batch
        route used to call the manager directly and re-implement a subset of
        this, and dropped ``account_id`` on the way to issuance (#666, D9).

        One domain's failure does not stop the rest. Per-item messages are
        fixed strings, never exception text. Returns one result dict per
        non-empty entry, in order.
        """
        results, created = [], []
        # Request names, a list of strings: not the settings' domain-entry
        # union, which only domain_entries.py decodes.
        for requested in domains:
            raw = requested.strip() if isinstance(requested, str) else ''
            if not raw:
                continue
            # The message a caller sees for a bad name, stated from the
            # validator rather than from an exception's text.
            ok, reason = validate_domain(raw)
            if not ok:
                results.append({'domain': raw, 'success': False,
                                'message': f'Invalid domain: {reason}'})
                continue
            try:
                prepared = self.prepare_create(
                    domain=raw, dns_provider=dns_provider, account_id=account_id,
                    ca_provider=ca_provider, ca_account_id=ca_account_id,
                    challenge_type=challenge_type, user=user,
                    ip_address=ip_address, audit_ctx=audit_ctx)
            except DomainOutOfScope:
                results.append({'domain': reason, 'success': False,
                                'message': 'API key not authorized for this domain'})
                continue
            except (CertificateNamesTaken, ExternalCertificate):
                results.append({'domain': reason, 'success': False,
                                'message': 'A name is covered by an external certificate'})
                continue
            except ValueError as e:
                logger.info("Batch create rejected %s: %s", _scrub_log(reason), e)
                results.append({'domain': reason, 'success': False,
                                'message': 'Invalid certificate request'})
                continue
            try:
                self._issue_create(prepared, register=False)
            except Exception as e:
                logger.warning("Batch create failed for %s: %s", _scrub_log(reason),
                               str(e).replace('\n', ' ').replace('\r', ' '))
                results.append({'domain': reason, 'success': False,
                                'message': 'Certificate creation failed'})
                continue
            created.append(prepared)
            results.append({'domain': reason, 'success': True,
                            'message': 'Certificate created'})

        if created:
            mutators = [_add_domain_entry(p) for p in created]

            def _register_all(s):
                for add in mutators:
                    add(s)

            try:
                self._settings.update(_register_all, 'certificate_created')
            except Exception as e:
                # The certificates exist; losing the tracking would drop them
                # out of the renewal loop in silence. Said loudly instead.
                logger.error(
                    "Batch certificates created but registering them for renewal "
                    "failed (%d domains may not auto-renew): %s", len(created), e)
        return results


    # ------------------------------------------------------------------
    # Configuration, as opposed to issuance
    # ------------------------------------------------------------------

    def read_metadata(self, domain):
        """The certificate's stored metadata, or ``{}``.

        A public read (#672). Route handlers were calling
        ``certificate_manager._load_metadata`` — a private method — which meant
        the manager could not change how it stores metadata without breaking
        them. Reading through the manager still matters, though, and this keeps
        that: it builds the path from the validated domain and quarantines
        corrupt JSON rather than silently returning ``{}``.
        """
        return self._certs._load_metadata(domain) or {}

    def update_config(self, domain, changes):
        """Apply a configuration change to a certificate's metadata.

        Takes the raw change set — not keyword arguments — because the
        semantics depend on a key being ABSENT versus present-and-null: an
        absent key leaves existing config alone, an explicit ``None`` deletes
        it. Keyword defaults cannot express that, and getting it wrong lets a
        DNS-only edit silently wipe a certificate's probe configuration.

        Validation lives here rather than in the route so both HTTP layers get
        the same answer, and raises :class:`ValueError` with the message the
        caller should surface.

        Returns ``(metadata, old_dns_provider)``.
        """
        # The whole read-modify-write happens under the domain lock, so an
        # in-flight renewal — which carries a pre-renewal metadata snapshot
        # across its entire certbot run — cannot clobber this write.
        with self._certs.domain_lock(domain):
            metadata = self.read_metadata(domain)
            old_dns_provider = metadata.get('dns_provider')

            for key in ('dns_provider', 'account_id', 'alias_dns_provider'):
                value = changes.get(key)
                if value:
                    metadata[key] = value

            if 'deployment_port' in changes:
                port = changes['deployment_port']
                if port is None:
                    metadata.pop('deployment_port', None)
                else:
                    try:
                        port = int(port)
                    except (TypeError, ValueError):
                        raise ValueError('deployment_port must be an integer')
                    if port < 1 or port > 65535:
                        raise ValueError('deployment_port must be 1-65535')
                    metadata['deployment_port'] = port

            if 'deployment_protocol' in changes:
                protocol = changes['deployment_protocol']
                if protocol is None:
                    metadata.pop('deployment_protocol', None)
                elif protocol not in PROBE_PROTOCOLS:
                    raise ValueError(
                        f"deployment_protocol must be one of {PROBE_PROTOCOLS!r}")
                else:
                    metadata['deployment_protocol'] = protocol

            if 'deployment_host' in changes:
                host = changes['deployment_host']
                if host is None:
                    metadata.pop('deployment_host', None)
                else:
                    if not isinstance(host, str):
                        raise ValueError('deployment_host must be a string')
                    host = host.strip()
                    # A probe target is a bare hostname: no scheme, no path, no
                    # whitespace, and no wildcard label — you deploy a
                    # certificate on a concrete name, not on "*.".
                    if (not host or len(host) > 253 or host.startswith('*.')
                            or any(c in host for c in ' \t/\\')
                            or '://' in host):
                        raise ValueError(
                            'deployment_host must be a bare hostname '
                            '(no scheme, path, whitespace, or wildcard)')
                    metadata['deployment_host'] = host

            # Notes and tags (#1043), under the same absent-versus-null rule as
            # the probe keys: absent leaves them alone, null (or an empty note
            # or list) removes them. They are validated in cert_labels, which the
            # deploy-hook path also reads from, so the two cannot disagree on
            # what a tag is.
            if 'notes' in changes:
                notes = changes['notes']
                notes = normalize_notes(notes) if notes is not None else ''
                if notes:
                    metadata['notes'] = notes
                else:
                    metadata.pop('notes', None)

            if 'tags' in changes:
                tags = changes['tags']
                tags = normalize_tags(tags) if tags is not None else []
                if tags:
                    metadata['tags'] = tags
                else:
                    metadata.pop('tags', None)

            # write_metadata, not _save_metadata: this is the one call site
            # whose outcome reaches a person, and the boolean threw the reason
            # away. "Failed to update metadata for domain: X" was produced by
            # a read-only volume and by a deliberate schema-downgrade refusal
            # alike, naming neither and suggesting nothing (#757). The
            # exceptions it raises are RuntimeError subclasses, so the route's
            # existing arm keeps handling them; it just has something to say
            # now.
            self._certs.write_metadata(domain, metadata)

            # The settings entry is written HERE, inside the same domain lock,
            # rather than by the caller afterwards.
            #
            # A domain's DNS provider is authoritative in two files: this
            # certificate's metadata.json, which issuance reads, and the
            # domain's entry in settings.json, which get_domain_dns_provider
            # reads. They were updated by two separate writes with the lock
            # released between them, and nothing reconciled them — so a
            # renewal starting in that window read the OLD provider from
            # settings while the metadata already said the new one, and
            # neither file was wrong on its own.
            #
            # Lock ordering: this takes the settings lock while holding the
            # domain lock. Checked before doing it — no settings mutate
            # callback anywhere acquires a domain lock, so the reverse order
            # does not exist and this cannot deadlock. Anything that adds one
            # would have to take the domain lock first.
            #
            # Only when a DNS field actually changed. Every settings save takes
            # a backup and counts against retention, so a note or a tag edit,
            # which has nothing to mirror, must not write settings.json at all:
            # tagging fifty certificates would otherwise leave fifty backups
            # named for a DNS provider change that never happened.
            if changes.get('dns_provider') or changes.get('account_id'):
                self._settings.update(
                    lambda s: self._write_domain_provider(s, domain, changes),
                    'dns_provider_change')

        return metadata, old_dns_provider

    @staticmethod
    def _write_domain_provider(settings, domain, changes):
        """Mirror the DNS provider onto the domain's settings entry.

        Only the keys the caller actually sent: an absent one means "leave
        alone", the same rule the metadata write above follows, so a probe-only
        edit does not touch the provider.
        """
        for entry in settings.get('domains', []):
            if isinstance(entry, dict) and entry.get('domain') == domain:
                if changes.get('dns_provider'):
                    entry['dns_provider'] = changes['dns_provider']
                if changes.get('account_id'):
                    entry['dns_account_id'] = changes['account_id']
                break

    def _check_csr(self, csr_pem, domain, *, san_domains, key_type, key_size,
                   elliptic_curve, scope_action, user, ip_address):
        """Everything that must be true of a CSR before anything happens.

        One copy, used by create and by reissue. A CSR is signed over its own
        subject and SANs and carries its own public key, so a request that
        also names SANs or a key shape is asking for something the CA will not
        deliver: it is refused rather than silently ignored, because the
        certificate would come back different from what was asked for with
        nothing to say why (#599).

        Extracted when reissue learned to take one (#876 item 6). Copying it
        would have meant two versions of a scope check, and the second copy is
        the one that stops being updated.
        """
        if not isinstance(csr_pem, (str, bytes)):
            raise ValueError('Invalid CSR: expected PEM text')
        if len(csr_pem) > MAX_CSR_BYTES:
            # Without this the limit on a CSR was the global body limit. A PEM
            # CSR for a 4096-bit key with a hundred names is a few kilobytes;
            # the bound is generous by two orders of magnitude and still says
            # no long before anything reaches the parser.
            raise ValueError(
                f'CSR too large: {len(csr_pem)} bytes. A certificate '
                f'request PEM is at most {MAX_CSR_BYTES} bytes.')
        if san_domains:
            raise ValueError(
                'san_domains cannot be combined with a CSR: the '
                'certificate covers the names inside the CSR')
        if key_type is not None or key_size is not None \
                or elliptic_curve is not None:
            raise ValueError(
                'key options cannot be combined with a CSR: the key was '
                'generated by the device that produced it')
        try:
            csr_names = csr_domains(read_csr(csr_pem))
        except CSRError as e:
            raise ValueError(f'Invalid CSR: {e}')
        # Scope-checked before any side effect, for the same reason the SANs
        # are: a CSR covering another tenant's name must not reach issuance
        # because the primary domain happened to be allowed.
        for name in csr_names:
            if name != domain:
                self._enforce_scope(name, scope_action, user, ip_address)
        return csr_names

    def keyless_domains(self, user=None):
        """The certificates whose lineage lost every private key (#966).

        The same test the renewal path uses to answer REISSUE_REQUIRED, so
        "what needs reissuing" and "what renewal refuses" cannot disagree.
        Filtered to the caller's scope before anything is attempted, so a
        scoped key neither sees nor probes another tenant's domains.
        """
        from .certificates import CertificateManager
        from .constants import iter_cert_domain_dirs

        scope = (user or {}).get('allowed_domains')
        found = []
        for domain_dir in iter_cert_domain_dirs(self._certs.cert_dir):
            domain = domain_dir.name
            if not self._auth.domain_matches_scope(domain, scope):
                continue
            if scope is not None and not self._certs.every_name_matches(
                    domain, lambda name: self._auth.domain_matches_scope(name, scope)):
                continue
            if CertificateManager._lineage_lost_its_key(domain_dir, domain):
                found.append(domain)
        return sorted(found)

    def prepare_reissue(self, *, domain, san_domains=None, dns_provider=None,
                        account_id=None, ca_provider=None, challenge_type=None,
                        domain_alias=None, alias_dns_provider=None,
                        key_type=None, key_size=None,
                        elliptic_curve=None, user=None, ip_address=None,
                        audit_ctx=None, csr_pem=None, acme_profile=None):
        """Validate and resolve an edit-and-reissue request (#267) without
        side effects, returning kwargs for :meth:`issue_reissue`.

        Field semantics: ``None`` means "keep the current value from the
        certificate's metadata" (so DNS-alias users never re-enter config);
        an explicit value overrides; for ``domain_alias`` an empty string
        clears the alias. ``san_domains=None`` keeps the current SAN set,
        ``[]`` drops every SAN. Key options are intentionally NOT inherited:
        metadata does not record the key shape, and omitting the flags makes
        certbot keep the lineage's existing key (an explicit option here is
        a deliberate re-key).

        Raises ``FileNotFoundError`` when no certificate exists for *domain*
        (a reissue edits something; creation is the create endpoint's job),
        ``ValueError`` on bad input, :class:`DomainOutOfScope` on scope.
        """
        domain = (domain or '').strip()
        # Same rebind-to-normalised as prepare_create: use the bare hostname
        # validate_domain returns, not the raw string, so a URL form cannot
        # drive `cert_dir / domain` here either. The reissue path builds the
        # same paths as create and must hold the same invariant.
        ok, normalized = validate_domain(domain)
        if not ok:
            raise ValueError(f'Invalid domain: {normalized}')
        domain = normalized

        # Before looking for the certificate: a caller whose scope does not
        # cover the name is told that, whether or not a certificate exists
        # for it.
        self._enforce_scope(domain, 'reissue', user, ip_address)

        cert_file = certificate_dir(self._certs.cert_dir, domain) / 'cert.pem'
        if not cert_file.exists():
            raise FileNotFoundError(
                f'No certificate found for {domain}. Use create instead.'
            )

        metadata = self._certs._load_metadata(domain)
        # Refused before anything is resolved: with no CA recorded, the
        # resolution below would pick the default CA and reissue from it.
        self._certs.refuse_external(domain, metadata=metadata)
        dns_provider_was_named = dns_provider is not None
        dns_account_was_named = account_id is not None

        # Whether the caller NAMED a SAN set, recorded before inheritance
        # rewrites it. With a CSR the distinction is the whole thing: naming
        # SANs alongside one is refused, because the CSR already carries the
        # names — while the set this certificate happens to have today is not
        # something the caller said, and must not turn every CSR rotation on a
        # multi-name certificate into an error.
        sans_were_named = san_domains is not None
        if san_domains is None:
            san_domains = metadata.get('san_domains') or []
        if not isinstance(san_domains, list):
            raise ValueError('Invalid san_domains format')
        if dns_provider is None:
            dns_provider = metadata.get('dns_provider')
        if account_id is None:
            account_id = metadata.get('account_id')
        if ca_provider is None:
            ca_provider = metadata.get('ca_provider')
        if challenge_type is None:
            challenge_type = metadata.get('challenge_type')
        if domain_alias is None:
            domain_alias = metadata.get('domain_alias')
        elif domain_alias == '':
            domain_alias = None
        if alias_dns_provider is None:
            # The alias zone may live with a different provider than the
            # primary (set via PATCH, issue #129); the reissue must keep
            # running the alias hook with that account.
            alias_dns_provider = metadata.get('alias_dns_provider')
        if not domain_alias:
            alias_dns_provider = None

        if domain_alias:
            ok, normalized_alias = validate_domain(domain_alias)
            if not ok:
                raise ValueError(f'Invalid domain_alias: {normalized_alias}')
            domain_alias = normalized_alias

        # Scope covers the primary and the FINAL SAN set (kept + added):
        # a scoped key must not be able to keep another tenant's SAN alive
        # through inheritance any more than it could add it explicitly. And
        # every name the certificate covers today: a reissue replaces it for
        # all of them, so naming a smaller set must not drop another tenant's.
        self._enforce_certificate_scope(domain, 'reissue', user, ip_address)
        for san in san_domains:
            san_clean = san.strip() if isinstance(san, str) else ''
            if san_clean:
                self._enforce_scope(san_clean, 'reissue_san', user, ip_address)

        csr_names = None
        if csr_pem is not None:
            csr_names = self._check_csr(csr_pem, domain,
                                        san_domains=san_domains if sans_were_named else None,
                                        key_type=key_type, key_size=key_size,
                                        elliptic_curve=elliptic_curve,
                                        scope_action='reissue_san',
                                        user=user, ip_address=ip_address)
            # The CSR carries the names. Anything inherited from the previous
            # certificate would be added to what it asks for, which is not a
            # reissue of that CSR.
            san_domains = []
        self._refuse_external_names(csr_names or [domain, *san_domains], owner=domain)

        if key_type is not None or key_size is not None or elliptic_curve is not None:
            ok, key_err = validate_key_options(key_type, key_size, elliptic_curve)
            if not ok:
                raise ValueError(key_err)
        acme_profile = _checked_profile(acme_profile)

        settings = self._settings.load_settings()
        if not ca_provider:
            ca_provider = settings.get('default_ca', 'letsencrypt')
        ca_account_id = metadata.get('ca_account_id') if ca_provider == metadata.get('ca_provider') else None
        email = self.resolve_ca_email(settings, ca_provider, ca_account_id)
        if not challenge_type:
            challenge_type = settings.get('challenge_type', 'dns-01')
        if challenge_type == 'prevalidated':
            if ca_provider != 'sectigo':
                raise ValueError('Prevalidated ACME is available only for Sectigo')
            if (dns_provider_was_named and dns_provider) or (dns_account_was_named and account_id) or domain_alias:
                raise ValueError('Prevalidated ACME does not use DNS providers, accounts or aliases')
            dns_provider = None
            account_id = None
        if challenge_type not in ('http-01', 'prevalidated') and not dns_provider:
            dns_provider = settings.get('dns_provider')
            if not dns_provider:
                raise ValueError('No DNS provider specified')

        return {
            'domain': domain,
            'email': email,
            'dns_provider': dns_provider,
            'account_id': account_id,
            'ca_provider': ca_provider,
            'ca_account_id': ca_account_id,
            'domain_alias': domain_alias,
            'alias_dns_provider': alias_dns_provider,
            'san_domains': san_domains,
            'challenge_type': challenge_type,
            'key_type': key_type,
            'key_size': key_size,
            'elliptic_curve': elliptic_curve,
            'acme_profile': acme_profile,
            'csr_pem': csr_pem,
            '_settings_dns_provider': settings.get('dns_provider'),
            '_audit_ctx': audit_ctx,
        }

    def resolve_ca_email(self, settings, ca_provider, ca_account_id):
        """Return the issuance email, or refuse the missing CA/email before work starts."""
        email = settings.get('email')
        ca_config, _ = resolve_ca_account(self._certs.ca_manager, ca_provider, ca_account_id, settings=settings)
        email = (ca_config or {}).get('email') or email
        if not email:
            raise EmailNotConfigured('Email not configured')
        return email

    def issue_reissue(self, prepared):
        """Blocking half of edit-and-reissue: certbot re-runs over the
        existing lineage (``replace=True``) and the commit pipeline rewrites
        files/metadata/storage. The old certificate keeps being served until
        certbot succeeds. Raises ``DomainOperationInProgress`` (409) or
        ``RuntimeError`` (certbot failure).
        """
        domain = prepared['domain']
        audit_ctx = prepared.get('_audit_ctx')
        try:
            result = self._certs.create_certificate(
                domain=domain,
                email=prepared['email'],
                dns_provider=prepared['dns_provider'],
                account_id=prepared['account_id'],
                ca_provider=prepared['ca_provider'],
                ca_account_id=prepared.get('ca_account_id'),
                domain_alias=prepared['domain_alias'],
                alias_dns_provider=prepared['alias_dns_provider'],
                san_domains=prepared['san_domains'],
                challenge_type=prepared['challenge_type'],
                key_type=prepared['key_type'],
                key_size=prepared['key_size'],
                elliptic_curve=prepared['elliptic_curve'],
                csr_pem=prepared.get('csr_pem'),
                acme_profile=prepared.get('acme_profile'),
                replace=True,
            )

            # Idempotent: repairs the settings entry if it ever went missing.
            resolved_dns_provider = (None if prepared['challenge_type'] == 'prevalidated' else
                                     prepared['dns_provider'] or prepared['_settings_dns_provider'])
            self._settings.update(
                _make_add_domain(domain, resolved_dns_provider, prepared['account_id']),
                'certificate_reissued',
            )
        except Exception as e:
            self._audit_emit(audit_ctx, 'reissue', domain, 'failure', error=e)
            # The same rule as issue_renew: a busy domain is a queue and a
            # missing certificate is a 404, neither pages anyone. Published
            # HERE and nowhere else: the sync route and the async executor
            # each kept their own copy, which is how create and renew came to
            # announce themselves twice (tests/test_one_issuance_one_event.py).
            from .certificates import DomainOperationInProgress
            if not isinstance(e, (DomainOperationInProgress, FileNotFoundError)):
                self._publish('certificate_failed',
                              {'domain': domain, 'error': str(e)})
            raise
        self._audit_emit(audit_ctx, 'reissue', domain, 'success', details={
            'ca_provider': prepared.get('ca_provider'),
            'challenge_type': prepared.get('challenge_type'),
            'san_count': len(prepared.get('san_domains') or []),
        })
        # A reissue refreshes the domain's certificate: consumers (deploy
        # hooks, notifications) react exactly as they do for a renewal.
        self._publish('certificate_renewed', {'domain': domain})
        return result

    def renew(self, *, domain, force=False, user=None, ip_address=None, audit_ctx=None):
        """Scope-check then renew an existing certificate, returning the
        manager's result dict. Path/sanitisation of *domain* is the adapter's
        responsibility (it owns ``cert_dir`` resolution); here we enforce scope
        and delegate. Raises :class:`DomainOutOfScope` (403),
        ``DomainOperationInProgress`` (409) or ``RuntimeError``.

        Equivalent to ``issue_renew(prepare_renew(...), force=force)``; split so
        async callers can authorize synchronously and defer the certbot call.
        """
        return self.issue_renew(
            self.prepare_renew(domain=domain, user=user, ip_address=ip_address,
                               audit_ctx=audit_ctx),
            force=force,
        )

    def prepare_renew(self, *, domain, user=None, ip_address=None, audit_ctx=None):
        """Authorize a renew request (scope check) with no side effects.
        Raises :class:`DomainOutOfScope`. Returns the resolved kwargs for
        :meth:`issue_renew`.
        """
        self._enforce_certificate_scope(domain, 'renew', user, ip_address)
        # Here as well as in the manager, so an async request is refused at
        # once instead of answering 202 and failing in the job.
        self._certs.refuse_external(domain)
        return {'domain': domain, '_audit_ctx': audit_ctx}

    def issue_renew(self, prepared, *, force=False):
        """Run the (blocking, deferrable) certbot renewal for a prepared renew
        request. Raises ``DomainOperationInProgress`` (409) or ``RuntimeError``.
        """
        domain = prepared['domain']
        audit_ctx = prepared.get('_audit_ctx')
        started = time.monotonic()
        try:
            result = self._certs.renew_certificate(domain, force=force)
        except Exception as e:
            self._audit_emit(audit_ctx, 'renew', domain, 'failure', error=e)
            # Not every refusal is a certificate failure. A busy domain is
            # "try again in a minute" and a missing certificate is a 404 —
            # publishing `certificate_failed` for either would page someone
            # for a queue. Only what the CA or the configuration refused,
            # and what broke inside CertMate, is an event.
            from .certificates import DomainOperationInProgress, ReissueRequired
            if not isinstance(e, (DomainOperationInProgress, FileNotFoundError)):
                self._publish('certificate_failed',
                              {'domain': domain, 'error': str(e)})
            # The metric follows the sweep's rule: a certificate that needs a
            # reissue did not fail to renew, renewal was never the remedy.
            if not isinstance(e, (DomainOperationInProgress, FileNotFoundError,
                                  ReissueRequired)):
                self._record_renewal(domain, False, started, e)
            raise
        self._audit_emit(audit_ctx, 'renew', domain, 'success',
                         details={'force': bool(force)})
        # renewed=False is certbot's "not yet due" no-op: nothing was
        # replaced, so deploy hooks must not fire. Default True keeps the
        # behaviour for older manager results without the flag.
        if bool(result.get('renewed', True)):
            self._publish('certificate_renewed', {'domain': domain})
            self._record_renewal(domain, True, started)
        # The renew answer has always carried `duration`, and create's has a value for it; only
        # renew's was null (#1108). The same clock `_record_renewal` reads.
        result.setdefault('duration', time.monotonic() - started)
        return result

    def _record_renewal(self, domain, success, started, error=None):
        """Feed the renewal metrics for a renewal run on request (#666 D7).

        They were fed by the nightly sweep only, so a renewal an operator ran
        by hand, including the one the CA refused for a rate limit, left no
        trace in Prometheus. The sweep calls the manager directly and records
        its own, so nothing is counted twice.
        """
        # Telemetry must not turn a renewal that happened into an error: the
        # metadata read is the one step here that can raise (the recorder
        # swallows its own), and without it the label is 'unknown'.
        try:
            metadata = self._certs._load_metadata(domain) or {}
        except OSError:
            metadata = {}
        self._certs._record_renewal_metrics(
            domain, metadata, success, time.monotonic() - started, error=error)


def _primary_name(names, requested):
    """The import's primary name: the one requested, normalised, which must be
    one of the certificate's DNS names; the first of them when none is asked for."""
    if requested is None or requested == '':
        requested = names[0]
    if not isinstance(requested, str):
        raise ValueError('Domain is required')
    ok, normalized = validate_domain(requested.strip())
    if not ok or normalized not in names:
        raise ValueError('Primary domain must be one of the certificate DNS names')
    return normalized


def _name_key(name):
    """A DNS name as compared for a collision: no case, no trailing dot."""
    return name.strip().rstrip('.').casefold()


def _external_metadata(domain, san_domains):
    """What the metadata of an external certificate says about it: the
    marker, and nothing that names a CA. A missing CA means "the default CA"
    on every issuing path, which is why CertificateManager also refuses on the
    settings entry's marker."""
    return {'domain': domain, 'san_domains': san_domains, 'external': True,
            'email': None, 'ca_provider': None, 'ca_account_id': None,
            'challenge_type': None, 'dns_provider': None, 'account_id': None,
            'domain_alias': None, 'alias_dns_provider': None, 'acme_profile': None,
            'auto_renew': False}


def _add_external_entry(domain):
    """The settings entry of an external certificate, as one mutator.

    No DNS provider, since none validates it; auto-renew off; and the marker,
    which together with the certificate's metadata keeps every issuing path
    off it (see CertificateManager.is_external).
    """
    entry = {'domain': domain, 'dns_provider': None, 'dns_account_id': None,
             'auto_renew': False, 'external': True}

    def _add(settings):
        domains_list = settings.get('domains', []) or []
        for index, existing in enumerate(domains_list):
            if entry_domain(existing) == domain:
                domains_list[index] = {**normalize_entry(existing), **entry}
                break
        else:
            domains_list.append(dict(entry))
        settings['domains'] = domains_list

    return _add


def _add_domain_entry(prepared):
    """The settings entry a prepared create registers, as one mutator."""
    return _make_add_domain(
        prepared['domain'],
        (None if prepared['challenge_type'] == 'prevalidated' else
         prepared['dns_provider'] or prepared['_settings_dns_provider']),
        prepared['account_id'], auto_renew=prepared.get('auto_renew'))


def _make_add_domain(domain, dns_provider, account_id, *, auto_renew=None):
    """Build the idempotent ``settings_manager.update`` mutator that appends
    *domain* to the tracked domains list unless it is already present."""

    def _add_domain(s):
        domains_list = s.get('domains', []) or []
        for index, entry in enumerate(domains_list):
            if entry_domain(entry) == domain:
                if auto_renew is not None:
                    domains_list[index] = {**normalize_entry(entry), 'auto_renew': auto_renew}
                return
        domains_list.append({
            'domain': domain,
            'dns_provider': dns_provider,
            'dns_account_id': account_id,
        })
        if auto_renew is not None:
            domains_list[-1]['auto_renew'] = auto_renew
        s['domains'] = domains_list

    return _add_domain
