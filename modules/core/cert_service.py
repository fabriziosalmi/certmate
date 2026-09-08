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

from .structured_logging import scrub_log_value
from .constants import PROBE_PROTOCOLS
from .csr_issuance import CSRError, csr_domains, read_csr
from .utils import validate_domain, validate_key_options

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
            _scrub_log(user.get('username')), operation,
            _scrub_log(domain), _scrub_log(user.get('allowed_domains')),
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
               account_id=None, ca_provider=None, challenge_type=None,
               domain_alias=None, key_type=None, key_size=None,
               elliptic_curve=None, user=None, ip_address=None, audit_ctx=None,
               csr_pem=None):
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
        """
        return self.issue_create(self.prepare_create(
            domain=domain, san_domains=san_domains, dns_provider=dns_provider,
            account_id=account_id, ca_provider=ca_provider,
            challenge_type=challenge_type, domain_alias=domain_alias,
            key_type=key_type, key_size=key_size, elliptic_curve=elliptic_curve,
            user=user, ip_address=ip_address, audit_ctx=audit_ctx,
            csr_pem=csr_pem,
        ))

    def prepare_create(self, *, domain, san_domains=None, dns_provider=None,
                        account_id=None, ca_provider=None, challenge_type=None,
                        domain_alias=None, key_type=None, key_size=None,
                        elliptic_curve=None, user=None, ip_address=None,
                        audit_ctx=None, csr_pem=None):
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
        if csr_pem is not None:
            if not isinstance(csr_pem, (str, bytes)):
                raise ValueError('Invalid CSR: expected PEM text')
            if len(csr_pem) > MAX_CSR_BYTES:
                # Same reasoning as the SAN bound above: without this, the
                # limit on a CSR was the global body limit. A PEM CSR for a
                # 4096-bit key with a hundred names is a few kilobytes; the
                # bound is generous by two orders of magnitude and still says
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
            # Scope-checked here, before any side effect, for the same reason
            # the SANs above are: a CSR covering another tenant's name must not
            # reach issuance because the primary domain happened to be allowed.
            for name in csr_names:
                if name != domain:
                    self._enforce_scope(name, 'create_san', user, ip_address)

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
        domain = prepared['domain']
        audit_ctx = prepared.get('_audit_ctx')
        try:
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
                csr_pem=prepared.get('csr_pem'),
            )

            # Append the new domain under the settings manager's lock so two
            # parallel creates for different domains cannot race and drop an entry.
            resolved_dns_provider = prepared['dns_provider'] or prepared['_settings_dns_provider']
            self._settings.update(
                _make_add_domain(domain, resolved_dns_provider, prepared['account_id']),
                'certificate_created',
            )
        except Exception as e:
            self._audit_emit(audit_ctx, 'create', domain, 'failure', error=e)
            raise
        logger.info("Ensured domain %s is in settings after certificate creation", _scrub_log(domain))
        self._audit_emit(audit_ctx, 'create', domain, 'success', details={
            'ca_provider': prepared.get('ca_provider'),
            'challenge_type': prepared.get('challenge_type'),
            'san_count': len(prepared.get('san_domains') or []),
        })
        return result


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

    def prepare_reissue(self, *, domain, san_domains=None, dns_provider=None,
                        account_id=None, ca_provider=None, challenge_type=None,
                        domain_alias=None, alias_dns_provider=None,
                        key_type=None, key_size=None,
                        elliptic_curve=None, user=None, ip_address=None,
                        audit_ctx=None):
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

        cert_file = self._certs.cert_dir / domain / 'cert.pem'
        if not cert_file.exists():
            raise FileNotFoundError(
                f'No certificate found for {domain}. Use create instead.'
            )

        metadata = self._certs._load_metadata(domain)

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
        # through inheritance any more than it could add it explicitly.
        self._enforce_scope(domain, 'reissue', user, ip_address)
        for san in san_domains:
            san_clean = san.strip() if isinstance(san, str) else ''
            if san_clean:
                self._enforce_scope(san_clean, 'reissue_san', user, ip_address)

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
            'alias_dns_provider': alias_dns_provider,
            'san_domains': san_domains,
            'challenge_type': challenge_type,
            'key_type': key_type,
            'key_size': key_size,
            'elliptic_curve': elliptic_curve,
            '_settings_dns_provider': settings.get('dns_provider'),
            '_audit_ctx': audit_ctx,
        }

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
                domain_alias=prepared['domain_alias'],
                alias_dns_provider=prepared['alias_dns_provider'],
                san_domains=prepared['san_domains'],
                challenge_type=prepared['challenge_type'],
                key_type=prepared['key_type'],
                key_size=prepared['key_size'],
                elliptic_curve=prepared['elliptic_curve'],
                replace=True,
            )

            # Idempotent: repairs the settings entry if it ever went missing.
            resolved_dns_provider = prepared['dns_provider'] or prepared['_settings_dns_provider']
            self._settings.update(
                _make_add_domain(domain, resolved_dns_provider, prepared['account_id']),
                'certificate_reissued',
            )
        except Exception as e:
            self._audit_emit(audit_ctx, 'reissue', domain, 'failure', error=e)
            raise
        self._audit_emit(audit_ctx, 'reissue', domain, 'success', details={
            'ca_provider': prepared.get('ca_provider'),
            'challenge_type': prepared.get('challenge_type'),
            'san_count': len(prepared.get('san_domains') or []),
        })
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
        self._enforce_scope(domain, 'renew', user, ip_address)
        return {'domain': domain, '_audit_ctx': audit_ctx}

    def issue_renew(self, prepared, *, force=False):
        """Run the (blocking, deferrable) certbot renewal for a prepared renew
        request. Raises ``DomainOperationInProgress`` (409) or ``RuntimeError``.
        """
        domain = prepared['domain']
        audit_ctx = prepared.get('_audit_ctx')
        try:
            result = self._certs.renew_certificate(domain, force=force)
        except Exception as e:
            self._audit_emit(audit_ctx, 'renew', domain, 'failure', error=e)
            raise
        self._audit_emit(audit_ctx, 'renew', domain, 'success',
                         details={'force': bool(force)})
        return result


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
