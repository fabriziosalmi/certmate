"""Certificate storage backends: inspection, configuration, migration.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as an
explicit `ApiContext`, which is what makes them importable — and therefore
testable — without constructing the whole manager graph.
"""
from functools import wraps
from pathlib import Path

from flask import request
from flask_restx import Resource

import logging

from .resource_context import ApiContext, instance_wide

logger = logging.getLogger(__name__)


def _local_dir(ctx, config):
    """Where a local_filesystem backend built here should write.

    Asks the storage manager, which is where the rule lives, rather than
    re-deriving `Path(config.get('cert_dir', 'certificates'))` — the relative
    path that #895 removed from the manager and left in three places here. A
    migrate that reads `./certificates` while issuance writes to the volume
    copies nothing and reports success.
    """
    manager = ctx.managers.get('storage')
    if manager is not None:
        return manager.local_cert_dir(config or {})
    return Path((config or {}).get('cert_dir') or 'certificates')

def _cert_dirs(node):
    """Every cert_dir a request body names, at any depth: the settings form,
    a connection test and a migration each nest it differently."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == 'cert_dir' and isinstance(value, str):
                yield value.strip()
            else:
                yield from _cert_dirs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _cert_dirs(item)


def refuses_published_cert_dir(view):
    """400 for a request that names a local cert_dir inside the directory
    served at /static/, before the view writes, tests or migrates anything."""
    @wraps(view)
    def guarded(*args, **kwargs):
        from ..core.storage_backends import publicly_served
        for chosen in _cert_dirs(request.get_json(silent=True)):
            if chosen and publicly_served(chosen):
                return {'error': f'cert_dir {chosen!r} is inside the directory this server publishes '
                                 'at /static/ to anyone: the private keys would be downloadable there',
                        'code': 'CERT_DIR_PUBLISHED'}, 400
        return view(*args, **kwargs)
    return guarded

def _local_storage_update(data):
    """The local_filesystem part of a storage settings save.

    `cert_dir` is written only when the caller named one. Defaulting to the
    literal `'certificates'` here is how every settings.json came to carry it
    whether or not anybody chose it — which is what forces `local_cert_dir` to
    read that exact string as "unset". A caller who names nothing leaves the
    field alone and follows CERTMATE_CERT_DIR.

    Module level for the same reason as `_local_dir`: `create_storage_resources`
    is budgeted and its ceiling only comes down.
    """
    chosen = (data.get('cert_dir') or '').strip()
    return {'cert_dir': chosen} if chosen else {}

# Where each optional backend's SDK comes from (docs/storage.md, "Backends").
SDK_REQUIREMENTS = {
    'azure_keyvault': 'requirements-azure-storage.txt',
    'aws_secrets_manager': 'requirements-aws-storage.txt',
    'hashicorp_vault': 'requirements-vault-storage.txt',
    'infisical': 'requirements-infisical-storage.txt',
}


class SavedSecretWithheld(ValueError):
    """A saved secret was not used, because the request names another address for it."""


# The field naming where a backend sends its secret itself, rather than a signature over it
# (SigV4 for S3 and Secrets Manager) or to its identity provider (Azure): the Vault token goes
# to vault_url in a header, Infisical's client credentials to site_url. A saved secret is reused
# only for the address it was saved for, with that address's default when none is stored.
_SECRET_DESTINATION = {
    'hashicorp_vault': ('vault_url', None),
    'infisical': ('site_url', 'https://app.infisical.com'),
}


def _saved_storage_config(ctx, backend_type):
    """The saved configuration of *backend_type*, nested or in the legacy flat shape, or {}."""
    stored = (ctx.settings.load_settings() or {}).get('certificate_storage') if ctx.settings else None
    if not isinstance(stored, dict):
        return {}
    if isinstance(stored.get(backend_type), dict):
        return stored[backend_type]
    if stored.get('backend') == backend_type:
        # The flat shape keeps the other backends' blocks beside its own keys: not this one's.
        return {k: v for k, v in stored.items() if k != 'backend' and not isinstance(v, dict)}
    return {}


def _with_saved_secrets(ctx, backend_type, config):
    """The form's configuration over the saved one, as saving merges it (#1424).

    The settings page never sends a saved secret back to the browser, so after a reload its
    secret fields are empty, and Test Connection and Migrate built the backend from the form
    alone: both refused until the token was typed again. Saving already reads an empty or
    masked secret as "keep the stored one" (_strip_masked_values); these do the same now.
    """
    from ..core.settings import _deep_merge_dict, _is_secret_key, _strip_masked_values
    form = _strip_masked_values(dict(config)) if isinstance(config, dict) else {}
    saved = _saved_storage_config(ctx, backend_type)
    field, default = _SECRET_DESTINATION.get(backend_type, (None, None))
    if field and (form.get(field) or default) != (saved.get(field) or default):
        missing = sorted(k for k in saved if _is_secret_key(k) and saved[k] and not form.get(k))
        if missing:
            raise SavedSecretWithheld(
                f'The saved {", ".join(missing)} is only used with the {field} it was saved for. '
                f'Enter it to use {form.get(field)}.')
        return form
    return _deep_merge_dict(saved, form)


def _migration_failure_message(error):
    if isinstance(error, SavedSecretWithheld):
        return f'Migration failed: {error}'
    return f'Migration failed ({type(error).__name__}). See server logs for details.'


def _test_failure(backend_type, error):
    """The answer to a Test Connection that failed: the exception's type only, since the
    message can carry tenant ids and request ids; for a missing SDK, which file installs it,
    which carries nothing secret and is the whole answer (#1422)."""
    if isinstance(error, SavedSecretWithheld):
        message = str(error)
    elif isinstance(error, ImportError) and backend_type in SDK_REQUIREMENTS:
        message = (f'The {backend_type} backend needs a Python package this installation does '
                   f'not have. Install {SDK_REQUIREMENTS[backend_type]} (docs/storage.md, '
                   f'"Adding a backend\'s SDK").')
    else:
        message = f'Connection test failed ({type(error).__name__}). See server logs for details.'
    return {'success': False, 'message': message, 'backend': backend_type}


def create_storage_resources(api, models, ctx: ApiContext) -> dict:
    """Build the storage-backend resources against *ctx*."""

    class StorageBackendInfo(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        @instance_wide(ctx, 'storage', 'the storage configuration')
        def get(self):
            """Get current storage backend information. A key restricted with `allowed_domains` is refused."""
            try:
                storage_manager = ctx.managers.get('storage')
                if not storage_manager:
                    return {'error': 'Storage manager not available'}, 503

                backend_name = storage_manager.get_backend_name()
                settings = ctx.settings.load_settings()
                storage_config = settings.get('certificate_storage', {})

                return {
                    'current_backend': backend_name,
                    'available_backends': [
                        'local_filesystem',
                        'azure_keyvault',
                        'aws_secrets_manager',
                        'hashicorp_vault',
                        'infisical',
                        's3_compatible'
                    ],
                    'configuration': {
                        'backend': storage_config.get('backend', 'local_filesystem'),
                        # The directory in USE, not the raw setting. It
                        # reported 'certificates' while the backend wrote to
                        # wherever CERTMATE_CERT_DIR pointed, so the one
                        # endpoint an operator asks "where are my certificates"
                        # answered with the string in the file.
                        'cert_dir': str(storage_manager.local_cert_dir(storage_config))
                    }
                }
            except Exception as e:
                logger.error(f"Error getting storage backend info: {e}")
                return {'error': 'Failed to get storage backend info'}, 500

    class StorageBackendConfig(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @api.expect(models['storage_config_model'])
        @refuses_published_cert_dir
        def post(self):
            """Update storage backend configuration"""
            try:
                data = api.payload
                backend_type = data.get('backend')
                valid_backends = [
                    'local_filesystem', 'azure_keyvault', 'aws_secrets_manager',
                    'hashicorp_vault', 'infisical', 's3_compatible'
                ]
                if backend_type not in valid_backends:
                    return {'error': 'Invalid backend type'}, 400

                # Build only the storage subtree to merge atomically.
                # Audit C2 (May 2026): the prior version wholesale-set
                # the per-backend dict (e.g. `storage['azure_keyvault']
                # = data.get('azure_keyvault', {})`). When the UI POSTs
                # the round-trip from GET /api/web/settings, the masked
                # sentinel `'********'` rides inside that dict and the
                # deep-merge propagates it down to the leaf — overwriting
                # the on-disk credential with the literal sentinel. The
                # fix is the same shape PR #215 applied to the settings
                # POST path: strip the sentinel BEFORE the merge so any
                # masked / empty secret field falls back to its on-disk
                # value, only genuinely-changed values overwrite.
                from ..core.settings import _strip_masked_values
                storage_update = {'backend': backend_type}
                if backend_type == 'local_filesystem':
                    storage_update.update(_local_storage_update(data))
                elif backend_type == 'azure_keyvault':
                    storage_update['azure_keyvault'] = data.get('azure_keyvault', {})
                elif backend_type == 'aws_secrets_manager':
                    storage_update['aws_secrets_manager'] = data.get('aws_secrets_manager', {})
                elif backend_type == 'hashicorp_vault':
                    storage_update['hashicorp_vault'] = data.get('hashicorp_vault', {})
                elif backend_type == 'infisical':
                    storage_update['infisical'] = data.get('infisical', {})
                elif backend_type == 's3_compatible':
                    storage_update['s3_compatible'] = data.get('s3_compatible', {})

                clean_payload = _strip_masked_values({'certificate_storage': storage_update})
                success = ctx.settings.atomic_update(clean_payload)

                if success:
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='update_config',
                            resource_type='storage_backend',
                            resource_id=backend_type,
                            status='success',
                            details={
                                'backend_type': backend_type
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {
                        'success': True,
                        'message': f'Storage backend updated to {backend_type}',
                        'backend': backend_type
                    }
                else:
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='update_config',
                            resource_type='storage_backend',
                            resource_id=backend_type,
                            status='failure',
                            details={
                                'backend_type': backend_type,
                                'reason': 'Atomic update failed'
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {'error': 'Failed to save storage configuration'}, 500

            except Exception as e:
                logger.error(f"Error updating storage backend config: {e}")
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='update_config',
                        resource_type='storage_backend',
                        resource_id=backend_type if 'backend_type' in locals() else 'unknown',
                        status='failure',
                        details={
                            'error': str(e)
                        },
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {'error': 'Failed to update storage backend configuration'}, 500

    class StorageBackendTest(Resource):
        @api.doc(security='Bearer')
        # Admin, like the save it supports: the request carries a whole
        # configuration and the server connects with it.
        @ctx.auth.require_role('admin')
        @api.expect(models['storage_test_config_model'])
        @refuses_published_cert_dir
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
                    InfisicalBackend, S3CompatibleBackend
                )

                # Test connection based on backend type
                try:
                    config = _with_saved_secrets(ctx, backend_type, config)
                    if backend_type == 'local_filesystem':
                        test_backend = LocalFileSystemBackend(
                            _local_dir(ctx, config))

                    elif backend_type == 'azure_keyvault':
                        test_backend = AzureKeyVaultBackend(config)

                    elif backend_type == 'aws_secrets_manager':
                        test_backend = AWSSecretsManagerBackend(config)

                    elif backend_type == 'hashicorp_vault':
                        test_backend = HashiCorpVaultBackend(config)

                    elif backend_type == 'infisical':
                        test_backend = InfisicalBackend(config)

                    elif backend_type == 's3_compatible':
                        test_backend = S3CompatibleBackend(config)

                    else:
                        return {'error': 'Invalid backend type'}, 400

                    # Every remote backend's public list_certificates() turns a
                    # failure into [] for the callers that must keep going. The
                    # Test button must not: it answered "Successfully connected"
                    # for a Vault host that does not exist, a token of `x` and an
                    # image without hvac (#1422). Ask the attempt, which raises.
                    lister = getattr(test_backend, '_list_certificates_attempt', None)
                    domains = lister() if lister else test_backend.list_certificates()

                    # When the Azure Key Vault backend is configured to write
                    # Certificate objects, the Service Principal also needs
                    # access to the Certificate API. list_certificates above
                    # already covers the secrets surface, so probe certificates
                    # explicitly here to surface permission gaps before save.
                    if backend_type == 'azure_keyvault' and getattr(test_backend, 'writes_certificate', False):
                        test_backend.verify_certificate_api_access()

                    return {
                        'success': True,
                        'message': f'Successfully connected to {backend_type}',
                        'backend': backend_type,
                        'certificate_count': len(domains)
                    }

                except Exception as test_error:
                    # Log the full exception for operator triage (includes any
                    # tenant IDs, request IDs and SDK error codes) but only
                    # return the exception type to the client to avoid leaking
                    # those identifiers to anyone who can hit the test endpoint.
                    logger.error(f"Storage backend connection test failed: {test_error}")
                    return _test_failure(backend_type, test_error)

            except Exception as e:
                logger.error(f"Error testing storage backend: {e}")
                return {'error': 'Failed to test storage backend'}, 500

    class StorageBackendMigrate(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        @api.expect(models['storage_migration_config_model'])
        @refuses_published_cert_dir
        def post(self):
            """Migrate certificates between storage backends.

            Payload is forgiving on purpose: the UI's "Start Migration"
            button has no way to remember the previously-active backend
            (the dropdown already shows the user's new target choice),
            so we accept either the explicit four-field form
            (``source_backend`` + ``source_config`` + ``target_backend`` +
            ``target_config``) or a minimal payload where source defaults
            to the currently-saved ``certificate_storage`` and the target
            comes in as the structured ``{backend, <backend>: {...}}`` blob
            the settings form already produces.
            """
            from ..core.storage_backends import (
                LocalFileSystemBackend, AzureKeyVaultBackend,
                AWSSecretsManagerBackend, HashiCorpVaultBackend,
                InfisicalBackend, S3CompatibleBackend
            )

            backend_classes = {
                'local_filesystem': LocalFileSystemBackend,
                'azure_keyvault': AzureKeyVaultBackend,
                'aws_secrets_manager': AWSSecretsManagerBackend,
                'hashicorp_vault': HashiCorpVaultBackend,
                'infisical': InfisicalBackend,
                's3_compatible': S3CompatibleBackend,
            }

            def _resolve_config(backend_type, raw):
                """Pull the per-backend sub-config out of either a flat dict
                (already the right shape) or the structured envelope the
                settings form emits (``{backend, <backend>: {...}}``)."""
                if not isinstance(raw, dict):
                    return {}
                if backend_type in raw and isinstance(raw[backend_type], dict):
                    return raw[backend_type]
                # local_filesystem stores ``cert_dir`` at the top level both
                # in settings and in the form payload, so the envelope and
                # the flat form are indistinguishable — return as-is.
                return {k: v for k, v in raw.items() if k != 'backend'}

            def _build_backend(backend_type, config):
                if backend_type == 'local_filesystem':
                    return LocalFileSystemBackend(_local_dir(ctx, config))
                return backend_classes[backend_type](config)

            try:
                data = api.payload or {}
                target_raw = data.get('target_config') or {}
                source_raw = data.get('source_config') or {}

                # Source defaults to the currently-active backend if the
                # caller didn't pass one — that's the dominant UI path.
                source_backend_type = data.get('source_backend')
                if not source_backend_type or not source_raw:
                    current = ctx.settings.load_settings() or {}
                    current_storage = current.get('certificate_storage') or {}
                    if not source_backend_type:
                        source_backend_type = current_storage.get(
                            'backend', 'local_filesystem')
                    if not source_raw:
                        source_raw = current_storage

                # Target backend may be passed explicitly or inferred from
                # the envelope produced by collectStorageBackendSettings().
                target_backend_type = (
                    data.get('target_backend')
                    or (target_raw.get('backend') if isinstance(target_raw, dict) else None)
                )

                if source_backend_type not in backend_classes:
                    return {'error': 'Invalid source backend type'}, 400
                if target_backend_type not in backend_classes:
                    return {'error': 'Invalid target backend type'}, 400

                source_config = _resolve_config(source_backend_type, source_raw)
                target_config = _resolve_config(target_backend_type, target_raw)

                try:
                    source_config = _with_saved_secrets(ctx, source_backend_type, source_config)
                    target_config = _with_saved_secrets(ctx, target_backend_type, target_config)
                    source_backend = _build_backend(source_backend_type, source_config)
                    target_backend = _build_backend(target_backend_type, target_config)

                    storage_manager = ctx.managers.get('storage')
                    if not storage_manager:
                        return {'error': 'Storage manager not available'}, 503

                    migration_results = storage_manager.migrate_certificates(
                        source_backend, target_backend)

                    successful = sum(1 for ok in migration_results.values() if ok)
                    total = len(migration_results)
                    failed = total - successful

                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        # A migration that left a certificate behind is not a
                        # success: the trail said `success` with `successful: 0,
                        # failed: 3` (#1422).
                        ctx.audit.log_operation(
                            operation='migrate',
                            resource_type='storage',
                            resource_id=f"{source_backend_type}_to_{target_backend_type}",
                            status='success' if failed == 0 else 'failure',
                            details={
                                'source_backend': source_backend_type,
                                'target_backend': target_backend_type,
                                'total_certificates': total,
                                'successful': successful,
                                'failed': failed
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                            error=(f'{failed} of {total} certificates were not migrated'
                                   if failed else None),
                        )

                    return {
                        'success': True,
                        'message': f'Migration completed: {successful}/{total} certificates migrated',
                        # migrated_count is the field the UI reads — keep it
                        # alongside migration_results for older API callers.
                        'migrated_count': successful,
                        'failed_count': failed,
                        'total': total,
                        'migration_results': migration_results,
                        'source_backend': source_backend_type,
                        'target_backend': target_backend_type,
                    }

                except Exception as migration_error:
                    logger.error(f"Storage migration failed: {migration_error}")
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='migrate',
                            resource_type='storage',
                            resource_id=f"{source_backend_type}_to_{target_backend_type}",
                            status='failure',
                            details={
                                'source_backend': source_backend_type,
                                'target_backend': target_backend_type,
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                            error=str(migration_error)
                        )
                    return {
                        'success': False,
                        'message': _migration_failure_message(migration_error),
                        'source_backend': source_backend_type,
                        'target_backend': target_backend_type,
                    }, 500

            except Exception as e:
                logger.error(f"Error during storage migration: {e}")
                return {'error': 'Failed to perform storage migration'}, 500

    class StorageAzureKeyVaultBackfill(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def post(self):
            """Backfill native Certificate objects for domains already stored as Secrets.

            Only valid when the active backend is azure_keyvault and its
            ``storage_mode`` is ``both``. In ``both`` mode ``list_certificates``
            walks the Secrets surface as well as the Certificate surface, so
            legacy domains stored only as Secrets are visible to the loop and
            get an imported Certificate object on first run. In ``certificate``
            mode the Secrets surface is invisible and the walk would silently
            no-op, so the operator must switch to ``both`` first.

            Accepts an optional ``?limit=N`` query parameter that caps how
            many domains are processed in a single call. Large vaults can
            paginate by calling repeatedly until ``remaining`` is ``0`` —
            each call is independent because already-imported domains are
            reported as ``skipped`` on subsequent runs.
            """
            try:
                storage_manager = ctx.managers.get('storage')
                if not storage_manager:
                    return {'error': 'Storage manager not available'}, 503

                backend = storage_manager.get_backend()
                if backend.get_backend_name() != 'azure_keyvault':
                    return {'error': 'Backfill is only available for the Azure Key Vault backend'}, 400
                current_mode = getattr(backend, 'storage_mode', None)
                if current_mode != 'both':
                    return {
                        'error': (
                            "Backfill requires storage_mode='both' so the legacy Secrets are "
                            "still listed. Active mode is '{}' — switch to 'both', run the "
                            "backfill, and then optionally switch to 'certificate'."
                        ).format(current_mode or 'unknown')
                    }, 400

                limit_raw = request.args.get('limit')
                limit = None
                if limit_raw is not None:
                    try:
                        limit = int(limit_raw)
                    except (TypeError, ValueError):
                        return {'error': "Query parameter 'limit' must be a positive integer"}, 400
                    if limit < 1:
                        return {'error': "Query parameter 'limit' must be a positive integer"}, 400

                results = {}
                all_domains = list(backend.list_certificates())
                processed = 0
                for domain in all_domains:
                    if limit is not None and processed >= limit:
                        break
                    processed += 1
                    try:
                        if backend.has_certificate_object(domain):
                            results[domain] = 'skipped'
                            continue
                        retrieved = backend.retrieve_certificate(domain)
                        if not retrieved:
                            results[domain] = 'error: no certificate data found'
                            continue
                        cert_files, metadata = retrieved
                        if backend.import_certificate_object(domain, cert_files, metadata):
                            results[domain] = 'imported'
                        else:
                            results[domain] = 'error: import returned false'
                    except Exception as per_domain:
                        logger.error(f"Backfill failed for {domain}: {per_domain}")
                        results[domain] = f'error: {type(per_domain).__name__}'

                imported = sum(1 for v in results.values() if v == 'imported')
                skipped = sum(1 for v in results.values() if v == 'skipped')
                errors = sum(1 for v in results.values() if v.startswith('error'))
                remaining = max(0, len(all_domains) - processed)
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='backfill',
                        resource_type='storage_azure_keyvault',
                        resource_id='certificates',
                        status='success' if errors == 0 else 'failure',
                        details={
                            'imported': imported,
                            'skipped': skipped,
                            'errors': errors,
                            'remaining': remaining
                        },
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )

                return {
                    'success': errors == 0,
                    'message': f'Backfill complete: {imported} imported, {skipped} skipped, {errors} errors',
                    'imported': imported,
                    'skipped': skipped,
                    'errors': errors,
                    'remaining': remaining,
                    'results': results,
                }

            except Exception as e:
                logger.error(f"Error during Azure Key Vault Certificate backfill: {e}")
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='backfill',
                        resource_type='storage_azure_keyvault',
                        resource_id='certificates',
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                        error=str(e)
                    )
                return {'error': 'Failed to backfill Certificate objects'}, 500

    return {
        'StorageBackendInfo': StorageBackendInfo,
        'StorageBackendConfig': StorageBackendConfig,
        'StorageBackendTest': StorageBackendTest,
        'StorageBackendMigrate': StorageBackendMigrate,
        'StorageAzureKeyVaultBackfill': StorageAzureKeyVaultBackfill,
    }
