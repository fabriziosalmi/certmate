"""Certificate downloads, and who is allowed to receive a private key.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as an
explicit `ApiContext`.

This group was the one the decomposition could not reach: both classes call
`_validate_domain_path`, which lived in `resources.py` alongside thirteen other
callers, so a module here could not use it without an import cycle. Moving that
helper to `path_validation.py` is what unblocked this.

The two sets below are the access rule, and they are the reason this group is
worth having on its own: `_PRIVATE_KEY_FILES` decides which downloads require
operator rather than viewer, and a viewer reaching a private key is the failure
that matters most in this file. They travel with the endpoints that enforce
them rather than staying behind as loose closure state.
"""
import io
import logging
import os
import tempfile
import zipfile

from flask import after_this_request, jsonify, request, send_file
from flask_restx import Resource

from ..core.constants import CERTIFICATE_FILES
from .path_validation import validate_domain_path as _validate_domain_path
from .resource_context import ApiContext, check_domain_scope, user_has_role

logger = logging.getLogger(__name__)

# Files whose download hands over key material. Downloading one requires
# operator; everything else is readable by a viewer.
_PRIVATE_KEY_FILES = frozenset({'privkey.pem', 'combined.pem', 'cert.pfx'})
_PUBLIC_DOWNLOAD_FILES = frozenset({'cert.pem', 'chain.pem', 'fullchain.pem'})


def create_download_resources(api, models, ctx: ApiContext,
                              privkey_to_pkcs1) -> dict:
    """Build the certificate-download resources against *ctx*.

    `privkey_to_pkcs1` is passed in rather than imported: it lives in
    `resources.py`, whose tests import it from there, and taking it as an
    argument avoids an import cycle without moving a second helper in the same
    change.
    """
    _privkey_to_pkcs1 = privkey_to_pkcs1

    def _check_domain_scope(domain, operation):
        return check_domain_scope(ctx, domain, operation)

    def _user_has_role(user, min_role):
        return user_has_role(user, min_role)

    class DownloadCertificate(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self, domain):
            """Download certificate files as ZIP, JSON, or individual file.

            Role gating is per-file: viewers can pull public material
            (cert.pem, chain.pem, fullchain.pem) and the public-only ZIP
            (?include_private=0); anything that exposes the private key
            (privkey.pem, combined.pem, format=json, default ZIP)
            requires operator role.

            ?file=privkey.pem&key_format=pkcs1 serves the key in legacy
            PKCS#1/SEC1 form for stacks that reject certbot's PKCS#8
            (issue #233); the default is the on-disk PKCS#8.

            ?format=json&key_format=pkcs1 adds private_key_pkcs1_pem to the
            JSON alongside the untouched private_key_pem, so an automation
            can pull everything it needs in one call instead of downloading
            the key a second time as a file (issue #398). The field is named
            for the encoding, not RSA: for an ECDSA key the traditional form
            is SEC1 ("BEGIN EC PRIVATE KEY"), and CertMate issues ECDSA by
            default.

            ?file=cert.pfx serves the encrypted PKCS#12 bundle when a PFX
            export password is configured (issue #230); 404 otherwise. It
            contains the private key, so it requires operator role.
            """
            try:
                scope_err = _check_domain_scope(domain, 'download')
                if scope_err:
                    return scope_err
                cert_dir, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
                if err:
                    return {'error': err, 'code': 'INVALID_REQUEST'}, 400
                if not cert_dir.exists():
                    return {'error': f'Certificate not found for domain: {domain}', 'code': 'CERTIFICATE_NOT_FOUND'}, 404

                user = getattr(request, 'current_user', None) or {}
                download_format = request.args.get('format')
                # Check for the optional 'file' parameter
                requested_file = request.args.get('file')
                include_private = str(request.args.get('include_private', '1')).lower() not in ('0', 'false', 'no', 'off')

                if download_format and download_format not in ['json']:
                    return {'error': 'Invalid format requested.', 'code': 'INVALID_FORMAT'}, 400

                # Optional private-key serialization. Certbot stores PKCS#8
                # ("BEGIN PRIVATE KEY"); some older stacks need the legacy
                # PKCS#1 form ("BEGIN RSA PRIVATE KEY"). Convert on download
                # rather than duplicating key material on disk (issue #233).
                key_format = request.args.get('key_format')
                if key_format is not None and key_format not in ('pkcs1', 'pkcs8'):
                    return {'error': "Invalid key_format; use 'pkcs1' or 'pkcs8'.", 'code': 'INVALID_KEY_FORMAT'}, 400
                if key_format and download_format != 'json' and requested_file != 'privkey.pem':
                    return {
                        'code': 'KEY_FORMAT_NOT_APPLICABLE',
                        'error': 'key_format applies to ?file=privkey.pem or ?format=json.'
                    }, 400

                def _privkey_denied(file_label):
                    """Emit audit + return 403 for viewer trying to pull privkey."""
                    if ctx.audit:
                        ctx.audit.log_authz_denied(
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
                        return {'error': 'format=json cannot be combined with file.', 'code': 'INCOMPATIBLE_PARAMETERS'}, 400

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
                                return {'error': f'Required cert file not found for domain {domain}: {filename}', 'code': 'CERT_FILE_NOT_FOUND'}, 404
                            payload[response_key] = file_path.read_text(encoding='utf-8')

                        # ?key_format=pkcs1 adds the legacy/traditional form
                        # ALONGSIDE private_key_pem rather than replacing it,
                        # so an existing consumer of format=json is unaffected
                        # (issue #398). Converted from the bytes just read —
                        # no second file read, no second path to validate.
                        # pkcs8 is what is already on disk, so asking for it
                        # here is a no-op by design.
                        if key_format == 'pkcs1':
                            try:
                                payload['private_key_pkcs1_pem'] = _privkey_to_pkcs1(
                                    payload['private_key_pem'].encode('utf-8')
                                ).decode('utf-8')
                            except (ValueError, TypeError) as e:
                                # The message is included, not just the type:
                                # cryptography emits static, descriptive text
                                # ("Password was not given but private key is
                                # encrypted", "format is invalid with this
                                # key") that carries no key material and tells
                                # an operator which of several very different
                                # problems they have. CR/LF scrubbed like every
                                # other interpolated value here.
                                logger.error(
                                    "Failed to convert private key to PKCS#1: %s: %s",
                                    type(e).__name__,
                                    str(e).replace('\r', ' ').replace('\n', ' '),
                                )
                                return {
                                    'code': 'KEY_CONVERSION_FAILED',
                                    'error': 'Could not convert the private key to PKCS#1 '
                                             '(the key type may not support it).'
                                }, 422

                        return jsonify(payload)
                    except FileNotFoundError:
                        return {'error': f'Required cert file not found for domain {domain}', 'code': 'CERT_FILE_NOT_FOUND'}, 404

                if requested_file:
                    # Security check: only allow specific certificate files
                    allowed_files = _PUBLIC_DOWNLOAD_FILES | _PRIVATE_KEY_FILES
                    if requested_file not in allowed_files:
                        return {'error': 'Invalid file requested.', 'code': 'INVALID_FILE'}, 400

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
                            return {'error': f'Required cert files not found for domain {domain}', 'code': 'CERT_FILE_NOT_FOUND'}, 404

                    file_path = cert_dir / requested_file
                    if not file_path.exists():
                        return {'error': f'File {requested_file} not found for domain {domain}', 'code': 'CERT_FILE_NOT_FOUND'}, 404

                    if requested_file == 'privkey.pem' and key_format == 'pkcs1':
                        # Re-resolve with a constant filename and confirm the
                        # path stays inside the (already validated) domain dir
                        # before reading — defense in depth, and keeps the new
                        # file read off any tainted path component.
                        key_path = os.path.realpath(cert_dir / 'privkey.pem')
                        if not key_path.startswith(os.path.realpath(cert_dir) + os.sep):
                            return {'error': 'Invalid path', 'code': 'INVALID_PATH'}, 400
                        try:
                            with open(key_path, 'rb') as fh:
                                pkcs1_pem = _privkey_to_pkcs1(fh.read())
                        except (ValueError, TypeError) as e:
                            # Same reasoning as the format=json branch above:
                            # the message is safe and diagnostic. Kept identical
                            # so the two conversion sites do not drift.
                            logger.error(
                                "Failed to convert private key to PKCS#1: %s: %s",
                                type(e).__name__,
                                str(e).replace('\r', ' ').replace('\n', ' '),
                            )
                            return {
                                'code': 'KEY_CONVERSION_FAILED',
                                'error': 'Could not convert the private key to PKCS#1 '
                                         '(the key type may not support it).'
                            }, 422
                        return send_file(
                            io.BytesIO(pkcs1_pem),
                            as_attachment=True,
                            download_name=f'{domain}_privkey_pkcs1.pem',
                            mimetype='application/x-pem-file',
                        )

                    file_mimetype = (
                        'application/x-pkcs12' if requested_file.endswith('.pfx')
                        else 'application/x-pem-file'
                    )
                    return send_file(
                        file_path,
                        as_attachment=True,
                        download_name=f'{domain}_{requested_file}',
                        mimetype=file_mimetype
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
                # The encrypted PKCS#12 bundle (only present when a PFX password
                # is configured, #230/#465) is key-bearing, so it rides only in
                # the private ZIP. The loop below writes it only if it exists.
                if include_private:
                    files_to_zip = files_to_zip + ('cert.pfx',)
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
                return {'error': 'Failed to download certificate', 'code': 'CERTIFICATE_DOWNLOAD_ERROR'}, 500

    class DownloadCertificateFile(Resource):
        # Path-style alias for the query-string form on DownloadCertificate.
        # Documented in discussion #183 as the canonical scripting URL
        # (curl ... /api/certificates/<domain>/download/fullchain). Without
        # this route the documented URL returned 404 (issue #212).
        #
        # Short names map 1:1 to the on-disk filenames. The role gate and
        # path-traversal guards mirror the ?file= branch in
        # DownloadCertificate.get() — keep the two in sync.
        _SHORT_NAME_TO_FILE = {
            'cert': 'cert.pem',
            'chain': 'chain.pem',
            'fullchain': 'fullchain.pem',
            'privkey': 'privkey.pem',
            'combined': 'combined.pem',
        }

        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self, domain, file_type):
            """Download a single certificate file by short name.

            Path-style equivalent of ``?file=<name>.pem`` on the parent
            ``/download`` route. ``file_type`` is one of ``cert``,
            ``chain``, ``fullchain``, ``privkey``, ``combined``.

            Role gating: viewers can pull public material (cert, chain,
            fullchain); ``privkey`` and ``combined`` require operator+.
            """
            requested_file = self._SHORT_NAME_TO_FILE.get(file_type)
            if requested_file is None:
                return {
                    'code': 'INVALID_FILE_TYPE',
                    'error': f'Invalid file type: {file_type}',
                    'hint': f"Allowed: {sorted(self._SHORT_NAME_TO_FILE)}",
                }, 400

            try:
                scope_err = _check_domain_scope(domain, 'download')
                if scope_err:
                    return scope_err
                cert_dir, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
                if err:
                    return {'error': err, 'code': 'INVALID_REQUEST'}, 400
                if not cert_dir.exists():
                    return {'error': f'Certificate not found for domain: {domain}', 'code': 'CERTIFICATE_NOT_FOUND'}, 404

                user = getattr(request, 'current_user', None) or {}

                if requested_file in _PRIVATE_KEY_FILES and not _user_has_role(user, 'operator'):
                    if ctx.audit:
                        ctx.audit.log_authz_denied(
                            operation='download',
                            resource_type='certificate',
                            resource_id=domain,
                            reason=f'viewer cannot download private-key material ({requested_file})',
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {
                        'error': 'operator role required to download private key material',
                        'code': 'PRIVKEY_REQUIRES_OPERATOR',
                        'hint': 'Use /download/fullchain to pull public material as a viewer.',
                    }, 403

                if requested_file == 'combined.pem':
                    try:
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
                        return {'error': f'Required cert files not found for domain {domain}', 'code': 'CERT_FILE_NOT_FOUND'}, 404

                file_path = cert_dir / requested_file
                if not file_path.exists():
                    return {'error': f'File {requested_file} not found for domain {domain}', 'code': 'CERT_FILE_NOT_FOUND'}, 404

                return send_file(
                    file_path,
                    as_attachment=True,
                    download_name=f'{domain}_{requested_file}',
                    mimetype='application/x-pem-file'
                )
            except Exception as e:
                logger.error(f"Error downloading {file_type} for {domain}: {e}")
                return {'error': 'Failed to download certificate file', 'code': 'CERTIFICATE_DOWNLOAD_ERROR'}, 500

    return {
        'DownloadCertificate': DownloadCertificate,
        'DownloadCertificateFile': DownloadCertificateFile,
    }
