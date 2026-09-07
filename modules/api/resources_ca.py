"""ACME CA provider connectivity checks.

Extracted from the `create_api_resources` closure (#667). The class is
unchanged; what used to be captured from the enclosing scope now arrives as an
explicit `ApiContext`, which is what makes it importable — and therefore
testable — without constructing the whole manager graph.

It gets a module of its own rather than joining the settings group it sits
beside in the closure: at ~270 lines it is substantial, and probing whether a
CA endpoint answers is a different concern from managing configuration.
"""
import logging
import tempfile

from flask_restx import Resource

from .resource_context import ApiContext

logger = logging.getLogger(__name__)


def create_ca_resources(api, models, ctx: ApiContext) -> dict:
    """Build the CA provider resources against *ctx*."""

    class CAProviderTest(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        @api.expect(models['ca_test_config_model'])
        def post(self):
            """Test CA provider connection"""
            try:
                data = api.payload
                ca_provider = data.get('ca_provider')
                config = data.get('config', {})

                # Import CA manager
                ca_manager = ctx.managers.get('ca')
                if not ca_manager:
                    return {'error': 'CA manager not available'}, 503

                # Test connection based on CA provider type
                try:
                    if ca_provider in ('letsencrypt', 'letsencrypt_staging'):
                        # Email-only validation; the directory is pinned per
                        # entry in CAManager (staging is its own CA since #279).
                        email = config.get('email', '')

                        if not email:
                            return {
                                'success': False,
                                'message': 'Email is required for Let\'s Encrypt',
                                'ca_provider': ca_provider
                            }

                        provider_name = ca_manager.ca_providers[ca_provider]['name']
                        return {
                            'success': True,
                            'message': f'{provider_name} configuration appears valid',
                            'ca_provider': ca_provider,
                            'directory_url': ca_manager.ca_providers[ca_provider]['production_url']
                        }

                    elif ca_provider == 'digicert':
                        # Test DigiCert ACME connection. Accept both EAB
                        # field spellings, like the generic branch below.
                        acme_url = config.get('acme_url', '')
                        eab_kid = config.get('eab_kid') or config.get('eab_key_id', '')
                        eab_hmac = config.get('eab_hmac') or config.get('eab_hmac_key', '')
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

                    elif ca_provider in ('zerossl', 'google', 'sslcom', 'actalis'):
                        # Fixed-directory EAB CAs share one shape: the ACME
                        # URL is pinned in CAManager, so the test validates
                        # EAB credentials + email. Accept both field
                        # spellings (the settings form posts eab_kid/eab_hmac
                        # for DigiCert but eab_key_id/eab_hmac_key here).
                        provider_name = ca_manager.ca_providers[ca_provider]['name']
                        eab_kid = config.get('eab_kid') or config.get('eab_key_id', '')
                        eab_hmac = config.get('eab_hmac') or config.get('eab_hmac_key', '')
                        email = config.get('email', '')

                        if not eab_kid or not eab_hmac:
                            return {
                                'success': False,
                                'message': f'EAB credentials (Key ID and HMAC Key) are required for {provider_name}',
                                'ca_provider': ca_provider
                            }

                        if not email:
                            return {
                                'success': False,
                                'message': f'Email is required for {provider_name}',
                                'ca_provider': ca_provider
                            }

                        return {
                            'success': True,
                            'message': f'{provider_name} configuration appears valid',
                            'ca_provider': ca_provider,
                            'acme_url': ca_manager.ca_providers[ca_provider]['production_url']
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
                        # SSLError BEFORE ConnectionError: requests' SSLError
                        # subclasses ConnectionError, so with the handlers the
                        # other way round the SSL branch was unreachable and a
                        # private CA whose certificate could not be verified
                        # was reported as "cannot reach the host on the
                        # required port" — sending the operator to check
                        # firewalls for a trust-anchor problem.
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
                        except requests.exceptions.ConnectionError:
                            return {
                                'success': False,
                                'message': 'Connection failed - ACME endpoint is not accessible. '
                                           'Ensure the CertMate server can reach the ACME host on the required port.',
                                'ca_provider': ca_provider
                            }
                        except Exception as conn_error:
                            logger.error(f"CA provider connection test failed: {conn_error}")
                            return {
                                'success': False,
                                'message': f'Connection test failed ({type(conn_error).__name__}). See server logs for details.',
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
                return {'success': False, 'message': f'CA provider test failed ({type(e).__name__}). See server logs for details.'}, 500

    return {
        'CAProviderTest': CAProviderTest,
    }
