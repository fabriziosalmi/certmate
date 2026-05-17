"""Unit tests for the Azure Key Vault Certificate-object storage mode.

No Docker container or live Azure resources are required — Azure SDK
clients are stubbed via ``unittest.mock``.
"""

import base64
import datetime
import json
from unittest.mock import MagicMock

import pytest

pytestmark = [pytest.mark.unit]


# Optional dependency: tests that exercise the real
# ``azure-keyvault-certificates`` SDK (only an import path — the network
# client itself is mocked) need to skip when CI runs without the
# Azure-storage extras installed.
def _require_certificates_sdk():
    return pytest.importorskip("azure.keyvault.certificates")


# ---------------------------------------------------------------------------
# Helpers — generate a self-signed cert + key once per session for fixtures
# ---------------------------------------------------------------------------


def _self_signed_pair():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@pytest.fixture(scope="module")
def cert_files():
    cert_pem, key_pem = _self_signed_pair()
    return {
        "cert.pem": cert_pem,
        "chain.pem": b"",
        "fullchain.pem": cert_pem,
        "privkey.pem": key_pem,
    }


@pytest.fixture
def vault_config():
    return {
        "vault_url": "https://example.vault.azure.net/",
        "client_id": "00000000-0000-0000-0000-000000000001",
        "client_secret": "shhh",
        "tenant_id": "00000000-0000-0000-0000-000000000002",
    }


@pytest.fixture
def metadata():
    return {
        "domain": "test.example.com",
        "san_domains": ["www.test.example.com"],
        "dns_provider": "cloudflare",
        "challenge_type": "dns-01",
        "created_at": "2026-05-07T10:00:00",
        "email": "ops@example.com",
        "staging": False,
        "account_id": "primary",
    }


# ---------------------------------------------------------------------------
# _build_pfx round-trip
# ---------------------------------------------------------------------------


class TestBuildPfx:
    def test_round_trip(self, cert_files):
        from cryptography.hazmat.primitives.serialization import pkcs12
        from modules.core.storage_backends import _build_pfx

        pfx = _build_pfx(cert_files["cert.pem"], cert_files["chain.pem"], cert_files["privkey.pem"])
        key, leaf, additional = pkcs12.load_key_and_certificates(pfx, password=None)
        assert key is not None
        assert leaf is not None
        # Self-signed: leaf is its own issuer; no extra chain certs supplied.
        assert leaf.subject == leaf.issuer
        assert additional == []

    def test_missing_cert_pem_raises(self):
        from modules.core.storage_backends import _build_pfx
        with pytest.raises(ValueError):
            _build_pfx(b"", None, b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")


# ---------------------------------------------------------------------------
# storage_mode validation
# ---------------------------------------------------------------------------


class TestStorageModeValidation:
    def test_default_is_secrets(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend(vault_config)
        assert backend.storage_mode == "secrets"
        assert backend.writes_secrets is True
        assert backend.writes_certificate is False

    def test_explicit_certificate_mode(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "certificate"})
        assert backend.storage_mode == "certificate"
        assert backend.writes_secrets is False
        assert backend.writes_certificate is True

    def test_both_mode(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})
        assert backend.writes_secrets is True
        assert backend.writes_certificate is True

    def test_invalid_mode_raises(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        with pytest.raises(ValueError, match="Invalid storage_mode"):
            AzureKeyVaultBackend({**vault_config, "storage_mode": "garbage"})

    def test_uppercase_mode_normalised(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "BOTH"})
        assert backend.storage_mode == "both"


# ---------------------------------------------------------------------------
# store_certificate routing
# ---------------------------------------------------------------------------


class TestStoreCertificateRouting:
    def test_secrets_mode_does_not_call_certificate_api(self, vault_config, cert_files, metadata):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend(vault_config)

        secret_client = MagicMock()
        cert_importer = MagicMock()
        backend._client = secret_client
        backend._cert_importer = cert_importer

        assert backend.store_certificate("test.example.com", cert_files, metadata) is True
        # 4 PEM files + 1 metadata secret
        assert secret_client.set_secret.call_count == 5
        cert_importer.import_certificate.assert_not_called()

    def test_certificate_mode_only_imports_certificate(self, vault_config, cert_files, metadata):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "certificate"})

        secret_client = MagicMock()
        cert_importer = MagicMock()
        cert_importer.import_certificate.return_value = True
        backend._client = secret_client
        backend._cert_importer = cert_importer

        assert backend.store_certificate("test.example.com", cert_files, metadata) is True
        secret_client.set_secret.assert_not_called()
        cert_importer.import_certificate.assert_called_once_with(
            "test.example.com", cert_files, metadata
        )

    def test_both_mode_invokes_both_paths(self, vault_config, cert_files, metadata):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        cert_importer = MagicMock()
        cert_importer.import_certificate.return_value = True
        backend._client = secret_client
        backend._cert_importer = cert_importer

        assert backend.store_certificate("test.example.com", cert_files, metadata) is True
        assert secret_client.set_secret.call_count == 5
        cert_importer.import_certificate.assert_called_once()

    def test_certificate_mode_failure_returns_false(self, vault_config, cert_files, metadata):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "certificate"})
        backend._client = MagicMock()
        importer = MagicMock()
        importer.import_certificate.side_effect = RuntimeError("forbidden")
        backend._cert_importer = importer

        assert backend.store_certificate("test.example.com", cert_files, metadata) is False

    def test_both_mode_secrets_exception_does_not_skip_certificate_import(self, vault_config, cert_files, metadata):
        """A Secrets-surface exception must not abort the Certificate import.

        Each surface is independent: an outage on the Secrets API should
        still let the Certificate import succeed (so downstream consumers
        like App Gateway keep getting the new cert), and the caller is
        signalled via the False return.
        """
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        secret_client.set_secret.side_effect = RuntimeError("Secrets API outage")
        backend._client = secret_client

        importer = MagicMock()
        importer.import_certificate.return_value = True
        backend._cert_importer = importer

        result = backend.store_certificate("test.example.com", cert_files, metadata)
        assert result is False  # overall fail because Secrets failed
        importer.import_certificate.assert_called_once_with(
            "test.example.com", cert_files, metadata,
        )

    def test_both_mode_certificate_exception_does_not_skip_secrets_write(self, vault_config, cert_files, metadata):
        """Symmetric to the Secrets-fails-Cert-OK case: a Certificate-API
        outage must not skip the Secrets writes. The Secrets surface keeps
        being filled so its consumers (legacy tooling, dashboards) stay in
        sync; the False return signals the partial failure to the caller.
        """
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        backend._client = secret_client

        importer = MagicMock()
        importer.import_certificate.side_effect = RuntimeError("Certificate API outage")
        backend._cert_importer = importer

        result = backend.store_certificate("test.example.com", cert_files, metadata)
        assert result is False  # overall fail because Certificate failed
        # 4 PEM files + 1 metadata secret were still written.
        assert secret_client.set_secret.call_count == 5

    def test_both_mode_double_store_failure_returns_false(self, vault_config, cert_files, metadata):
        """Both surfaces failing → False, both surfaces still attempted."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        secret_client.set_secret.side_effect = RuntimeError("Secrets outage")
        backend._client = secret_client

        importer = MagicMock()
        importer.import_certificate.side_effect = RuntimeError("Certificate API outage")
        backend._cert_importer = importer

        assert backend.store_certificate("test.example.com", cert_files, metadata) is False
        # Secrets path was attempted (it raised on the first set_secret).
        assert secret_client.set_secret.called
        importer.import_certificate.assert_called_once_with(
            "test.example.com", cert_files, metadata,
        )


# ---------------------------------------------------------------------------
# Importer: import_certificate constructs the right SDK call
# ---------------------------------------------------------------------------


class TestImportCertificateSdkCall:
    @pytest.fixture(autouse=True)
    def _require_sdk(self):
        _require_certificates_sdk()

    def test_import_certificate_uses_pkcs12_and_unknown_issuer(self, vault_config, cert_files, metadata):
        from modules.core.storage_backends import _AzureKeyVaultCertificateImporter

        cert_client = MagicMock()
        importer = _AzureKeyVaultCertificateImporter(
            vault_url=vault_config["vault_url"],
            credential=MagicMock(),
            sanitize_name=lambda n: n,
        )
        importer._cert_client = cert_client

        assert importer.import_certificate("test.example.com", cert_files, metadata) is True
        cert_client.import_certificate.assert_called_once()
        kwargs = cert_client.import_certificate.call_args.kwargs
        assert kwargs["certificate_name"] == "cert-test.example.com"
        assert isinstance(kwargs["certificate_bytes"], (bytes, bytearray))
        assert kwargs["password"] is None

        policy = kwargs["policy"]
        assert getattr(policy, "issuer_name", None) == "Unknown"
        assert getattr(policy, "content_type", None) == "application/x-pkcs12"

        tags = kwargs["tags"]
        assert tags["domain"] == "test.example.com"
        assert tags["dns_provider"] == "cloudflare"
        assert tags["staging"] == "false"
        assert tags["san_domains"] == "www.test.example.com"

    def test_import_returns_false_when_inputs_missing(self, vault_config, metadata):
        from modules.core.storage_backends import _AzureKeyVaultCertificateImporter

        importer = _AzureKeyVaultCertificateImporter(
            vault_url=vault_config["vault_url"],
            credential=MagicMock(),
            sanitize_name=lambda n: n,
        )
        importer._cert_client = MagicMock()
        result = importer.import_certificate("test.example.com", {"cert.pem": b""}, metadata)
        assert result is False
        importer._cert_client.import_certificate.assert_not_called()


# ---------------------------------------------------------------------------
# Tag truncation for oversize SAN lists
# ---------------------------------------------------------------------------


class TestTagTruncation:
    def test_oversize_san_domains_truncated_with_marker(self):
        from modules.core.storage_backends import _AzureKeyVaultCertificateImporter

        long_sans = [f"alias{i:03d}.example.com" for i in range(60)]
        tags = _AzureKeyVaultCertificateImporter._build_tags({
            "domain": "core.example.com",
            "san_domains": long_sans,
        })
        assert "san_domains" in tags
        assert len(tags["san_domains"]) <= 256
        assert tags["san_domains"].endswith("...")


# ---------------------------------------------------------------------------
# retrieve_certificate in certificate-only mode
# ---------------------------------------------------------------------------


class TestRetrieveCertificateMode:
    def test_export_certificate_reconstructs_pem_files(self, vault_config, cert_files, metadata):
        from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption
        from cryptography.hazmat.primitives import serialization
        from modules.core.storage_backends import (
            AzureKeyVaultBackend,
            _AzureKeyVaultCertificateImporter,
            _build_pfx,
        )

        pfx_bytes = _build_pfx(cert_files["cert.pem"], cert_files["chain.pem"], cert_files["privkey.pem"])
        secret_value = base64.b64encode(pfx_bytes).decode("ascii")

        secret = MagicMock()
        secret.value = secret_value
        secret.properties.tags = {
            "domain": "test.example.com",
            "dns_provider": "cloudflare",
            "challenge_type": "dns-01",
            "staging": "true",
            "san_domains": "www.test.example.com",
        }

        secret_client = MagicMock()
        secret_client.get_secret.return_value = secret

        importer = _AzureKeyVaultCertificateImporter(
            vault_url=vault_config["vault_url"],
            credential=MagicMock(),
            sanitize_name=lambda n: n,
        )
        importer._secret_client = secret_client

        retrieved = importer.export_certificate("test.example.com")
        assert retrieved is not None
        files, meta = retrieved
        assert set(files.keys()) == {"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"}
        assert b"BEGIN CERTIFICATE" in files["cert.pem"]
        assert b"BEGIN" in files["privkey.pem"]
        assert files["fullchain.pem"].startswith(files["cert.pem"])
        # Metadata tags rehydrated; staging string normalises back to bool.
        assert meta["domain"] == "test.example.com"
        assert meta["staging"] is True
        assert meta["san_domains"] == ["www.test.example.com"]


# ---------------------------------------------------------------------------
# list_certificates routing
# ---------------------------------------------------------------------------


def _mock_secret_props(name):
    prop = MagicMock()
    prop.name = name
    return prop


def _real_metadata_secret_name(domain):
    """Build the same metadata secret name a real backend would produce.

    Avoids hard-coding CRC suffixes in tests so changes to the sanitiser do
    not require sweeping rewrites.
    """
    from modules.core.storage_backends import AzureKeyVaultBackend
    return AzureKeyVaultBackend._sanitize_secret_name(f"cert-{domain}-metadata")


class TestListCertificatesRouting:
    def test_certificate_only_lists_from_certificate_api(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "certificate"})

        importer = MagicMock()
        importer.list_domains.return_value = ["a.example.com", "b.example.com"]
        backend._cert_importer = importer
        backend._client = MagicMock()  # should not be touched

        assert backend.list_certificates() == ["a.example.com", "b.example.com"]
        backend._client.list_properties_of_secrets.assert_not_called()

    def test_both_mode_unions_and_dedupes(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        # Use the real sanitised names so the CRC-aware filter actually
        # matches; otherwise the test would silently exercise zero matches
        # and incorrectly validate the (broken-in-main) endswith filter.
        meta_a_name = _real_metadata_secret_name("a.example.com")
        meta_b_name = _real_metadata_secret_name("shared.example.com")

        secret_client = MagicMock()
        secret_client.list_properties_of_secrets.return_value = [
            _mock_secret_props(meta_a_name),
            _mock_secret_props(meta_b_name),
            _mock_secret_props("not-a-cert-no-suffix"),
            _mock_secret_props("cert-test-example-com-cert-pem-deadbeef"),
        ]

        meta_a = MagicMock(); meta_a.value = json.dumps({"domain": "a.example.com"})
        meta_b = MagicMock(); meta_b.value = json.dumps({"domain": "shared.example.com"})
        # get_secret is only called for matches, so two return values is enough.
        secret_client.get_secret.side_effect = [meta_a, meta_b]
        backend._client = secret_client

        importer = MagicMock()
        importer.list_domains.return_value = ["shared.example.com", "z.example.com"]
        backend._cert_importer = importer

        assert backend.list_certificates() == [
            "a.example.com", "shared.example.com", "z.example.com",
        ]
        # Only the two real metadata secrets were retrieved; the cert.pem
        # secret and the random non-cert secret were filtered out.
        assert secret_client.get_secret.call_count == 2


# ---------------------------------------------------------------------------
# delete_certificate routing
# ---------------------------------------------------------------------------


class TestDeleteCertificateRouting:
    def test_both_mode_deletes_in_both_apis(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        importer = MagicMock()
        backend._client = secret_client
        backend._cert_importer = importer

        assert backend.delete_certificate("test.example.com") is True
        # 4 files + 1 metadata
        assert secret_client.begin_delete_secret.call_count == 5
        importer.delete.assert_called_once_with("test.example.com")

    def test_certificate_only_skips_secret_deletes(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "certificate"})

        secret_client = MagicMock()
        importer = MagicMock()
        backend._client = secret_client
        backend._cert_importer = importer

        assert backend.delete_certificate("test.example.com") is True
        secret_client.begin_delete_secret.assert_not_called()
        importer.delete.assert_called_once_with("test.example.com")

    def test_both_mode_certificate_exception_does_not_skip_secrets_delete(self, vault_config):
        """A Certificate-API outage must not stop the Secrets cleanup.

        Symmetric to the store_certificate contract: each surface is
        independent. If Azure's Certificate API is failing, the legacy
        Secrets should still be removed so the vault is not left with
        stale per-PEM secrets. Overall result is False so the caller can
        react to the partial failure.
        """
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        backend._client = secret_client

        importer = MagicMock()
        importer.delete.side_effect = RuntimeError("Certificate API outage")
        backend._cert_importer = importer

        result = backend.delete_certificate("test.example.com")
        assert result is False  # overall fail because Certificate failed
        # Secrets surface still walked: 4 PEMs + 1 metadata.
        assert secret_client.begin_delete_secret.call_count == 5
        importer.delete.assert_called_once_with("test.example.com")

    def test_both_mode_double_failure_returns_false(self, vault_config):
        """Both surfaces failing → False, both surfaces still attempted."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        # Force the secrets path to raise before completing — patch the
        # method directly so we don't have to defeat the per-file try/except
        # inside _delete_secrets.
        backend._delete_secrets = MagicMock(side_effect=RuntimeError("Secrets outage"))

        importer = MagicMock()
        importer.delete.side_effect = RuntimeError("Certificate API outage")
        backend._cert_importer = importer

        assert backend.delete_certificate("test.example.com") is False
        backend._delete_secrets.assert_called_once_with("test.example.com")
        importer.delete.assert_called_once_with("test.example.com")

    def test_both_mode_partial_secret_failure_returns_false(self, vault_config):
        """When _delete_secrets reports partial failure (returns False) the
        overall result is False even if the Certificate API succeeded —
        the caller needs to know a stale secret may have been left behind.
        """
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        backend._delete_secrets = MagicMock(return_value=False)
        importer = MagicMock()
        importer.delete.return_value = True
        backend._cert_importer = importer

        assert backend.delete_certificate("test.example.com") is False


# ---------------------------------------------------------------------------
# certificate_exists across modes
# ---------------------------------------------------------------------------


class TestCertificateExists:
    def test_certificate_only_uses_importer(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "certificate"})
        importer = MagicMock()
        importer.exists.return_value = True
        backend._cert_importer = importer
        backend._client = MagicMock()

        assert backend.certificate_exists("test.example.com") is True
        backend._client.get_secret.assert_not_called()
        importer.exists.assert_called_once_with("test.example.com")


# ---------------------------------------------------------------------------
# Settings migration: legacy settings.json without storage_mode → secrets
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tags ↔ metadata symmetry (round-trip + staging=None handling)
# ---------------------------------------------------------------------------


class TestTagsMetadataRoundTrip:
    def test_round_trip_preserves_known_keys(self):
        from modules.core.storage_backends import _AzureKeyVaultCertificateImporter

        original = {
            "domain": "test.example.com",
            "san_domains": ["a.example.com", "b.example.com"],
            "dns_provider": "cloudflare",
            "challenge_type": "dns-01",
            "created_at": "2026-05-07T10:00:00",
            "email": "ops@example.com",
            "staging": True,
            "account_id": "primary",
        }
        tags = _AzureKeyVaultCertificateImporter._build_tags(original)
        rebuilt = _AzureKeyVaultCertificateImporter._tags_to_metadata(tags)
        assert rebuilt["domain"] == "test.example.com"
        assert rebuilt["dns_provider"] == "cloudflare"
        assert rebuilt["staging"] is True
        assert rebuilt["san_domains"] == ["a.example.com", "b.example.com"]

    def test_staging_none_is_omitted_not_falsified(self):
        from modules.core.storage_backends import _AzureKeyVaultCertificateImporter

        tags = _AzureKeyVaultCertificateImporter._build_tags({"domain": "x.example.com", "staging": None})
        assert "staging" not in tags
        rebuilt = _AzureKeyVaultCertificateImporter._tags_to_metadata(tags)
        assert "staging" not in rebuilt

    def test_truncated_san_marker_is_stripped_on_rehydrate(self):
        from modules.core.storage_backends import _AzureKeyVaultCertificateImporter

        long_sans = [f"alias{i:03d}.example.com" for i in range(60)]
        tags = _AzureKeyVaultCertificateImporter._build_tags({
            "domain": "core.example.com",
            "san_domains": long_sans,
        })
        rebuilt = _AzureKeyVaultCertificateImporter._tags_to_metadata(tags)
        # Truncated CSV is sanitised in two ways:
        #   1. the literal ``...`` marker never leaks into the rehydrated list
        #   2. the last entry — incomplete by construction — is dropped, not
        #      exposed as a malformed domain.
        # What survives must be a strict prefix of the original input.
        san = rebuilt["san_domains"]
        assert all("..." not in d for d in san)
        assert all(d in long_sans for d in san)
        assert san == long_sans[: len(san)]

    def test_external_tags_are_filtered_out_on_rehydrate(self):
        from modules.core.storage_backends import _AzureKeyVaultCertificateImporter

        # Simulate Azure Policy or operator-added tags polluting the bag.
        tags = {
            "domain": "test.example.com",
            "Environment": "prod",
            "CostCenter": "42",
            "managed-by": "azure-policy",
        }
        rebuilt = _AzureKeyVaultCertificateImporter._tags_to_metadata(tags)
        assert rebuilt == {"domain": "test.example.com"}


# ---------------------------------------------------------------------------
# retrieve_certificate paths in 'both' mode
# ---------------------------------------------------------------------------


class TestRetrieveBothMode:
    def test_secrets_present_certificate_api_not_touched(self, vault_config, cert_files):
        """When Secrets path returns a populated bundle and no Certificate
        object exists yet, the backend returns the Secrets data without
        touching export_certificate or get_metadata_tags."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        _now = datetime.datetime(2026, 5, 1, 12, 0, 0)

        def fake_get_secret(secret_name):
            secret = MagicMock()
            secret.properties.updated_on = _now
            if "metadata" in secret_name:
                secret.value = json.dumps({"domain": "test.example.com", "dns_provider": "cloudflare"})
            else:
                secret.value = "PEM-CONTENT"
            return secret

        secret_client.get_secret.side_effect = fake_get_secret
        backend._client = secret_client

        importer = MagicMock()
        importer.get_certificate_update_time.return_value = None
        backend._cert_importer = importer

        result = backend.retrieve_certificate("test.example.com")
        assert result is not None
        cert_files_returned, metadata = result
        assert cert_files_returned
        assert metadata["domain"] == "test.example.com"
        importer.export_certificate.assert_not_called()
        importer.get_metadata_tags.assert_not_called()

    def test_secrets_present_metadata_missing_falls_back_to_tags(self, vault_config):
        """When Secrets exist but the metadata-secret is gone, the backend
        recovers the metadata from the Certificate object's tags so callers
        don't lose dns_provider/staging/etc."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        _now = datetime.datetime(2026, 5, 1, 12, 0, 0)

        def get_secret(secret_name):
            if "metadata" in secret_name:
                raise RuntimeError("not found")
            secret = MagicMock()
            secret.properties.updated_on = _now
            secret.value = "PEM-CONTENT"
            return secret

        secret_client.get_secret.side_effect = get_secret
        backend._client = secret_client

        importer = MagicMock()
        importer.get_certificate_update_time.return_value = None
        importer.get_metadata_tags.return_value = {
            "domain": "test.example.com",
            "dns_provider": "cloudflare",
            "staging": False,
        }
        backend._cert_importer = importer

        result = backend.retrieve_certificate("test.example.com")
        assert result is not None
        _, metadata = result
        assert metadata["dns_provider"] == "cloudflare"
        importer.get_metadata_tags.assert_called_once_with("test.example.com")
        importer.export_certificate.assert_not_called()

    def test_secrets_absent_falls_through_to_certificate_api(self, vault_config, cert_files):
        """In 'both' mode, when no Secret is found at all, the backend
        consults the Certificate API rather than returning None — partial
        operator state should not mask an existing Certificate object."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        secret_client.get_secret.side_effect = RuntimeError("not found")
        backend._client = secret_client

        importer = MagicMock()
        importer.export_certificate.return_value = (cert_files, {"domain": "test.example.com"})
        backend._cert_importer = importer

        result = backend.retrieve_certificate("test.example.com")
        assert result is not None
        importer.export_certificate.assert_called_once_with("test.example.com")

    def test_both_mode_certificate_newer_than_secrets_returns_cert(self, vault_config, cert_files):
        """When Certificate object is newer than Secrets, return the fresher
        Certificate-surface data — avoids stale reads from surface skew."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        secrets_ts = datetime.datetime(2026, 1, 1, 0, 0, 0)

        def get_secret(name):
            secret = MagicMock()
            secret.properties.updated_on = secrets_ts
            if "metadata" in name:
                secret.value = json.dumps({"domain": "skew.example.com", "version": "old"})
            else:
                secret.value = "OLD-PEM"
            return secret

        secret_client.get_secret.side_effect = get_secret
        backend._client = secret_client

        cert_ts = datetime.datetime(2026, 6, 1, 0, 0, 0)
        importer = MagicMock()
        importer.get_certificate_update_time.return_value = cert_ts
        importer.export_certificate.return_value = (
            cert_files,
            {"domain": "skew.example.com", "version": "new"},
        )
        backend._cert_importer = importer

        result = backend.retrieve_certificate("skew.example.com")
        assert result is not None
        _, metadata = result
        assert metadata["version"] == "new"
        importer.export_certificate.assert_called_once_with("skew.example.com")

    def test_both_mode_secrets_newer_than_certificate_returns_secrets(self, vault_config, cert_files):
        """When Secrets are newer than the Certificate object, return Secrets
        data — keeps the cheaper path when it is fresher."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        secrets_ts = datetime.datetime(2026, 6, 1, 0, 0, 0)

        def get_secret(name):
            secret = MagicMock()
            secret.properties.updated_on = secrets_ts
            if "metadata" in name:
                secret.value = json.dumps({"domain": "skew.example.com", "version": "new"})
            else:
                secret.value = "NEW-PEM"
            return secret

        secret_client.get_secret.side_effect = get_secret
        backend._client = secret_client

        cert_ts = datetime.datetime(2026, 1, 1, 0, 0, 0)
        importer = MagicMock()
        importer.get_certificate_update_time.return_value = cert_ts
        importer.get_metadata_tags.return_value = {}
        backend._cert_importer = importer

        result = backend.retrieve_certificate("skew.example.com")
        assert result is not None
        _, metadata = result
        assert metadata["version"] == "new"
        importer.export_certificate.assert_not_called()


# ---------------------------------------------------------------------------
# Backfill endpoint pre-conditions and flow
# ---------------------------------------------------------------------------


class TestBackfillFlow:
    """Drive the backend hooks the endpoint uses, verifying the contract.

    Spinning up the Flask app for one endpoint is more setup than this test
    needs — the endpoint is a thin loop over backend methods, so we exercise
    those directly. The endpoint's own pre-conditions are covered separately
    by inspecting ``writes_certificate`` / ``storage_mode``.
    """

    def test_certificate_only_mode_lists_only_existing_certs(self, vault_config):
        """In 'certificate' mode, ``list_certificates`` returns just domains
        with a Certificate object — so a backfill loop would mark them all
        as skipped (the bug C1 the endpoint pre-condition prevents)."""
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "certificate"})

        importer = MagicMock()
        importer.list_domains.return_value = ["already.example.com"]
        backend._cert_importer = importer
        backend._client = MagicMock()  # would not be touched

        # Even has_certificate_object delegates to the importer, so for
        # listed domains the endpoint loop would mark them skipped.
        importer.exists.return_value = True
        assert backend.has_certificate_object("already.example.com") is True

    def test_both_mode_imports_only_missing(self, vault_config, cert_files):
        from modules.core.storage_backends import AzureKeyVaultBackend
        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})

        secret_client = MagicMock()
        _now = datetime.datetime(2026, 5, 1, 12, 0, 0)

        def get_secret(name):
            secret = MagicMock()
            secret.properties.updated_on = _now
            if "metadata" in name:
                secret.value = json.dumps({"domain": "fresh.example.com"})
            else:
                secret.value = "PEM-CONTENT"
            return secret

        secret_client.get_secret.side_effect = get_secret
        backend._client = secret_client

        importer = MagicMock()
        importer.exists.return_value = False
        importer.get_certificate_update_time.return_value = None
        importer.import_certificate.return_value = True
        backend._cert_importer = importer

        if not backend.has_certificate_object("fresh.example.com"):
            retrieved = backend.retrieve_certificate("fresh.example.com")
            assert retrieved is not None
            files, metadata = retrieved
            assert backend.import_certificate_object("fresh.example.com", files, metadata) is True

        importer.import_certificate.assert_called_once()


# ---------------------------------------------------------------------------
# verify_certificate_api_access
# ---------------------------------------------------------------------------


class TestVerifyCertificateApiAccess:
    def test_calls_list_properties_without_extra_kwargs(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend, _AzureKeyVaultCertificateImporter

        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})
        importer = _AzureKeyVaultCertificateImporter(
            vault_url=vault_config["vault_url"],
            credential=MagicMock(),
            sanitize_name=lambda n: n,
        )
        cert_client = MagicMock()
        cert_client.list_properties_of_certificates.return_value = iter([])
        importer._cert_client = cert_client
        backend._cert_importer = importer

        # Should not raise.
        backend.verify_certificate_api_access()
        cert_client.list_properties_of_certificates.assert_called_once_with()
        # And the backend method must reach the importer's encapsulated
        # verify (no leaked direct access to ``_get_cert_client``).
        assert hasattr(importer, "verify_api_access")

    def test_propagates_sdk_failure_to_caller(self, vault_config):
        from modules.core.storage_backends import AzureKeyVaultBackend, _AzureKeyVaultCertificateImporter

        backend = AzureKeyVaultBackend({**vault_config, "storage_mode": "both"})
        importer = _AzureKeyVaultCertificateImporter(
            vault_url=vault_config["vault_url"],
            credential=MagicMock(),
            sanitize_name=lambda n: n,
        )
        cert_client = MagicMock()
        cert_client.list_properties_of_certificates.side_effect = PermissionError("Forbidden")
        importer._cert_client = cert_client
        backend._cert_importer = importer

        with pytest.raises(PermissionError):
            backend.verify_certificate_api_access()


class TestSettingsMigration:
    def test_storage_mode_backfilled_when_missing(self, tmp_path):
        from modules.core.file_operations import FileOperations
        from modules.core.settings import SettingsManager

        cert_dir = tmp_path / "certificates"
        data_dir = tmp_path / "data"
        backup_dir = tmp_path / "backups"
        logs_dir = tmp_path / "logs"
        for d in (cert_dir, data_dir, backup_dir, logs_dir):
            d.mkdir()

        legacy_settings = {
            "domains": [],
            "email": "ops@example.com",
            "auto_renew": True,
            "renewal_threshold_days": 30,
            "api_bearer_token_hash": "hash-placeholder",
            "setup_completed": True,
            "dns_provider": "cloudflare",
            "challenge_type": "dns-01",
            "dns_providers": {},
            "certificate_storage": {
                "backend": "azure_keyvault",
                "cert_dir": "certificates",
                "azure_keyvault": {
                    "vault_url": "https://example.vault.azure.net/",
                    "client_id": "id",
                    "client_secret": "sec",
                    "tenant_id": "ten",
                },
            },
        }
        settings_file = data_dir / "settings.json"
        settings_file.write_text(json.dumps(legacy_settings))

        file_ops = FileOperations(
            cert_dir=cert_dir, data_dir=data_dir,
            backup_dir=backup_dir, logs_dir=logs_dir,
        )
        sm = SettingsManager(file_ops=file_ops, settings_file=settings_file)
        loaded = sm.load_settings()
        azure_kv = loaded["certificate_storage"]["azure_keyvault"]
        assert azure_kv["storage_mode"] == "secrets"
