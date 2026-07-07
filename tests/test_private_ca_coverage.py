"""
Coverage-focused unit tests for modules/core/private_ca.PrivateCAGenerator.

Before this file the module sat at 0% coverage. The CA is the root of trust
for every client certificate CertMate issues — a bug here invalidates every
downstream cert, and the absence of unit tests meant regressions could ship
silently. This file pins the contract for each public method against the
crypto primitives that actually run in production (the `cryptography`
library — no mocks).

The CA-generation step is expensive (~5-10s for the 4096-bit RSA keygen)
so we share one freshly-built CA across the whole module via a
module-scoped fixture, and have a separate per-test fixture for the
init/regenerate paths that need an empty directory.
"""
from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from modules.core.private_ca import PrivateCAGenerator


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def shared_ca_dir(tmp_path_factory):
    """One CA generated per test module — saves ~5-10s vs per-test keygen."""
    d = tmp_path_factory.mktemp("ca_shared")
    ca = PrivateCAGenerator(ca_dir=d)
    assert ca.initialize() is True, "shared CA fixture must initialize"
    return d


@pytest.fixture(scope="module")
def shared_ca(shared_ca_dir):
    """A loaded PrivateCAGenerator pointing at the module-shared CA on disk."""
    ca = PrivateCAGenerator(ca_dir=shared_ca_dir)
    assert ca.initialize() is True
    return ca


@pytest.fixture
def empty_ca_dir(tmp_path):
    """An empty directory for tests that need a fresh init path."""
    return tmp_path / "ca_empty"


def _make_csr(common_name: str, san_dns: list[str] | None = None,
              extended_key_usage: list = None) -> tuple[x509.CertificateSigningRequest, rsa.RSAPrivateKey]:
    """Build a real CSR for use in signing tests. RSA-2048 keeps it fast."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                   backend=default_backend())
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    if san_dns:
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )
    if extended_key_usage:
        csr_builder = csr_builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usage), critical=False,
        )
    csr = csr_builder.sign(key, hashes.SHA256(), backend=default_backend())
    return csr, key


# ---------------------------------------------------------------------------
# CA initialization & on-disk shape
# ---------------------------------------------------------------------------


class TestInitialization:
    def test_initialize_creates_key_cert_and_metadata(self, empty_ca_dir):
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert ca.initialize() is True
        assert ca.ca_key_path.exists()
        assert ca.ca_cert_path.exists()
        assert ca.ca_metadata_path.exists()

    def test_initialize_returns_false_when_dir_uncreatable(self, tmp_path):
        """A directory we cannot create (parent is a regular file) must
        surface as False without raising."""
        blocker = tmp_path / "is_a_file"
        blocker.write_text("not a directory")
        unreachable = blocker / "ca"
        ca = PrivateCAGenerator(ca_dir=unreachable)
        assert ca.initialize() is False

    def test_initialize_idempotent_loads_existing_ca(self, empty_ca_dir):
        first = PrivateCAGenerator(ca_dir=empty_ca_dir)
        first.initialize()
        cert_bytes_first = first.ca_cert_path.read_bytes()

        second = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert second.initialize() is True
        cert_bytes_second = second.ca_cert_path.read_bytes()
        assert cert_bytes_first == cert_bytes_second, (
            "Re-initializing on existing CA must NOT regenerate — that would "
            "invalidate every cert already signed by the previous CA"
        )

    def test_force_initialize_backs_up_and_regenerates(self, empty_ca_dir):
        first = PrivateCAGenerator(ca_dir=empty_ca_dir)
        first.initialize()
        old_serial = first.get_ca_certificate().serial_number

        second = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert second.initialize(force=True) is True
        new_serial = second.get_ca_certificate().serial_number

        assert new_serial != old_serial, "force=True must produce a new CA"
        backup_dir = empty_ca_dir / "backups"
        assert backup_dir.exists()
        assert any(p.suffix == ".key" for p in backup_dir.iterdir()), (
            "force=True must back up the old private key"
        )
        assert any(p.suffix == ".crt" for p in backup_dir.iterdir()), (
            "force=True must back up the old certificate"
        )


# ---------------------------------------------------------------------------
# CA certificate shape (the bit that determines whether downstream certs
# validate). This is the most important set of assertions in the file:
# if any of these drift, every issued client cert is suspect.
# ---------------------------------------------------------------------------


class TestCACertificateShape:
    def test_ca_uses_4096_bit_rsa(self, shared_ca):
        key = shared_ca.get_ca_private_key()
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_ca_certificate_is_self_signed(self, shared_ca):
        cert = shared_ca.get_ca_certificate()
        assert cert.subject == cert.issuer, "CA must be self-signed"

    def test_ca_certificate_has_basic_constraints_ca_true(self, shared_ca):
        cert = shared_ca.get_ca_certificate()
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.critical is True
        assert bc.value.ca is True, "basicConstraints.cA must be TRUE"

    def test_ca_certificate_has_key_usage_for_signing(self, shared_ca):
        cert = shared_ca.get_ca_certificate()
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True, (
            "KeyUsage.keyCertSign must be asserted — without it RFC 5280 "
            "validators reject downstream certs signed by this CA"
        )
        assert ku.value.crl_sign is True, "KeyUsage.cRLSign required for CRL issuance"
        assert ku.value.digital_signature is True

    def test_ca_validity_is_about_10_years(self, shared_ca):
        cert = shared_ca.get_ca_certificate()
        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        # 3650 ± 1 day for clock drift between not_valid_before assignment
        # and the test moment.
        assert 3648 <= validity_days <= 3651, (
            f"CA validity must be ~10 years; got {validity_days} days"
        )

    def test_ca_subject_advertises_certmate(self, shared_ca):
        cert = shared_ca.get_ca_certificate()
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn and cn[0].value == "CertMate CA"
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert org and org[0].value == "CertMate"

    def test_ca_certificate_signature_verifies_against_its_public_key(self, shared_ca):
        """RFC 5280 §6.1: a self-signed CA's signature must verify against
        its own SubjectPublicKey. If this fails the CA is structurally
        broken and nothing downstream will validate."""
        cert = shared_ca.get_ca_certificate()
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )  # raises InvalidSignature on failure

    @pytest.mark.skipif(os.name == "nt", reason="POSIX-only permission check")
    def test_ca_private_key_has_owner_only_perms(self, shared_ca):
        """0o600 — the private key must not be readable by group/other.
        On Windows the chmod is a no-op and the perm bits don't apply."""
        mode = stat.S_IMODE(os.stat(shared_ca.ca_key_path).st_mode)
        assert mode == 0o600, (
            f"CA private key must be 0o600 (owner read+write only); got {oct(mode)}"
        )


# ---------------------------------------------------------------------------
# Loaded-state guards. Operations that depend on a loaded CA must NOT
# silently succeed when the CA isn't loaded — they must return None.
# ---------------------------------------------------------------------------


class TestLoadedStateGuard:
    def test_is_ca_loaded_false_before_initialize(self, empty_ca_dir):
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert ca.is_ca_loaded() is False

    def test_sign_returns_none_when_ca_not_loaded(self, empty_ca_dir):
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        csr, _ = _make_csr("test.example.com")
        assert ca.sign_certificate_request(csr) is None

    def test_generate_crl_returns_none_when_ca_not_loaded(self, empty_ca_dir):
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert ca.generate_crl([]) is None


# ---------------------------------------------------------------------------
# Certificate signing — the security-critical workflow. Every assertion in
# this class blocks a class of compromise (wrong issuer => downstream cert
# trusts the wrong root; missing EKU => cert can be used for the wrong
# purpose; invalid signature => cert is forged from the CA's perspective).
# ---------------------------------------------------------------------------


class TestSignCertificateRequest:
    def test_signed_cert_keeps_csr_subject(self, shared_ca):
        csr, _ = _make_csr("alice@example.com")
        cert = shared_ca.sign_certificate_request(csr)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn and cn[0].value == "alice@example.com"

    def test_signed_cert_issuer_matches_ca_subject(self, shared_ca):
        csr, _ = _make_csr("test.example.com")
        cert = shared_ca.sign_certificate_request(csr)
        assert cert.issuer == shared_ca.get_ca_certificate().subject

    def test_signed_cert_validity_matches_days_valid(self, shared_ca):
        csr, _ = _make_csr("test.example.com")
        cert = shared_ca.sign_certificate_request(csr, days_valid=90)
        days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        assert 89 <= days <= 91

    def test_signed_cert_signature_verifies_against_ca_public_key(self, shared_ca):
        """The whole point of having a CA: a signed cert must verify against
        the CA's public key. If this assertion ever fails, the CA is broken
        and no downstream client will trust certs it issues."""
        csr, _ = _make_csr("test.example.com")
        cert = shared_ca.sign_certificate_request(csr)
        ca_pubkey = shared_ca.get_ca_certificate().public_key()
        ca_pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

    def test_signed_cert_carries_csr_san(self, shared_ca):
        csr, _ = _make_csr("multi.example.com",
                           san_dns=["multi.example.com", "alt.example.com"])
        cert = shared_ca.sign_certificate_request(csr)
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert sorted(dns_names) == ["alt.example.com", "multi.example.com"]

    def test_signed_cert_has_subject_key_identifier(self, shared_ca):
        csr, _ = _make_csr("test.example.com")
        cert = shared_ca.sign_certificate_request(csr)
        # Required by RFC 5280 §4.2.1.2 for path validation efficiency.
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        assert ski is not None

    def test_signed_cert_has_authority_key_identifier(self, shared_ca):
        csr, _ = _make_csr("test.example.com")
        cert = shared_ca.sign_certificate_request(csr)
        # Required to link the cert to the CA that issued it.
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        assert aki is not None

    def test_client_auth_eku_applied(self, shared_ca):
        csr, _ = _make_csr("client.example.com")
        cert = shared_ca.sign_certificate_request(csr, extended_key_usage=["clientAuth"])
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku.value, (
            "clientAuth EKU must not implicitly include serverAuth — a client "
            "cert that can authenticate a server is a privilege escalation"
        )

    def test_server_auth_eku_applied(self, shared_ca):
        csr, _ = _make_csr("server.example.com")
        cert = shared_ca.sign_certificate_request(csr, extended_key_usage=["serverAuth"])
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_unknown_eku_ignored_silently(self, shared_ca):
        """An unknown EKU string (typo, future-extension) must not crash the
        signer — the cert is issued without that EKU. The function logs a
        warning; the test only pins that no exception escapes."""
        csr, _ = _make_csr("test.example.com")
        cert = shared_ca.sign_certificate_request(csr, extended_key_usage=["bogusEKU"])
        assert cert is not None
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value
        except x509.ExtensionNotFound:
            pass  # acceptable — unknown EKU just produced no EKU extension


# ---------------------------------------------------------------------------
# CRL generation — wrong CRL == silent revocation bypass.
# ---------------------------------------------------------------------------


class TestGenerateCRL:
    def test_crl_pem_returned_with_empty_revoked_list(self, shared_ca):
        crl_pem = shared_ca.generate_crl([])
        assert crl_pem is not None
        crl = x509.load_pem_x509_crl(crl_pem)
        assert len(list(crl)) == 0

    def test_crl_carries_revoked_serials(self, shared_ca):
        serials = [123456789, 987654321, 555555]
        crl_pem = shared_ca.generate_crl(serials)
        crl = x509.load_pem_x509_crl(crl_pem)
        present = {entry.serial_number for entry in crl}
        assert present == set(serials), (
            f"CRL must contain exactly the revoked serials; missing="
            f"{set(serials)-present}, extra={present-set(serials)}"
        )

    def test_crl_issuer_matches_ca_subject(self, shared_ca):
        crl_pem = shared_ca.generate_crl([])
        crl = x509.load_pem_x509_crl(crl_pem)
        assert crl.issuer == shared_ca.get_ca_certificate().subject

    def test_crl_signature_verifies_against_ca(self, shared_ca):
        """An attacker could otherwise present a forged CRL to clear a
        revoked serial. Verifying the CA signed the CRL is the only thing
        between revocation enforcement and a silent bypass."""
        crl_pem = shared_ca.generate_crl([42])
        crl = x509.load_pem_x509_crl(crl_pem)
        ca_pubkey = shared_ca.get_ca_certificate().public_key()
        ca_pubkey.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            crl.signature_hash_algorithm,
        )

    def test_crl_persisted_to_disk(self, shared_ca):
        shared_ca.generate_crl([1, 2, 3])
        assert shared_ca.crl_path.exists()
        assert shared_ca.crl_path.read_bytes() == shared_ca.get_crl_pem()

    def test_get_crl_pem_returns_none_when_not_yet_generated(self, empty_ca_dir):
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        ca.initialize()
        # No generate_crl yet — file shouldn't exist.
        assert ca.get_crl_pem() is None


# ---------------------------------------------------------------------------
# FIX 1 — CA private key must be 0600 from the first byte on disk, and the
# write must be crash-safe (atomic rename). The old open()+chmod pattern left
# the root CA key world-readable under the umask for a window, and a crash
# mid-write left a corrupt CA. These pin both properties.
# ---------------------------------------------------------------------------


class TestCAKeyFilePermissions:
    def test_ca_key_final_mode_is_0600(self, empty_ca_dir):
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert ca.initialize() is True
        mode = stat.S_IMODE(os.stat(ca.ca_key_path).st_mode)
        assert mode == 0o600, f"CA key mode must be 0600, got {oct(mode)}"
        assert not (mode & 0o077), "CA private key must not be group/other accessible"

    def test_ca_key_is_0600_at_the_instant_it_goes_live(self, empty_ca_dir, monkeypatch):
        """Spy on os.replace: capture the mode of the temp file at the exact
        instant it is renamed over ca.key. Because the temp is created 0600 by
        mkstemp and never widened, the key is provably never world-readable at
        any point — not merely 0600 after the fact."""
        captured = {}
        real_replace = os.replace

        def spy_replace(src, dst):
            if str(dst).endswith("ca.key"):
                captured["mode"] = stat.S_IMODE(os.stat(src).st_mode)
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", spy_replace)
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert ca.initialize() is True
        assert captured.get("mode") == 0o600, (
            "the file that becomes ca.key must be 0600 at rename time, never 0644"
        )

    def test_ca_cert_is_locked_down_and_atomic(self, empty_ca_dir):
        ca = PrivateCAGenerator(ca_dir=empty_ca_dir)
        assert ca.initialize() is True
        # The CA cert is served over HTTP by certmate, not read off disk by
        # other users, so the whole CA dir stays 0600 (no world-read). The
        # atomic rename must also leave no stray .tmp- files on success.
        cert_mode = stat.S_IMODE(os.stat(ca.ca_cert_path).st_mode)
        assert cert_mode == 0o600, f"CA cert should be 0600, got {oct(cert_mode)}"
        assert not (cert_mode & 0o077), "CA cert must not be group/other accessible"
        leftovers = list(empty_ca_dir.glob(".tmp-*"))
        assert not leftovers, f"atomic write left temp files behind: {leftovers}"


# ---------------------------------------------------------------------------
# FIX 2 — CRL must preserve each entry's persisted revocation date across
# regenerations (not stamp them all with now()) and carry a CRLReason.
# ---------------------------------------------------------------------------


class TestCRLRevocationDateAndReason:
    def test_crl_preserves_revoked_at_and_reason_across_regeneration(self, shared_ca):
        from cryptography.x509.oid import CRLEntryExtensionOID

        fixed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        record = {
            "serial_number": 424242,
            "revoked_at": "2026-01-02T03:04:05",  # naive == UTC
            "reason_revoked": "keyCompromise",
        }

        # First regeneration.
        pem1 = shared_ca.generate_crl([record])
        crl1 = x509.load_pem_x509_crl(pem1)
        entry1 = crl1.get_revoked_certificate_by_serial_number(424242)
        assert entry1 is not None
        assert entry1.revocation_date_utc == fixed
        reason1 = entry1.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON)
        assert reason1.value.reason == x509.ReasonFlags.key_compromise

        # Second regeneration with the original record PLUS a newer revocation.
        # The bug was that generate_crl stamped EVERY entry with now(), so the
        # older entry's date silently moved forward on each regen.
        pem2 = shared_ca.generate_crl([
            record,
            {"serial_number": 999, "revoked_at": None, "reason_revoked": None},
        ])
        crl2 = x509.load_pem_x509_crl(pem2)
        entry2 = crl2.get_revoked_certificate_by_serial_number(424242)
        assert entry2.revocation_date_utc == fixed, (
            "regeneration must NOT rewrite an older entry's revocation_date"
        )

    def test_int_serial_entry_has_no_crl_reason(self, shared_ca):
        """Legacy bare-int entries stay supported: they revoke at 'now' with
        no CRLReason (RFC 5280 unspecified SHOULD be absent)."""
        from cryptography import x509 as _x

        pem = shared_ca.generate_crl([778899])
        crl = _x.load_pem_x509_crl(pem)
        entry = crl.get_revoked_certificate_by_serial_number(778899)
        assert entry is not None
        assert not list(entry.extensions), "int entry must carry no CRL entry extensions"

    def test_unspecified_reason_adds_no_crl_reason_extension(self, shared_ca):
        pem = shared_ca.generate_crl([
            {"serial_number": 5150, "revoked_at": None, "reason_revoked": "unspecified"},
        ])
        crl = x509.load_pem_x509_crl(pem)
        entry = crl.get_revoked_certificate_by_serial_number(5150)
        assert not list(entry.extensions), "'unspecified' must not emit a CRLReason"


# ---------------------------------------------------------------------------
# FIX 4 — signing must NOT copy BasicConstraints / KeyUsage from an untrusted
# CSR. A CSR asking for ca=True + keyCertSign must yield a pinned leaf.
# ---------------------------------------------------------------------------


class TestSignRejectsCAEscalation:
    @staticmethod
    def _malicious_csr():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                       backend=default_backend())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.example.com")])
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(name)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("evil.example.com")]),
                critical=False,
            )
        )
        return builder.sign(key, hashes.SHA256(), backend=default_backend())

    def test_ca_true_csr_yields_leaf_basic_constraints_false(self, shared_ca):
        cert = shared_ca.sign_certificate_request(self._malicious_csr())
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.value.ca is False, "signer must force BasicConstraints ca=False"
        assert bc.critical is True

    def test_key_cert_sign_from_csr_is_stripped(self, shared_ca):
        cert = shared_ca.sign_certificate_request(self._malicious_csr())
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ku.value.key_cert_sign is False, "leaf must not be able to sign certs"
        assert ku.value.crl_sign is False, "leaf must not be able to sign CRLs"
        assert ku.value.digital_signature is True

    def test_san_still_carried_over_from_csr(self, shared_ca):
        """Hardening must not throw the baby out: SAN is the one extension we
        still honor from the CSR."""
        cert = shared_ca.sign_certificate_request(self._malicious_csr())
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        # Equality per element (not a substring `in` check) so the static
        # analyzer does not read this as URL-substring sanitization.
        assert any(name == "evil.example.com" for name in dns_names)


# ---------------------------------------------------------------------------
# Metadata round-trip.
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_metadata_records_key_size_and_serial(self, shared_ca):
        meta = shared_ca.get_ca_metadata()
        assert meta is not None
        assert meta["key_size"] == 4096
        assert meta["common_name"] == "CertMate CA"
        # Serial number is stored as string because Python ints are bigger
        # than the IEEE 754 doubles JSON encodes natively.
        assert str(shared_ca.get_ca_certificate().serial_number) == meta["serial_number"]


# ---------------------------------------------------------------------------
# PEM export.
# ---------------------------------------------------------------------------


class TestPEMExport:
    def test_get_ca_cert_pem_is_parseable(self, shared_ca):
        pem = shared_ca.get_ca_cert_pem()
        assert pem and pem.startswith(b"-----BEGIN CERTIFICATE-----")
        x509.load_pem_x509_certificate(pem)  # raises on failure

    def test_export_ca_cert_writes_pem(self, shared_ca, tmp_path):
        out = tmp_path / "exported_ca.pem"
        assert shared_ca.export_ca_cert(out) is True
        assert out.exists()
        x509.load_pem_x509_certificate(out.read_bytes())  # raises on failure


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
