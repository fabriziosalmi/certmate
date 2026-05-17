"""
Coverage-focused unit tests for modules/core/csr_handler.CSRHandler.

Before this file the module sat at 0% coverage. CSR validation is the
entry-point for the client-certificate issuance flow — every malformed,
oversized, or malicious CSR passes through `validate_csr_pem` before
PrivateCA signs it. A regression in the validator can either lock out
legitimate users (false reject) or let through malformed input that
crashes downstream signing code (false accept).

Tests group by method and target a specific failure mode per case.
Real CSRs built with the `cryptography` library — no mocks of crypto.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from modules.core.csr_handler import CSRHandler


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_csr_pem(common_name: str = "alice@example.com",
                   san_dns: list[str] | None = None,
                   san_email: list[str] | None = None,
                   key_size: int = 2048) -> bytes:
    """Produce a valid PEM-encoded CSR for use in validator tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size,
                                   backend=default_backend())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    sans = []
    if san_dns:
        sans.extend(x509.DNSName(d) for d in san_dns)
    if san_email:
        sans.extend(x509.RFC822Name(e) for e in san_email)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    csr = builder.sign(key, hashes.SHA256(), backend=default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)


def _csr_without_cn_pem() -> bytes:
    """Build a CSR whose subject has NO CommonName. Used to verify the
    validator rejects this corner case rather than silently passing it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                   backend=default_backend())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NoCN"),
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        key, hashes.SHA256(), backend=default_backend()
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# validate_csr_pem — the security-critical entry point.
# ---------------------------------------------------------------------------


class TestValidateCSRPem:
    def test_valid_csr_accepted(self):
        pem = _build_csr_pem("valid@example.com")
        ok, err, csr = CSRHandler.validate_csr_pem(pem)
        assert ok is True
        assert err is None
        assert csr is not None
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "valid@example.com"

    def test_empty_bytes_rejected(self):
        ok, err, csr = CSRHandler.validate_csr_pem(b"")
        assert ok is False
        assert err == "CSR is empty"
        assert csr is None

    def test_none_input_rejected_gracefully(self):
        ok, err, csr = CSRHandler.validate_csr_pem(None)
        assert ok is False
        # Empty / None must both be rejected — the explicit message for
        # empty bytes, anything else surfaces as the generic message.
        assert err is not None
        assert csr is None

    def test_garbage_pem_rejected(self):
        ok, err, csr = CSRHandler.validate_csr_pem(b"not a real PEM file at all")
        assert ok is False
        assert err is not None
        assert csr is None

    def test_truncated_pem_rejected(self):
        truncated = _build_csr_pem()[:50]  # drop the body
        ok, err, csr = CSRHandler.validate_csr_pem(truncated)
        assert ok is False
        assert csr is None

    def test_csr_without_common_name_rejected(self):
        """A CSR with no CN cannot be issued meaningfully — the cert needs
        an identity. The validator must catch this rather than letting
        the signer produce an unidentifiable cert."""
        pem = _csr_without_cn_pem()
        ok, err, csr = CSRHandler.validate_csr_pem(pem)
        assert ok is False
        assert err == "CSR has no Common Name"

    def test_validator_returns_csr_object_callers_can_pass_to_signer(self):
        """The validate→sign handoff is currently:
            ok, _, csr = validate_csr_pem(pem)
            sign_certificate_request(csr, ...)
        — so the validator MUST return the parsed CSR on success, not
        force the caller to re-parse the PEM (which would mean the
        validation was decorative)."""
        pem = _build_csr_pem("downstream@example.com")
        ok, _, csr = CSRHandler.validate_csr_pem(pem)
        assert isinstance(csr, x509.CertificateSigningRequest)


# ---------------------------------------------------------------------------
# get_csr_info — extracts data the UI / API surfaces to humans.
# ---------------------------------------------------------------------------


class TestGetCSRInfo:
    def test_extracts_common_name_and_org(self):
        pem = _build_csr_pem("info@example.com")
        _, _, csr = CSRHandler.validate_csr_pem(pem)
        info = CSRHandler.get_csr_info(csr)
        assert info["common_name"] == "info@example.com"
        assert info["organization"] == "Test"
        assert info["country"] == "US"

    def test_missing_subject_fields_default_to_empty_string(self):
        """Optional subject fields (OU, locality, email) must NOT raise
        KeyError when absent — the UI assumes a dict with all keys."""
        pem = _build_csr_pem("minimal@example.com")
        _, _, csr = CSRHandler.validate_csr_pem(pem)
        info = CSRHandler.get_csr_info(csr)
        for k in ("organizational_unit", "locality", "email", "state"):
            assert info.get(k) == "", (
                f"{k} should default to empty string for missing field, got {info.get(k)!r}"
            )

    def test_reports_key_size(self):
        pem = _build_csr_pem("k@example.com", key_size=2048)
        _, _, csr = CSRHandler.validate_csr_pem(pem)
        assert CSRHandler.get_csr_info(csr)["key_size"] == 2048

    def test_extracts_dns_sans(self):
        pem = _build_csr_pem("san@example.com",
                             san_dns=["alt1.example.com", "alt2.example.com"])
        _, _, csr = CSRHandler.validate_csr_pem(pem)
        sans = CSRHandler.get_csr_info(csr)["subject_alt_names"]
        dns_pairs = sorted(s for s in sans if s[0] == "DNS")
        assert dns_pairs == [("DNS", "alt1.example.com"), ("DNS", "alt2.example.com")]

    def test_extracts_email_sans(self):
        pem = _build_csr_pem("e@example.com", san_email=["x@example.com"])
        _, _, csr = CSRHandler.validate_csr_pem(pem)
        sans = CSRHandler.get_csr_info(csr)["subject_alt_names"]
        assert ("Email", "x@example.com") in sans

    def test_no_san_extension_returns_empty_list(self):
        pem = _build_csr_pem("nosan@example.com")
        _, _, csr = CSRHandler.validate_csr_pem(pem)
        assert CSRHandler.get_csr_info(csr)["subject_alt_names"] == []

    def test_reports_signature_algorithm(self):
        pem = _build_csr_pem("sig@example.com")
        _, _, csr = CSRHandler.validate_csr_pem(pem)
        # cryptography's _name is something like "sha256WithRSAEncryption".
        assert "sha256" in CSRHandler.get_csr_info(csr)["signature_algorithm"].lower()


# ---------------------------------------------------------------------------
# create_csr — input validation. The bulk of the security work is here:
# reject obviously bad input before it reaches the cryptographic builder.
# ---------------------------------------------------------------------------


class TestCreateCSR:
    def test_creates_valid_csr_with_defaults(self):
        csr_pem, key_pem, err = CSRHandler.create_csr("test@example.com")
        assert err is None
        assert csr_pem is not None and key_pem is not None
        assert csr_pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
        assert key_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        # Round-trip — the produced CSR must validate.
        ok, _, _ = CSRHandler.validate_csr_pem(csr_pem)
        assert ok is True

    def test_creates_csr_with_4096_key(self):
        csr_pem, _, err = CSRHandler.create_csr("k4096@example.com", key_size=4096)
        assert err is None
        _, _, csr = CSRHandler.validate_csr_pem(csr_pem)
        assert csr.public_key().key_size == 4096

    @pytest.mark.parametrize("bad_size", [512, 1024, 3072, 8192, 0, -1])
    def test_rejects_invalid_key_sizes(self, bad_size):
        csr_pem, key_pem, err = CSRHandler.create_csr("k@example.com", key_size=bad_size)
        assert csr_pem is None and key_pem is None
        assert err == "Key size must be 2048 or 4096"

    def test_rejects_empty_common_name(self):
        csr_pem, _, err = CSRHandler.create_csr("")
        assert csr_pem is None
        assert "Common name" in (err or "")

    def test_rejects_oversized_common_name(self):
        """RFC 5280: CN UTF-8 String is bounded at 64 characters."""
        csr_pem, _, err = CSRHandler.create_csr("x" * 65)
        assert csr_pem is None
        assert "1-64 characters" in (err or "")

    @pytest.mark.parametrize("evil_cn", [
        "name\x00null",            # null byte injection
        "name\nLDAP injection",    # newline
        "name\rcr injection",      # carriage return
        "tab\there",               # tab
        "\x1f",                    # DEL-area control char
    ])
    def test_rejects_control_characters_in_cn(self, evil_cn):
        """Control characters in the CN can corrupt downstream log parsers,
        certbot stderr handling, or LDAP integrations. Reject early."""
        csr_pem, _, err = CSRHandler.create_csr(evil_cn)
        assert csr_pem is None
        assert "control characters" in (err or "").lower()

    def test_rejects_too_many_sans(self):
        """100-SAN ceiling is documented; over that = DoS via slow signing
        + bloated cert. Test the boundary."""
        too_many = [f"san{i}.example.com" for i in range(101)]
        csr_pem, _, err = CSRHandler.create_csr("many@example.com",
                                                alternative_names=too_many)
        assert csr_pem is None
        assert "maximum 100" in (err or "")

    def test_accepts_exactly_100_sans(self):
        """The boundary: exactly 100 SANs MUST be accepted."""
        sans = [f"san{i}.example.com" for i in range(100)]
        csr_pem, _, err = CSRHandler.create_csr("max@example.com",
                                                alternative_names=sans)
        assert err is None
        assert csr_pem is not None

    def test_san_extension_persisted_in_csr(self):
        csr_pem, _, _ = CSRHandler.create_csr("san@example.com",
                                              alternative_names=["alt.example.com"])
        _, _, csr = CSRHandler.validate_csr_pem(csr_pem)
        ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names = ext.value.get_values_for_type(x509.DNSName)
        assert "alt.example.com" in names

    def test_key_usage_extension_added_critical(self):
        csr_pem, _, _ = CSRHandler.create_csr("ku@example.com")
        _, _, csr = CSRHandler.validate_csr_pem(csr_pem)
        ku_ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        assert ku_ext.critical is True
        assert ku_ext.value.digital_signature is True
        # Client cert keys must NOT be allowed to sign certs.
        assert ku_ext.value.key_cert_sign is False, (
            "key_cert_sign on a non-CA CSR would let a holder mint sub-certs "
            "if the issuer accepted CSR extensions blindly"
        )


# ---------------------------------------------------------------------------
# save_csr_and_key + load_csr_from_file — round-trip with permissions.
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_save_writes_both_files(self, tmp_path):
        csr_pem, key_pem, _ = CSRHandler.create_csr("save@example.com")
        ok, csr_path, key_path = CSRHandler.save_csr_and_key(
            csr_pem, key_pem, tmp_path, "saveme"
        )
        assert ok is True
        assert Path(csr_path).exists()
        assert Path(key_path).exists()
        assert Path(csr_path).suffix == ".csr"
        assert Path(key_path).suffix == ".key"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX-only permission check")
    def test_saved_key_is_0600(self, tmp_path):
        """A CSR's accompanying private key must NOT be world/group-readable
        — it's the same private key the cert will be issued against."""
        csr_pem, key_pem, _ = CSRHandler.create_csr("perm@example.com")
        ok, _, key_path = CSRHandler.save_csr_and_key(
            csr_pem, key_pem, tmp_path, "perm"
        )
        assert ok is True
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600, f"saved key must be 0o600; got {oct(mode)}"

    def test_load_csr_from_file_round_trip(self, tmp_path):
        csr_pem, key_pem, _ = CSRHandler.create_csr("rt@example.com")
        ok, csr_path, _ = CSRHandler.save_csr_and_key(
            csr_pem, key_pem, tmp_path, "roundtrip"
        )
        ok, err, csr = CSRHandler.load_csr_from_file(Path(csr_path))
        assert ok is True
        assert err is None
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "rt@example.com"

    def test_load_csr_from_missing_file_returns_false(self, tmp_path):
        ok, err, csr = CSRHandler.load_csr_from_file(tmp_path / "nope.csr")
        assert ok is False
        assert csr is None
        assert err is not None

    def test_load_csr_from_garbage_file_returns_false(self, tmp_path):
        bogus = tmp_path / "bogus.csr"
        bogus.write_bytes(b"this is not a CSR")
        ok, err, csr = CSRHandler.load_csr_from_file(bogus)
        assert ok is False
        assert csr is None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
