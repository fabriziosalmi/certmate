"""certbot's command line gets a certificate from CertMate's ACME server (#1484).

The server sent the leaf alone (decision G3 on #476: the root goes into trust
stores from /acme/root), and certbot 5.8.0 splits what it downloads into a
certificate and a chain and refuses one certificate: "failed to parse
fullchain into cert and chain: less than 2 certificates in chain". It
registered, proved http-01 and finalized, then wrote nothing. lego, acme.sh
and cert-manager accept the leaf alone, which is why the interoperability runs
passed.

The download now carries the root after the leaf. A root in the chain is
redundant for a TLS server, and allowed (RFC 8446 section 4.4.2); it keeps the
design of signing leaves from the root (G2), and is applied at download, so a
certificate issued before reads the same way.

The real certbot, against the real server in process, EAB required, http-01
answered by certbot --standalone (the harness of #1461's test).
"""
import pytest
from cryptography import x509

from tests.test_the_eab_key_stays_out_of_certbots_log import _issue, acme_server_requiring_eab  # noqa: F401

pytestmark = [pytest.mark.unit]


def test_certbot_writes_the_certificate_and_its_chain(acme_server_requiring_eab, tmp_path, monkeypatch):  # noqa: F811
    entry, directory, http01_port = acme_server_requiring_eab
    result, lineage, _logs = _issue(tmp_path, monkeypatch, directory, http01_port,
                                    {'eab_kid': entry['kid'], 'eab_hmac': entry['hmac_key']})

    assert result.returncode == 0, result.stderr[-2000:]
    fullchain = x509.load_pem_x509_certificates((lineage / 'fullchain.pem').read_bytes())
    leaf = x509.load_pem_x509_certificate((lineage / 'cert.pem').read_bytes())
    chain = x509.load_pem_x509_certificates((lineage / 'chain.pem').read_bytes())
    assert [c.subject for c in fullchain] == [leaf.subject, chain[0].subject]
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ['eab.lab.internal']
    leaf.verify_directly_issued_by(chain[0])
    assert chain[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
