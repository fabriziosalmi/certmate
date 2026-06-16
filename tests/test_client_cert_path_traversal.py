"""Regression: a malicious Common Name cannot escape the client-cert tree.

modules/core/client_certificates.py built the on-disk identifier straight from
the CN (only spaces replaced) and ran ``cert_subdir.mkdir(parents=True)`` before
anything else. A CN like ``../../../../tmp/evil`` therefore created — and wrote
a CA-signed key + cert + metadata into — a directory OUTSIDE the managed tree.
The pre-existing ``_validate_identifier`` guard was only ever applied on
*retrieval*, never to the value that *constructs* the identifier.

The fix slugifies the CN at the construction site (covering single + batch +
any future caller) and asserts containment before mkdir. Benign CNs keep their
old identifier byte-for-byte.
"""
from pathlib import Path

import pytest

from modules.core.client_certificates import (
    ClientCertificateManager,
    _slugify_common_name,
)
from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    pca = PrivateCAGenerator(tmp_path_factory.mktemp("ca"))
    assert pca.initialize() is True
    return pca


@pytest.fixture
def mgr(ca, tmp_path):
    return ClientCertificateManager(tmp_path / "client-certs", ca)


@pytest.mark.parametrize("cn", [
    "../../../../tmp/cm_pwned/evil",
    "../escape",
    "a/b/c",
    "..\\..\\win",
    "x\x00y",
    "..",
])
def test_malicious_common_name_stays_inside_tree(mgr, cn, tmp_path):
    ok, _err, data = mgr.create_client_certificate(common_name=cn)
    root = (tmp_path / "client-certs").resolve()
    if ok:
        ident = data["identifier"]
        assert "/" not in ident and "\\" not in ident and ".." not in ident
        for p in data["paths"].values():
            if p:
                assert Path(p).resolve().is_relative_to(root), f"escaped tree: {p}"
    # In no case may anything be written outside the client-cert root: the
    # only child of tmp_path must remain the manager's own directory.
    assert not (tmp_path / "cm_pwned").exists()
    assert {p.name for p in tmp_path.iterdir()} == {"client-certs"}


def test_slug_is_filesystem_safe():
    assert _slugify_common_name("../../etc/passwd") == "etc-passwd"
    assert _slugify_common_name("..\\..\\win") == "win"
    assert _slugify_common_name("a..b") == "a.b"          # traversal token killed
    assert _slugify_common_name("///") == "client"
    assert _slugify_common_name("") == "client"
    assert _slugify_common_name("x\x00y") == "x-y"


def test_benign_cn_unchanged_and_retrievable(mgr):
    # Dots / spaces behave exactly as the old code did, so the identifier and
    # therefore existing retrieval paths are unaffected.
    assert _slugify_common_name("svc.example.com") == "svc.example.com"
    assert _slugify_common_name("John Doe") == "john-doe"

    ok, err, data = mgr.create_client_certificate(common_name="svc.example.com")
    assert ok, err
    ident = data["identifier"]
    assert ident.startswith("svc.example.com-")
    assert mgr.get_certificate_file(ident, "crt")
