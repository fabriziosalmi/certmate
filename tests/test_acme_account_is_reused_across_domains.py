"""A batch of new domains must not become a batch of new ACME accounts.

`--config-dir` is per domain (`ca_manager.build_certbot_command`), and certbot
keeps its ACME account under the config dir. So every new domain registered a
brand-new account with the CA.

That is not a rounding error in this product: `POST /api/web/certificates/batch`
accepts **50 domains in one request** (`cert_routes.py:84`), and 50 domains was
50 account registrations from one IP in one run — which no CA allows. It also
left 50 account private keys on disk, each one a credential that every backup
then carried.

The fix copies a sibling domain's `accounts/` tree in before certbot runs, so
certbot finds a registered account and skips registration. It cannot bind a
certificate to the wrong account: certbot indexes accounts by the ACME
directory URL, so a tree that does not match the `--server` in use is ignored
and certbot registers exactly as before. Matching on ca_provider and
ca_account_id is the belt-and-braces on top, for two CA accounts with different
EAB credentials on the same server.

Best-effort by design: any failure leaves the directory untouched and the run
proceeds unchanged. This is an optimisation on the issuance path, and the
issuance path must not acquire a new way to fail.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    cert_dir.mkdir()
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {}
    return CertificateManager(
        cert_dir=cert_dir, settings_manager=settings_manager,
        dns_manager=MagicMock()), cert_dir


def _seed_domain(cert_dir, name, *, ca_provider="letsencrypt", ca_account_id=None,
                 with_account=True):
    """A domain directory as certbot leaves it, with or without an account."""
    domain_dir = cert_dir / name
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "metadata.json").write_text(json.dumps({
        "domain": name, "ca_provider": ca_provider, "ca_account_id": ca_account_id,
    }), encoding="utf-8")
    if with_account:
        account = domain_dir / "accounts" / "acme-v02.api.letsencrypt.org" / "directory" / "abc123"
        account.mkdir(parents=True)
        (account / "private_key.json").write_text('{"n": "account-key"}', encoding="utf-8")
        (account / "regr.json").write_text('{"uri": "https://acme/acct/1"}', encoding="utf-8")
    return domain_dir


def _accounts(domain_dir):
    return sorted(p.name for p in (domain_dir / "accounts").rglob("*.json"))


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------

def test_a_new_domain_reuses_a_siblings_account(manager):
    cert_manager, cert_dir = manager
    _seed_domain(cert_dir, "first.example.com")
    (cert_dir / "second.example.com").mkdir()

    donor = cert_manager._seed_acme_account(
        "second.example.com", cert_dir, "letsencrypt", None)

    assert donor == "first.example.com"
    assert _accounts(cert_dir / "second.example.com") == ["private_key.json", "regr.json"], (
        "the account tree was not copied, so certbot will register a new "
        "account for this domain"
    )


def test_a_domain_that_already_has_an_account_is_left_alone(manager):
    """Never clobber a registered account with somebody else's."""
    cert_manager, cert_dir = manager
    _seed_domain(cert_dir, "first.example.com")
    existing = _seed_domain(cert_dir, "second.example.com")
    (existing / "accounts" / "acme-v02.api.letsencrypt.org" / "directory" / "abc123"
     / "private_key.json").write_text('{"n": "its-own-key"}', encoding="utf-8")

    donor = cert_manager._seed_acme_account(
        "second.example.com", cert_dir, "letsencrypt", None)

    assert donor is None
    key = (existing / "accounts" / "acme-v02.api.letsencrypt.org" / "directory"
           / "abc123" / "private_key.json").read_text(encoding="utf-8")
    assert "its-own-key" in key, "an existing account key was overwritten"


def test_a_different_ca_provider_is_not_a_donor(manager):
    cert_manager, cert_dir = manager
    _seed_domain(cert_dir, "first.example.com", ca_provider="zerossl")
    (cert_dir / "second.example.com").mkdir()

    assert cert_manager._seed_acme_account(
        "second.example.com", cert_dir, "letsencrypt", None) is None


def test_a_different_ca_account_is_not_a_donor(manager):
    """Two accounts on one server, told apart by their EAB credentials."""
    cert_manager, cert_dir = manager
    _seed_domain(cert_dir, "first.example.com", ca_account_id="production")
    (cert_dir / "second.example.com").mkdir()

    assert cert_manager._seed_acme_account(
        "second.example.com", cert_dir, "letsencrypt", "staging") is None


def test_a_failure_never_reaches_the_caller(manager):
    """The issuance path must not gain a new way to fail."""
    cert_manager, cert_dir = manager
    _seed_domain(cert_dir, "first.example.com")
    (cert_dir / "second.example.com").mkdir()

    with patch("modules.core.certificates.shutil.copytree",
               side_effect=OSError("disk full")):
        assert cert_manager._seed_acme_account(
            "second.example.com", cert_dir, "letsencrypt", None) is None

    assert not (cert_dir / "second.example.com" / "accounts").exists() or \
        not list((cert_dir / "second.example.com" / "accounts").rglob("*.json"))


# --------------------------------------------------------------------------
# The real path
# --------------------------------------------------------------------------

def test_the_issuance_path_seeds_before_certbot_runs(manager):
    """Pin the wiring: it is the create path that must do this, not a helper
    nobody calls. Ordering matters — after certbot has run it is too late."""
    cert_manager, cert_dir = manager
    seen = {}

    def record(domain, cd, ca_provider, ca_account_id):
        seen['called'] = (domain, ca_provider, ca_account_id)
        return None

    with patch.object(CertificateManager, "_seed_acme_account", side_effect=record):
        with patch.object(cert_manager, "shell_executor") as shell:
            shell.run.side_effect = AssertionError(
                "certbot ran before the account was seeded"
                if 'called' not in seen else "stop here")
            try:
                cert_manager.create_certificate(
                    domain="new.example.com", email="ops@example.com",
                    dns_provider="cloudflare", dns_config={"api_token": "t"},
                    ca_provider="letsencrypt")
            except Exception:
                pass

    assert seen.get('called'), (
        "create_certificate never seeded the ACME account; every new domain "
        "will keep registering its own"
    )
    assert seen['called'][0] == "new.example.com"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
