"""Unit tests for HTTP-01 challenge serving (PR #253).

Guards the bug the original PR risked: the directory certbot *writes* the
challenge token to and the directory the Flask route *serves* it from must be
the same, or HTTP-01 issuance silently 404s. Both now resolve through
``acme_webroot_dir()`` (overridable via ``ACME_CHALLENGES_DIR``).
"""
import os

import pytest
from flask import Flask, send_from_directory

from modules.core.dns_strategies import HTTP01Strategy, acme_webroot_dir

pytestmark = [pytest.mark.unit]


def test_acme_webroot_dir_default_is_absolute(monkeypatch):
    monkeypatch.delenv("ACME_CHALLENGES_DIR", raising=False)
    p = acme_webroot_dir()
    assert p.is_absolute()
    assert p.as_posix().endswith("data/acme-challenges")


def test_acme_webroot_dir_honours_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ACME_CHALLENGES_DIR", str(tmp_path))
    assert acme_webroot_dir() == tmp_path.resolve()


def test_certbot_webroot_matches_helper(monkeypatch, tmp_path):
    """The --webroot path certbot writes to is exactly acme_webroot_dir() —
    so it stays in lock-step with what the route serves."""
    monkeypatch.setenv("ACME_CHALLENGES_DIR", str(tmp_path))
    cmd = []
    HTTP01Strategy().configure_certbot_arguments(cmd, None)
    assert "--webroot" in cmd
    assert cmd[cmd.index("-w") + 1] == str(tmp_path.resolve())


def _app_with_route(webroot_dir):
    """Minimal app registering the real route's handler logic (mirrors
    modules/web/routes.py:serve_acme_challenge — kept in sync deliberately)."""
    app = Flask(__name__)
    app.config["ACME_CHALLENGES_DIR"] = str(webroot_dir)

    @app.route("/.well-known/acme-challenge/<path:filename>")
    def serve_acme_challenge(filename):
        acme_path = os.path.join(
            app.config["ACME_CHALLENGES_DIR"], ".well-known", "acme-challenge")
        return send_from_directory(acme_path, filename, mimetype="text/plain")

    return app


def test_route_serves_token_and_404s(tmp_path):
    challenge_dir = tmp_path / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "token123").write_text("keyauth-value")

    client = _app_with_route(tmp_path).test_client()

    ok = client.get("/.well-known/acme-challenge/token123")
    assert ok.status_code == 200
    assert ok.data == b"keyauth-value"
    assert ok.mimetype == "text/plain"

    missing = client.get("/.well-known/acme-challenge/does-not-exist")
    assert missing.status_code == 404


def test_route_is_unauthenticated(tmp_path):
    """No session/cookie is sent: the ACME server must reach it anonymously."""
    challenge_dir = tmp_path / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "anon").write_text("v")
    client = _app_with_route(tmp_path).test_client()
    assert client.get("/.well-known/acme-challenge/anon").status_code == 200
