"""Something must run the acme-dns suite, and against a real server.

acme-dns is the path with the worst precedent in this product: the certbot
plugin CertMate used until v2.24.0 exposed no credentials-file option, so every
acme-dns issuance failed in every release that advertised the feature. The
replacement was verified by hand, once. This is the wiring that keeps it
verified.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SUITE = REPO_ROOT / "tests" / "test_acme_dns_live.py"

pytestmark = [pytest.mark.unit]


def test_the_suite_exists():
    assert SUITE.exists()


def test_a_workflow_runs_it():
    text = CI.read_text(encoding="utf-8")
    assert "test_acme_dns_live.py" in text, "no workflow runs the acme-dns suite"
    assert "joohoi/acme-dns" in text, (
        "the workflow does not start an acme-dns, so the suite would skip — "
        "which is what it does when its endpoint is unset."
    )


def test_the_workflow_starts_the_database_acme_dns_needs():
    """The official image is built without the sqlite driver.

    Without postgres it starts, serves DNS, and dies on the first API call
    with `sql: unknown driver "sqlite3"` — which cost an hour the first time.
    """
    text = CI.read_text(encoding="utf-8")
    assert re.search(r"postgres:\d+", text), (
        "no postgres in the workflow; acme-dns cannot store an account without "
        "it and every registration panics."
    )


def test_the_suite_asks_dns_and_not_only_the_api():
    """The point of the whole exercise.

    A test that stops at "the POST returned 200" is a test a mock would also
    pass, and passing is exactly what the broken implementation did for
    releases.
    """
    source = SUITE.read_text(encoding="utf-8")
    assert "dns.resolver" in source, (
        "the suite no longer queries DNS, so it verifies the call rather than "
        "the record — the failure mode this exists for."
    )
