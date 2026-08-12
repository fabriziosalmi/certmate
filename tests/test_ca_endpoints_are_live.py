"""Every built-in CA must serve an ACME directory that exists.

`digicert` pointed at `https://acme.digicert.com/v2/DV`. That hostname does not
resolve — NXDOMAIN from Cloudflare's resolver, while `one.digicert.com`,
`www.digicert.com` and `docs.digicert.com` all answer, so it is the name that is
gone, not the network. It was CertCentral's legacy ACME service, which DigiCert
stopped supporting on **24 February 2026**. The entry, the settings UI's
pre-filled default, and the CA guide in five languages went on naming it for
months afterwards, while the README advertised DigiCert ACME as a supported CA
with EAB.

Nobody noticed because a CA endpoint is only exercised during a real issuance
against that CA, and CertMate's release gate issues against Let's Encrypt
staging. Four CAs (ZeroSSL, Google Trust Services, SSL.com, Actalis) were
probed at the same time and all four answered correctly — this was one entry
rotting, not a systemic problem, which is precisely why nothing surfaced it.

The reachability check needs the network and lives in CI, marked so the offline
suite skips it. What runs everywhere is the offline half: the shape of the URLs
and the fact that a dead one cannot come back unnoticed.
"""
import json
import re
import urllib.error
import urllib.request

import pytest

from modules.core.ca_manager import CAManager  # noqa: E402

# Deliberately NO module-level `unit` mark. Marks are additive, so one here
# would put the network tests into `make test-unit` — an offline suite that
# quietly reaches five external CAs (Copilot, #538). The offline tests carry
# `unit` individually; the network ones carry `network` only.


def _network_is_reachable():
    """One probe, cached, against a host that is not one of the CAs.

    The network-marked tests below skip when this fails — but only then, and
    only after saying so. A gate that skips whenever its subject is missing is
    how the entry-point contract test spent months asserting the negation of
    its own guard; the difference here is that CI always has the network, so
    the checks always run where it counts.
    """
    if not hasattr(_network_is_reachable, "_result"):
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    "https://acme-v02.api.letsencrypt.org/directory",
                    headers={"User-Agent": "certmate-ca-check"}),
                timeout=15).close()
            _network_is_reachable._result = True
        except Exception:
            _network_is_reachable._result = False
    return _network_is_reachable._result


requires_network = pytest.mark.skipif(
    not _network_is_reachable(),
    reason="no outbound HTTPS: CA reachability not checked (CI always has it)")

# Hosts known to be gone. A regression here is not hypothetical: this is the
# exact string that shipped, and re-adding it must fail offline, immediately,
# without waiting for a network probe.
RETIRED_HOSTS = {
    "acme.digicert.com": (
        "CertCentral's legacy ACME service, retired 24 February 2026. The "
        "hostname no longer resolves. Use the DigiCert ONE mPKI directory: "
        "https://one.digicert.com/mpki/api/v1/acme/v2/directory (regional — an "
        "account outside the default region has its own, shown in CertCentral)."
    ),
}


def _registry():
    providers = CAManager(settings_manager=None).ca_providers
    assert len(providers) >= 5, f"only {len(providers)} CAs in the registry"
    return providers


def _urls():
    found = []
    for key, config in _registry().items():
        for field in ("production_url", "staging_url"):
            url = config.get(field)
            if url and url != "custom":
                found.append((key, field, url))
    return found


@pytest.mark.unit
def test_the_registry_exposes_urls():
    """Guard the guard: an empty list would make every check below vacuous."""
    assert len(_urls()) >= 8, f"only {len(_urls())} CA URLs found in the registry"


@pytest.mark.unit
@pytest.mark.parametrize("key,field,url", _urls(),
                         ids=[f"{k}.{f}" for k, f, _u in _urls()])
def test_no_ca_points_at_a_retired_host(key, field, url):
    host = re.sub(r"^https?://([^/]+).*$", r"\1", url)
    assert host not in RETIRED_HOSTS, (
        f"{key}.{field} points at {host}: {RETIRED_HOSTS[host]}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("key,field,url", _urls(),
                         ids=[f"{k}.{f}" for k, f, _u in _urls()])
def test_every_ca_url_is_https(key, field, url):
    assert url.startswith("https://"), (
        f"{key}.{field} is {url!r} — an ACME directory fetched over plain HTTP "
        f"lets whoever is in the middle choose the CA."
    )


@pytest.mark.network
@requires_network
@pytest.mark.parametrize("key,field,url", _urls(),
                         ids=[f"{k}.{f}" for k, f, _u in _urls()])
def test_every_ca_serves_a_real_acme_directory(key, field, url):
    """Fetch each directory and check it is one. Requires the network.

    A directory that 404s, or answers with something that is not a directory,
    means issuance against that CA cannot start — the failure an operator would
    otherwise meet on their first certificate.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "certmate-ca-check"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            # Read to EOF, capped. 4096 bytes truncated mid-object on any
            # directory larger than that, so a healthy CA would have failed on
            # a JSON error (Copilot, #538). 1 MiB is far past any real
            # directory and still bounds a misbehaving server.
            body = response.read(1024 * 1024).decode("utf-8", "replace")
    except urllib.error.URLError as error:
        pytest.fail(
            f"{key}.{field} ({url}) is unreachable: {error}. If the CA has "
            f"retired this endpoint, update modules/core/ca_manager.py, the "
            f"settings UI default, the CA guide in all five languages, and add "
            f"the dead host to RETIRED_HOSTS so it cannot come back."
        )

    assert status == 200, f"{key}.{field} ({url}) returned HTTP {status}"
    try:
        directory = json.loads(body)
    except ValueError:
        pytest.fail(f"{key}.{field} ({url}) did not return JSON: {body[:200]!r}")

    missing = [f for f in ("newNonce", "newAccount", "newOrder")
               if f not in directory]
    assert not missing, (
        f"{key}.{field} ({url}) answered, but the document is missing "
        f"{missing} — it is not an ACME directory."
    )


@pytest.mark.network
@requires_network
def test_no_ca_demands_eab_without_the_registry_knowing():
    """One direction only, because only one direction breaks issuance.

    If a directory sets `externalAccountRequired` and the registry does not,
    account registration fails on a message about external account binding
    that names neither the CA nor the setting to fix.

    The converse is legitimate and this test used to fail on it: RFC 8555 does
    not oblige a CA to advertise the field, and SSL.com's directory reports
    `false` while its ACME credentials are issued from the customer portal.
    Requiring symmetry made the check reject a correct registry entry.
    """
    mismatches = []
    for key, config in _registry().items():
        url = config.get("production_url")
        if not url or url == "custom":
            continue
        request = urllib.request.Request(
            url, headers={"User-Agent": "certmate-ca-check"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                directory = json.loads(
                    response.read(1024 * 1024).decode("utf-8", "replace"))
        except Exception:
            continue          # reachability is the previous test's business
        advertised = bool(directory.get("meta", {}).get("externalAccountRequired"))
        if advertised and not config.get("requires_eab"):
            mismatches.append(
                f"{key}: the directory sets externalAccountRequired, but the "
                f"registry has requires_eab={config.get('requires_eab')} — "
                f"registration will fail without EAB credentials")
    assert not mismatches, "\n  ".join(mismatches)
