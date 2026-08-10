"""The provider table's availability column must match what we actually ship.

It said `Stable` on all twenty-nine rows. A column with one value is not a
status — it cannot be wrong about any particular provider, which is why four
wrong entries sat in the most-read table in the README:

  * **Namecheap** — the only release on PyPI is 1.0.0, an alpha targeting
    Python 2.7-3.8, incompatible with certbot 2.x on Python 3.12. Not a
    judgement call: `NamecheapStrategy`'s own docstring says exactly that, and
    requirements.txt records the removal in a comment. The README called it
    Stable anyway.
  * **Scaleway** — 0.0.7, alpha, still declaring Python 2.7 support. A comment
    in requirements.txt, never a pin.
  * **PowerDNS** — pulls `dns-lexicon<=3.5.6`, which conflicts with the rest of
    the extended set. Not in the default image.
  * **Infomaniak** — pinned in no requirements file at all.

The check below reads the requirements files, which are the only thing that
decides what is in an image, and compares them with what the table claims.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

# provider display name (as written in the README) -> PyPI distribution.
# Derived from the plugin, with the cases where the two names differ. Every
# entry is checked below against the requirements files: a name nothing
# mentions is a name nobody can verify.
DISTRIBUTIONS = {
    "Cloudflare": "certbot-dns-cloudflare",
    "AWS Route53": "certbot-dns-route53",
    "Azure DNS": "certbot-dns-azure",
    "Google Cloud DNS": "certbot-dns-google",
    "DigitalOcean": "certbot-dns-digitalocean",
    "PowerDNS": "certbot-dns-powerdns",
    "RFC2136": "certbot-dns-rfc2136",
    "Linode": "certbot-dns-linode",
    "Akamai Edge DNS": "certbot-plugin-edgedns",
    "Gandi": "certbot-dns-gandi",
    "OVH": "certbot-dns-ovh",
    "Namecheap": "certbot-dns-namecheap",
    "Vultr": "certbot-dns-vultr",
    "DNS Made Easy": "certbot-dns-dnsmadeeasy",
    "NS1": "certbot-dns-nsone",              # entry point dns-ns1
    "Hetzner": "certbot-dns-hetzner",
    "Hetzner Cloud": "certbot-dns-hetzner-cloud",
    "Porkbun": "certbot-dns-porkbun",
    "GoDaddy": "certbot-dns-godaddy",
    "Hurricane Electric": "certbot-dns-he-ddns",
    "Dynu": "certbot-dns-dynudns",           # entry point dns-dynu
    "ArvanCloud": "certbot-dns-arvancloud",
    "Infomaniak": "certbot-dns-infomaniak",
    "Scaleway": "certbot-dns-scaleway",
    "deSEC": "certbot-dns-desec",
    "DuckDNS": "certbot-dns-duckdns",
}

# Providers CertMate implements itself, with no certbot plugin involved.
NATIVE = {"EfficientIP SOLIDserver", "ACME-DNS", "Custom Script"}


def _requirements(name):
    path = REPO_ROOT / name
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _is_pinned(text, distribution):
    return bool(re.search(rf"^{re.escape(distribution)}==", text, re.M))


def _is_only_a_comment(text, distribution):
    return (not _is_pinned(text, distribution)
            and bool(re.search(rf"^#.*{re.escape(distribution)}", text, re.M)))


def _expected(distribution):
    """What the availability column should say, from the requirements alone."""
    base = _requirements("requirements.txt")
    extended = _requirements("requirements-extended.txt")
    optional = "".join(_requirements(p.name) for p in REPO_ROOT.glob("requirements-*.txt"))
    if _is_pinned(base, distribution):
        return "Stable"
    if _is_pinned(extended, distribution):
        return "Extended image"
    if _is_pinned(optional, distribution):
        return "Stable"          # per-cloud extras (aws/gcp/azure) are supported
    if _is_only_a_comment(base + extended, distribution):
        return {"Separate install", "Unavailable"}
    return {"Separate install", "Unavailable"}


def _table_rows():
    """(display name, availability) for every row of the provider table."""
    rows = []
    for line in README.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\|\s*\*\*(.+?)\*\*[^|]*\|.*\|\s*\*\*([\w ]+)\*\*\s*\|\s*$",
                         line)
        if match and "Credentials" not in line:
            name = re.sub(r"\s*\(.*?\)", "", match.group(1)).strip()
            rows.append((name, match.group(2).strip()))
    return rows


def test_the_table_is_being_parsed():
    rows = _table_rows()
    assert len(rows) >= 25, (
        f"parsed {len(rows)} provider rows out of README.md — the table format "
        f"changed and every check below would pass over nothing."
    )
    values = {status for _name, status in rows}
    assert len(values) > 1, (
        f"every row says {values}. A column with one value is decoration, not "
        f"a status: that is how four wrong entries survived in it."
    )


@pytest.mark.parametrize("distribution", sorted(set(DISTRIBUTIONS.values())))
def test_every_distribution_name_is_one_the_requirements_know(distribution):
    """The table above must describe real packages, or it proves nothing."""
    everything = "".join(
        _requirements(p.name) for p in REPO_ROOT.glob("requirements*.txt"))
    assert distribution in everything, (
        f"{distribution} is named in this test's mapping but appears in no "
        f"requirements file, pinned or commented. Either the name is wrong or "
        f"the provider is gone."
    )


@pytest.mark.parametrize("name,claimed", _table_rows(),
                         ids=[n for n, _s in _table_rows()])
def test_the_availability_column_matches_the_requirements(name, claimed):
    if name in NATIVE:
        assert claimed == "Stable", (
            f"{name} is implemented natively by CertMate, with no plugin to "
            f"install — it cannot be anything but Stable."
        )
        return
    distribution = DISTRIBUTIONS.get(name)
    assert distribution, (
        f"README lists a provider this test does not know: {name!r}. Add it to "
        f"DISTRIBUTIONS (or NATIVE) rather than leaving it unchecked."
    )
    expected = _expected(distribution)
    allowed = {expected} if isinstance(expected, str) else expected
    assert claimed in allowed, (
        f"README says {name} is '{claimed}', but {distribution} is "
        f"{'pinned in ' + ', '.join(p.name for p in REPO_ROOT.glob('requirements*.txt') if _is_pinned(_requirements(p.name), distribution)) if any(_is_pinned(_requirements(p.name), distribution) for p in REPO_ROOT.glob('requirements*.txt')) else 'pinned nowhere'}. "
        f"Expected one of {sorted(allowed)}."
    )
