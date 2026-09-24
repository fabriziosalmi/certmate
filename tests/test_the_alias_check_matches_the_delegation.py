"""Four DNS-alias defects, found by the certmate-website session on v2.35.0.

1. **`alias_dns_provider` could not be set at create.** PATCH reads it, reissue
   reads it, `create_certificate` has taken it as a keyword for as long as the
   feature has existed — and the create route dropped it, answering 201. The
   only way to create an alias certificate whose alias zone lives with another
   provider was to create it wrong and then PATCH it.

2. **acme-dns delegations were reported as a mismatch.** The expectation was
   always `_acme-challenge.<alias>`. That is right for the certbot-style alias
   in docs/dns-providers.md, and wrong for acme-dns: `_acme_dns_change` POSTs
   the TXT to the acme-dns subdomain *itself* and requires
   `domain_alias == subdomain`, so the CNAME the operator is told to publish
   points at the bare name. A correct delegation read `status: mismatch`.

3. **The alias check ignored `dns_resolver`.** It went to Cloudflare's DoH
   endpoint whatever the instance was configured to use — while `CheckCAA`, in
   the same API module, honours it. On a split-horizon instance an internal
   delegation that exists was reported `missing`; on an air-gapped one the
   check could only fail.

4. **The docstring's own example was rejected.** `create_certificate` offered
   `'_acme-challenge.validation.example.org'` as the value to pass, and
   `validate_domain` has no underscore in its label pattern.
"""
import pytest

from modules.core.certificates import CertificateManager
from modules.core.utils import validate_domain

pytestmark = [pytest.mark.unit]


# --- 2. the expectation depends on who publishes the record ---------------

def test_a_certbot_style_alias_expects_the_challenge_label():
    expectations = CertificateManager.build_dns_alias_expectations(
        'example.com', 'validation.example.org')

    assert expectations == [{
        'source': '_acme-challenge.example.com',
        'expected_target': '_acme-challenge.validation.example.org',
    }]


def test_an_acme_dns_alias_expects_the_bare_subdomain():
    """THE regression. This is the record acme-dns itself tells you to
    publish, and it was reported as a mismatch."""
    alias = 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.acme-dns.io'

    expectations = CertificateManager.build_dns_alias_expectations(
        'example.com', alias, alias_provider='acme-dns')

    assert expectations[0]['expected_target'] == alias


def test_the_prefix_is_still_stripped_from_an_over_helpful_alias():
    """CONTROL. An operator who pastes the challenge name as the alias gets
    the same answer as one who pastes the target — in both shapes."""
    for provider, expected in (
            (None, '_acme-challenge.validation.example.org'),
            ('acme-dns', 'validation.example.org')):
        expectations = CertificateManager.build_dns_alias_expectations(
            'example.com', '_acme-challenge.validation.example.org',
            alias_provider=provider)
        assert expectations[0]['expected_target'] == expected


def test_every_san_gets_its_own_source_record():
    """CONTROL that the provider branch did not disturb the fan-out."""
    expectations = CertificateManager.build_dns_alias_expectations(
        'example.com', 'validation.example.org',
        ['www.example.com', '*.example.com'], alias_provider='acme-dns')

    assert [e['source'] for e in expectations] == [
        '_acme-challenge.example.com',
        '_acme-challenge.www.example.com',
    ]
    assert {e['expected_target'] for e in expectations} == {'validation.example.org'}


# --- 3. the configured resolver is the one that answers -------------------

def test_the_alias_check_uses_the_configured_nameservers():
    """`dns_resolver` exists so an instance can say which resolver to trust.
    Every other lookup honours it; this one hardcoded Cloudflare DoH."""
    import inspect

    source = inspect.getsource(CertificateManager._resolve_cname)

    assert 'configured_nameservers' in source
    assert '_resolve_cname_via' in source


def test_an_instance_that_configures_nothing_behaves_as_before():
    """CONTROL. The DoH path is the fallback, not a removal — an instance
    with no nameservers configured must not change behaviour."""
    import inspect
    import re
    from urllib.parse import urlsplit

    source = inspect.getsource(CertificateManager._resolve_cname)
    doh = inspect.getsource(CertificateManager._resolve_cname_doh)

    assert '_resolve_cname_doh' in source
    # The URL is extracted and its host compared, rather than searched for as
    # a substring. A hostname tested with `in` against a larger string says
    # nothing about where it matched — which is exactly what CodeQL's
    # incomplete-url-substring-sanitization rule is about, and it is right
    # about the pattern even in a test.
    urls = re.findall(r"f?'(https://[^']+)'", doh)
    assert urls, 'no URL literal found in the fallback — this reads nothing'
    assert urlsplit(urls[0]).hostname == 'cloudflare-dns.com'


# --- 4. the docstring example is a value the API accepts ------------------

def test_the_documented_alias_example_is_accepted():
    """It was `'_acme-challenge.validation.example.org'`, which
    validate_domain refuses — the docstring told the caller to send a 400."""
    import inspect

    doc = inspect.getdoc(CertificateManager.create_certificate) or ''
    line = next(line for line in doc.splitlines() if 'domain_alias:' in line)

    assert '_acme-challenge' not in line.split('e.g.')[-1]
    assert validate_domain('validation.example.org')[0] is True


def test_the_prefixed_form_is_still_refused():
    """CONTROL on the claim above: the example changed because the validator
    is right, not because it was loosened."""
    ok, reason = validate_domain('_acme-challenge.validation.example.org')

    assert ok is False
    assert '_acme-challenge' in reason


# --- 1. create accepts the alias provider ---------------------------------

def test_create_takes_an_alias_provider():
    import inspect

    from modules.core.cert_service import CertificateService

    for method in (CertificateService.create, CertificateService.prepare_create):
        params = inspect.signature(method).parameters
        assert 'alias_dns_provider' in params, (
            f'{method.__name__} still cannot be told which provider hosts '
            f'the alias zone'
        )


def test_every_lifecycle_call_that_takes_an_alias_passes_its_provider():
    """Sync create, async create and reissue. Reissue already did; the two
    create paths did not, and the async one matters as much because it
    prepares synchronously and defers only the issuance.

    Counted per call rather than per file: the first version of this asserted
    "exactly 2" from a guess and failed on correct code, because reissue was
    a third site it had not looked for.
    """
    import ast
    import inspect

    from modules.api import resources_lifecycle

    tree = ast.parse(inspect.getsource(resources_lifecycle))
    service_calls = [
        ast.unparse(node) for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and any(kw.arg == 'domain_alias' for kw in node.keywords)
    ]

    assert len(service_calls) >= 3, (
        f'expected the two create paths and reissue, found {len(service_calls)}')
    for call in service_calls:
        assert 'alias_dns_provider' in call, (
            f'a lifecycle call takes domain_alias and drops its provider: {call}'
        )


def test_it_reaches_the_issuance_call():
    """The signature accepting it and the issuance receiving it are two
    different claims; the first without the second is this defect again."""
    import ast
    import inspect

    from modules.core.cert_service import CertificateService

    source = inspect.getsource(CertificateService.issue_create)
    calls = [ast.unparse(n) for n in ast.walk(ast.parse(source.strip()))
             if isinstance(n, ast.Call)]

    assert any('create_certificate' in c and 'alias_dns_provider' in c
               for c in calls)


def test_an_alias_provider_without_an_alias_is_dropped():
    """It only means something alongside domain_alias, and storing it alone
    would make the metadata say something the issuance does not do."""
    import inspect

    source = inspect.getsource(
        __import__('modules.core.cert_service', fromlist=['x']).CertificateService.prepare_create)

    assert 'if not domain_alias:' in source
    assert 'alias_dns_provider = None' in source
