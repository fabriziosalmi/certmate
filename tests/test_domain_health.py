"""Tests for the name-level checks (``modules/core/domain_health.py``).

The checks themselves are pure — each takes the answer it is judging — so
everything here runs offline against scripted DNS, and the assertions are
about what CertMate *concludes*, not about what it fetched.

The centre of gravity is the blocklist: the tool these checks came from read a
refusal (``127.255.255.x``, what every public resolver gets from Spamhaus) as
"not listed", which is how a check reports clean while having learned nothing.
Several tests here exist only to keep that from coming back, at both levels —
the single answer, and the summary over several lists.
"""
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from modules.core import domain_health as dh
from modules.core.cert_inventory import CertInventory

pytestmark = [pytest.mark.unit]

# A globally routable address, used wherever a test needs one a blocklist would
# actually answer about. It cannot be an RFC 5737 documentation address
# (192.0.2.0/24 and friends): those are not global, which is exactly the
# property `not_covered_reason` tests, so every blocklist test here used to
# exercise a path production will now never take. Nothing contacts it.
PUBLIC = '8.8.8.8'
PUBLIC_REVERSED = '8.8.8.8'
# Likewise for IPv6: 2001:db8::/32 is the documentation range and is NOT
# global, so it is excluded for being non-public before the IPv6 rule is ever
# reached. A test about the IPv6 rule needs an address that is genuinely
# routable.
PUBLIC_V6 = '2606:4700::1'


# --------------------------------------------------------------------------- #
# SPF
# --------------------------------------------------------------------------- #

def test_spf_absent_is_a_finding():
    result = dh.check_spf('example.com', ['google-site-verification=x'])
    assert result['status'] == dh.FAILING
    assert 'no v=spf1' in result['detail']


def test_spf_published_is_ok():
    result = dh.check_spf('example.com', ['v=spf1 include:_spf.google.com ~all'])
    assert result['status'] == dh.OK
    assert result['record'] == 'v=spf1 include:_spf.google.com ~all'


def test_two_spf_records_are_a_failure_not_a_warning():
    # Receivers treat this as permerror, which is worse than having none.
    result = dh.check_spf('example.com', ['v=spf1 ~all', 'v=spf1 -all'])
    assert result['status'] == dh.FAILING
    assert 'permerror' in result['detail']


def test_spf_without_an_all_mechanism_is_a_warning():
    result = dh.check_spf('example.com', ['v=spf1 include:_spf.google.com'])
    assert result['status'] == dh.WARNING


def test_spf_plus_all_authorises_everyone():
    result = dh.check_spf('example.com', ['v=spf1 +all'])
    assert result['status'] == dh.FAILING
    assert '+all' in result['detail']


def test_spf_lookup_that_did_not_complete_is_unknown_not_missing():
    result = dh.check_spf('example.com', None)
    assert result['status'] == dh.UNKNOWN
    assert result['status'] != dh.FAILING


# --------------------------------------------------------------------------- #
# DMARC
# --------------------------------------------------------------------------- #

def test_dmarc_absent_is_a_finding():
    assert dh.check_dmarc('example.com', [])['status'] == dh.FAILING


@pytest.mark.parametrize('policy', ['none', 'quarantine', 'reject'])
def test_every_published_dmarc_policy_is_reported_not_marked(policy):
    """p=none is a deliberate first step. Calling it a failure is an opinion."""
    result = dh.check_dmarc('example.com', [f'v=DMARC1; p={policy}; rua=mailto:a@b.c'])
    assert result['status'] == dh.OK
    assert result['policy'] == policy


def test_dmarc_without_a_policy_is_a_finding():
    result = dh.check_dmarc('example.com', ['v=DMARC1; rua=mailto:a@b.c'])
    assert result['status'] == dh.FAILING
    assert 'no p=' in result['detail']


def test_dmarc_lookup_failure_is_unknown():
    assert dh.check_dmarc('example.com', None)['status'] == dh.UNKNOWN


# --------------------------------------------------------------------------- #
# MX
# --------------------------------------------------------------------------- #

def test_no_mx_is_a_warning_not_a_failure():
    """A domain that receives no mail is a choice, not a defect."""
    result = dh.check_mx('example.com', [])
    assert result['status'] == dh.WARNING


def test_mx_present_lists_the_hosts():
    result = dh.check_mx('example.com', ['alt1.aspmx.l.google.com'])
    assert result['status'] == dh.OK
    assert result['hosts'] == ['alt1.aspmx.l.google.com']
    assert '1 mail exchanger' in result['detail']


def test_mx_lookup_failure_is_unknown():
    assert dh.check_mx('example.com', None)['status'] == dh.UNKNOWN


# --------------------------------------------------------------------------- #
# Blocklists — the three states
# --------------------------------------------------------------------------- #

def test_reversed_query_name_for_ipv4():
    # A literal, not PUBLIC: 8.8.8.8 reverses to itself, which would let a
    # broken implementation pass.
    assert dh.rbl_query_name('192.0.2.13') == '13.2.0.192'


def test_reversed_query_name_for_ipv6():
    name = dh.rbl_query_name('2001:db8::1')
    assert name.endswith('8.b.d.0.1.0.0.2')
    assert name.startswith('1.0.0.0')


@pytest.mark.parametrize('codes,expected', [
    ([], 'not_listed'),
    (['127.0.0.2'], 'listed'),
    (['127.0.0.4', '127.0.0.2'], 'listed'),
    (['127.0.0.10'], 'policy'),
    (['127.0.0.11'], 'policy'),
    (['127.255.255.252'], 'refused'),
    (['127.255.255.254'], 'refused'),
])
def test_a_dnsbl_answer_is_classified_by_what_it_means(codes, expected):
    assert dh.classify_rbl_answer(codes) == expected


def test_a_refusal_is_never_read_as_not_listed():
    """The defect this module exists to avoid, at the single-answer level."""
    assert dh.classify_rbl_answer(['127.255.255.254']) != 'not_listed'


def test_a_listing_mixed_with_a_refusal_counts_as_refused():
    # If one of the codes says "we did not answer you", the rest is not an
    # answer about this address either.
    assert dh.classify_rbl_answer(['127.0.0.2', '127.255.255.254']) == 'refused'


def _lookup(answers, default=None, selftest=True):
    """A DNSBL lookup over ``{query_name: [codes] | None}``.

    Every list answers its own test points the way the convention says, so a
    test about a real address is not silently answered by an unusable list.
    Pass ``selftest=False`` to script a resolver that is not reaching the
    lists at all.
    """
    asked = []

    def lookup(name):
        asked.append(name)
        if name in answers:
            return answers[name]
        if selftest and name.startswith(dh.RBL_SELFTEST_LISTED + '.'):
            return ['127.0.0.2']
        if selftest and name.startswith(dh.RBL_SELFTEST_UNLISTED + '.'):
            return []
        return default if default is not None else []

    lookup.asked = asked
    return lookup


def _real_addresses(lookup):
    """The queries that were about a real address, not a self-test."""
    return [n for n in lookup.asked
            if not n.startswith((dh.RBL_SELFTEST_LISTED + '.',
                                 dh.RBL_SELFTEST_UNLISTED + '.'))]


def test_every_list_refusing_is_unknown_not_clean():
    """The defect at the summary level: four refusals is not 'not listed'."""
    lookup = _lookup({}, default=['127.255.255.254'], selftest=False)
    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.UNKNOWN
    assert 'not listed' not in result['detail']
    assert len(result['unanswered']) == len(dh.DEFAULT_RBLS)


def test_every_lookup_failing_is_unknown_not_clean():
    """A lookup that never came back is not an empty answer either."""
    def failing(name):
        return None

    result = dh.check_blocklists('example.com', [PUBLIC], failing)
    assert result['status'] == dh.UNKNOWN


def test_not_listed_everywhere_is_ok():
    result = dh.check_blocklists('example.com', [PUBLIC], _lookup({}))
    assert result['status'] == dh.OK
    assert result['detail'] == f'not listed on {len(dh.DEFAULT_RBLS)} blocklists'


def test_a_listing_is_reported_with_the_list_that_holds_it():
    lookup = _lookup({f'{PUBLIC_REVERSED}.zen.spamhaus.org': ['127.0.0.2']})
    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.FAILING
    assert result['detail'] == 'listed on zen.spamhaus.org'
    assert result['listings'] == [{'address': PUBLIC,
                                   'list': 'zen.spamhaus.org',
                                   'codes': ['127.0.0.2']}]


def test_a_pbl_only_answer_is_not_a_reputation_finding():
    """127.0.0.10/11 describes the address range, not this host's behaviour."""
    lookup = _lookup({f'{PUBLIC_REVERSED}.zen.spamhaus.org': ['127.0.0.10']})
    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.OK


def test_some_lists_refusing_keeps_the_answer_but_says_so():
    lookup = _lookup({f'{PUBLIC_REVERSED}.zen.spamhaus.org': ['127.255.255.254']})
    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.WARNING
    assert len(result['unanswered']) == 1
    assert 'unanswered' in result['detail']


def test_a_listing_still_wins_over_a_refusal_elsewhere():
    lookup = _lookup({f'{PUBLIC_REVERSED}.zen.spamhaus.org': ['127.0.0.2'],
                      f'{PUBLIC_REVERSED}.bl.spamcop.net': ['127.255.255.254']})
    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.FAILING


# --------------------------------------------------------------------------- #
# The self-test: is the list answering us at all?
# --------------------------------------------------------------------------- #
#
# Found on a real machine, not reasoned about: the developer laptop's resolver
# (Tailscale MagicDNS forwarding to 8.8.8.8) answers NXDOMAIN for
# 2.0.0.127.zen.spamhaus.org — an address Spamhaus keeps permanently listed.
# Queried directly, 8.8.8.8/1.1.1.1/9.9.9.9/208.67.222.222 all answer
# 127.255.255.254 for the same name. So a refusal reaches a client in two
# shapes, and only one of them is self-describing. Without these tests the
# module reported `ok` for a domain about which it had learned nothing, which
# is the exact defect it was written to prevent.

def test_a_list_that_answers_its_test_point_is_usable():
    assert dh.list_is_answering('zen.spamhaus.org', _lookup({})) is True


def test_a_list_that_answers_nxdomain_for_everything_is_not_usable():
    """The shape that looks exactly like 'nothing is listed'."""
    assert dh.list_is_answering('zen.spamhaus.org', _lookup({}, selftest=False)) is False


def test_a_list_that_refuses_the_test_point_is_not_usable():
    lookup = _lookup({}, default=['127.255.255.254'], selftest=False)
    assert dh.list_is_answering('zen.spamhaus.org', lookup) is False


def test_a_list_whose_test_point_lookup_fails_is_not_usable():
    assert dh.list_is_answering('zen.spamhaus.org', lambda name: None) is False


def test_a_list_that_reports_the_never_listed_address_is_not_usable():
    """A resolver that answers everything — hijacked, or wildcarding a TLD —
    would otherwise have every domain reported as listed everywhere."""
    lookup = _lookup({f'{dh.RBL_SELFTEST_UNLISTED}.zen.spamhaus.org': ['127.0.0.2']})
    assert dh.list_is_answering('zen.spamhaus.org', lookup) is False


def test_a_test_point_answered_with_a_policy_code_still_counts():
    lookup = _lookup({f'{dh.RBL_SELFTEST_LISTED}.zen.spamhaus.org': ['127.0.0.10']})
    assert dh.list_is_answering('zen.spamhaus.org', lookup) is True


def test_a_resolver_that_answers_nxdomain_for_every_list_reports_unknown():
    """The whole point: silence from a list that is not answering us is not
    evidence that a domain is clean."""
    lookup = _lookup({}, selftest=False)
    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.UNKNOWN
    assert len(result['unanswered']) == len(dh.DEFAULT_RBLS)
    assert 'test point' in result['unanswered'][0]


def test_an_unusable_list_is_never_queried_about_a_real_address():
    lookup = _lookup({}, selftest=False)
    dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert _real_addresses(lookup) == []


def test_a_list_that_passes_its_test_point_then_times_out_is_unanswered():
    """The list is reachable, this one query was not answered. That is still
    not evidence the address is clean."""
    def lookup(name):
        if name.startswith(dh.RBL_SELFTEST_LISTED + '.'):
            return ['127.0.0.2']
        if name.startswith(dh.RBL_SELFTEST_UNLISTED + '.'):
            return []
        return None

    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.UNKNOWN
    assert all('the lookup failed' in u for u in result['unanswered'])


def test_one_broken_list_does_not_discard_the_others():
    def lookup(name):
        if name.endswith('.bl.spamcop.net'):
            return []          # answers nothing, including its test point
        if name.startswith(dh.RBL_SELFTEST_LISTED + '.'):
            return ['127.0.0.2']
        return []
    result = dh.check_blocklists('example.com', [PUBLIC], lookup)
    assert result['status'] == dh.WARNING
    assert result['unanswered'] == [
        'bl.spamcop.net: did not answer its own test point, so its answers '
        'about this domain would mean nothing']


def test_the_self_test_is_asked_once_per_sweep_not_once_per_name():
    lookup = _lookup({})
    cache = {}
    for name in ('a.example', 'b.example', 'c.example'):
        dh.check_blocklists(name, [PUBLIC], lookup, cache=cache)
    selftests = [n for n in lookup.asked
                 if n.startswith((dh.RBL_SELFTEST_LISTED + '.',
                                  dh.RBL_SELFTEST_UNLISTED + '.'))]
    assert len(selftests) == 2 * len(dh.DEFAULT_RBLS)


def test_the_sweep_shares_one_self_test_across_every_name(tmp_path):
    asked = []

    def rbl(name):
        asked.append(name)
        if name.startswith(dh.RBL_SELFTEST_LISTED + '.'):
            return ['127.0.0.2']
        return []

    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'one.com': {}, 'two.com': {}, 'three.com': {}},
    }, lookups=(lambda n: [], lambda n: [], lambda n: [PUBLIC], rbl))
    manager.run_check()
    selftests = [n for n in asked
                 if n.startswith((dh.RBL_SELFTEST_LISTED + '.',
                                  dh.RBL_SELFTEST_UNLISTED + '.'))]
    assert len(selftests) == 2 * len(dh.DEFAULT_RBLS)


def test_a_domain_with_no_address_is_unknown_not_clean():
    result = dh.check_blocklists('example.com', [], _lookup({}))
    assert result['status'] == dh.UNKNOWN


def test_an_address_lookup_that_failed_is_unknown():
    assert dh.check_blocklists('example.com', None, _lookup({}))['status'] == dh.UNKNOWN


def test_only_the_first_few_addresses_are_queried():
    """A CDN name answers with many addresses; each costs a query per list."""
    lookup = _lookup({})
    addresses = [f'8.8.8.{i}' for i in range(1, 12)]
    dh.check_blocklists('example.com', addresses, lookup)
    assert len(_real_addresses(lookup)) == dh.MAX_ADDRESSES * len(dh.DEFAULT_RBLS)


def test_an_unparseable_address_is_skipped_not_fatal():
    lookup = _lookup({})
    result = dh.check_blocklists('example.com', ['not-an-ip', PUBLIC], lookup)
    assert result['status'] == dh.OK
    assert len(_real_addresses(lookup)) == len(dh.DEFAULT_RBLS)


# --------------------------------------------------------------------------- #
# HSTS
# --------------------------------------------------------------------------- #

def test_no_hsts_header_is_a_finding():
    result = dh.check_hsts('')
    assert result['status'] == dh.FAILING


def test_unreachable_site_is_unknown_not_missing_hsts():
    result = dh.check_hsts(None)
    assert result['status'] == dh.UNKNOWN


def test_a_long_max_age_is_ok_and_reports_its_flags():
    result = dh.check_hsts('max-age=31536000; includeSubDomains; preload')
    assert result['status'] == dh.OK
    assert result['max_age'] == 31536000
    assert result['includes_subdomains'] is True
    assert result['preload'] is True


def test_a_short_max_age_is_a_warning():
    result = dh.check_hsts('max-age=300')
    assert result['status'] == dh.WARNING
    assert '300' in result['detail']


def test_max_age_zero_is_a_failure_because_it_forgets_the_policy():
    result = dh.check_hsts('max-age=0')
    assert result['status'] == dh.FAILING


def test_a_header_without_max_age_is_a_failure():
    result = dh.check_hsts('includeSubDomains')
    assert result['status'] == dh.FAILING
    assert 'no max-age' in result['detail']


def test_a_quoted_max_age_is_still_read():
    assert dh.check_hsts('max-age="31536000"')['status'] == dh.OK


@pytest.mark.parametrize('host', ['example.com\r\nX-Evil: 1', 'example.com\nX: 1',
                                  'example.com with space', 'example.com\tx'])
def test_a_host_that_could_split_the_request_is_refused_before_anything_resolves(
        host, monkeypatch):
    """The name is about to become a request line, so it never gets that far.

    Asserting only on the None return would pass either way — getaddrinfo
    refuses these too — so this asserts the refusal happens *first*.
    """
    resolved = []
    monkeypatch.setattr('modules.core.cert_probe._resolve_and_guard',
                        lambda *a: resolved.append(a) or (None, None, 'unused'))
    assert dh.fetch_hsts_header(host) is None
    assert resolved == []


def test_hsts_fetch_returns_none_when_the_guard_refuses(monkeypatch):
    monkeypatch.setattr('modules.core.cert_probe._resolve_and_guard',
                        lambda host, port, allow_private: (None, None, 'target refused'))
    assert dh.fetch_hsts_header('internal.example.com') is None


# --------------------------------------------------------------------------- #
# The other response headers
# --------------------------------------------------------------------------- #

PROTECTED = {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
             'X-Content-Type-Options': 'nosniff'}


def test_a_fully_protected_response_is_ok():
    result = dh.check_security_headers(_served(PROTECTED))
    assert result['status'] == dh.OK
    assert result['broken'] == [] and result['missing'] == []


def test_x_frame_options_counts_even_without_csp_frame_ancestors():
    result = dh.check_security_headers(_served({
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff'}))
    assert result['status'] == dh.OK


def test_csp_frame_ancestors_counts_without_x_frame_options():
    """frame-ancestors supersedes X-Frame-Options; demanding both would report
    a correctly configured site as unprotected."""
    result = dh.check_security_headers(_served(PROTECTED))
    assert result['headers']['x_frame_options'] is None
    assert result['headers']['frame_ancestors_in_csp'] is True
    assert result['status'] == dh.OK


def test_a_bare_response_warns_about_each_missing_header():
    result = dh.check_security_headers(_served({}))
    assert result['status'] == dh.WARNING
    assert len(result['missing']) == 3


def test_an_x_frame_options_value_browsers_ignore_is_a_finding():
    """ALLOW-FROM was dropped by every modern browser. A site relying on it
    believes it is protected and is not, which is worse than knowing."""
    result = dh.check_security_headers(_served(dict(
        PROTECTED, **{'X-Frame-Options': 'ALLOW-FROM https://partner.example'})))
    assert result['status'] == dh.FAILING
    assert 'not a value browsers honour' in result['broken'][0]


@pytest.mark.parametrize('value', ['DENY', 'SAMEORIGIN', 'deny', ' sameorigin '])
def test_the_two_values_browsers_honour_are_accepted(value):
    result = dh.check_security_headers(_served({
        'X-Frame-Options': value,
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff'}))
    assert result['status'] == dh.OK


@pytest.mark.parametrize('value', ['ALLOW-FROM', 'allow-from', 'ALLOWALL',
                                   'SAME-ORIGIN', 'yes'])
def test_no_other_value_is_accepted(value):
    """Pins the set, not one example of what is outside it: browsers honour
    DENY and SAMEORIGIN and ignore everything else, including the ALLOW-FROM
    that sites still carry."""
    result = dh.check_security_headers(_served(dict(
        PROTECTED, **{'X-Frame-Options': value})))
    assert result['status'] == dh.FAILING


def test_report_only_csp_alone_is_a_finding_not_a_csp():
    result = dh.check_security_headers(_served({
        'Content-Security-Policy-Report-Only': "default-src 'self'",
        'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff'}))
    assert result['status'] == dh.FAILING
    assert 'nothing is blocked' in result['broken'][0]


def test_report_only_beside_a_real_csp_is_fine():
    result = dh.check_security_headers(_served(dict(
        PROTECTED, **{'Content-Security-Policy-Report-Only': "default-src 'none'"})))
    assert result['status'] == dh.OK


def test_a_content_type_options_value_that_is_not_nosniff_is_a_finding():
    result = dh.check_security_headers(_served(dict(
        PROTECTED, **{'X-Content-Type-Options': 'sniff'})))
    assert result['status'] == dh.FAILING
    assert 'does nothing' in result['broken'][0]


def test_headers_are_read_case_insensitively():
    """Servers disagree about header case, and HTTP says it does not matter."""
    result = dh.check_security_headers(_served({
        'content-security-policy': "frame-ancestors 'none'",
        'X-CONTENT-TYPE-OPTIONS': 'nosniff'}))
    assert result['status'] == dh.OK


def test_an_unreachable_site_has_unknown_headers_not_missing_ones():
    result = dh.check_security_headers(None)
    assert result['status'] == dh.UNKNOWN


def test_a_host_that_only_redirects_is_unknown_not_unprotected():
    """The apex 301s somewhere CertMate could not follow. The redirect's own
    headers say nothing about the page, and reporting "no CSP" from them would
    be a finding about a response nobody browses."""
    result = dh.check_security_headers(_served({}, stopped_at_redirect=True))
    assert result['status'] == dh.UNKNOWN
    assert 'redirects' in result['detail']


def test_the_result_names_the_host_the_headers_came_from():
    result = dh.check_security_headers(_served(PROTECTED, final_host='www.example.com'))
    assert result['checked_host'] == 'www.example.com'


# --- disclosure ------------------------------------------------------------ #

def test_a_server_header_with_a_version_is_reported():
    result = dh.check_disclosure(_served({'Server': 'nginx/1.24.0'}))
    assert result['status'] == dh.WARNING
    assert result['disclosed'] == ['Server: nginx/1.24.0']


@pytest.mark.parametrize('server', ['nginx', 'cloudflare', 'Apache', 'gws'])
def test_a_server_header_naming_only_the_product_discloses_nothing(server):
    """The tool these checks came from reported `Server: cloudflare` as
    "Server Version Disclosed". There is no version in it to disclose."""
    result = dh.check_disclosure(_served({'Server': server}))
    assert result['status'] == dh.OK
    assert result['disclosed'] == []


def test_no_server_header_at_all_is_ok():
    assert dh.check_disclosure(_served({}))['status'] == dh.OK


@pytest.mark.parametrize('name,value', [
    ('X-Powered-By', 'PHP/8.2.1'),
    ('X-AspNet-Version', '4.0.30319'),
    ('X-AspNetMvc-Version', '5.2'),
    ('X-Generator', 'Drupal 10'),
])
def test_a_header_whose_only_job_is_disclosure_is_reported(name, value):
    """Unlike Server, these carry no protocol meaning: they exist to say what
    is running, so any value is the whole finding."""
    result = dh.check_disclosure(_served({name: value}))
    assert result['status'] == dh.WARNING
    assert result['disclosed'] == [f'{name.lower()}: {value}']


def test_several_disclosures_are_all_reported():
    result = dh.check_disclosure(_served({'Server': 'Apache/2.4.58',
                                          'X-Powered-By': 'PHP/8.2.1'}))
    assert len(result['disclosed']) == 2


def test_disclosure_is_never_a_failure():
    """Knowing the version does not let anyone in; it saves reconnaissance."""
    result = dh.check_disclosure(_served({'Server': 'nginx/1.24.0',
                                          'X-Powered-By': 'PHP/5.2.0'}))
    assert result['status'] == dh.WARNING


def test_an_unreachable_site_discloses_unknown():
    assert dh.check_disclosure(None)['status'] == dh.UNKNOWN


def test_disclosure_is_still_read_from_a_pure_redirect():
    """Unlike the protective headers, a redirect's own Server header is this
    host's, and it is what it leaks to anyone who touches the apex."""
    result = dh.check_disclosure(_served({'Server': 'nginx/1.24.0'},
                                         stopped_at_redirect=True))
    assert result['status'] == dh.WARNING


# --------------------------------------------------------------------------- #
# Rolling several checks into one answer
# --------------------------------------------------------------------------- #

def test_the_worst_check_decides_the_name():
    assert dh.worst_status({'a': {'status': dh.OK},
                            'b': {'status': dh.FAILING}}) == dh.FAILING
    assert dh.worst_status({'a': {'status': dh.OK},
                            'b': {'status': dh.WARNING}}) == dh.WARNING


def test_a_check_that_could_not_run_does_not_make_the_name_ok():
    assert dh.worst_status({'a': {'status': dh.OK},
                            'b': {'status': dh.UNKNOWN}}) == dh.UNKNOWN


def test_no_checks_at_all_is_unknown():
    assert dh.worst_status({}) == dh.UNKNOWN


def _served(headers=None, *, final_host='example.com', first_hsts=None,
            stopped_at_redirect=False):
    """A scripted :func:`fetch_response_headers` result."""
    headers = headers if headers is not None else {}
    if first_hsts is None:
        first_hsts = headers.get('Strict-Transport-Security')
    return {'headers': headers, 'final_host': final_host,
            'first_hsts': first_hsts, 'stopped_at_redirect': stopped_at_redirect}


def _lookups(txt=None, mx=None, addresses=None, rbl=None):
    return (
        lambda name: (txt or {}).get(name, []),
        lambda name: (mx or {}).get(name, []),
        lambda name: (addresses or {}).get(name, []),
        lambda name: (rbl or {}).get(name, []),
    )


def test_mail_checks_only_run_for_a_registrable_domain():
    """DMARC falls back to the organisational domain, so asking
    _dmarc.www.example.com alone would report 'no DMARC' for a domain that
    publishes one."""
    checks = dh.check_name(
        'www.example.com', lookups=_lookups(),
        headers_fetcher=lambda host: _served(
            {'Strict-Transport-Security': 'max-age=31536000'}),
        is_registrable=False)
    assert set(checks) == {'hsts', 'security_headers', 'disclosure'}


def test_a_registrable_domain_gets_every_check():
    checks = dh.check_name('example.com', lookups=_lookups(),
                           headers_fetcher=lambda host: _served(),
                           is_registrable=True)
    assert set(checks) == {'spf', 'dmarc', 'mx', 'blocklists', 'hsts',
                           'security_headers', 'disclosure'}


def test_the_checks_the_operator_turned_off_do_not_run():
    checks = dh.check_name('example.com', lookups=_lookups(),
                           headers_fetcher=lambda host: _served(),
                           mail=False, blocklists=False)
    assert set(checks) == {'hsts', 'security_headers', 'disclosure'}


def test_dmarc_is_asked_at_the_underscore_prefix():
    asked = []

    def txt(name):
        asked.append(name)
        return ['v=DMARC1; p=reject'] if name.startswith('_dmarc.') else []

    lookups = (txt, lambda n: [], lambda n: [], lambda n: [])
    checks = dh.check_name('example.com', lookups=lookups, headers=False)
    assert '_dmarc.example.com' in asked
    assert checks['dmarc']['status'] == dh.OK


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #

def test_the_result_round_trips_through_the_inventory(tmp_path):
    inventory = CertInventory(tmp_path)
    checks = {'spf': {'status': dh.FAILING, 'detail': 'no v=spf1 record'}}
    inventory.record_domain_health('Example.COM', dh.FAILING, checks)
    stored = inventory.get_domain_health('example.com')
    assert stored['name'] == 'example.com'
    assert stored['status'] == dh.FAILING
    assert stored['checks'] == checks


def test_a_re_check_replaces_the_previous_answer(tmp_path):
    inventory = CertInventory(tmp_path)
    inventory.record_domain_health('example.com', dh.FAILING,
                                   {'spf': {'status': dh.FAILING, 'detail': 'gone'}})
    inventory.record_domain_health('example.com', dh.OK,
                                   {'spf': {'status': dh.OK, 'detail': 'published'}})
    stored = inventory.get_domain_health('example.com')
    assert stored['status'] == dh.OK
    assert stored['checks']['spf']['detail'] == 'published'


def test_the_listing_opens_on_what_is_wrong(tmp_path):
    inventory = CertInventory(tmp_path)
    inventory.record_domain_health('ok.example', dh.OK, {})
    inventory.record_domain_health('unknown.example', dh.UNKNOWN, {})
    inventory.record_domain_health('bad.example', dh.FAILING, {})
    inventory.record_domain_health('warn.example', dh.WARNING, {})
    assert [r['name'] for r in inventory.list_domain_health()] == [
        'bad.example', 'warn.example', 'unknown.example', 'ok.example']


def test_a_name_no_longer_tracked_is_forgotten(tmp_path):
    inventory = CertInventory(tmp_path)
    inventory.record_domain_health('kept.example', dh.OK, {})
    inventory.record_domain_health('gone.example', dh.OK, {})
    assert inventory.prune_domain_health(['kept.example']) == 1
    assert inventory.get_domain_health('gone.example') is None
    assert inventory.get_domain_health('kept.example') is not None


def test_recording_a_nameless_result_is_refused(tmp_path):
    inventory = CertInventory(tmp_path)
    with pytest.raises(ValueError):
        inventory.record_domain_health('  ', dh.OK, {})


def test_an_existing_v4_inventory_gains_the_table_without_losing_rows(tmp_path):
    """The migration is the part an upgrade actually runs."""
    inventory = CertInventory(tmp_path)
    inventory.record_registration({'domain': 'example.com', 'status': 'ok',
                                   'expires_at': '2027-01-01T00:00:00+00:00'})
    # Put the database back to v4, table and all, as an older CertMate left it.
    with sqlite3.connect(str(inventory.db_path)) as conn:
        conn.execute('DROP TABLE domain_health')
        conn.execute('PRAGMA user_version = 4')

    reopened = CertInventory(tmp_path)
    assert reopened.get_registration('example.com')['status'] == 'ok'
    reopened.record_domain_health('example.com', dh.OK, {})
    assert reopened.get_domain_health('example.com') is not None
    with sqlite3.connect(str(reopened.db_path)) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 5


# --------------------------------------------------------------------------- #
# Due / not due
# --------------------------------------------------------------------------- #

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


def test_a_name_never_checked_is_due():
    assert dh.is_due(None, NOW) is True
    assert dh.is_due({}, NOW) is True


def test_a_name_checked_this_morning_is_not_due_again():
    record = {'checked_at': (NOW - timedelta(hours=2)).isoformat()}
    assert dh.is_due(record, NOW) is False


def test_a_name_checked_yesterday_is_due():
    record = {'checked_at': (NOW - timedelta(hours=25)).isoformat()}
    assert dh.is_due(record, NOW) is True


def test_an_unreadable_timestamp_is_treated_as_due():
    assert dh.is_due({'checked_at': 'whenever'}, NOW) is True


def test_a_naive_timestamp_is_read_as_utc_not_crashed_on():
    record = {'checked_at': (NOW - timedelta(hours=2)).replace(tzinfo=None).isoformat()}
    assert dh.is_due(record, NOW) is False


# --------------------------------------------------------------------------- #
# The sweep
# --------------------------------------------------------------------------- #

def _manager(tmp_path, settings, **kwargs):
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = settings
    inventory = CertInventory(tmp_path)
    cert_dir = tmp_path / 'certificates'
    cert_dir.mkdir(exist_ok=True)
    kwargs.setdefault('lookups', _lookups())
    kwargs.setdefault('headers_fetcher', lambda host: _served({
        'Strict-Transport-Security': 'max-age=31536000',
        'Content-Security-Policy': "frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
    }))
    kwargs.setdefault('now', lambda: NOW)
    return dh.DomainHealthManager(settings_manager, inventory, cert_dir, **kwargs)


def test_the_sweep_does_nothing_until_it_is_switched_on(tmp_path):
    manager = _manager(tmp_path, {'domains': {'example.com': {}}})
    result = manager.run_check()
    assert result['skipped'] is True
    assert result['reason'] == 'disabled'
    assert manager.inventory.list_domain_health() == []


def test_a_host_and_its_registrable_domain_are_both_tracked(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'www.example.com': {}},
    })
    tracked = manager.tracked_names()
    assert tracked['www.example.com'] is False
    assert tracked['example.com'] is True


def test_a_wildcard_name_is_tracked_as_its_registrable_domain(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'*.example.com': {}},
    })
    tracked = manager.tracked_names()
    assert '*.example.com' not in tracked
    assert tracked.get('example.com') is True


def test_the_sweep_stores_one_row_per_name_with_the_worst_status(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    })
    result = manager.run_check()
    assert result['skipped'] is False
    stored = manager.inventory.get_domain_health('example.com')
    # No SPF and no DMARC in the scripted zone, so the name is failing.
    assert stored['status'] == dh.FAILING
    assert stored['checks']['spf']['status'] == dh.FAILING
    assert stored['checks']['hsts']['status'] == dh.OK


def test_a_second_sweep_the_same_day_asks_nothing_again(tmp_path):
    asked = []

    def txt(name):
        asked.append(name)
        return []

    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    }, lookups=(txt, lambda n: [], lambda n: [], lambda n: []))
    manager.run_check()
    first = len(asked)
    assert first > 0
    second = manager.run_check()
    assert len(asked) == first
    assert second['summary']['checked'] == 0


def test_force_re_checks_a_name_that_is_not_due(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    })
    manager.run_check()
    assert manager.run_check(force=True)['summary']['checked'] >= 1


def test_force_runs_even_while_the_sweep_is_switched_off(tmp_path):
    """The operator asking for a scan now is not the scheduler."""
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': False, 'include_inventory': False},
        'domains': {'example.com': {}},
    })
    result = manager.run_check(force=True)
    assert result['skipped'] is False
    assert result['summary']['checked'] >= 1


def test_one_name_blowing_up_does_not_stop_the_sweep(tmp_path):
    def exploding(name):
        if name in ('boom.com', '_dmarc.boom.com'):
            raise RuntimeError('resolver on fire')
        return []

    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'boom.com': {}, 'fine.com': {}},
    }, lookups=(exploding, lambda n: [], lambda n: [], lambda n: []))
    result = manager.run_check()
    names = {r['name'] for r in result['results']}
    assert names == {'boom.com', 'fine.com'}
    assert manager.inventory.get_domain_health('fine.com')['status'] != dh.UNKNOWN
    assert manager.inventory.get_domain_health('boom.com')['status'] == dh.UNKNOWN


def test_a_failed_name_is_recorded_as_unknown_not_as_passing(tmp_path):
    def exploding(name):
        raise RuntimeError('resolver on fire')

    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    }, lookups=(exploding, lambda n: [], lambda n: [], lambda n: []))
    manager.run_check()
    stored = manager.inventory.get_domain_health('example.com')
    assert stored['status'] == dh.UNKNOWN
    assert 'RuntimeError' in stored['checks']['error']['detail']


def test_the_sweep_forgets_a_name_that_left(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    })
    manager.inventory.record_domain_health('old.example', dh.OK, {})
    result = manager.run_check()
    assert result['summary']['forgotten'] == 1
    assert manager.inventory.get_domain_health('old.example') is None


def test_the_run_stops_at_the_cap_and_says_how_many_it_deferred(tmp_path):
    domains = {f'example{i}.com': {} for i in range(5)}
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': domains,
    })
    result = manager.run_check(max_names=2)
    assert result['summary']['checked'] == 2
    assert result['summary']['deferred'] == len(manager.tracked_names()) - 2


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def test_the_config_defaults_to_off(tmp_path):
    manager = _manager(tmp_path, {})
    assert manager.get_config()['enabled'] is False


def test_saving_the_config_normalises_and_persists(tmp_path):
    manager = _manager(tmp_path, {})
    clean = manager.save_config({'enabled': 'yes', 'extra_domains': ['  Example.COM ', '']})
    assert clean['enabled'] is True
    assert clean['extra_domains'] == ['example.com']
    assert manager.settings_manager.update.called


def test_an_extra_name_that_is_not_a_domain_is_refused(tmp_path):
    manager = _manager(tmp_path, {})
    with pytest.raises(ValueError):
        manager.save_config({'extra_domains': ['not a domain']})


# --------------------------------------------------------------------------- #
# The live lookups, without a network
# --------------------------------------------------------------------------- #
#
# These two functions are where "could not ask" is turned into None and "asked,
# nothing there" into []. Every check above rests on that distinction, so the
# translation is tested directly rather than left to the one path that reaches
# real DNS. No test here opens a socket.

class _Rdata:
    def __init__(self, text=None, strings=None, exchange=None):
        self._text, self.strings, self.exchange = text, strings, exchange

    def __str__(self):
        return self._text


@pytest.fixture
def fake_dns(monkeypatch):
    """dnspython replaced by a resolver over ``{(name, rdtype): answer}``."""
    import dns.exception
    import dns.resolver

    zone, asked = {}, []

    class Resolver:
        lifetime = None

        def resolve(self, name, rdtype):
            asked.append((name, rdtype))
            answer = zone.get((name, rdtype), [])
            if isinstance(answer, Exception):
                raise answer
            return answer

    monkeypatch.setattr(dns.resolver, 'Resolver', Resolver)
    return {'zone': zone, 'asked': asked, 'dns': dns}


def test_a_name_that_exists_with_no_such_record_is_an_empty_answer(fake_dns):
    """NoAnswer/NXDOMAIN mean "asked, nothing there" — which is not None."""
    txt, mx, addresses, rbl = dh.dns_lookups()
    fake_dns['zone'][('a.example.com', 'TXT')] = fake_dns['dns'].resolver.NoAnswer()
    fake_dns['zone'][('b.example.com', 'TXT')] = fake_dns['dns'].resolver.NXDOMAIN()
    assert txt('a.example.com') == []
    assert txt('b.example.com') == []


def test_a_lookup_that_could_not_be_made_is_none(fake_dns):
    txt, mx, addresses, rbl = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'TXT')] = fake_dns['dns'].exception.Timeout()
    fake_dns['zone'][('example.com', 'MX')] = fake_dns['dns'].resolver.NoNameservers()
    fake_dns['zone'][('example.com', 'A')] = fake_dns['dns'].exception.DNSException()
    assert txt('example.com') is None
    assert mx('example.com') is None
    assert rbl('example.com') is None


def test_a_dnsbl_answer_comes_back_as_its_codes(fake_dns):
    _, _, _, rbl = dh.dns_lookups()
    fake_dns['zone'][(f'{PUBLIC_REVERSED}.zen.spamhaus.org', 'A')] = [
        _Rdata('127.0.0.2'), _Rdata('127.0.0.4')]
    assert rbl(f'{PUBLIC_REVERSED}.zen.spamhaus.org') == ['127.0.0.2', '127.0.0.4']


def test_a_dnsbl_with_nothing_on_this_address_answers_empty(fake_dns):
    """An empty answer is 'not listed'. Only a failure is None."""
    _, _, _, rbl = dh.dns_lookups()
    fake_dns['zone'][(f'{PUBLIC_REVERSED}.zen.spamhaus.org', 'A')] = (
        fake_dns['dns'].resolver.NXDOMAIN())
    assert rbl(f'{PUBLIC_REVERSED}.zen.spamhaus.org') == []


def test_txt_strings_are_joined_the_way_a_long_record_arrives(fake_dns):
    """A TXT record over 255 bytes arrives as several strings; SPF is one
    value, so reading only the first would truncate the record being judged."""
    txt, _, _, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'TXT')] = [
        _Rdata(strings=[b'v=spf1 include:_spf.example.net ', b'-all'])]
    assert txt('example.com') == ['v=spf1 include:_spf.example.net -all']


def test_mx_exchanges_lose_their_trailing_dot(fake_dns):
    _, mx, _, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'MX')] = [_Rdata(exchange='mx1.example.net.')]
    assert mx('example.com') == ['mx1.example.net']


def test_addresses_come_from_both_families(fake_dns):
    _, _, addresses, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'A')] = [_Rdata(PUBLIC)]
    fake_dns['zone'][('example.com', 'AAAA')] = [_Rdata('2001:db8::1')]
    assert addresses('example.com') == [PUBLIC, '2001:db8::1']


def test_an_ipv6_failure_does_not_discard_the_ipv4_answers(fake_dns):
    """Plenty of resolvers time out on AAAA alone. Throwing away the A records
    would turn a working name into 'could not check'."""
    _, _, addresses, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'A')] = [_Rdata(PUBLIC)]
    fake_dns['zone'][('example.com', 'AAAA')] = fake_dns['dns'].exception.Timeout()
    assert addresses('example.com') == [PUBLIC]


def test_an_ipv4_failure_with_nothing_else_is_none(fake_dns):
    _, _, addresses, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'A')] = fake_dns['dns'].exception.Timeout()
    fake_dns['zone'][('example.com', 'AAAA')] = fake_dns['dns'].exception.Timeout()
    assert addresses('example.com') is None


def test_the_resolver_is_given_the_timeout_it_was_asked_for(fake_dns):
    import dns.resolver
    dh.dns_lookups(timeout=1.5)
    assert dns.resolver.Resolver.lifetime is None  # set per instance, not class
    txt, _, _, _ = dh.dns_lookups(timeout=1.5)
    txt('example.com')
    assert fake_dns['asked'][-1] == ('example.com', 'TXT')


class _FakeSocket:
    """Enough of a socket for http.client to read one scripted response."""

    def __init__(self, response=b'', raises=None):
        self._response, self._raises, self.sent = response, raises, b''
        self.closed = False

    def settimeout(self, t):
        pass

    def connect(self, addr):
        if isinstance(self._raises, Exception):
            raise self._raises

    def sendall(self, data):
        self.sent += data

    def makefile(self, mode, *a, **kw):
        import io
        return io.BufferedReader(io.BytesIO(self._response))

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


@pytest.fixture
def fake_https(monkeypatch):
    """socket + TLS replaced, so the header fetch runs without a network."""
    import ssl

    state = {'socket': None, 'server_hostname': None, 'sockets': None,
             'sni': [], 'guarded': []}

    def guard(host, port, allow_private):
        state['guarded'].append(host)
        return (2, PUBLIC, None)

    monkeypatch.setattr('modules.core.cert_probe._resolve_and_guard', guard)

    def make_socket(family, type_):
        # `sockets` scripts one response per connection, for redirect chains.
        if state['sockets'] is not None:
            return state['sockets'].pop(0)
        return state['socket']

    class Context:
        minimum_version = None
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, sock, server_hostname=None):
            state['server_hostname'] = server_hostname
            state['sni'].append(server_hostname)
            if isinstance(state.get('tls_error'), Exception):
                raise state['tls_error']
            return sock

    monkeypatch.setattr(dh.socket, 'socket', make_socket)
    monkeypatch.setattr(ssl, 'create_default_context', lambda: Context())
    return state


def test_the_header_the_host_serves_is_returned(fake_https):
    fake_https['socket'] = _FakeSocket(
        b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\n'
        b'Content-Length: 0\r\n\r\n')
    assert dh.fetch_hsts_header('example.com') == 'max-age=31536000'


def test_a_host_that_serves_no_hsts_returns_empty_not_none(fake_https):
    """'' means asked and absent; None means could not ask. check_hsts reads
    them as a finding and as unknown respectively, so they cannot be merged."""
    fake_https['socket'] = _FakeSocket(
        b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    assert dh.fetch_hsts_header('example.com') == ''


def test_the_request_carries_the_name_not_the_address(fake_https):
    """The connection goes to the validated IP, so the Host header and SNI are
    the only things telling the server which site is wanted."""
    sock = _FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    fake_https['socket'] = sock
    dh.fetch_hsts_header('example.com')
    assert b'Host: example.com\r\n' in sock.sent
    assert sock.sent.startswith(b'HEAD / HTTP/1.1\r\n')
    assert fake_https['server_hostname'] == 'example.com'


def test_a_refused_connection_is_none(fake_https):
    fake_https['socket'] = _FakeSocket(raises=ConnectionRefusedError('nope'))
    assert dh.fetch_hsts_header('example.com') is None


def test_a_certificate_the_browser_would_reject_gives_no_answer(fake_https):
    """A browser ignores HSTS from a connection it did not trust, so a header
    read over one would describe a policy nobody applies."""
    import ssl
    fake_https['socket'] = _FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    fake_https['tls_error'] = ssl.SSLCertVerificationError('self-signed')
    assert dh.fetch_hsts_header('example.com') is None


def test_a_reply_that_is_not_http_is_none(fake_https):
    fake_https['socket'] = _FakeSocket(b'not http at all\r\n\r\n')
    assert dh.fetch_hsts_header('example.com') is None


# --------------------------------------------------------------------------- #
# Where the tracked names come from
# --------------------------------------------------------------------------- #

def test_sans_in_a_certificate_metadata_file_are_tracked(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    })
    meta = manager.cert_dir / 'example.com'
    meta.mkdir(parents=True)
    (meta / 'metadata.json').write_text(
        '{"san_domains": ["shop.example.com", "mail.example.net"]}', encoding='utf-8')
    tracked = manager.tracked_names()
    assert tracked.get('shop.example.com') is False
    assert tracked.get('example.net') is True


def test_an_unreadable_metadata_file_is_skipped(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    })
    meta = manager.cert_dir / 'example.com'
    meta.mkdir(parents=True)
    (meta / 'metadata.json').write_text('{ not json', encoding='utf-8')
    assert manager.tracked_names().get('example.com') is True


def test_names_the_inventory_discovered_are_tracked_when_asked(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': True},
        'domains': {},
    })
    manager.inventory.record_observation(
        fingerprint='a' * 64, host='discovered.example.org', port=443,
        subject_cn='discovered.example.org', san_dns=['alt.example.net'],
        source='probed')
    tracked = manager.tracked_names()
    assert tracked.get('discovered.example.org') is False
    assert tracked.get('example.net') is True


def test_a_name_that_could_split_a_query_never_becomes_a_tracked_name(tmp_path):
    manager = _manager(tmp_path, {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'domains': {'example.com': {}},
    })
    manager.settings_manager.load_settings.return_value['domain_health']['extra_domains'] = [
        'evil.com\r\nX: 1', 'ok.com']
    tracked = manager.tracked_names()
    assert not any('\r' in n or '\n' in n for n in tracked)
    assert tracked.get('ok.com') is True


# --------------------------------------------------------------------------- #
# Through the API
# --------------------------------------------------------------------------- #
#
# The HTTP layer has its own coverage floor for a reason (#662): a resource
# that no test enters is a resource whose auth, scope filter and error path
# are only believed to work. These drive the real app.

@pytest.fixture
def real_app(tmp_path, monkeypatch):
    from modules.core.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    return create_app()


def test_the_health_endpoint_lists_what_was_found(real_app):
    application, container = real_app
    inv = container.managers['cert_inventory']
    inv.record_domain_health('bad.example', dh.FAILING,
                             {'spf': {'status': dh.FAILING, 'detail': 'no v=spf1 record'}})
    inv.record_domain_health('fine.example', dh.OK,
                             {'spf': {'status': dh.OK, 'detail': 'published'}})
    body = application.test_client().get('/api/inventory/health').get_json()
    assert [n['name'] for n in body['names']] == ['bad.example', 'fine.example']
    assert body['summary'] == {'total': 2,
                               'by_status': {'failing': 1, 'warning': 0,
                                             'unknown': 0, 'ok': 1}}
    assert body['names'][0]['checks']['spf']['detail'] == 'no v=spf1 record'


def test_the_health_endpoint_counts_a_status_it_has_no_column_for(real_app):
    """A row written by a newer CertMate must not make the summary throw."""
    application, container = real_app
    container.managers['cert_inventory'].record_domain_health(
        'odd.example', 'something-new', {})
    body = application.test_client().get('/api/inventory/health').get_json()
    assert body['summary']['by_status']['something-new'] == 1


def test_the_health_endpoint_filters_by_scope(tmp_path, monkeypatch):
    """A viewer key scoped to one tenant sees that tenant's names only.

    The bearer token is set first: an instance still in setup mode serves
    every request as admin and ignores the key, so the scope would never be
    exercised and this would pass for the wrong reason.
    """
    import secrets

    from modules.core.factory import create_app
    admin_token = secrets.token_urlsafe(32)
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', admin_token)
    application, container = create_app()
    assert not container.managers['auth'].is_setup_mode()

    inv = container.managers['cert_inventory']
    inv.record_domain_health('tenant-a.example', dh.OK, {})
    inv.record_domain_health('tenant-b.example', dh.OK, {})
    client = application.test_client()
    admin = {'Authorization': f'Bearer {admin_token}'}
    created = client.post('/api/keys', headers=admin, json={
        'name': 'tenant-a', 'role': 'viewer', 'allowed_domains': ['tenant-a.example']})
    assert created.status_code in (200, 201), created.get_json()
    scoped = {'Authorization': f'Bearer {created.get_json()["token"]}'}

    seen = client.get('/api/inventory/health', headers=scoped).get_json()
    assert [n['name'] for n in seen['names']] == ['tenant-a.example']
    assert seen['summary']['total'] == 1
    everything = client.get('/api/inventory/health', headers=admin).get_json()
    assert [n['name'] for n in everything['names']] == ['tenant-a.example',
                                                        'tenant-b.example']


def test_the_health_endpoint_says_so_when_there_is_no_inventory(real_app):
    application, container = real_app
    container.managers['cert_inventory'] = None
    response = application.test_client().get('/api/inventory/health')
    assert response.status_code == 503
    assert response.get_json()['code'] == 'INVENTORY_UNAVAILABLE'


def test_config_round_trips_the_health_section(real_app):
    application, _ = real_app
    client = application.test_client()
    assert client.get('/api/inventory/config').get_json()['domain_health'] == {
        'enabled': False, 'include_inventory': True, 'check_mail': True,
        'check_blocklists': True, 'check_headers': True,
        'check_weak_tls': False, 'extra_domains': []}
    r = client.post('/api/inventory/config', json={'domain_health': {
        'enabled': True, 'check_blocklists': False, 'extra_domains': ['brand.it']}})
    assert r.status_code == 200
    saved = r.get_json()['domain_health']
    assert saved['enabled'] is True
    assert saved['check_blocklists'] is False
    assert saved['extra_domains'] == ['brand.it']
    bad = client.post('/api/inventory/config', json={'domain_health': {
        'extra_domains': ['not a domain']}})
    assert bad.status_code == 400


def test_scan_runs_the_health_check_after_the_registration_one(real_app):
    application, container = real_app
    mgr = container.managers['domain_health']
    mgr.run_check = MagicMock(return_value={'skipped': True, 'reason': 'disabled',
                                            'results': []})
    body = application.test_client().post('/api/inventory/scan').get_json()
    assert list(body)[-1] == 'domain_health'
    mgr.run_check.assert_called_once_with()


def test_a_health_check_that_blows_up_does_not_lose_the_rest_of_the_scan(real_app):
    application, container = real_app
    container.managers['domain_health'].run_check = MagicMock(
        side_effect=RuntimeError('resolver on fire'))
    body = application.test_client().post('/api/inventory/scan').get_json()
    assert body['domain_health'] == {'error': 'domain health check failed'}
    assert 'discovery' in body and 'ct_monitoring' in body


def test_a_scan_on_an_instance_without_the_health_manager_still_scans(real_app):
    """Nothing in the tree builds one today, but the resource is written to
    work without it, and untested "cannot happen" branches are how that stops
    being true."""
    application, container = real_app
    container.managers.pop('domain_health')
    body = application.test_client().post('/api/inventory/scan').get_json()
    assert 'domain_health' not in body
    assert 'discovery' in body


# --------------------------------------------------------------------------- #
# Following a redirect, and knowing when not to
# --------------------------------------------------------------------------- #
#
# Most estates answer the apex with a 301 to www. Reading the protective
# headers off that 301 would report "no CSP" for a site that serves one, so
# the hop is followed — but only within the same registrable domain, and only
# after the SSRF guard has passed the new name too.

def _resp(status_line, headers=b'', body_len=b'Content-Length: 0\r\n'):
    return _FakeSocket(status_line + b'\r\n' + headers + body_len + b'\r\n')


REDIRECT_TO_WWW = _resp(b'HTTP/1.1 301 Moved Permanently',
                        b'Location: https://www.example.com/\r\n'
                        b'Strict-Transport-Security: max-age=31536000\r\n')


def test_a_redirect_to_www_is_followed_and_its_headers_are_the_answer(fake_https):
    fake_https['sockets'] = [
        REDIRECT_TO_WWW,
        _resp(b'HTTP/1.1 200 OK', b"Content-Security-Policy: frame-ancestors 'none'\r\n"),
    ]
    served = dh.fetch_response_headers('example.com')
    assert served['final_host'] == 'www.example.com'
    assert served['stopped_at_redirect'] is False
    assert dh.check_security_headers(served)['headers']['frame_ancestors_in_csp'] is True


def test_hsts_is_read_from_the_first_response_not_the_last(fake_https):
    """A browser records HSTS from whatever the host sent, including a 301.
    Taking it from the last hop would miss an apex that sets it."""
    fake_https['sockets'] = [REDIRECT_TO_WWW, _resp(b'HTTP/1.1 200 OK')]
    served = dh.fetch_response_headers('example.com')
    assert served['first_hsts'] == 'max-age=31536000'
    assert dh.check_hsts(served['first_hsts'])['status'] == dh.OK


def test_each_hop_goes_through_the_guard_and_carries_its_own_sni(fake_https):
    fake_https['sockets'] = [REDIRECT_TO_WWW, _resp(b'HTTP/1.1 200 OK')]
    dh.fetch_response_headers('example.com')
    assert fake_https['guarded'] == ['example.com', 'www.example.com']
    assert fake_https['sni'] == ['example.com', 'www.example.com']


def test_a_redirect_off_the_estate_is_not_followed(fake_https):
    """Following it would read someone else's headers and file them under
    this domain."""
    fake_https['sockets'] = [_resp(b'HTTP/1.1 302 Found',
                                   b'Location: https://evil.example.net/\r\n')]
    served = dh.fetch_response_headers('example.com')
    assert served['final_host'] == 'example.com'
    assert served['stopped_at_redirect'] is True
    assert fake_https['guarded'] == ['example.com']


def test_a_redirect_to_plain_http_is_not_followed(fake_https):
    fake_https['sockets'] = [_resp(b'HTTP/1.1 301 Moved Permanently',
                                   b'Location: http://www.example.com/\r\n')]
    assert dh.fetch_response_headers('example.com')['stopped_at_redirect'] is True


def test_a_redirect_with_no_location_stops(fake_https):
    fake_https['sockets'] = [_resp(b'HTTP/1.1 301 Moved Permanently')]
    assert dh.fetch_response_headers('example.com')['stopped_at_redirect'] is True


def test_a_redirect_loop_stops_instead_of_going_round(fake_https):
    a = _resp(b'HTTP/1.1 301 Moved Permanently',
              b'Location: https://www.example.com/\r\n')
    b = _resp(b'HTTP/1.1 301 Moved Permanently',
              b'Location: https://example.com/\r\n')
    fake_https['sockets'] = [a, b]
    served = dh.fetch_response_headers('example.com')
    assert served['final_host'] == 'www.example.com'
    assert fake_https['guarded'] == ['example.com', 'www.example.com']


def test_a_chain_longer_than_the_cap_stops_at_the_cap(fake_https):
    fake_https['sockets'] = [
        _resp(b'HTTP/1.1 301 Moved Permanently', b'Location: https://a.example.com/\r\n'),
        _resp(b'HTTP/1.1 301 Moved Permanently', b'Location: https://b.example.com/\r\n'),
        _resp(b'HTTP/1.1 301 Moved Permanently', b'Location: https://c.example.com/\r\n'),
        _resp(b'HTTP/1.1 301 Moved Permanently', b'Location: https://d.example.com/\r\n'),
    ]
    served = dh.fetch_response_headers('example.com', max_redirects=2)
    assert served['final_host'] == 'b.example.com'
    assert served['stopped_at_redirect'] is True


def test_a_hop_that_cannot_be_reached_is_not_an_answer_about_the_page(fake_https):
    fake_https['sockets'] = [REDIRECT_TO_WWW,
                             _FakeSocket(raises=ConnectionRefusedError('nope'))]
    served = dh.fetch_response_headers('example.com')
    assert served['stopped_at_redirect'] is True
    assert served['first_hsts'] == 'max-age=31536000'
    assert dh.check_security_headers(served)['status'] == dh.UNKNOWN


def test_a_relative_location_is_not_treated_as_another_host(fake_https):
    fake_https['sockets'] = [_resp(b'HTTP/1.1 302 Found', b'Location: /home\r\n')]
    served = dh.fetch_response_headers('example.com')
    assert served['final_host'] == 'example.com'
    assert fake_https['guarded'] == ['example.com']


def test_a_plain_200_makes_exactly_one_request(fake_https):
    fake_https['sockets'] = [_resp(b'HTTP/1.1 200 OK')]
    served = dh.fetch_response_headers('example.com')
    assert served['stopped_at_redirect'] is False
    assert fake_https['guarded'] == ['example.com']


def test_the_three_header_checks_share_one_request(fake_https):
    """Three answers, one fetch: a site should not be asked three times to
    produce the same response."""
    fake_https['sockets'] = [_resp(b'HTTP/1.1 200 OK',
                                   b'Strict-Transport-Security: max-age=31536000\r\n'
                                   b"Content-Security-Policy: frame-ancestors 'none'\r\n"
                                   b'X-Content-Type-Options: nosniff\r\n')]
    checks = dh.check_name('example.com', lookups=_lookups(), mail=False,
                           blocklists=False)
    assert fake_https['guarded'] == ['example.com']
    assert checks['hsts']['status'] == dh.OK
    assert checks['security_headers']['status'] == dh.OK
    assert checks['disclosure']['status'] == dh.OK


def test_a_host_redirecting_to_itself_is_not_followed(fake_https):
    """Some hosts 301 http->https on the same name and answer the https HEAD
    with the same redirect. Following it would just ask again."""
    fake_https['sockets'] = [_resp(b'HTTP/1.1 301 Moved Permanently',
                                   b'Location: https://example.com/\r\n')]
    served = dh.fetch_response_headers('example.com')
    assert served['final_host'] == 'example.com'
    assert served['stopped_at_redirect'] is True
    assert fake_https['guarded'] == ['example.com']


# --------------------------------------------------------------------------- #
# Four ways a check could still have said "clean"
# --------------------------------------------------------------------------- #
#
# All four were found by the certmate-website session reading the module in
# order to describe it. Each is the same shape as the defect the module was
# written to prevent, one level further down.

@pytest.mark.parametrize('record,expected', [
    # `all` is a mechanism, and a mechanism is a whole token. Matched as a bare
    # word, a dot counts as a boundary, so this record — which has no
    # all-mechanism at all — reported `ok`.
    ('v=spf1 include:all.example.net', dh.WARNING),
    ('v=spf1 include:small.example.com', dh.WARNING),
    ('v=spf1 a:mail.allied.net', dh.WARNING),
    # ...while a real all-mechanism, with or without a qualifier, still counts.
    ('v=spf1 a:mail.allied.net -all', dh.OK),
    ('v=spf1 include:_spf.example.net ~all', dh.OK),
    ('v=spf1 ?all', dh.OK),
    # A bare `all` is `+all` by RFC 7208, and authorises everyone.
    ('v=spf1 all', dh.FAILING),
    ('v=spf1 +all', dh.FAILING),
])
def test_all_is_matched_as_a_mechanism_not_as_a_word(record, expected):
    assert dh.check_spf('example.com', [record])['status'] == expected


def _answering_lists(extra=None):
    """A resolver where every list answers both its test points correctly,
    recording what it was asked so a test can assert nothing went out."""
    extra = extra or {}
    asked = []

    def lookup(name):
        asked.append(name)
        if name in extra:
            return extra[name]
        if name.startswith(dh.RBL_SELFTEST_LISTED + '.'):
            return ['127.0.0.2']
        if name.startswith(dh.RBL_SELFTEST_UNLISTED + '.'):
            return []
        return []

    lookup.asked = asked
    return lookup


# --------------------------------------------------------------------------- #
# An internal address is not theirs to see, and not theirs to answer about
# --------------------------------------------------------------------------- #

PRIVATE_SHAPES = [
    ('10.1.2.3', 'RFC 1918'),
    ('192.168.7.9', 'RFC 1918'),
    ('172.16.0.1', 'RFC 1918'),
    ('127.0.0.1', 'loopback'),
    ('169.254.1.1', 'link-local'),
    ('100.64.0.1', 'carrier-grade NAT'),
    ('fd00::1', 'unique local'),
]


@pytest.mark.parametrize('address,kind', PRIVATE_SHAPES,
                         ids=[f'{a} ({k})' for a, k in PRIVATE_SHAPES])
def test_a_non_public_address_is_never_sent_to_a_blocklist(address, kind):
    """Two things at once, and the second is the one that bites.

    A DNSBL lists hosts that send mail on the internet; it has nothing to say
    about 10.0.0.0/8, so an empty answer is not "clean". And asking is not
    free — the query carries an internal address to four third parties, which
    is a piece of the estate's topology they had no reason to receive.

    `100.64.0.1` is in the list on purpose: `is_private` answers False for
    carrier-grade NAT, so a check written with that test would have kept
    sending those.
    """
    lookup = _answering_lists()
    result = dh.check_blocklists('internal.example', [address], lookup)

    assert _real_addresses(lookup) == []
    assert result['status'] == dh.UNKNOWN
    assert any(address in n for n in result['not_covered'])


def test_a_public_address_beside_a_private_one_is_still_checked():
    """Split-horizon DNS is ordinary. The public address is the one a
    blocklist can answer about, and it is answered about."""
    lookup = _answering_lists()
    result = dh.check_blocklists('mixed.example', ['8.8.8.8', '10.1.2.3'], lookup)

    assert result['status'] == dh.OK
    assert len(result['not_covered']) == 1
    queried = _real_addresses(lookup)
    assert queried, 'the public address was not checked either'
    assert all(q.startswith('8.8.8.8.') for q in queried)
    assert not any('3.2.1.10' in q for q in queried), 'the private address went out'


def test_a_listing_on_the_public_address_still_reports():
    lookup = _answering_lists({'8.8.8.8.zen.spamhaus.org': ['127.0.0.2']})
    result = dh.check_blocklists('mixed.example', [PUBLIC, '10.1.2.3'], lookup)
    assert result['status'] == dh.FAILING


@pytest.mark.parametrize('address', ['8.8.8.8', '1.1.1.1', '2606:4700::1'])
def test_a_public_address_is_not_mistaken_for_an_internal_one(address):
    """The other direction: over-filtering would make the check useless."""
    reason = dh.not_covered_reason(address)
    if address.count(':'):
        assert reason and 'IPv6' in reason      # excluded, but for the other reason
    else:
        assert reason is None


def test_the_reason_says_which_kind_it_is():
    """An operator reading `not_covered` should not have to guess whether an
    address was skipped for being internal or for being IPv6."""
    assert 'not a public address' in dh.not_covered_reason('10.1.2.3')
    assert 'IPv6' in dh.not_covered_reason('2606:4700::1')


def test_an_unparseable_address_is_left_to_the_caller():
    assert dh.not_covered_reason('not-an-address') is None


def test_an_ipv6_only_domain_is_unknown_not_clean():
    """The test points are 127.0.0.2 and 127.0.0.1: they prove a list answers
    about IPv4 and say nothing about IPv6. Most DNSBLs do not list IPv6 at
    all, so an empty answer about an AAAA address is indistinguishable from
    "this list does not serve IPv6" — the same false-clean as a refusal read
    as "not listed"."""
    result = dh.check_blocklists('example.com', [PUBLIC_V6], _answering_lists())
    assert result['status'] == dh.UNKNOWN
    assert 'IPv6' in result['not_covered'][0]
    # The detail carries the reasons rather than a sentence per case, so a
    # third kind of uncoverable address does not need new prose here.
    assert 'nothing about this domain could be asked' in result['detail']
    assert 'IPv6' in result['detail']


def test_an_ipv6_address_is_never_queried_against_an_ipv4_self_tested_list():
    asked = []

    def lookup(name):
        asked.append(name)
        return _answering_lists()(name)

    dh.check_blocklists('example.com', [PUBLIC_V6], lookup)
    assert not [n for n in asked if n.startswith('1.0.0.0.0')]


def test_a_clean_dual_stack_domain_stays_ok_and_still_says_what_it_skipped():
    """Most real domains are dual-stack. Counting the IPv6 address as an
    unanswered lookup would put nearly every healthy domain at a permanent
    warning, and a warning that is always on is one nobody reads. The IPv6
    address is a boundary of what these lists cover, not a hole in coverage of
    something we should have checked, so it is reported without changing the
    verdict."""
    result = dh.check_blocklists('example.com', [PUBLIC, PUBLIC_V6],
                                 _answering_lists())
    assert result['status'] == dh.OK
    assert result['unanswered'] == []
    assert any('IPv6' in n for n in result['not_covered'])
    # The detail says something was skipped. Which kind is in `not_covered`,
    # because the detail now covers both reasons and naming one there would
    # be wrong for the other.
    assert 'not asked about' in result['detail']


def test_a_refused_list_still_downgrades_a_dual_stack_domain():
    """The two are kept apart, not conflated in the other direction: a list
    that refused is still a hole, IPv6 present or not."""
    lookup = _answering_lists({f'{PUBLIC_REVERSED}.zen.spamhaus.org': ['127.255.255.254']})
    result = dh.check_blocklists('example.com', [PUBLIC, PUBLIC_V6], lookup)
    assert result['status'] == dh.WARNING
    assert len(result['unanswered']) == 1
    assert len(result['not_covered']) == 1


def test_a_listing_on_ipv4_is_still_a_finding_on_a_dual_stack_domain():
    lookup = _answering_lists({f'{PUBLIC_REVERSED}.zen.spamhaus.org': ['127.0.0.2']})
    result = dh.check_blocklists('example.com', [PUBLIC, PUBLIC_V6], lookup)
    assert result['status'] == dh.FAILING


def test_an_ipv4_only_domain_is_unaffected():
    result = dh.check_blocklists('example.com', [PUBLIC], _answering_lists())
    assert result['status'] == dh.OK
    assert result['not_covered'] == []
    assert 'IPv6' not in result['detail']


def test_a_negative_control_that_did_not_answer_does_not_pass_the_list():
    """The negative control exists to catch a list, or a resolver, that
    answers everything. A query that never came back cannot rule that out, so
    it is not evidence in the list's favour."""
    def lookup(name):
        if name.startswith(dh.RBL_SELFTEST_LISTED + '.'):
            return ['127.0.0.2']
        if name.startswith(dh.RBL_SELFTEST_UNLISTED + '.'):
            return None          # the control lookup failed
        return []

    assert dh.list_is_answering('zen.spamhaus.org', lookup) is False
    assert dh.check_blocklists('example.com', [PUBLIC],
                               lookup)['status'] == dh.UNKNOWN


def test_an_aaaa_failure_does_not_discard_a_good_a_answer(fake_dns):
    _, _, addresses, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'A')] = [_Rdata(PUBLIC)]
    fake_dns['zone'][('example.com', 'AAAA')] = fake_dns['dns'].exception.Timeout()
    assert addresses('example.com') == [PUBLIC]


def test_an_a_failure_does_not_stop_aaaa_being_tried(fake_dns):
    """An A lookup that timed out used to end the whole thing, so a name that
    would have answered on AAAA reported "could not look"."""
    _, _, addresses, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'A')] = fake_dns['dns'].exception.Timeout()
    fake_dns['zone'][('example.com', 'AAAA')] = [_Rdata('2001:db8::1')]
    assert addresses('example.com') == ['2001:db8::1']


def test_only_both_families_failing_is_could_not_look(fake_dns):
    _, _, addresses, _ = dh.dns_lookups()
    fake_dns['zone'][('example.com', 'A')] = fake_dns['dns'].exception.Timeout()
    fake_dns['zone'][('example.com', 'AAAA')] = fake_dns['dns'].exception.Timeout()
    assert addresses('example.com') is None
