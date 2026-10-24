"""The IP-address certificate identifier: validation, classification and the
on-disk name derived from it (#1130, foundation).

Let's Encrypt issues for an IP address only in the short-lived profile and only
over HTTP-01. Before any of that can be wired into issuance, three pure pieces
have to hold: tell an IP apart from a domain, decide which IPs are issuable, and
turn an issuable one into a safe certificate name. IPv6 is refused for now (its
colons cannot be one path segment; that waits on #854), and only globally
routable IPv4 is accepted (LE validates by connecting to the address).
"""
import pytest

from modules.core.domain_paths import is_path_safe_segment
from modules.core.utils import (
    cert_name_for_ip,
    is_ip_identifier,
    validate_ip_identifier,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("value", [
    "1.1.1.1", "8.8.8.8", "192.168.1.1", "127.0.0.1",
    "::1", "2606:4700:4700::1111", " 9.9.9.9 ",
])
def test_an_ip_literal_is_recognised_as_an_ip(value):
    assert is_ip_identifier(value) is True


@pytest.mark.parametrize("value", [
    "example.com", "not-an-ip", "", "1.1.1.1.1", "999.1.1.1",
    "ip-1-1-1-1", "1.1.1", "example.com:443",
])
def test_a_name_that_is_not_an_ip_is_not(value):
    assert is_ip_identifier(value) is False


@pytest.mark.parametrize("value,canonical", [
    ("1.1.1.1", "1.1.1.1"),
    ("8.8.8.8", "8.8.8.8"),
    ("  9.9.9.9  ", "9.9.9.9"),
    ("15.15.15.15", "15.15.15.15"),
])
def test_a_globally_routable_ipv4_is_accepted(value, canonical):
    ok, result = validate_ip_identifier(value)
    assert ok is True
    assert result == canonical


@pytest.mark.parametrize("value", [
    "192.168.1.1", "10.0.0.1", "172.16.0.1",   # private
    "127.0.0.1",                               # loopback
    "169.254.1.1",                             # link-local
    "100.64.0.1",                              # CGNAT / shared
    "0.0.0.0",                                 # unspecified
    "224.0.0.1",                               # multicast
    "192.0.2.1", "198.51.100.1", "203.0.113.1",  # RFC 5737 documentation
])
def test_a_non_global_ipv4_is_refused(value):
    ok, reason = validate_ip_identifier(value)
    assert ok is False
    assert "globally-routable" in reason


@pytest.mark.parametrize("value", ["::1", "2606:4700:4700::1111", "fe80::1", "2001:db8::1"])
def test_ipv6_is_refused_for_now_and_names_854(value):
    ok, reason = validate_ip_identifier(value)
    assert ok is False
    assert "IPv6" in reason and "#854" in reason


@pytest.mark.parametrize("value", ["", "   ", "example.com", "not-an-ip", "1.1.1.1.1", None])
def test_a_non_ip_is_refused(value):
    ok, reason = validate_ip_identifier(value)
    assert ok is False
    assert reason


def test_the_derived_name_turns_dots_into_one_safe_segment():
    assert cert_name_for_ip("192.0.2.1") == "ip-192-0-2-1"


@pytest.mark.parametrize("value", ["1.1.1.1", "8.8.8.8", "203.0.113.1", "255.255.255.255"])
def test_the_derived_name_is_always_a_safe_path_segment(value):
    # Tied to the real rule, not a copy of it: the name an IP certificate is
    # stored under must never escape or split a path.
    assert is_path_safe_segment(cert_name_for_ip(value)) is True


def test_an_accepted_ip_round_trips_to_a_safe_name():
    ok, canonical = validate_ip_identifier("1.1.1.1")
    assert ok is True
    assert is_path_safe_segment(cert_name_for_ip(canonical)) is True
