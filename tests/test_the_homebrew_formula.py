"""The Homebrew formula for certmate-cli (#1032) installs the client this
repository ships.

Verified with a local tap: built from source, `certmate health` read a live
instance, `brew test` and `brew audit --strict --online` passed. The formula
pins sdists by URL and sha256, so it silently keeps installing the old client
after a release unless something compares the two; this does.
"""
import re
import tomllib
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
FORMULA = (REPO / 'deploy' / 'homebrew' / 'certmate-cli.rb').read_text()


def _version(package):
    with open(REPO / 'clients' / package / 'pyproject.toml', 'rb') as f:
        return tomllib.load(f)['project']['version']


def test_the_formula_installs_the_current_cli():
    url = re.search(r'^  url "([^"]+)"', FORMULA, re.M).group(1)
    assert url.endswith(f"/certmate_cli-{_version('certmate-cli')}.tar.gz"), url


def test_the_formula_installs_the_current_sdk():
    block = re.search(r'resource "certmate-sdk" do\n\s+url "([^"]+)"', FORMULA).group(1)
    assert block.endswith(f"/certmate_sdk-{_version('certmate-sdk')}.tar.gz"), block


def test_certifi_comes_from_homebrew_not_a_resource():
    assert 'depends_on "certifi"' in FORMULA
    assert 'resource "certifi"' not in FORMULA


def test_every_resource_is_pinned_by_hash():
    resources = re.findall(r'resource "[^"]+" do\n\s+url "[^"]+"\n\s+sha256 "[0-9a-f]{64}"', FORMULA)
    assert len(resources) == FORMULA.count('resource "')
