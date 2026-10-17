"""A missing DNS plugin names the remedy for the tier it is in.

The README sorts certbot DNS plugins into tiers: pinned in requirements.txt (in
the default image), pinned in requirements-extended.txt (an EXTRA_REQUIREMENTS
build), or in no image at all (a derived image). The error for a missing plugin
used to say "Docker users: rebuild with REQUIREMENTS_FILE=requirements.txt" for
every one of them, which is the default and only helps an image built from
requirements-minimal.txt; since the image ships no pip, the "pip install" next
to it cannot be followed inside a container either.

The plugins are picked from the requirements files themselves, so the test
follows the files when a plugin moves between tiers.
"""
import pytest

from modules.core.dns_strategies import _pins, plugin_install_hint

pytestmark = [pytest.mark.unit]


def _dns_plugins(filename):
    return {name for name in _pins(filename) if name.startswith('certbot-dns-')}


DEFAULT = _dns_plugins('requirements.txt')
EXTENDED_ONLY = _dns_plugins('requirements-extended.txt') - DEFAULT
NOWHERE = 'certbot-dns-scaleway'


def test_the_tiers_the_test_relies_on_exist():
    """The control: if a tier is empty, the cases below test nothing."""
    assert 'certbot-dns-cloudflare' in DEFAULT
    assert EXTENDED_ONLY, 'requirements-extended.txt adds no DNS plugin of its own'
    assert NOWHERE not in DEFAULT | _dns_plugins('requirements-extended.txt')


@pytest.mark.parametrize('package', sorted(DEFAULT))
def test_a_default_plugin_points_at_the_default_build(package):
    hint = plugin_install_hint(package)
    assert 'REQUIREMENTS_FILE=requirements.txt' in hint
    assert 'EXTRA_REQUIREMENTS' not in hint and 'derived image' not in hint


@pytest.mark.parametrize('package', sorted(EXTENDED_ONLY))
def test_an_extended_plugin_points_at_the_extended_build(package):
    hint = plugin_install_hint(package)
    assert 'EXTRA_REQUIREMENTS=requirements-extended.txt' in hint
    assert 'REQUIREMENTS_FILE' not in hint and 'derived image' not in hint


def test_a_plugin_in_no_image_points_at_a_derived_image():
    hint = plugin_install_hint(NOWHERE)
    assert 'derived image' in hint
    assert 'REQUIREMENTS_FILE' not in hint and 'EXTRA_REQUIREMENTS' not in hint


def test_every_hint_says_how_to_install_from_source():
    for package in (*DEFAULT, *EXTENDED_ONLY, NOWHERE):
        assert f'pip install {package}' in plugin_install_hint(package)


def test_a_missing_requirements_file_is_not_an_error(monkeypatch, tmp_path):
    """A source checkout without the files, or a trimmed image, still gets a hint."""
    monkeypatch.setattr('modules.core.dns_strategies._REQUIREMENTS_DIR', tmp_path)
    assert 'derived image' in plugin_install_hint('certbot-dns-cloudflare')
