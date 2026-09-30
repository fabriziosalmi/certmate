"""Homebrew: the formula lives in the tap and a release job keeps it current
(#1032).

A copy of the formula in this repository, held to the client versions,
blocked every client release: the version bump cannot carry an sha256 that
only exists once PyPI has the new sdist. So the tap is the one place the
formula lives, and `bump-homebrew` in publish-clients.yml updates it after
publishing, installs it with brew, and pushes only if that works.

Verified: the bump script leaves the current formula byte-identical, rewrites
exactly the cli URL/sha256 and the certmate-sdk resource for another version,
and the rewritten formula, tapped from a local checkout as the job does, built
and passed `brew test`.
"""
import importlib.util
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('bump', REPO / 'scripts' / 'bump_homebrew_formula.py')
bump = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bump)

FORMULA = '''class CertmateCli < Formula
  url "https://files.pythonhosted.org/x/certmate_cli-0.1.5.tar.gz"
  sha256 "''' + 'a' * 64 + '''"

  resource "annotated-doc" do
    url "https://files.pythonhosted.org/x/annotated_doc-0.0.4.tar.gz"
    sha256 "''' + 'b' * 64 + '''"
  end

  resource "certmate-sdk" do
    url "https://files.pythonhosted.org/x/certmate_sdk-0.1.5.tar.gz"
    sha256 "''' + 'c' * 64 + '''"
  end
end
'''


def test_the_bump_rewrites_the_cli_and_the_sdk_and_nothing_else():
    cli = ('https://files.pythonhosted.org/y/certmate_cli-0.2.0.tar.gz', 'd' * 64)
    sdk = ('https://files.pythonhosted.org/y/certmate_sdk-0.2.0.tar.gz', 'e' * 64)
    out = bump.bump(FORMULA, cli, sdk)
    assert f'  url "{cli[0]}"' in out and f'  sha256 "{cli[1]}"' in out
    assert f'url "{sdk[0]}"' in out and f'sha256 "{sdk[1]}"' in out
    # The other resource is untouched.
    assert 'annotated_doc-0.0.4.tar.gz' in out and 'b' * 64 in out


def test_a_formula_it_does_not_recognise_is_refused():
    with pytest.raises(SystemExit):
        bump.bump(FORMULA.replace('resource "certmate-sdk"', 'resource "other"'),
                  ('u', 'd' * 64), ('u', 'e' * 64))


def test_there_is_no_second_copy_of_the_formula_here():
    assert not (REPO / 'deploy' / 'homebrew' / 'certmate-cli.rb').exists()


def test_the_release_job_installs_before_it_pushes():
    wf = yaml.safe_load((REPO / '.github' / 'workflows' / 'publish-clients.yml').read_text())
    job = wf['jobs']['bump-homebrew']
    assert job['needs'] == 'publish-cli'
    assert job['if'] == "startsWith(github.ref, 'refs/tags/clients-v')"
    names = [s.get('name') for s in job['steps']]
    assert names.index('Install and test it before pushing') < names.index('Push the bump')
    tap = next(s for s in job['steps'] if s.get('name') == 'Check out the tap')
    assert tap['with']['token'] == '${{ secrets.HOMEBREW_TAP_TOKEN }}'
