"""`renew_certificate` was 393 lines and C(36); it is four units now (#666).

The issue's headline was `create_certificate` at F(115), and that half was
done in #916: 115 → 18, 590 lines → 317. Renewal was left, and by the time
the create path had been decomposed it was the worse of the two — C(36) to
create's 21, and the longer function.

Why it mattered here more than the number suggests. Every defect this
repository has found on the renewal path in the last two months was a branch
somewhere in the middle of that method: the private-CA trust bundle that
creation passed and renewal never read, so a private-CA certificate could
never renew; the corrupt-metadata write that destroyed `dns_provider`,
`san_domains` and every `deployment_*` key in one pass; the half-finished
publish that the "not yet due" branch returned past, so nothing retried it.
Each one had to be reasoned about with the domain lock held, the artifacts
half-built and the certbot command half-assembled — and each one was a place
where creation and renewal had drifted, because the two were not comparable
side by side.

The four units, and what each one answers:

* `_prepare_renewal_dns` — what certbot needs to answer the challenge. Five
  cases, and the one place they can be compared with the create path's
  `_resolve_challenge_and_dns`.
* `_reconcile_without_renewal` — certbot said "not yet due"; does what we
  serve still agree with what certbot holds?
* `_publish_renewed_certificate` — a renewal happened: publish, stamp, store,
  report.
* `_renewal_failed` — certbot exited non-zero; raise what the operator needs.

This file is the ratchet. The complexity budget cannot hold it — an entry at
or below the general limit of 40 is rejected by design, and 16 is well under
— so without something here nothing stops the method growing back.
"""
import json
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from tests.renewal_path import _self_calls, renewal_path_source

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent

# Measured 16 after the extraction. Four of headroom for an honest new branch,
# and no more: at 36 this method was where every renewal defect lived.
RENEW_CEILING = 20

UNITS = (
    '_prepare_renewal_dns',
    '_reconcile_without_renewal',
    '_publish_renewed_certificate',
    '_renewal_failed',
)


def _complexity_over(limit):
    """What flake8 reports over *limit*, as {qualified name: score}.

    The same instrument `scripts/check_complexity_budget.py` uses, and for the
    reason its docstring gives: an independent calculation would disagree with
    the linter at the margins, and the linter's number is the one the lint step
    acts on.
    """
    result = subprocess.run(
        [sys.executable, '-m', 'flake8', 'modules/core/certificates.py',
         '--select=C901', f'--max-complexity={limit}'],
        cwd=REPO, capture_output=True, text=True, timeout=300)
    assert result.returncode in (0, 1), result.stderr
    pattern = re.compile(r".+?:\d+:\d+: C901 '(.+?)' is too complex \((\d+)\)")
    found = {}
    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        assert match, f'unparsed flake8 line: {line}'
        found[match.group(1)] = int(match.group(2))
    return found


# --- the ratchet -----------------------------------------------------------

def test_renew_certificate_stays_decomposed():
    """THE ratchet. It was 36; it is 16."""
    over = _complexity_over(RENEW_CEILING)

    assert 'CertificateManager.renew_certificate' not in over, (
        f"renew_certificate is at "
        f"{over.get('CertificateManager.renew_certificate')}, over the "
        f"{RENEW_CEILING} this change left it under. Put the new branch in one "
        f"of the units it delegates to, or add a unit."
    )


def test_the_units_are_not_the_old_method_under_new_names():
    """CONTROL on the ratchet: moving the complexity into one helper would
    satisfy the test above and change nothing. Each unit carries its own
    ceiling, and the sum is not allowed to hide in one of them."""
    over = _complexity_over(RENEW_CEILING)

    for unit in UNITS:
        assert f'CertificateManager.{unit}' not in over, (
            f'{unit} is at {over[f"CertificateManager.{unit}"]}; the '
            f'decomposition moved the problem rather than solving it')


def test_each_unit_exists_and_is_reached_from_the_entry_point():
    """A unit nothing calls is dead code with a good name."""
    import inspect

    called = _self_calls(inspect.getsource(CertificateManager.renew_certificate))

    for unit in UNITS:
        assert hasattr(CertificateManager, unit), f'{unit} is gone'
        assert unit in called, (
            f'{unit} exists but renew_certificate no longer calls it')


def test_nothing_calls_back_into_the_entry_point():
    """The delegation points one way. A unit that called `renew_certificate`
    would re-take the domain lock it is already holding and deadlock — with a
    timeout, so it would surface as DomainOperationInProgress against no other
    operation, which is exactly the trap the CSR short-circuit at the top of
    the method exists to avoid."""
    import inspect

    for unit in UNITS:
        source = inspect.getsource(getattr(CertificateManager, unit))
        assert 'self.renew_certificate' not in source, unit


# --- the units, driven ------------------------------------------------------

def _manager(tmp_path, storage_manager=None):
    settings = MagicMock()
    settings.load_settings.return_value = {}
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings,
        dns_manager=MagicMock(),
        storage_manager=storage_manager,
        ca_manager=None,
    )


def _certificate_on_disk(tmp_path, domain='unit.example.com', served=b'OLD'):
    """A domain directory with a live lineage and a flat published copy."""
    domain_dir = tmp_path / domain
    live = domain_dir / 'live' / domain
    live.mkdir(parents=True)
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
        (live / name).write_bytes(b'NEW-' + name.encode())
        (domain_dir / name).write_bytes(served + b'-' + name.encode())
    (domain_dir / 'metadata.json').write_text(json.dumps({'domain': domain}))
    return domain, domain_dir


def test_the_not_due_branch_republishes_a_served_copy_that_disagrees(tmp_path):
    """Driven directly, which is the point of the decomposition: this branch
    used to be reachable only by running certbot and having it no-op.

    The defect it carries is real — a half-finished publish became permanent,
    because this path returns before the copy the renewed path makes.
    """
    domain, domain_dir = _certificate_on_disk(tmp_path)
    manager = _manager(tmp_path)

    result = manager._reconcile_without_renewal(domain, domain_dir,
                                                {'domain': domain})

    assert result['success'] is True
    assert result['renewed'] is False
    assert result['repaired'], 'the disagreement was not reported'
    assert (domain_dir / 'cert.pem').read_bytes() == b'NEW-cert.pem'


def test_the_not_due_branch_touches_nothing_when_the_copies_agree(tmp_path):
    """CONTROL. A branch that republished unconditionally would pass the test
    above and rewrite four files every night for every certificate."""
    domain, domain_dir = _certificate_on_disk(tmp_path)
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
        (domain_dir / name).write_bytes(b'NEW-' + name.encode())
    before = {p.name: p.stat().st_mtime_ns
              for p in domain_dir.glob('*.pem')}
    manager = _manager(tmp_path)

    result = manager._reconcile_without_renewal(domain, domain_dir,
                                                {'domain': domain})

    assert result['repaired'] is None
    after = {p.name: p.stat().st_mtime_ns for p in domain_dir.glob('*.pem')}
    assert after == before


def test_the_renewed_branch_publishes_stamps_and_reports(tmp_path):
    domain, domain_dir = _certificate_on_disk(tmp_path)
    manager = _manager(tmp_path)
    metadata = {'domain': domain}

    result = manager._publish_renewed_certificate(
        domain, domain_dir, metadata, domain_dir / 'metadata.json')

    assert result == {'success': True, 'renewed': True, 'domain': domain,
                      'message': 'Certificate renewed successfully'}
    assert (domain_dir / 'cert.pem').read_bytes() == b'NEW-cert.pem'
    assert metadata['renewed_at'], 'the renewal was not stamped'
    on_disk = json.loads((domain_dir / 'metadata.json').read_text())
    assert on_disk['renewed_at'] == metadata['renewed_at'], (
        'the stamp reached the caller but not the file')


def test_the_failure_branch_always_raises(tmp_path):
    """It returns nothing, so a caller that forgot to let it propagate would
    carry on with None rather than a plausible-looking result dict."""
    manager = _manager(tmp_path)
    finished = MagicMock()
    finished.returncode = 1
    finished.stderr = 'Detail: some problem'

    with pytest.raises(RuntimeError, match='Renewal failed'):
        manager._renewal_failed('unit.example.com', finished,
                                {'ca_provider': 'letsencrypt'}, 'dns-01')


def test_the_failure_branch_reports_the_redacted_stderr(tmp_path):
    """certbot's stderr can carry the ACME account URI and other material the
    create path already strips before logging or surfacing it."""
    manager = _manager(tmp_path)
    finished = MagicMock()
    finished.returncode = 1
    finished.stderr = ('Detail: see https://acme-v02.api.letsencrypt.org/acme/'
                       'authz-v3/9876543210 for details')

    with pytest.raises(RuntimeError) as raised:
        manager._renewal_failed('unit.example.com', finished, {}, 'dns-01')

    from modules.core.utils import sanitize_certbot_stderr
    assert str(raised.value).endswith(
        sanitize_certbot_stderr(finished.stderr)) or \
        sanitize_certbot_stderr(finished.stderr) in str(raised.value)


# --- what the extraction must not have changed ----------------------------

def test_the_whole_path_still_carries_the_contract():
    """The extraction moved code; it must not have moved the promises. Every
    key the route reads still appears somewhere on the renewal path."""
    source = renewal_path_source()

    for key in ('success', 'renewed', 'domain', 'message', 'storage_warning'):
        assert f"'{key}'" in source, f'{key} left the renewal path'
    # And the three things the path must still do, named rather than implied.
    for call in ('_publish_flat_files', '_store_in_backend', '_write_pfx',
                 '_invalidate_certificate_info_cache'):
        assert call in source, f'{call} left the renewal path'
