"""The shipped systemd unit must be able to boot and to finish an issuance.

Docker is the exercised deployment surface; the systemd unit ships alongside it
and nothing ran it. It had drifted into a state where it could not work:

* gunicorn was started with no ``--timeout``, so it used the 30-second default
  while DNS-01 issuance routinely runs for minutes — certbot was reaped
  mid-issuance. The container image sets 300 for exactly this reason.
* ``ProtectSystem=strict`` with a ``ReadWritePaths`` covering only two of the
  four directories the startup writeability probe requires, so the service
  raised at boot instead of starting.
* It shipped a placeholder credential, identical on every installation that
  never changed it.

These tests pin the unit against the application's own requirements rather than
against a copy of them (#653, #654).
"""
import ast
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / 'certmate.service'
FACTORY = ROOT / 'modules' / 'core' / 'factory.py'


def _unit_directives():
    """Map directive -> list of values, ignoring comments."""
    out = {}
    for raw in UNIT.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('['):
            continue
        if '=' not in line:
            continue
        key, _, value = line.partition('=')
        out.setdefault(key.strip(), []).append(value.strip())
    return out


def _dirs_the_startup_probe_requires():
    """The directory labels factory.py's boot writeability probe checks.

    Read from the application rather than restated here: if a fifth directory
    is ever added to that probe, this test fails until the unit grants it,
    which is the drift that stopped the service booting.

    Parsed with ast rather than a regex so that reformatting the source (quote
    style, wrapping) cannot make this silently stop deriving the real list.
    """
    tree = ast.parse(FACTORY.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == 'required'
                   for t in node.targets):
            continue
        if not isinstance(node.value, ast.List):
            continue
        labels = [
            elt.elts[0].value
            for elt in node.value.elts
            if isinstance(elt, ast.Tuple) and elt.elts
            and isinstance(elt.elts[0], ast.Constant)
            and isinstance(elt.elts[0].value, str)
        ]
        if labels:
            return labels
    raise AssertionError(
        "could not find the startup writeability probe's directory list")


def test_gunicorn_is_given_a_timeout_long_enough_for_issuance():
    exec_start = _unit_directives()['ExecStart'][0]
    assert '--timeout' in exec_start, (
        "gunicorn defaults to a 30s worker timeout; DNS-01 issuance takes "
        "minutes, so without an explicit --timeout certbot is killed mid-run"
    )


def _effective_exec_start_timeout():
    """The timeout ExecStart actually passes to gunicorn.

    Resolves a ${VAR} reference through the unit's own Environment=, because
    asserting only that the variable is declared would pass while ExecStart
    hard-coded a different value and left the service misconfigured.
    """
    directives = _unit_directives()
    exec_start = directives['ExecStart'][0]
    match = re.search(r'--timeout\s+(\S+)', exec_start)
    assert match, "ExecStart passes no --timeout"
    value = match.group(1)

    ref = re.fullmatch(r'\$\{(\w+)\}|\$(\w+)', value)
    if ref:
        name = ref.group(1) or ref.group(2)
        for env in directives.get('Environment', []):
            key, _, env_value = env.partition('=')
            if key.strip() == name:
                return env_value.strip()
        raise AssertionError(
            f"ExecStart references ${{{name}}} but the unit never sets it, so "
            f"gunicorn would receive an empty timeout"
        )
    return value


def test_the_unit_timeout_matches_the_container():
    """CONTROL: the two deployment surfaces must not disagree on this value."""
    unit_timeout = _effective_exec_start_timeout()

    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
    container_timeout = re.search(r'ENV GUNICORN_TIMEOUT=(\d+)', dockerfile)
    assert container_timeout, "Dockerfile no longer states GUNICORN_TIMEOUT"
    assert unit_timeout == container_timeout.group(1), (
        f"systemd effectively passes {unit_timeout}, the image says "
        f"{container_timeout.group(1)} — the same workload needs the same "
        f"budget on both surfaces"
    )


def test_readwritepaths_covers_every_directory_the_app_requires_at_boot():
    # Whole paths, not substrings: granting only /opt/certmate/backups/unified
    # would satisfy a substring check while the directory the probe actually
    # writes to stayed read-only.
    granted = {
        Path(token).name
        for directive in _unit_directives().get('ReadWritePaths', [])
        for token in directive.split()
    }
    missing = [d for d in _dirs_the_startup_probe_requires()
               if d not in granted]
    assert not missing, (
        f"ProtectSystem=strict makes everything else read-only, and the boot "
        f"probe raises RuntimeError when a required directory is not writable. "
        f"Not granted: {missing}"
    )


def test_the_unit_ships_no_credential_value():
    """A credential committed here is identical on every install that never
    changed it."""
    for env in _unit_directives().get('Environment', []):
        key, _, value = env.partition('=')
        assert 'TOKEN' not in key.upper() or not value.strip(), (
            f"{key} carries a value in the shipped unit; secrets belong in an "
            f"operator-owned EnvironmentFile"
        )
