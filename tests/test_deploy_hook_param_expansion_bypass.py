"""
Regression test for the deploy-hook validator parameter-expansion bypass.

The previous safe-vars regex `\\$\\{?CERTMATE_[A-Z_]+\\}?` accepted partial
brace forms: `${CERTMATE_FOO` (no close) AND `${CERTMATE_FOO}` (closed) both
matched. Bash parameter-expansion operators always sit between the variable
name and the closing brace, so when the operator+value+close was appended
the stripping regex still consumed `${CERTMATE_FOO` and left only the tail:

  Input:        ${CERTMATE_FOO:-/etc/passwd}
  After strip:  __SAFE__:-/etc/passwd}
  Dangerous:    nothing matches
  -> validator returns OK; at runtime bash expands to /etc/passwd if
     CERTMATE_FOO is unset.

The fix requires the closing brace IMMEDIATELY after the name. None of the
parameter-expansion forms match safe_vars, the unchanged `\\$\\{` rule in
the dangerous-shell regex catches them, and the validator rejects.

This test pins both directions:
  - bypass attempts (must BLOCK)
  - legitimate $CERTMATE_FOO / ${CERTMATE_FOO} forms (must PASS)
"""
from __future__ import annotations

import pytest

from modules.core.deployer import DeployManager


# Parameter expansion bypass attempts that were silently accepted before the fix.
BYPASS_CASES = [
    "echo ${CERTMATE_FOO:-/etc/passwd}",          # default value (most exploitable)
    "echo ${CERTMATE_FOO:=/etc/shadow}",          # assign default
    "echo ${CERTMATE_FOO:+anything}",             # conditional substitution
    "echo ${CERTMATE_FOO:?error}",                # error if unset
    "echo ${CERTMATE_FOO//a/b}",                  # in-string substitution
    "echo ${CERTMATE_FOO%y}",                     # trailing strip
    "echo ${CERTMATE_FOO#x}",                     # leading strip
    "cat ${CERTMATE_PATH:-/etc/shadow}",          # full attack: arbitrary read
    "echo ${CERTMATE_FOO",                        # unclosed brace (was matched before)
    "echo ${UNRELATED_VAR}",                      # unrelated var (was always blocked)
]

# Legitimate uses CertMate documents and that real hooks rely on.
LEGITIMATE_CASES = [
    "echo $CERTMATE_DOMAIN",
    "echo ${CERTMATE_DOMAIN}",
    "echo $CERTMATE_FULLCHAIN_PATH",
    "echo ${CERTMATE_FULLCHAIN_PATH}",
    "cp $CERTMATE_CERT_PATH /etc/nginx/ssl/cert.pem",
    "cp ${CERTMATE_CERT_PATH} /etc/nginx/ssl/cert.pem",
    "/usr/sbin/nginx -s reload",
    "docker exec nginx nginx -s reload",
    "echo $CERTMATE_FOO_BAR_BAZ",                 # underscores in name
    "echo ${CERTMATE_FOO}EXTRA",                  # concatenation
]


@pytest.mark.parametrize("command", BYPASS_CASES, ids=lambda s: s[:60])
def test_param_expansion_bypass_attempts_are_blocked(command):
    ok, reason = DeployManager._is_command_safe(command)
    assert ok is False, (
        f"Validator must block {command!r} — it would expand at runtime "
        f"to a path outside CertMate's intended env vars"
    )
    assert reason is not None
    assert "metacharacter" in reason.lower() or "shell" in reason.lower(), (
        f"Reason should mention the metacharacter / shell rule, got: {reason!r}"
    )


@pytest.mark.parametrize("command", LEGITIMATE_CASES, ids=lambda s: s[:60])
def test_legitimate_certmate_var_references_still_pass(command):
    ok, reason = DeployManager._is_command_safe(command)
    assert ok is True, (
        f"Regression: legitimate command {command!r} must still pass "
        f"(rejected with reason: {reason!r})"
    )
    assert reason is None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
