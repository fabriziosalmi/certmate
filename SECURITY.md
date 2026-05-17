# Security Policy

CertMate handles TLS private keys, ACME account credentials, and DNS-provider
API tokens. We take security reports seriously and treat them as the highest
priority class of issue in this project.

## Supported versions

Only the latest minor release line receives security fixes. Operators running
older lines should upgrade to the latest patch on `2.6.x` before reporting —
fixes for retired lines are out of scope.

| Version  | Supported          |
| -------- | ------------------ |
| `2.6.x`  | Yes                |
| `< 2.6`  | No (please upgrade) |

The supported line moves forward with each `2.x.0` release. When `2.7.0` ships,
`2.6.x` is retired the day `2.7.0` is tagged.

## Reporting a vulnerability

**Do not open a public GitHub issue or pull request for security reports.**
Public disclosure before a fix is available puts every operator running
CertMate at risk.

### Preferred channel — GitHub Private Vulnerability Reporting

Open a private security advisory:
<https://github.com/fabriziosalmi/certmate/security/advisories/new>

This is the recommended path. It keeps the report private, gives both sides a
durable record, lets the maintainer coordinate a fix in a private fork, and
the published advisory becomes the CVE record once a fix ships.

### Fallback channel — email

If you cannot use GitHub advisories (no GitHub account, the form is
unavailable, the bug is in the advisory flow itself), email
**fabrizio.salmi@gmail.com** with:

- A descriptive subject prefixed with `[certmate-security]`
- The CertMate version you tested against (output of `docker image inspect`
  or the running container's `/health` endpoint includes the version)
- Reproduction steps or a proof-of-concept
- The impact you observed and the impact you expect

Encrypted email is welcome but not required.

## What to expect

| Stage | Target |
| ----- | ------ |
| Acknowledgement of the report | within 72 hours |
| Triage decision (accept / decline / need more info) | within 7 days |
| Fix landed on `main` (for accepted reports) | within 30 days for high/critical severity |
| Public advisory + release | coordinated with the reporter |

If a report sits in `accept` state for longer than the target above, send a
gentle nudge to the same channel.

## Scope

In scope:

- The CertMate application code in this repository (Python backend, JS
  dashboard, Flask routes, certbot integration, storage backends, deploy
  hooks).
- The Docker image published from this repository.
- The default configuration shipped in the repository.

Out of scope:

- Third-party dependencies whose vulnerabilities should be reported upstream
  (certbot, acme.sh, the Azure / AWS / GCP SDKs, etc.). We will of course
  pull in the fixed version once it lands upstream.
- Operator misconfiguration (running CertMate as root, exposing the
  dashboard on a public interface without auth, granting overly broad DNS
  API tokens, etc.). The documentation calls these out; if you find a
  scenario where the default configuration is unsafe, that *is* in scope.
- Issues that require physical access or local root on the host running
  CertMate.

## Coordinated disclosure

We coordinate disclosure with the reporter. For high or critical severity:

- A fix lands on a private branch.
- A release is prepared and the security advisory is drafted in parallel.
- The release tag, the advisory publication, and (where appropriate) the
  CVE request all go out together.
- The advisory credits the reporter unless they request anonymity.

Thank you for taking the time to make CertMate safer for the operators who
depend on it.
