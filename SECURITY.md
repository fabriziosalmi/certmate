# Security Policy

CertMate handles TLS private keys, ACME account credentials, and DNS-provider
API tokens. We take security reports seriously and treat them as the highest
priority class of issue in this project.

## Supported versions

Only the latest minor release line receives security fixes. Operators running
older lines should upgrade to the latest patch on `2.21.x` before reporting —
fixes for retired lines are out of scope.

| Version   | Supported           |
| --------- | ------------------- |
| `2.21.x`  | Yes                 |
| `< 2.21`  | No (please upgrade) |

The supported line moves forward with each `2.x.0` release. With `2.21.0`
tagged, `2.18.x` and earlier are retired.

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

## Security model notes

### Deploy hooks are an admin-controlled execution surface

Deploy hooks run operator-configured shell commands on the CertMate host after a
successful issuance or renewal (to reload nginx/HAProxy, copy the certificate
into place, run custom scripts). This is **intentional**: a user with the
**admin** role can configure commands that CertMate then executes, so admin
access is equivalent to shell access on the host.

Hook commands are validated to reject shell metacharacters and references to
CertMate's own infrastructure secrets (`settings.json`, `api_bearer_token`,
`client_secret`, `vault_token`, `.env`). That validation is defence-in-depth
against accidental footguns — it is **not** a sandbox and is not intended to
contain a malicious admin. The issued certificate's own private key
(`privkey.pem`) is deliberately **not** blocked, because installing it is the
normal job of a deploy hook.

Treat the admin role as highly privileged: grant it only to trusted operators,
and prefer scoped, non-admin API keys for automation that only needs to create
or download certificates.

## Known dependency constraint

### GHSA-537c-gmf6-5ccf — vulnerable OpenSSL statically linked in `cryptography` wheels

CertMate currently pins `cryptography==46.0.7`, which is flagged HIGH by
GHSA-537c-gmf6-5ccf: wheels of `cryptography` prior to `48.0.1` statically
link an OpenSSL vulnerable to CVE-2026-45447 (heap use-after-free in
`PKCS7_verify()`, OpenSSL security advisory of 2026-06-09). The fixed
versions are `48.0.1` and later; there is no backported fix on the `46.x`
or `47.x` lines (`46.0.7` is the final `46.x` release).

**Why the bump is blocked.** The constraint chain, verified against PyPI
metadata and a clean-room install on 2026-07-07:

- `acme==3.3.0` requires `pyOpenSSL>=25.0.0`; `josepy==1.13.0` also depends
  on pyOpenSSL. These pins, together with `certbot==2.10.0`, are
  deliberately held (see issue #103).
- The first pyOpenSSL release whose metadata admits cryptography `48.x` is
  `26.2.0` (`cryptography>=46.0.0,<49`). The pinned `pyopenssl==26.0.0`
  caps at `<47`, and `26.1.0` caps at `<48`.
- pyOpenSSL `26.2.0` (2026-05-04) removed the long-deprecated
  `OpenSSL.crypto.X509Extension`.
- `acme==3.3.0` references `crypto.X509Extension` in the signature of
  `acme.crypto_util.gen_ss_cert()` without `from __future__ import
  annotations`, so the name is evaluated at import time. With
  `pyopenssl>=26.2.0`, `import acme.crypto_util` — and therefore every
  `certbot` invocation — fails with `AttributeError: module 'OpenSSL.crypto'
  has no attribute 'X509Extension'` (reproduced with
  `cryptography==48.0.1` + `pyopenssl==26.2.0`: `certbot --version`
  crashes).
- The same applies to `cryptography` `49.x`, which needs `pyopenssl>=26.3.0`.

In short: every cryptography version that fixes the GHSA requires a
pyOpenSSL that breaks the pinned ACME stack at import.

**Mitigation / actual exposure.** The vulnerable code path is
`PKCS7_verify()` (PKCS#7 / S/MIME signature verification):

- No CertMate code path reaches it. Nothing in `modules/` or `app.py`, nor
  in the pinned `certbot` / `acme` / `josepy` stack, performs PKCS#7 or
  S/MIME verification, and pyca/cryptography's Python API does not expose
  PKCS#7 signature verification at all (it can only create and serialize
  PKCS#7 structures). The vulnerable function is present in the statically
  linked library but unreachable from CertMate.
- The operations that do run inside the statically linked OpenSSL —
  X.509 parsing and issuance, CSR handling, the private CA, client
  certificates, OCSP/CRL checks, and audit-log signing — do not touch the
  PKCS#7 routines.
- CertMate's TLS network I/O (gunicorn/Flask, `requests` to ACME and DNS
  provider APIs) uses Python's `ssl` module, which links the interpreter's
  own OpenSSL, not the copy inside the cryptography wheel.

**Fix path.** The certbot 5.x migration epic (issue #103): newer `acme`
releases drop the removed pyOpenSSL API but require `josepy>=2` and a newer
certbot line. Once that migration lands, `pyopenssl>=26.2.0` and
`cryptography>=48.0.1` unblock together, and the Dependabot alerts for
GHSA-537c-gmf6-5ccf can be closed. Until then the alerts remain open by
choice, not by oversight.

## Coordinated disclosure

We coordinate disclosure with the reporter. For high or critical severity:

- A fix lands on a private branch.
- A release is prepared and the security advisory is drafted in parallel.
- The release tag, the advisory publication, and (where appropriate) the
  CVE request all go out together.
- The advisory credits the reporter unless they request anonymity.

Thank you for taking the time to make CertMate safer for the operators who
depend on it.
