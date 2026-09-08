# Security Policy

CertMate handles TLS private keys, ACME account credentials, and DNS-provider
API tokens. We take security reports seriously and treat them as the highest
priority class of issue in this project.

## Supported versions

Only the latest minor release line receives security fixes. Operators running
older lines should upgrade to the latest patch on `2.29.x` before reporting —
fixes for retired lines are out of scope.

| Version   | Supported           |
| --------- | ------------------- |
| `2.29.x`  | Yes                 |
| `< 2.29`  | No (please upgrade) |

The supported line moves forward with each `2.x.0` release; everything below
it is retired at that moment. This file is updated by the release tooling, so
the line above is always the one currently receiving fixes.

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

### Keeping credentials out of `settings.json`

DNS provider API tokens and the OIDC client secret are stored in
`settings.json` as cleartext JSON, in a file written `0600`. The permission is
correct and is not the interesting part: that file is what gets backed up,
copied between hosts, mounted into a container and attached to a bug report.

Any of those fields can instead **name** where its value lives, the way
`API_BEARER_TOKEN_FILE` already does for the bearer token. Beside a field, write
`<field>_file` with a path or `<field>_env` with a variable name:

```json
{
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "prod": { "api_token_file": "/run/secrets/cloudflare_api_token" }
      }
    }
  },
  "oidc": { "client_secret_env": "CERTMATE_OIDC_CLIENT_SECRET" }
}
```

The value is read at the moment it is used — to run certbot, or to build the
OIDC client — and is never written back, so a settings save does not turn a
reference into a stored secret. Listing accounts and rendering the settings page
do not read it at all: an account counts as configured because the reference is
present, not because the secret could be read.

Details worth knowing before relying on it:

- A reference **wins over** a value in the same field. Adding `api_token_file`
  next to an existing `api_token` switches over immediately; the stale literal
  is ignored rather than silently preferred.
- `_file` wins over `_env` if both are present.
- Trailing whitespace is stripped, because `docker secret` and
  `kubectl create secret --from-file` both produce files ending in a newline.
- A reference that resolves to nothing is **refused**, not treated as empty. A
  missing mount fails issuance with a log line naming the field and the path,
  rather than sending a blank token to the DNS provider.

This does not encrypt anything and is not a substitute for protecting the data
volume. What it does is let the highest-value secrets live wherever the
deployment already keeps secrets, instead of in the file that travels.

## Known dependency constraint

CertMate pins `cryptography==46.0.7` and `pyopenssl==26.0.0`. Every version
that would clear the advisories below needs a pyOpenSSL that breaks the pinned
ACME stack, so the pins are held deliberately: the alerts are open by choice,
not by oversight. One reason blocks all of them, and one fix clears all of
them (issue #103); both are described once, after the advisories.

**Four advisories are held by this constraint.** The first is a flaw in the
OpenSSL statically linked into the `cryptography` wheel; the other three,
published 2026-08-03, are in `cryptography`'s own code and are reached only
through specific APIs. That difference is what makes the reachability argument
below hold for the three, and it is why they are analysed separately rather
than folded into the first.

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

**Re-verified 2026-08-08 against `cryptography==50.0.0` (Dependabot #516), and
the situation has become more dangerous, not less.**

- **pip now accepts the combination.** `pip install certbot==2.10.0
  josepy==1.13.0 cryptography==50.0.0` resolves and installs cleanly, pulling
  `pyopenssl==26.4.0`. The dependency metadata no longer refuses it, so the
  guard rail that used to stop this bump at resolution time is gone. The
  failure has moved from install time to run time: an image builds green and
  then dies the first time it tries to issue a certificate.
- **The failure is now `X509Req`, not `X509Extension`.** pyOpenSSL 26.4.0 has
  dropped both (`hasattr(OpenSSL.crypto, 'X509Req') == False`), and `X509Req`
  is the one that breaks first.
- **`certbot` itself no longer starts.** Not merely `acme.crypto_util`:
  `certbot --version` raises `AttributeError: module 'OpenSSL.crypto' has no
  attribute 'X509Req'` from `certbot/_internal/main.py:21`. CertMate drives
  certbot as a CLI subprocess, so this is the entire issuance path, not a
  library nicety.

So the pin is now doing more work than it was, not less: nothing upstream
enforces it any more. Do not relax `cryptography` or `pyopenssl` here without
re-running that clean-room install and confirming `certbot --version` still
answers. The real fix remains the certbot 5.x stack migration (#103).

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

### The 2026-08-03 advisories in `cryptography`'s own code

Three further advisories against `cryptography <= 46.0.7` were published on
2026-08-03. They are a different shape from the one above: the defect is in
`cryptography`'s own Rust and Python code, not in the linked OpenSSL, so each
is reached through one named API and through nothing else.

| Advisory | Severity | Defect | Reached through | First fixed in |
| --- | --- | --- | --- | --- |
| GHSA-g6cj-pr64-35w5 | HIGH | duplicate self-signed intermediates cause exponential X.509 path building | `cryptography.x509.verification` | 49.0.0 |
| GHSA-jwv3-5hgf-82ww | HIGH | PKCS#7 `EnvelopedData` decryption exposes a Bleichenbacher oracle | the PKCS#7 decryption API | 50.0.0 |
| GHSA-m2h6-j472-rp4c | MEDIUM | the verifier accepts wildcard DNS names, allowing escape from `permittedSubtrees` name constraints | `cryptography.x509.verification` | 49.0.0 |

**Actual exposure: none of the three is reachable.** Two need the X.509
verifier (`PolicyBuilder` / `ClientVerifier` / `ServerVerifier`), one needs
PKCS#7 `EnvelopedData` decryption. Neither API is called anywhere in the
shipped stack — verified across `modules/`, `app.py` and the pinned
`certbot==2.10.0` / `acme==3.3.0` / `josepy==1.13.0`, none of which references
`x509.verification`, `PolicyBuilder`, `ClientVerifier`, `ServerVerifier`,
`pkcs7` or `EnvelopedData`.

What CertMate does use from `cryptography` is X.509 parsing and building,
`Fernet`, hashes, key serialization, RSA and Ed25519 key generation, and
PBKDF2. The `.pfx` export
(`modules/core/storage_backends.py:175`) calls `serialization.pkcs12`, which
is PKCS#12 — a different structure and a different code path from the PKCS#7
`EnvelopedData` decryption the Bleichenbacher advisory describes. CertMate
never decrypts PKCS#7 at all; it only ever writes PKCS#12.

**The constraint has tightened, not loosened.** Clearing all three needs
`cryptography>=50.0.0`, and 50.0.0 is the exact version the re-verification
above proves fatal: it installs cleanly and then `certbot --version` dies on
`X509Req`. The version that would close these alerts is the version that
breaks issuance.

**Fix path.** The certbot 5.x migration epic (issue #103): newer `acme`
releases drop the removed pyOpenSSL API but require `josepy>=2` and a newer
certbot line. Once that migration lands, `pyopenssl>=26.2.0` and
`cryptography>=48.0.1` unblock together, and all four Dependabot alerts above
can be closed. Until then they remain open by choice, not by oversight, and
this section is the record of that choice: an advisory against `cryptography`
that is not listed here has not been assessed, and should be treated as new.

### How this list is kept complete

Two checks reconcile this section with reality, because a list that claims to
be complete and is not is worse than no list.

- **`scripts/check_advisories.py`** (scheduled) asks GitHub which Dependabot
  alerts the repository is carrying — open, or dismissed as `tolerable_risk` —
  and fails when one of them is not named above. It was written after this
  section documented one advisory while three more, published against the same
  pin, sat open and unmentioned through a release.
- **`scripts/check_resolved_advisories.py`** (on every pull request, inside
  `security-scan`) asks OSV about the packages that are **actually installed in
  the image**, captured with `pip freeze` from inside it, and fails the same
  way.

The second exists because the first cannot see what ships. Dependabot reads the
manifests, and so does any scanner pointed at the repository; both then resolve
each transitive constraint to the **lowest version it admits**, which is not
what `pip install` produces. Measured against v2.29.0 on 2026-09-08:

| package | manifest scan reports | actually in the image |
|---|---|---|
| `pyjwt` | 2.9.0 — 7 advisories | **2.13.0 — none** |
| `requests` | 2.9.2 — 5 | **2.34.2 — none** |
| `pygments` | 2.9.0 — 2 | **not installed** |
| `idna` | 3.9.0 — 1 | **3.19 — none** |
| `filelock` | 3.9.1 — 2 | **3.32.5 — none** |
| `protobuf` | 4.25.9 — 1 | **7.36.1 — none** |

All eighteen were false positives. `pyjwt` is the one worth naming: it arrives
transitively through `msal` (Azure DNS), the floor `msal` declares is 2.9.0,
and an audit reported those seven advisories as shipping in the default image.
They do not — so no reachability argument is needed for them, and none is
recorded here. **If you are looking at a manifest-level alert against a package
that is not in the table above, check the version in the image before assessing
it.**

Scanning the resolved set gives the answer this section can actually stand
behind: four advisories, all `cryptography==46.0.7`, all documented above.

## Supply-chain posture for Python dependencies

This section exists so the absence of hash pinning is a **decision on record**
rather than an oversight (issue #686). What CertMate does and does not claim
about the packages in its images:

**What is guaranteed.** `requirements.lock` and `requirements-minimal.lock`
hold the **fully resolved** install set for the two main variants — every
transitive package at an exact version — and the image installs from them. That
part is no longer build-day luck: `requirements.txt` pins 42 packages and
resolves to 118, so 76 of the packages in a published image used to be whatever
the index served that day, with no record in the repository of which. The locks
are generated by pip's own resolver inside the pinned base image
(`scripts/regenerate_lockfiles.sh`), never by hand.

Every direct dependency in `requirements.txt` and
`requirements-minimal.txt` is pinned to an exact version, and CI fails if a
package is pinned to two different versions across files, if a certbot plugin
is pinned above the certbot pin, or if any advertised
`EXTRA_REQUIREMENTS` combination stops resolving. The base image is pinned by
digest. Published images carry an SPDX SBOM and SLSA provenance, so what
shipped is auditable after the fact. Extras layers install under
`-c ${REQUIREMENTS_FILE}`, so an optional backend cannot move a pin the base
layer holds deliberately.

**What is not guaranteed.** The locks carry **no hashes**. Nothing verifies that
the wheels installed are the wheels that were reviewed. A version pin — even a
complete, transitive one — does not defend against a **re-published or
compromised artifact at that same version**. PyPI does not allow re-uploading a
filename, so this requires a compromise of the index or of the maintainer's
account — but it is a real class of attack and this project does not currently
detect it. The optional variants (the DNS and storage sets) have no lock at all
and still resolve at build time; only the two main variants are locked.

**Why no hashes, specifically.** `--require-hashes` is all-or-nothing per
install: every requirement, including every transitive one, must carry a hash or
pip refuses the file. That collides with how these images are built — 12
requirements files and a layered `EXTRA_REQUIREMENTS` model whose documented
combinations multiply rather than compose, so the hashes would be needed per
variant and per platform, not once.
Doing it partially is worse than not doing it: a half-hashed set fails installs
with errors that name the wrong cause, and the reliable response is to route
around the mechanism with `--no-deps` or a second unhashed install. The project
would then carry the maintenance cost of lockfiles *and* the false confidence
of a guard people bypass.

One reason previously given here has since been **measured and withdrawn**:
"two architectures resolving different binary wheels". For `requirements.txt`
and `requirements-minimal.txt` the resolution is byte-identical on `linux/amd64`
and `linux/arm64`, which is why one lockfile per variant is enough.
`scripts/regenerate_lockfiles.sh` resolves both architectures and refuses to
write if they ever disagree, so this stays a measurement rather than a memory.
It does not resolve the hash question — a hash is per *wheel*, and identical
versions can still mean different wheels — but the reason it was leaning on was
not true.

**Keeping the locks honest.** Installing from a lock means a bump to
`requirements.txt` has no effect until the lock is regenerated: a security patch
could merge, go green, and never reach the image.
`tests/test_the_transitive_set_is_written_down.py` fails when a direct pin and
its lock disagree, so that is a red check rather than a silent non-delivery.
The opposite risk — a transitive frozen at a version that later turns out to be
vulnerable — is covered by `scripts/check_resolved_advisories.py`, which asks
OSV about the set actually installed in the built image on every build. Refresh
the locks with `scripts/regenerate_lockfiles.sh` whenever a pin moves, and
whenever that advisory scan reports something the direct pins do not explain.

**A rebuild is not expected to be bit-identical.** The runtime stage installs
three OS packages (`bash`, `curl`, `tini`) with an unpinned `apt-get install`,
so two builds of the same commit, days apart, can carry different versions of
them. That is deliberate: pinning the three would break the build on every
base-image bump, and a genuinely reproducible OS layer needs a snapshot mirror,
which is a project rather than a line. The consequence is recorded here so
nobody reads a digest mismatch between two builds of one commit as evidence of
tampering — it is the expected outcome. What the image actually contains is
answerable from the SBOM that ships with it.

**What the image contains is an allowlist, not a denylist.** The runtime stage
names what it copies — `app.py`, `modules/`, `templates/`, `static/`,
`scripts/` and the requirements files — rather than copying the tree and
subtracting. Until v2.29.0 it did the latter, and the published image carried
the Helm chart, the client SDK sources, the MCP server, the monitoring assets,
a demo directory and a licensing PDF. None of it was reachable by the process,
but a denylist ships whatever nobody remembered to add to it.
`tests/test_image_ships_only_what_it_runs.py` checks the built image, not the
Dockerfile.

**If you are threat-modelling against this**, the honest summary is:
auditability, not integrity. The SBOM tells you what you got; it does not prove
it is what was intended.

## Coordinated disclosure

We coordinate disclosure with the reporter. For high or critical severity:

- A fix lands on a private branch.
- A release is prepared and the security advisory is drafted in parallel.
- The release tag, the advisory publication, and (where appropriate) the
  CVE request all go out together.
- The advisory credits the reporter unless they request anonymity.

Thank you for taking the time to make CertMate safer for the operators who
depend on it.
